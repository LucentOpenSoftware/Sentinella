//! Scan cache — avoid rescanning files that haven't changed.
//!
//! Two-tier: fast in-memory HashMap + persistent SQLite backing store.
//! On startup, loads from SQLite. On record, writes to both.
//! Survives daemon restarts — no need to rescan 100K files.
//!
//! Key: (path, size, mtime) → last scan result + signature DB generation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread;
use std::time::SystemTime;

/// Maximum entries in memory. LRU eviction at this limit.
const MAX_MEMORY_ENTRIES: usize = 50_000;
const DB_WRITE_QUEUE_CAP: usize = 4096;

/// ☠️ R6-LETHAL: bytes of file content folded into the cache key.
/// Without this, the cache key was `(path, size, mtime)` only — and a
/// user with write access to their own file could overwrite the
/// contents with malware, pad/truncate to the same size, then restore
/// the mtime via `SetFileTime()`. The watcher would hit the cache, get
/// "clean", and skip both ARGUS and ClamAV. Total scanner bypass.
///
/// Reading 64KB and SHA-256-hashing it costs ~0.1ms — cheap compared to
/// the 100-500ms ARGUS scan it would replace, but defeats the trivial
/// in-place overwrite attack because the attacker now also has to match
/// the first 64KB of the original benign bytes (which on real PE/ELF
/// payloads contains code, imports, symbol tables — not just a header).
const FINGERPRINT_PREFIX_BYTES: usize = 64 * 1024;

/// Truncated SHA-256 stored in the cache. 128 bits is enough to make
/// brute-force preimage attacks against a single file infeasible while
/// keeping the on-disk row compact.
type ContentFingerprint = [u8; 16];

fn compute_content_fingerprint(path: &Path) -> Option<ContentFingerprint> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; FINGERPRINT_PREFIX_BYTES];
    let mut total_read = 0;
    while total_read < FINGERPRINT_PREFIX_BYTES {
        match file.read(&mut buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(_) => return None,
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(&buf[..total_read]);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    Some(out)
}

/// Cache integrity seed — keyed hash (not cryptographic HMAC) to detect
/// externally injected/modified cache entries. Uses DefaultHasher (SipHash).
/// An attacker who runs `sqlite3 scan_cache.db "UPDATE scan_cache SET clean=1"`
/// will have entries with invalid hashes → cache miss → file rescanned.
///
/// Not a security boundary against adversaries with vault key access.
/// Detects casual tampering and accidental corruption.
static CACHE_INTEGRITY_SECRET: std::sync::OnceLock<[u8; 16]> = std::sync::OnceLock::new();

/// Set the cache integrity secret (called during daemon startup).
pub fn set_cache_integrity_secret(secret: &[u8]) {
    let mut key = [0u8; 16];
    for (i, byte) in secret.iter().take(16).enumerate() {
        key[i] = *byte;
    }
    let _ = CACHE_INTEGRITY_SECRET.set(key);
}

/// Compute integrity hash for a cache entry.
/// Returns a u64 hash that must match for the entry to be trusted.
fn cache_entry_hash(
    path: &std::path::Path,
    size: u64,
    mtime: u64,
    clean: bool,
    content_fp: &ContentFingerprint,
) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let secret = CACHE_INTEGRITY_SECRET.get().copied().unwrap_or([0u8; 16]);

    let mut hasher = DefaultHasher::new();
    secret.hash(&mut hasher);
    path.to_string_lossy().as_ref().hash(&mut hasher);
    size.hash(&mut hasher);
    mtime.hash(&mut hasher);
    clean.hash(&mut hasher);
    content_fp.hash(&mut hasher);
    secret.hash(&mut hasher); // Double-keyed.
    hasher.finish()
}

#[derive(Debug, Clone)]
struct CacheEntry {
    size: u64,
    mtime: u64,
    /// R6-LETHAL: short content fingerprint folded into the cache key so
    /// in-place tampering (overwrite + SetFileTime to preserve mtime+size)
    /// produces a cache miss.
    content_fp: ContentFingerprint,
    clean: bool,
    sig_generation: u64,
    last_accessed: u64,
}

/// Thread-safe scan result cache with optional SQLite persistence.
pub struct ScanCache {
    inner: Mutex<CacheInner>,
    db_tx: Option<SyncSender<DbWrite>>,
}

struct CacheInner {
    entries: HashMap<PathBuf, CacheEntry>,
    sig_generation: u64,
    access_counter: u64,
    hits: u64,
    misses: u64,
    db_write_drops: u64,
}

enum DbWrite {
    Record {
        path: PathBuf,
        size: u64,
        mtime: u64,
        content_fp: ContentFingerprint,
        clean: bool,
        sig_generation: u64,
    },
    Invalidate {
        sig_generation: u64,
    },
}

impl ScanCache {
    /// Create a new in-memory-only cache.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                entries: HashMap::new(),
                sig_generation: 1,
                access_counter: 0,
                hits: 0,
                misses: 0,
                db_write_drops: 0,
            }),
            db_tx: None,
        }
    }

    /// Create a cache with SQLite persistence at the given path.
    /// Falls back to in-memory if SQLite fails.
    pub fn with_persistence(db_path: &Path) -> Self {
        let db = match open_cache_db(db_path) {
            Ok(conn) => {
                tracing::info!(path = %db_path.display(), "scan cache database opened");
                Some(conn)
            }
            Err(e) => {
                tracing::warn!(%e, "scan cache persistence unavailable — using memory only");
                None
            }
        };

        // Load existing entries from SQLite.
        let mut entries = HashMap::new();
        let mut sig_generation = 1u64;
        if let Some(ref conn) = db {
            match load_from_db(conn) {
                Ok((loaded, loaded_gen)) => {
                    let count = loaded.len();
                    entries = loaded;
                    sig_generation = loaded_gen;
                    tracing::info!(
                        entries = count,
                        generation = loaded_gen,
                        "scan cache loaded from disk"
                    );
                }
                Err(e) => {
                    tracing::warn!(%e, "failed to load scan cache from disk");
                }
            }
        }

        let db_tx = db.map(start_db_writer);

        Self {
            inner: Mutex::new(CacheInner {
                entries,
                sig_generation,
                access_counter: 0,
                hits: 0,
                misses: 0,
                db_write_drops: 0,
            }),
            db_tx,
        }
    }

    /// Check a file using already-fetched metadata to avoid duplicate stat calls.
    ///
    /// R6-LETHAL: validates a short content fingerprint in addition to
    /// (size, mtime). A user-mode attacker can spoof size+mtime via
    /// `SetFileTime()` on a file they own, so without the fingerprint
    /// the cache was a trivial scanner bypass.
    pub fn check_with_metadata(&self, path: &Path, meta: &std::fs::Metadata) -> Option<bool> {
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Quick pre-check: lock, look up by path, compare cheap fields
        // first. Only compute the fingerprint if cheap fields match —
        // that way a cache MISS still costs zero file I/O.
        // Capture `clean` here (under the lock) alongside the fingerprint.
        // Re-fetching `clean` after the lock is released is a fail-open bug:
        // if the entry is LRU-evicted in the fingerprint-compute window,
        // `get(path)` returns None and the old `unwrap_or(true)` reported a
        // vanished entry as CLEAN → scanner skip. Snapshotting `clean` now
        // turns an eviction race into a correct cache miss.
        let (expected_fp, cached_clean, current_access) = {
            let mut inner = self.inner.lock().ok()?;
            inner.access_counter += 1;
            let current_gen = inner.sig_generation;
            let current_access = inner.access_counter;
            match inner.entries.get(path) {
                Some(entry)
                    if entry.size == size
                        && entry.mtime == mtime
                        && entry.sig_generation == current_gen =>
                {
                    (entry.content_fp, entry.clean, current_access)
                }
                _ => {
                    inner.misses += 1;
                    return None;
                }
            }
        };

        // Compute fingerprint with lock released.
        let actual_fp = compute_content_fingerprint(path)?;
        if actual_fp != expected_fp {
            // mtime+size matched but content differs → in-place tamper.
            // Treat as miss; the caller will re-scan.
            tracing::debug!(
                path = %path.display(),
                "scan cache: content fingerprint mismatch — re-scanning (mtime+size preserved tamper attempt?)"
            );
            if let Ok(mut inner) = self.inner.lock() {
                inner.misses += 1;
                // Drop the stale entry so a future record_with_metadata
                // does not double-evict.
                inner.entries.remove(path);
            }
            return None;
        }

        // Hit — bump LRU stamp. Return the `clean` value snapshotted under
        // the first lock; an entry evicted in the race is irrelevant since
        // we already proved content matches what was cached.
        let mut inner = self.inner.lock().ok()?;
        if let Some(entry) = inner.entries.get_mut(path) {
            entry.last_accessed = current_access;
        }
        inner.hits += 1;
        Some(cached_clean)
    }

    /// Record using already-fetched metadata to avoid duplicate stat calls.
    pub fn record_with_metadata(&self, path: &Path, meta: &std::fs::Metadata, clean: bool) {
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // R6-LETHAL: compute fingerprint before taking the lock so the
        // file I/O doesn't serialize cache writers. If the file becomes
        // unreadable here (race with deletion), skip the record — the
        // next access will scan fresh.
        let Some(content_fp) = compute_content_fingerprint(path) else {
            return;
        };

        let mut inner = match self.inner.lock() {
            Ok(i) => i,
            Err(_) => return,
        };

        inner.access_counter += 1;

        // Evict oldest in-memory entries if at capacity.
        if inner.entries.len() >= MAX_MEMORY_ENTRIES {
            let threshold = inner
                .access_counter
                .saturating_sub(MAX_MEMORY_ENTRIES as u64 / 2);
            inner.entries.retain(|_, e| e.last_accessed > threshold);
        }

        let current_gen = inner.sig_generation;
        let current_acc = inner.access_counter;

        // Write to memory.
        inner.entries.insert(
            path.to_path_buf(),
            CacheEntry {
                size,
                mtime,
                content_fp,
                clean,
                sig_generation: current_gen,
                last_accessed: current_acc,
            },
        );

        // Write to SQLite (fire-and-forget — don't block scan on disk I/O failure).
        drop(inner);

        if let Some(tx) = &self.db_tx {
            match tx.try_send(DbWrite::Record {
                path: path.to_path_buf(),
                size,
                mtime,
                content_fp,
                clean,
                sig_generation: current_gen,
            }) {
                Ok(_) => {}
                Err(TrySendError::Full(_)) => {
                    if let Ok(mut inner) = self.inner.lock() {
                        inner.db_write_drops += 1;
                    }
                }
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
    }

    /// Invalidate all cache entries (e.g., after signature update).
    pub fn invalidate_all(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.sig_generation += 1;
            let new_gen = inner.sig_generation;
            drop(inner);
            self.enqueue_invalidation(new_gen);
            tracing::info!(generation = new_gen, "scan cache invalidated");
        }
    }

    /// Get cache statistics: (hits, misses, entries).
    pub fn stats(&self) -> (u64, u64, usize) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let _db_write_drops = inner.db_write_drops;
        (inner.hits, inner.misses, inner.entries.len())
    }

    fn enqueue_invalidation(&self, sig_generation: u64) {
        if let Some(tx) = &self.db_tx {
            match tx.try_send(DbWrite::Invalidate { sig_generation }) {
                Ok(_) => {}
                Err(TrySendError::Full(_)) => {
                    if let Ok(mut inner) = self.inner.lock() {
                        inner.db_write_drops += 1;
                    }
                    tracing::warn!("scan cache database queue full; dropped generation write");
                }
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  SQLite helpers
// ═══════════════════════════════════════════════════════════════

fn start_db_writer(conn: rusqlite::Connection) -> SyncSender<DbWrite> {
    let (tx, rx) = mpsc::sync_channel::<DbWrite>(DB_WRITE_QUEUE_CAP);
    let _ = thread::Builder::new()
        .name("scan-cache-db".into())
        .spawn(move || {
            while let Ok(write) = rx.recv() {
                match write {
                    DbWrite::Record {
                        path,
                        size,
                        mtime,
                        content_fp,
                        clean,
                        sig_generation,
                    } => {
                        if let Err(e) = write_to_db(
                            &conn,
                            &path,
                            size,
                            mtime,
                            &content_fp,
                            clean,
                            sig_generation,
                        ) {
                            tracing::debug!(%e, path = %path.display(), "scan cache db write failed");
                        }
                    }
                    DbWrite::Invalidate { sig_generation } => {
                        if let Err(e) = write_generation_to_db(&conn, sig_generation) {
                            tracing::debug!(%e, "scan cache generation write failed");
                        }
                    }
                }
            }
        });
    tx
}

fn open_cache_db(path: &Path) -> Result<rusqlite::Connection, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }
    let conn = rusqlite::Connection::open(path).map_err(|e| format!("open: {e}"))?;

    // WAL mode for concurrent reads.
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .map_err(|e| format!("pragma: {e}"))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scan_cache (
            path TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            mtime INTEGER NOT NULL,
            clean INTEGER NOT NULL,
            sig_generation INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            integrity_hash INTEGER NOT NULL DEFAULT 0,
            content_fp BLOB
        );
        CREATE TABLE IF NOT EXISTS cache_meta (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cache_gen ON scan_cache(sig_generation);",
    )
    .map_err(|e| format!("schema: {e}"))?;

    // D-3 fix: add integrity_hash column if upgrading from older schema.
    let _ = conn.execute(
        "ALTER TABLE scan_cache ADD COLUMN integrity_hash INTEGER NOT NULL DEFAULT 0",
        [],
    );
    // R6-LETHAL: add content_fp column if upgrading from older schema.
    let _ = conn.execute("ALTER TABLE scan_cache ADD COLUMN content_fp BLOB", []);

    Ok(conn)
}

fn load_from_db(
    conn: &rusqlite::Connection,
) -> Result<(HashMap<PathBuf, CacheEntry>, u64), String> {
    // Load generation.
    let sgen: u64 = conn
        .query_row(
            "SELECT value FROM cache_meta WHERE key = 'sig_generation'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(1) as u64;

    // Load entries for current generation with integrity verification.
    // D-3 fix: entries with invalid integrity_hash are REJECTED (cache miss).
    let mut stmt = conn
        .prepare(
            "SELECT path, size, mtime, clean, integrity_hash, content_fp FROM scan_cache WHERE sig_generation = ?1 LIMIT ?2",
        )
        .map_err(|e| format!("prepare: {e}"))?;

    let rows = stmt
        .query_map(
            rusqlite::params![sgen as i64, MAX_MEMORY_ENTRIES as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, i64>(3)? != 0,
                    row.get::<_, i64>(4).unwrap_or(0) as u64,
                    row.get::<_, Option<Vec<u8>>>(5).unwrap_or(None),
                ))
            },
        )
        .map_err(|e| format!("query: {e}"))?;

    let mut entries = HashMap::new();
    let mut counter = 0u64;
    let mut rejected = 0u64;
    for row in rows {
        if let Ok((path_str, size, mtime, clean, stored_hash, fp_blob)) = row {
            let path = PathBuf::from(&path_str);

            // R6-LETHAL: reject any row without a content fingerprint.
            // These would be either pre-upgrade entries (no fingerprint
            // recorded) or attacker-inserted rows. Either way we cannot
            // trust them — skip and let the next scan refresh.
            let fp_vec = match fp_blob {
                Some(v) if v.len() == 16 => v,
                _ => {
                    rejected += 1;
                    continue;
                }
            };
            let mut content_fp = [0u8; 16];
            content_fp.copy_from_slice(&fp_vec);

            // D-3 fix: verify integrity hash before trusting cache entry.
            // Bug R3-4: previously `stored_hash != 0` allowed an attacker to
            // bypass tamper detection via SQL `UPDATE scan_cache SET integrity_hash=0`
            // — entry would be accepted unchecked. Now ANY mismatch (including
            // zero, which a fresh-keyed entry will never legitimately produce)
            // is rejected.
            let expected_hash = cache_entry_hash(&path, size, mtime, clean, &content_fp);
            if stored_hash != expected_hash {
                rejected += 1;
                tracing::warn!(
                    path = path_str,
                    "scan cache: INTEGRITY MISMATCH — entry rejected (possible tampering)"
                );
                continue;
            }

            counter += 1;
            entries.insert(
                path,
                CacheEntry {
                    size,
                    mtime,
                    content_fp,
                    clean,
                    sig_generation: sgen,
                    last_accessed: counter,
                },
            );
        }
    }
    if rejected > 0 {
        tracing::warn!(
            rejected,
            "scan cache: {} entries rejected due to integrity mismatch",
            rejected
        );
    }

    Ok((entries, sgen))
}

fn write_generation_to_db(conn: &rusqlite::Connection, sig_generation: u64) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('sig_generation', ?1)",
        rusqlite::params![sig_generation as i64],
    )
    .map_err(|e| format!("generation: {e}"))?;
    Ok(())
}

fn write_to_db(
    conn: &rusqlite::Connection,
    path: &Path,
    size: u64,
    mtime: u64,
    content_fp: &ContentFingerprint,
    clean: bool,
    sig_generation: u64,
) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // D-3 fix: include integrity hash — externally inserted/modified entries
    // won't have a valid hash and will be treated as cache misses.
    // R6-LETHAL: fingerprint is part of the integrity hash, so SQL UPDATE
    // of just `content_fp` invalidates the entry on next load.
    let ihash = cache_entry_hash(path, size, mtime, clean, content_fp) as i64;

    conn.execute(
        "INSERT OR REPLACE INTO scan_cache (path, size, mtime, clean, sig_generation, updated_at, integrity_hash, content_fp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            path.to_string_lossy().as_ref(),
            size as i64,
            mtime as i64,
            clean as i64,
            sig_generation as i64,
            now,
            ihash,
            content_fp.as_slice(),
        ],
    )
    .map_err(|e| format!("insert: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(path: &Path, bytes: &[u8]) -> std::fs::Metadata {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
        drop(f);
        std::fs::metadata(path).unwrap()
    }

    #[test]
    fn r6_lethal_inplace_content_swap_misses_cache() {
        // The previous (size, mtime)-only cache key let an attacker
        // overwrite a "clean" file with malware bytes while preserving
        // size + mtime → cache HIT → file never re-scanned.
        // With the content fingerprint folded in, the same trick must
        // produce a MISS so the scanner re-runs.
        let dir = std::env::temp_dir().join("sent_r6_cache_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("victim.bin");

        // Fixed payload of EXACTLY this size — we'll overwrite in-place
        // with another payload of the same length.
        let clean = vec![0xAAu8; 70_000]; // > 64KB so fingerprint window matters.
        let dirty = vec![0xBBu8; 70_000];

        let meta_clean = write_file(&p, &clean);
        let cache = ScanCache::new();
        cache.record_with_metadata(&p, &meta_clean, true);

        // Cache HIT path: same file, same metadata.
        assert_eq!(
            cache.check_with_metadata(&p, &meta_clean),
            Some(true),
            "fresh entry should hit"
        );

        // Tamper: overwrite contents in-place but pretend mtime stayed.
        // We can't reliably SetFileTime in cross-platform tests, so we
        // construct the lookup's metadata struct from the ORIGINAL mtime
        // — emulating the attacker who calls SetFileTime() to restore it.
        write_file(&p, &dirty); // length identical
        let attacker_meta = meta_clean.clone(); // pretend mtime unchanged

        // With the fingerprint check, this MUST miss.
        assert!(
            cache.check_with_metadata(&p, &attacker_meta).is_none(),
            "BUG: in-place content swap returned cache hit — scanner bypass possible"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn r6_fingerprint_stable_for_unchanged_file() {
        // Sanity: repeated lookups on an unchanged file should keep hitting.
        let dir = std::env::temp_dir().join("sent_r6_cache_test2");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("clean.bin");
        let meta = write_file(&p, b"hello world");

        let cache = ScanCache::new();
        cache.record_with_metadata(&p, &meta, true);
        assert_eq!(cache.check_with_metadata(&p, &meta), Some(true));
        assert_eq!(cache.check_with_metadata(&p, &meta), Some(true));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

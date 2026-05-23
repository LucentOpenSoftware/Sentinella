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

#[derive(Debug, Clone)]
struct CacheEntry {
    size: u64,
    mtime: u64,
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
    pub fn check_with_metadata(&self, path: &Path, meta: &std::fs::Metadata) -> Option<bool> {
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut inner = self.inner.lock().ok()?;
        inner.access_counter += 1;
        let current_gen = inner.sig_generation;
        let current_access = inner.access_counter;

        let result = inner.entries.get(path).and_then(|entry| {
            if entry.size == size && entry.mtime == mtime && entry.sig_generation == current_gen {
                Some(entry.clean)
            } else {
                None
            }
        });

        if result.is_some() {
            if let Some(entry) = inner.entries.get_mut(path) {
                entry.last_accessed = current_access;
            }
            inner.hits += 1;
        } else {
            inner.misses += 1;
        }
        result
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
                        clean,
                        sig_generation,
                    } => {
                        if let Err(e) = write_to_db(&conn, &path, size, mtime, clean, sig_generation)
                        {
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
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cache_meta (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cache_gen ON scan_cache(sig_generation);",
    )
    .map_err(|e| format!("schema: {e}"))?;

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

    // Load entries for current generation (limit to MAX to prevent OOM).
    let mut stmt = conn
        .prepare(
            "SELECT path, size, mtime, clean FROM scan_cache WHERE sig_generation = ?1 LIMIT ?2",
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
                ))
            },
        )
        .map_err(|e| format!("query: {e}"))?;

    let mut entries = HashMap::new();
    let mut counter = 0u64;
    for row in rows {
        if let Ok((path, size, mtime, clean)) = row {
            counter += 1;
            entries.insert(
                PathBuf::from(path),
                CacheEntry {
                    size,
                    mtime,
                    clean,
                    sig_generation: sgen,
                    last_accessed: counter,
                },
            );
        }
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
    clean: bool,
    sig_generation: u64,
) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    conn.execute(
        "INSERT OR REPLACE INTO scan_cache (path, size, mtime, clean, sig_generation, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            path.to_string_lossy().as_ref(),
            size as i64,
            mtime as i64,
            clean as i64,
            sig_generation as i64,
            now,
        ],
    )
    .map_err(|e| format!("insert: {e}"))?;

    Ok(())
}

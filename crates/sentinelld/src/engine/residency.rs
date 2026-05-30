//! MpoolResidencyManager — lifecycle management for file-backed ClamAV engine cache.
//!
//! The cache file (`clamav-engine-mpool.cache`) backs the ClamAV signature engine's
//! memory pool. This module manages:
//!   - Cache creation and versioning
//!   - Stale detection (signature DB changed → cache invalid)
//!   - Corruption detection (keyed hash on metadata)
//!   - Rebuild orchestration
//!   - Fallback to anonymous allocation
//!   - Region diagnostics
//!
//! Safety invariant: cache corruption NEVER crashes, blocks startup, or alters detection.
//! Invalid cache → automatic rebuild from CVD files.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Cache metadata — stored alongside the cache file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// ClamAV signature database version (from CVD header).
    pub db_version: u32,
    /// Signature database timestamp (unix seconds).
    pub db_timestamp: i64,
    /// Engine compile timestamp.
    pub compile_timestamp: i64,
    /// Enhanced signature provider fingerprint.
    /// Changes when provider or provider files change → cache invalidation.
    pub provider_fingerprint: String,
    /// Compile duration in milliseconds.
    pub compile_ms: u64,
    /// Total mapped bytes across all regions.
    pub mapped_bytes: u64,
    /// Number of mapped regions.
    pub region_count: u32,
    /// Signature count loaded.
    pub signature_count: u32,
    /// Whether file-backed mode was active.
    pub file_backed: bool,
    /// Keyed hash of metadata fields (vault-key-seeded, not cryptographic HMAC).
    /// Detects accidental corruption. Not a security boundary.
    pub integrity_hash: String,
}

const SCHEMA_VERSION: u32 = 1;

/// The residency manager.
pub struct MpoolResidencyManager {
    /// Cache directory.
    cache_dir: PathBuf,
    /// Cache file path.
    cache_path: PathBuf,
    /// Metadata file path.
    meta_path: PathBuf,
    /// Current metadata (loaded or fresh).
    metadata: Option<CacheMetadata>,
    /// Whether file-backed mode is active.
    file_backed_active: bool,
    /// Fallback reason (if file-backed failed).
    fallback_reason: Option<String>,
}

impl MpoolResidencyManager {
    /// Initialize the residency manager.
    pub fn new() -> Self {
        let p = crate::paths::paths();
        let cache_dir = p.cache_dir();
        let cache_path = p.mpool_cache();
        let meta_path = p.mpool_meta();

        Self {
            cache_dir,
            cache_path,
            meta_path,
            metadata: None,
            file_backed_active: false,
            fallback_reason: None,
        }
    }

    /// Prepare for engine load. Creates cache directory, sets env var.
    /// Returns the cache file path for the mpool to use.
    ///
    /// Always deletes any existing cache file. The mpool implementation
    /// appends and 64KB-aligns each region, so reusing an existing file
    /// causes monotonic growth across reloads (977MB → 1955MB → 2932MB …).
    /// Starting fresh each time keeps the file at the actual engine size.
    pub fn prepare(&mut self) -> PathBuf {
        if let Err(e) = std::fs::create_dir_all(&self.cache_dir) {
            warn!(error = %e, "residency: cache dir creation failed");
            self.fallback_reason = Some(format!("mkdir failed: {e}"));
        }

        // Always delete previous cache file before each compile.
        // CREATE_ALWAYS in mpool.c will recreate it fresh. This prevents
        // the cache file from growing unboundedly across engine reloads.
        if self.cache_path.exists() {
            match std::fs::remove_file(&self.cache_path) {
                Ok(()) => info!("residency: previous cache file removed for clean rebuild"),
                Err(e) => warn!(error = %e, "residency: cache file removal failed (may still be mapped)"),
            }
        }
        // Also wipe the metadata sidecar so we don't confuse the next load.
        let _ = std::fs::remove_file(&self.meta_path);

        self.cache_path.clone()
    }

    /// Record that engine compilation completed successfully.
    pub fn record_compile(
        &mut self,
        db_version: u32,
        db_timestamp: i64,
        compile_ms: u64,
        mapped_bytes: u64,
        region_count: u32,
        signature_count: u32,
        file_backed: bool,
        provider_fingerprint: &str,
    ) {
        self.file_backed_active = file_backed;

        let meta = CacheMetadata {
            schema_version: SCHEMA_VERSION,
            db_version,
            db_timestamp,
            compile_timestamp: chrono::Utc::now().timestamp(),
            provider_fingerprint: provider_fingerprint.to_string(),
            compile_ms,
            mapped_bytes,
            region_count,
            signature_count,
            file_backed,
            integrity_hash: String::new(), // Computed below.
        };

        // Compute integrity hash.
        let mut meta_with_hash = meta.clone();
        meta_with_hash.integrity_hash = self.compute_meta_hash(&meta);

        // Save metadata.
        if let Err(e) = self.save_metadata(&meta_with_hash) {
            warn!(error = %e, "residency: metadata save failed");
        } else {
            debug!("residency: metadata saved");
        }

        self.metadata = Some(meta_with_hash);
    }

    /// Check if cached engine matches current signature database.
    ///
    /// NOTE: Currently unused — engine always rebuilds from CVD on startup.
    /// This method exists for future warm-startup optimization where the
    /// engine could skip recompilation if the cache is valid.
    /// DO NOT wire into production until mpool reload-at-same-address is proven.
    pub fn is_cache_valid(
        &self,
        current_db_version: u32,
        current_provider_fingerprint: &str,
    ) -> bool {
        match &self.metadata {
            Some(meta) => {
                if meta.schema_version != SCHEMA_VERSION {
                    debug!("residency: schema version mismatch");
                    return false;
                }
                if meta.db_version != current_db_version {
                    debug!(
                        cached = meta.db_version,
                        current = current_db_version,
                        "residency: DB version mismatch — cache stale"
                    );
                    return false;
                }
                if meta.provider_fingerprint != current_provider_fingerprint {
                    debug!("residency: provider fingerprint changed — cache stale");
                    return false;
                }
                // Verify integrity hash.
                let expected = self.compute_meta_hash(meta);
                if meta.integrity_hash != expected {
                    warn!("residency: metadata integrity mismatch — possible tampering");
                    return false;
                }
                true
            }
            None => false,
        }
    }

    /// Invalidate cache (e.g., after signature update).
    pub fn invalidate(&mut self) {
        info!("residency: cache invalidated — will rebuild on next start");
        let _ = std::fs::remove_file(&self.cache_path);
        let _ = std::fs::remove_file(&self.meta_path);
        self.metadata = None;
    }

    /// Get diagnostics.
    pub fn diagnostics(&self) -> serde_json::Value {
        let cache_size_mb = if self.cache_path.exists() {
            std::fs::metadata(&self.cache_path)
                .map(|m| m.len() / (1024 * 1024))
                .unwrap_or(0)
        } else {
            0
        };

        serde_json::json!({
            "file_backed": self.file_backed_active,
            "cache_path": self.cache_path.to_string_lossy(),
            "cache_file_mb": cache_size_mb,
            "metadata": self.metadata.as_ref().map(|m| serde_json::json!({
                "db_version": m.db_version,
                "signature_count": m.signature_count,
                "compile_ms": m.compile_ms,
                "mapped_mb": m.mapped_bytes / (1024 * 1024),
                "region_count": m.region_count,
                "compile_timestamp": m.compile_timestamp,
            })),
            "fallback_reason": self.fallback_reason,
        })
    }

    /// Cache file path.
    pub fn cache_path(&self) -> &Path {
        &self.cache_path
    }

    /// Whether file-backed mode is active.
    pub fn is_file_backed(&self) -> bool {
        self.file_backed_active
    }

    // ── Private helpers ──────────────────────────────────────

    fn load_metadata(&self) -> Option<CacheMetadata> {
        let json = std::fs::read_to_string(&self.meta_path).ok()?;
        serde_json::from_str(&json).ok()
    }

    fn save_metadata(&self, meta: &CacheMetadata) -> Result<(), String> {
        let json = serde_json::to_string_pretty(meta).map_err(|e| format!("serialize: {e}"))?;
        // Atomic-rename + fsync: a torn mpool meta makes the cache appear
        // corrupt next start → full engine recompile (10s+ scan-blind window).
        let tmp = self.meta_path.with_extension("json.tmp");
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| format!("open temp meta: {e}"))?;
            f.write_all(json.as_bytes())
                .map_err(|e| format!("write meta: {e}"))?;
            f.sync_all().map_err(|e| format!("sync meta: {e}"))?;
        }
        std::fs::rename(&tmp, &self.meta_path).map_err(|e| format!("rename meta: {e}"))?;
        Ok(())
    }

    fn compute_meta_hash(&self, meta: &CacheMetadata) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // CRYPTO FIX: previously DefaultHasher (SipHash → 64-bit output mixed
        // with vault key as a hash-input, not a MAC key). That gives no formal
        // MAC security; an attacker with mpool-cache write access could craft
        // a poisoned meta whose SipHash matches → daemon loads a stale or
        // attacker-shaped mpool image without detection. Real HMAC-SHA256
        // with the same vault key gives EUF-CMA security and 256-bit output
        // (64 hex chars in the same `integrity_hash` String field).
        //
        // Backward compat: existing .meta files have 16-char hashes → all
        // appear "tampered" on first verify post-upgrade → forced cache
        // recompile, which is the SAFE outcome (the old hash was not
        // trustworthy anyway).
        let vault_key_path = crate::paths::paths().vault_integrity_key();
        let key = std::fs::read(&vault_key_path).unwrap_or_default();
        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(&key) {
            Ok(m) => m,
            Err(_) => {
                // new_from_slice only fails on zero-length keys for HMAC; if
                // the vault key isn't readable yet, fall back to an empty
                // (deterministic) key — the meta is still single-use per
                // daemon and the failure mode is "treated as tampered next
                // load" which forces a recompile.
                <Hmac<Sha256> as Mac>::new_from_slice(&[0u8; 32])
                    .expect("HMAC-SHA256 accepts any key length")
            }
        };
        mac.update(&meta.schema_version.to_le_bytes());
        mac.update(&meta.db_version.to_le_bytes());
        mac.update(&meta.db_timestamp.to_le_bytes());
        mac.update(meta.provider_fingerprint.as_bytes());
        mac.update(&meta.mapped_bytes.to_le_bytes());
        mac.update(&meta.region_count.to_le_bytes());
        mac.update(&meta.signature_count.to_le_bytes());

        let tag = mac.finalize().into_bytes();
        let mut hex = String::with_capacity(tag.len() * 2);
        for b in tag.iter() {
            use std::fmt::Write as _;
            let _ = write!(hex, "{:02x}", b);
        }
        hex
    }
}

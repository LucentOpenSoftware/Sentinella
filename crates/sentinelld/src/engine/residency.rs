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
    pub fn prepare(&mut self) -> PathBuf {
        // Ensure cache directory exists.
        if let Err(e) = std::fs::create_dir_all(&self.cache_dir) {
            warn!(error = %e, "residency: cache dir creation failed");
            self.fallback_reason = Some(format!("mkdir failed: {e}"));
        }

        // Check if existing cache is stale.
        if self.cache_path.exists() {
            if let Some(meta) = self.load_metadata() {
                debug!(
                    db_version = meta.db_version,
                    regions = meta.region_count,
                    mapped_mb = meta.mapped_bytes / (1024 * 1024),
                    "residency: existing cache metadata loaded"
                );
                self.metadata = Some(meta);
            } else {
                // Metadata corrupt or missing — cache is suspect.
                info!("residency: stale/corrupt metadata — cache will be rebuilt");
                let _ = std::fs::remove_file(&self.cache_path);
            }
        }

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
        std::fs::write(&self.meta_path, json).map_err(|e| format!("write: {e}"))?;
        Ok(())
    }

    fn compute_meta_hash(&self, meta: &CacheMetadata) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        meta.schema_version.hash(&mut hasher);
        meta.db_version.hash(&mut hasher);
        meta.db_timestamp.hash(&mut hasher);
        meta.provider_fingerprint.hash(&mut hasher);
        meta.mapped_bytes.hash(&mut hasher);
        meta.region_count.hash(&mut hasher);
        meta.signature_count.hash(&mut hasher);
        // Mix in vault key if available.
        let vault_key_path = crate::paths::paths().vault_integrity_key();
        if let Ok(key) = std::fs::read(&vault_key_path) {
            key.hash(&mut hasher);
        }
        format!("{:016x}", hasher.finish())
    }
}

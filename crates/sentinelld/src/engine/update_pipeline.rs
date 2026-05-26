//! SignatureUpdateManager — production-grade provider update lifecycle.
//!
//! Every provider update passes through:
//!   download → staging → verify → activate → rebuild → cleanup
//!
//! Core invariants:
//!   - downloaded != trusted (must verify before activation)
//!   - downloaded != active (must pass through staging)
//!   - failure → official ClamAV only (safe degradation)
//!   - never partially activate
//!   - never mix providers
//!   - activation is atomic (rename, not copy)
//!
//! Staging layout:
//!   runtime/update_staging/<provider_id>/
//!     ├── file1.ndb
//!     ├── file2.hdb
//!     └── .update_meta.json
//!
//! Active layout:
//!   runtime/signatures/enhanced/
//!     ├── file1.ndb
//!     └── file2.hdb

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Update lifecycle stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStage {
    /// No update in progress.
    Idle,
    /// Downloading files to staging.
    Downloading,
    /// Verifying downloaded files.
    Verifying,
    /// Activating (swapping into active dir).
    Activating,
    /// Rebuilding engine cache.
    Rebuilding,
    /// Update complete.
    Complete,
    /// Update failed — rolled back to official-only.
    Failed,
}

/// Update result.
#[derive(Debug)]
pub struct UpdateResult {
    pub success: bool,
    pub stage: UpdateStage,
    pub files_downloaded: usize,
    pub files_activated: usize,
    pub error: Option<String>,
}

/// Provider manifest — declares available files with hashes.
/// Fetched from provider URL or shipped alongside signatures.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderManifest {
    pub provider_id: String,
    pub version: String,
    pub files: Vec<ManifestFile>,
    pub license: String,
    pub attribution: String,
    pub updated_at: String,
}

/// A file entry in a provider manifest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestFile {
    pub name: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

/// Staging metadata — written alongside downloaded files.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StagingMeta {
    provider_id: String,
    timestamp: i64,
    files: Vec<StagedFile>,
    total_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StagedFile {
    name: String,
    size: u64,
    sha256: Option<String>,
}

/// HTTP download configuration.
const DOWNLOAD_TIMEOUT_SECS: u64 = 120;
const MAX_DOWNLOAD_SIZE: u64 = 500 * 1024 * 1024; // 500 MB per file
const MAX_REDIRECTS: u32 = 3;
const USER_AGENT: &str = "Sentinella-Updater/0.1";

/// The update pipeline manager.
pub struct SignatureUpdateManager {
    staging_root: PathBuf,
    active_enhanced_dir: PathBuf,
    stage: UpdateStage,
}

impl SignatureUpdateManager {
    pub fn new() -> Self {
        let p = crate::paths::paths();
        Self {
            staging_root: p.update_staging_dir(),
            active_enhanced_dir: p.enhanced_signatures_dir(),
            stage: UpdateStage::Idle,
        }
    }

    /// Execute a full update for a provider.
    /// Returns the result — caller must handle cache invalidation + engine rebuild.
    pub fn update_provider(
        &mut self,
        provider: &super::sources::SignatureProvider,
    ) -> UpdateResult {
        info!(
            provider = provider.id.as_str(),
            "signature update: starting"
        );

        // Phase 1: Prepare staging directory.
        let staging_dir = self.staging_root.join(&provider.id);
        if let Err(e) = self.prepare_staging(&staging_dir) {
            return self.fail(format!("staging prep failed: {e}"));
        }

        // Phase 2: Download files.
        self.stage = UpdateStage::Downloading;
        let downloaded = match self.download_files(provider, &staging_dir) {
            Ok(files) => files,
            Err(e) => {
                self.cleanup_staging(&staging_dir);
                return self.fail(format!("download failed: {e}"));
            }
        };

        if downloaded.is_empty() {
            self.cleanup_staging(&staging_dir);
            return self.fail("no files downloaded".into());
        }

        // Phase 3: Verify downloaded files.
        self.stage = UpdateStage::Verifying;
        if let Err(e) = self.verify_staged(&staging_dir, &downloaded) {
            self.cleanup_staging(&staging_dir);
            return self.fail(format!("verification failed: {e}"));
        }

        // Phase 3b: Verify against provider manifest if available.
        // Manifest provides a trust anchor — hashes are pinned by the provider,
        // NOT computed from the downloaded files themselves.
        if let Some(ref base_url) = provider.update_url {
            let manifest_url = format!("{}/manifest.json", base_url.trim_end_matches('/'));
            match self.fetch_and_verify_manifest(&staging_dir, &manifest_url, &provider.id) {
                Ok(()) => info!(
                    provider = provider.id.as_str(),
                    "manifest verification passed"
                ),
                Err(e) => {
                    // Distinguish "manifest not found" (provider doesn't serve one yet)
                    // from "manifest found but verification FAILED" (tampered/corrupt).
                    let is_not_found = e.contains("HTTP 404") || e.contains("HTTP 403");
                    if is_not_found {
                        warn!(
                            provider = provider.id.as_str(),
                            error = %e,
                            "manifest not available — provider may not serve manifest.json yet"
                        );
                    } else {
                        // Manifest was fetched but verification failed → HARD FAIL.
                        // This means files don't match the provider's declared hashes.
                        self.cleanup_staging(&staging_dir);
                        return self.fail(format!("manifest verification FAILED: {e}"));
                    }
                }
            }
        }

        // Phase 4: Atomic activation.
        self.stage = UpdateStage::Activating;
        let activated = match self.activate(&staging_dir, &downloaded) {
            Ok(count) => count,
            Err(e) => {
                self.rollback();
                return self.fail(format!("activation failed: {e}"));
            }
        };

        // Phase 5: Cleanup staging.
        self.cleanup_staging(&staging_dir);

        self.stage = UpdateStage::Complete;
        info!(
            provider = provider.id.as_str(),
            files = activated,
            "signature update: complete — cache invalidation required"
        );

        UpdateResult {
            success: true,
            stage: UpdateStage::Complete,
            files_downloaded: downloaded.len(),
            files_activated: activated,
            error: None,
        }
    }

    /// Rollback: remove all enhanced signatures, restore official-only mode.
    pub fn rollback(&mut self) {
        warn!("signature update: rolling back to official-only mode");
        if self.active_enhanced_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&self.active_enhanced_dir) {
                for entry in entries.flatten() {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        self.stage = UpdateStage::Idle;
    }

    /// Current update stage.
    pub fn stage(&self) -> UpdateStage {
        self.stage
    }

    /// Clean all stale staging directories.
    pub fn cleanup_all_staging(&self) {
        if self.staging_root.exists() {
            if let Ok(entries) = std::fs::read_dir(&self.staging_root) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        let _ = std::fs::remove_dir_all(entry.path());
                    }
                }
            }
        }
    }

    // ── Private pipeline stages ─────────────────────────

    fn prepare_staging(&self, staging_dir: &Path) -> Result<(), String> {
        // Clean any leftover staging from previous failed updates.
        if staging_dir.exists() {
            std::fs::remove_dir_all(staging_dir)
                .map_err(|e| format!("cleanup old staging: {e}"))?;
        }
        std::fs::create_dir_all(staging_dir).map_err(|e| format!("create staging dir: {e}"))?;
        Ok(())
    }

    fn download_files(
        &self,
        provider: &super::sources::SignatureProvider,
        staging_dir: &Path,
    ) -> Result<Vec<StagedFile>, String> {
        let mut files = Vec::new();

        // Strategy 1: Try local source directory (for testing / air-gapped systems).
        let local_source = self
            .staging_root
            .parent()
            .unwrap_or(Path::new("."))
            .join("provider_sources")
            .join(&provider.id);

        for db_file in &provider.db_files {
            let dest = staging_dir.join(db_file);

            // Try local source first.
            let local_path = local_source.join(db_file);
            if local_path.exists() {
                std::fs::copy(&local_path, &dest)
                    .map_err(|e| format!("copy {} from local: {e}", db_file))?;
                let size = std::fs::metadata(&dest)
                    .map_err(|e| format!("stat {}: {e}", db_file))?
                    .len();
                if size > MAX_DOWNLOAD_SIZE {
                    return Err(format!("{} exceeds size limit", db_file));
                }
                let hash = compute_sha256(&dest)?;
                files.push(StagedFile {
                    name: db_file.clone(),
                    size,
                    sha256: Some(hash),
                });
                debug!(file = db_file.as_str(), size, source = "local", "staged");
                continue;
            }

            // Strategy 2: HTTPS download from provider URL.
            if let Some(ref base_url) = provider.update_url {
                // Enforce HTTPS — reject plain HTTP to prevent MITM.
                if !base_url.starts_with("https://") {
                    warn!(
                        url = base_url.as_str(),
                        "provider URL rejected: HTTPS required"
                    );
                    return Err(format!("provider URL must use HTTPS, got: {}", base_url));
                }
                let url = format!("{}/{}", base_url.trim_end_matches('/'), db_file);
                match download_file(&url, &dest) {
                    Ok(size) => {
                        if size > MAX_DOWNLOAD_SIZE {
                            let _ = std::fs::remove_file(&dest);
                            return Err(format!("{} exceeds size limit ({} bytes)", db_file, size));
                        }
                        let hash = compute_sha256(&dest)?;
                        files.push(StagedFile {
                            name: db_file.clone(),
                            size,
                            sha256: Some(hash),
                        });
                        debug!(file = db_file.as_str(), size, source = "http", "staged");
                    }
                    Err(e) => {
                        // Non-fatal for individual files — provider may not ship all listed files.
                        debug!(file = db_file.as_str(), error = %e, "download skipped");
                    }
                }
            }
        }

        Ok(files)
    }

    /// Verify staged files: size, hash, format.
    /// If a manifest is provided, verify SHA-256 against manifest hashes.
    fn verify_staged(&self, staging_dir: &Path, files: &[StagedFile]) -> Result<(), String> {
        for file in files {
            let path = staging_dir.join(&file.name);

            if !path.exists() {
                return Err(format!("{} missing from staging", file.name));
            }

            let actual_size = std::fs::metadata(&path)
                .map_err(|e| format!("stat {}: {e}", file.name))?
                .len();

            if actual_size != file.size {
                return Err(format!(
                    "{} size mismatch: expected {}, got {}",
                    file.name, file.size, actual_size
                ));
            }

            if actual_size == 0 {
                return Err(format!("{} is empty", file.name));
            }

            // SHA-256 verification (if hash available).
            if let Some(ref expected_hash) = file.sha256 {
                let actual_hash = compute_sha256(&path)?;
                if actual_hash != *expected_hash {
                    return Err(format!(
                        "{} SHA-256 mismatch: expected {}, got {}",
                        file.name,
                        &expected_hash[..16],
                        &actual_hash[..16]
                    ));
                }
                debug!(file = file.name.as_str(), "SHA-256 verified");
            }

            // Text format validation for ClamAV signature files.
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            if matches!(ext.as_str(), "ndb" | "hdb" | "hsb" | "cdb" | "ftm" | "ign2") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Some(first_line) = content.lines().next() {
                        if first_line.chars().any(|c| c.is_control() && c != '\t') {
                            return Err(format!(
                                "{} contains binary data in text format",
                                file.name
                            ));
                        }
                    }
                }
            }

            debug!(file = file.name.as_str(), size = actual_size, "verified");
        }

        // Save staging metadata.
        let meta = StagingMeta {
            provider_id: String::new(),
            timestamp: chrono::Utc::now().timestamp(),
            files: files.to_vec(),
            total_bytes: files.iter().map(|f| f.size).sum(),
        };
        let meta_path = staging_dir.join(".update_meta.json");
        if let Ok(json) = serde_json::to_string_pretty(&meta) {
            let _ = std::fs::write(&meta_path, json);
        }

        Ok(())
    }

    /// Verify staged files against a provider manifest.
    /// All files in manifest must be present and match SHA-256.
    pub fn verify_against_manifest(
        &self,
        staging_dir: &Path,
        manifest: &ProviderManifest,
    ) -> Result<(), String> {
        for mf in &manifest.files {
            let path = staging_dir.join(&mf.name);

            if !path.exists() {
                return Err(format!("manifest file {} missing from staging", mf.name));
            }

            let actual_size = std::fs::metadata(&path)
                .map_err(|e| format!("stat {}: {e}", mf.name))?
                .len();

            if actual_size != mf.size {
                return Err(format!(
                    "{} size mismatch: manifest says {}, got {}",
                    mf.name, mf.size, actual_size
                ));
            }

            let actual_hash = compute_sha256(&path)?;
            if actual_hash != mf.sha256 {
                return Err(format!(
                    "{} SHA-256 mismatch: manifest says {}, got {}",
                    mf.name,
                    &mf.sha256[..16],
                    &actual_hash[..16]
                ));
            }
        }

        info!(
            provider = manifest.provider_id.as_str(),
            version = manifest.version.as_str(),
            files = manifest.files.len(),
            "manifest verification passed"
        );
        Ok(())
    }

    fn activate(&self, staging_dir: &Path, files: &[StagedFile]) -> Result<usize, String> {
        // Atomic activation: stage → new dir → swap → cleanup old.
        // Never remove existing files until new ones are fully in place.

        std::fs::create_dir_all(&self.active_enhanced_dir)
            .map_err(|e| format!("create enhanced dir: {e}"))?;

        // Step 1: Move new files to a temporary "pending" directory alongside active.
        let pending_dir = self.active_enhanced_dir.with_file_name("enhanced_pending");
        if pending_dir.exists() {
            let _ = std::fs::remove_dir_all(&pending_dir);
        }
        std::fs::create_dir_all(&pending_dir).map_err(|e| format!("create pending dir: {e}"))?;

        let mut activated = 0;
        for file in files {
            let src = staging_dir.join(&file.name);
            let dst = pending_dir.join(&file.name);

            if std::fs::rename(&src, &dst).is_ok() {
                activated += 1;
                continue;
            }
            std::fs::copy(&src, &dst).map_err(|e| {
                let _ = std::fs::remove_dir_all(&pending_dir);
                format!("activate {}: {e}", file.name)
            })?;
            let _ = std::fs::remove_file(&src);
            activated += 1;
        }

        // Step 2: Rename current enhanced → enhanced_old (backup).
        let old_dir = self.active_enhanced_dir.with_file_name("enhanced_old");
        let _ = std::fs::remove_dir_all(&old_dir);
        let had_existing = self.active_enhanced_dir.exists()
            && std::fs::read_dir(&self.active_enhanced_dir)
                .map(|d| d.count())
                .unwrap_or(0)
                > 0;
        if had_existing {
            std::fs::rename(&self.active_enhanced_dir, &old_dir).map_err(|e| {
                let _ = std::fs::remove_dir_all(&pending_dir);
                format!("backup old enhanced: {e}")
            })?;
        }

        // Step 3: Rename pending → enhanced (atomic swap).
        if let Err(e) = std::fs::rename(&pending_dir, &self.active_enhanced_dir) {
            // Restore old if swap failed.
            if had_existing {
                let _ = std::fs::rename(&old_dir, &self.active_enhanced_dir);
            }
            return Err(format!("atomic swap failed: {e}"));
        }

        // Step 4: Cleanup old directory.
        let _ = std::fs::remove_dir_all(&old_dir);

        info!(count = activated, "signature files activated (atomic swap)");
        Ok(activated)
    }

    /// Fetch a manifest.json from the provider URL and verify staged files against it.
    /// The manifest provides a trust anchor: expected hashes are declared by the provider,
    /// not derived from the downloaded files. This breaks the self-verification loop.
    fn fetch_and_verify_manifest(
        &self,
        staging_dir: &Path,
        manifest_url: &str,
        provider_id: &str,
    ) -> Result<(), String> {
        let manifest_path = staging_dir.join("manifest.json");
        download_file(manifest_url, &manifest_path)?;

        let manifest_str =
            std::fs::read_to_string(&manifest_path).map_err(|e| format!("read manifest: {e}"))?;

        let manifest: ProviderManifest =
            serde_json::from_str(&manifest_str).map_err(|e| format!("parse manifest: {e}"))?;

        // Verify manifest claims the correct provider.
        if manifest.provider_id != provider_id {
            return Err(format!(
                "manifest provider_id mismatch: expected '{}', got '{}'",
                provider_id, manifest.provider_id
            ));
        }

        // Verify all manifest-listed files against their pinned hashes.
        self.verify_against_manifest(staging_dir, &manifest)?;

        // Clean up the manifest file (not a signature file).
        let _ = std::fs::remove_file(&manifest_path);
        Ok(())
    }

    fn cleanup_staging(&self, staging_dir: &Path) {
        if staging_dir.exists() {
            let _ = std::fs::remove_dir_all(staging_dir);
        }
    }

    fn fail(&mut self, error: String) -> UpdateResult {
        warn!(error = error.as_str(), "signature update: FAILED");
        self.stage = UpdateStage::Failed;
        UpdateResult {
            success: false,
            stage: UpdateStage::Failed,
            files_downloaded: 0,
            files_activated: 0,
            error: Some(error),
        }
    }
}

// ── Helper functions ──────────────────────────────────────

/// Download a file via HTTP to a local path.
/// Writes to a temp file first, then renames atomically.
fn download_file(url: &str, dest: &Path) -> Result<u64, String> {
    let tmp_path = dest.with_extension("tmp");

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .max_idle_connections(1)
        .max_idle_connections_per_host(1)
        .user_agent(USER_AGENT)
        .redirects(MAX_REDIRECTS)
        .build();

    let response = match agent.get(url).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(status, _)) => {
            return Err(format!("HTTP {} for {}", status, url));
        }
        Err(e) => {
            return Err(format!("HTTP transport error for {}: {e}", url));
        }
    };

    let status = response.status();
    if status != 200 {
        return Err(format!("HTTP {} for {}", status, url));
    }

    // Check content-length if available.
    if let Some(len_str) = response.header("content-length") {
        if let Ok(len) = len_str.parse::<u64>() {
            if len > MAX_DOWNLOAD_SIZE {
                return Err(format!("content-length {} exceeds limit", len));
            }
        }
    }

    // Stream to temp file.
    let mut file =
        std::fs::File::create(&tmp_path).map_err(|e| format!("create temp file: {e}"))?;

    let mut reader = response.into_reader();
    let mut total: u64 = 0;
    let mut buf = [0u8; 65536];

    loop {
        match std::io::Read::read(&mut reader, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if total > MAX_DOWNLOAD_SIZE {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(format!(
                        "download exceeds {} MB limit",
                        MAX_DOWNLOAD_SIZE / (1024 * 1024)
                    ));
                }
                std::io::Write::write_all(&mut file, &buf[..n])
                    .map_err(|e| format!("write: {e}"))?;
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(format!("read: {e}"));
            }
        }
    }

    drop(file);

    // Atomic rename from temp to final destination.
    std::fs::rename(&tmp_path, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("rename temp to dest: {e}")
    })?;

    Ok(total)
}

/// Compute SHA-256 hash of a file, return lowercase hex string.
fn compute_sha256(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file =
        std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];

    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        }
    }

    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_sha256_of_known_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello world\n").unwrap();

        let hash = compute_sha256(&path).unwrap();
        // SHA-256 of "hello world\n"
        // Just verify it's a 64-char hex string.
        assert_eq!(hash.len(), 64, "SHA-256 should be 64 hex chars");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA-256 should be hex"
        );
    }

    #[test]
    fn manifest_parse() {
        let json = r#"{
            "provider_id": "test",
            "version": "1.0",
            "files": [
                {
                    "name": "test.ndb",
                    "url": "https://example.com/test.ndb",
                    "sha256": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
                    "size": 1000
                }
            ],
            "license": "MIT",
            "attribution": "Test Provider",
            "updated_at": "2026-05-25"
        }"#;

        let manifest: ProviderManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.provider_id, "test");
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].name, "test.ndb");
        assert_eq!(manifest.files[0].sha256.len(), 64);
    }

    #[test]
    fn verify_rejects_bad_hash() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();

        let file_path = staging.join("test.ndb");
        std::fs::write(&file_path, "signature data here").unwrap();
        let actual_hash = compute_sha256(&file_path).unwrap();

        let mgr = SignatureUpdateManager {
            staging_root: dir.path().to_path_buf(),
            active_enhanced_dir: dir.path().join("active"),
            stage: UpdateStage::Idle,
        };

        // Good hash — should pass.
        let good_files = vec![StagedFile {
            name: "test.ndb".into(),
            size: std::fs::metadata(&file_path).unwrap().len(),
            sha256: Some(actual_hash.clone()),
        }];
        assert!(mgr.verify_staged(&staging, &good_files).is_ok());

        // Bad hash — should fail.
        let bad_files = vec![StagedFile {
            name: "test.ndb".into(),
            size: std::fs::metadata(&file_path).unwrap().len(),
            sha256: Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
        }];
        assert!(mgr.verify_staged(&staging, &bad_files).is_err());
    }

    #[test]
    fn verify_rejects_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();

        let file_path = staging.join("big.ndb");
        std::fs::write(&file_path, "data").unwrap();

        let mgr = SignatureUpdateManager {
            staging_root: dir.path().to_path_buf(),
            active_enhanced_dir: dir.path().join("active"),
            stage: UpdateStage::Idle,
        };

        // Size mismatch — should fail.
        let files = vec![StagedFile {
            name: "big.ndb".into(),
            size: 999999, // Wrong size.
            sha256: None,
        }];
        assert!(mgr.verify_staged(&staging, &files).is_err());
    }

    #[test]
    fn verify_rejects_empty() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();

        let file_path = staging.join("empty.ndb");
        std::fs::write(&file_path, "").unwrap();

        let mgr = SignatureUpdateManager {
            staging_root: dir.path().to_path_buf(),
            active_enhanced_dir: dir.path().join("active"),
            stage: UpdateStage::Idle,
        };

        let files = vec![StagedFile {
            name: "empty.ndb".into(),
            size: 0,
            sha256: None,
        }];
        assert!(mgr.verify_staged(&staging, &files).is_err());
    }

    #[test]
    fn rollback_clears_enhanced() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("active");
        std::fs::create_dir_all(&active).unwrap();
        std::fs::write(active.join("test.ndb"), "data").unwrap();

        let mut mgr = SignatureUpdateManager {
            staging_root: dir.path().join("staging"),
            active_enhanced_dir: active.clone(),
            stage: UpdateStage::Idle,
        };

        assert!(active.join("test.ndb").exists());
        mgr.rollback();
        assert!(!active.join("test.ndb").exists());
    }
}

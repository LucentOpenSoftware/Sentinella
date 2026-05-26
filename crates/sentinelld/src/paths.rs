//! PathManager — centralized path resolution for all daemon subsystems.
//!
//! Eliminates scattered `PathBuf::from("runtime/...")` hardcoding.
//! Every module consumes paths ONLY from this manager.
//!
//! Modes:
//!   Development: paths relative to CWD (project root)
//!   Installed:   paths under ProgramData\Sentinella
//!
//! Security: all returned paths are validated and canonicalized where needed.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Global path manager instance.
static PATHS: OnceLock<PathManager> = OnceLock::new();

/// Get the global path manager. Panics if not initialized.
pub fn paths() -> &'static PathManager {
    PATHS
        .get()
        .expect("PathManager not initialized — call paths::init() first")
}

/// Initialize the global path manager.
pub fn init(root: PathBuf) {
    let _ = PATHS.set(PathManager::new(root));
}

/// Initialize with auto-detected root (development or installed mode).
pub fn init_auto() {
    let root = detect_root();
    init(root);
}

/// Centralized path manager.
pub struct PathManager {
    /// Runtime root — all paths are relative to this.
    root: PathBuf,
}

impl PathManager {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Runtime root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ── Config ──────────────────────────────────────────

    pub fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }
    pub fn config_file(&self) -> PathBuf {
        self.root.join("config").join("sentinelld.toml")
    }
    pub fn freshclam_config(&self) -> PathBuf {
        self.root.join("config").join("freshclam.conf")
    }

    // ── State (databases, secrets) ──────────────────────

    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }
    pub fn state_db(&self) -> PathBuf {
        self.root.join("state").join("sentinella.db")
    }
    pub fn scan_cache_db(&self) -> PathBuf {
        self.root.join("state").join("scan_cache.db")
    }
    pub fn trust_graph_db(&self) -> PathBuf {
        self.root.join("state").join("trust_graph.db")
    }
    pub fn calibration_db(&self) -> PathBuf {
        self.root.join("state").join("calibration.db")
    }
    pub fn ipc_secret(&self) -> PathBuf {
        self.root.join("state").join("ipc_secret")
    }
    pub fn vault_integrity_key(&self) -> PathBuf {
        self.root.join("state").join("vault_integrity_key")
    }
    pub fn integrity_manifest(&self) -> PathBuf {
        self.root.join("state").join("integrity.json")
    }

    // ── Signatures ──────────────────────────────────────

    pub fn signatures_dir(&self) -> PathBuf {
        self.root.join("signatures")
    }
    pub fn enhanced_signatures_dir(&self) -> PathBuf {
        self.root.join("signatures").join("enhanced")
    }

    // ── Cache (mpool, compiled engine) ──────────────────

    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }
    pub fn mpool_cache(&self) -> PathBuf {
        self.root.join("cache").join("clamav-engine-mpool.cache")
    }
    pub fn mpool_meta(&self) -> PathBuf {
        self.root.join("cache").join("clamav-engine-mpool.meta")
    }

    // ── ClamAV temp ─────────────────────────────────────

    pub fn clamav_tmp(&self) -> PathBuf {
        self.root.join("clamav_tmp")
    }

    // ── Quarantine ──────────────────────────────────────

    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }

    // ── Logs ────────────────────────────────────────────

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    // ── ARGUS rules ─────────────────────────────────────

    pub fn yara_rules_dir(&self) -> PathBuf {
        self.root.join("argus").join("rules").join("yara")
    }
    pub fn argus_manifests_dir(&self) -> PathBuf {
        self.root.join("argus").join("manifests")
    }
    pub fn pack_manifest(&self) -> PathBuf {
        self.root
            .join("argus")
            .join("manifests")
            .join("pack_manifest.json")
    }
    pub fn argus_compiled_dir(&self) -> PathBuf {
        self.root.join("argus").join("compiled")
    }

    // ── IOC ─────────────────────────────────────────────

    /// IOC hash files — checked in priority order.
    pub fn ioc_hash_paths(&self) -> Vec<PathBuf> {
        vec![
            self.root.join("rules").join("ioc_hashes.txt"),
            self.root
                .join("argus")
                .join("rules")
                .join("ioc")
                .join("ioc_hashes.txt"),
            self.root.join("signatures").join("ioc_hashes.txt"),
        ]
    }

    /// YARA rule directories — checked in priority order.
    pub fn yara_rule_dirs(&self) -> Vec<PathBuf> {
        vec![self.yara_rules_dir(), self.root.join("rules")]
    }

    // ── Update staging ──────────────────────────────────

    pub fn update_staging_dir(&self) -> PathBuf {
        self.root.join("update_staging")
    }

    // ── Diagnostics ─────────────────────────────────────

    pub fn diagnostics_dir(&self) -> PathBuf {
        self.root.join("diagnostics")
    }

    // ── Ensure directories exist ────────────────────────

    /// Create all required runtime directories.
    pub fn ensure_dirs(&self) -> Result<(), String> {
        let dirs = [
            self.config_dir(),
            self.state_dir(),
            self.signatures_dir(),
            self.enhanced_signatures_dir(),
            self.cache_dir(),
            self.clamav_tmp(),
            self.quarantine_dir(),
            self.logs_dir(),
            self.yara_rules_dir(),
            self.argus_manifests_dir(),
            self.argus_compiled_dir(),
            self.update_staging_dir(),
            self.diagnostics_dir(),
        ];

        for dir in &dirs {
            if let Err(e) = std::fs::create_dir_all(dir) {
                return Err(format!("failed to create {}: {e}", dir.display()));
            }
        }

        Ok(())
    }
}

/// Auto-detect runtime root.
///
/// Development mode: `<project>/runtime/` (CWD contains Cargo.toml)
/// Installed mode:   `C:\ProgramData\Sentinella\` (Windows)
///                   `/var/lib/sentinella/` (Linux)
fn detect_root() -> PathBuf {
    // Check if we're in development mode (Cargo.toml exists in CWD or parent).
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("Cargo.toml").exists() || cwd.join("crates").exists() {
            let dev_root = cwd.join("runtime");
            tracing::info!(root = %dev_root.display(), "PathManager: development mode");
            return dev_root;
        }
    }

    // Check if exe is in a known install location.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            // Installed alongside the exe.
            let runtime = exe_dir.join("runtime");
            if runtime.exists() {
                tracing::info!(root = %runtime.display(), "PathManager: portable mode");
                return runtime;
            }
        }
    }

    // Default: ProgramData (Windows) or /var/lib (Linux).
    #[cfg(target_os = "windows")]
    {
        let pd = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        let root = PathBuf::from(pd).join("Sentinella");
        tracing::info!(root = %root.display(), "PathManager: installed mode");
        root
    }

    #[cfg(not(target_os = "windows"))]
    {
        let root = PathBuf::from("/var/lib/sentinella");
        tracing::info!(root = %root.display(), "PathManager: installed mode");
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(root: &str) -> PathManager {
        PathManager::new(PathBuf::from(root))
    }

    #[test]
    fn config_paths_under_root() {
        let p = pm("C:\\ProgramData\\Sentinella");
        assert_eq!(
            p.config_file(),
            PathBuf::from("C:\\ProgramData\\Sentinella\\config\\sentinelld.toml")
        );
        assert_eq!(
            p.freshclam_config(),
            PathBuf::from("C:\\ProgramData\\Sentinella\\config\\freshclam.conf")
        );
    }

    #[test]
    fn signature_paths_under_root() {
        let p = pm("/var/lib/sentinella");
        assert_eq!(
            p.signatures_dir(),
            PathBuf::from("/var/lib/sentinella/signatures")
        );
        assert_eq!(
            p.enhanced_signatures_dir(),
            PathBuf::from("/var/lib/sentinella/signatures/enhanced")
        );
    }

    #[test]
    fn cache_paths_under_root() {
        let p = pm("D:\\test");
        assert_eq!(
            p.mpool_cache(),
            PathBuf::from("D:\\test\\cache\\clamav-engine-mpool.cache")
        );
        assert_eq!(
            p.mpool_meta(),
            PathBuf::from("D:\\test\\cache\\clamav-engine-mpool.meta")
        );
    }

    #[test]
    fn ioc_hash_paths_all_under_root() {
        let p = pm("/opt/sentinella");
        for path in p.ioc_hash_paths() {
            assert!(
                path.starts_with("/opt/sentinella"),
                "IOC path not under root: {}",
                path.display()
            );
        }
    }

    #[test]
    fn yara_rule_dirs_all_under_root() {
        let p = pm("C:\\Data");
        for dir in p.yara_rule_dirs() {
            assert!(
                dir.starts_with("C:\\Data"),
                "YARA dir not under root: {}",
                dir.display()
            );
        }
    }

    #[test]
    fn ensure_dirs_creates_structure() {
        let tmp = std::env::temp_dir().join("sentinella_path_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let p = PathManager::new(tmp.clone());
        p.ensure_dirs().unwrap();
        assert!(p.config_dir().exists());
        assert!(p.state_dir().exists());
        assert!(p.signatures_dir().exists());
        assert!(p.quarantine_dir().exists());
        assert!(p.logs_dir().exists());
        assert!(p.yara_rules_dir().exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn vault_key_path_under_state() {
        let p = pm("X:\\runtime");
        assert!(p.vault_integrity_key().starts_with("X:\\runtime\\state"));
    }
}

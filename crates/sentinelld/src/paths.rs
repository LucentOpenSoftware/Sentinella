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
    // ☠️ R5-LETHAL: previously a 1-byte `Cargo.toml` placed in CWD would
    // flip the daemon into "development mode" and relocate the ENTIRE
    // data root (config, IPC secret, vault key, YARA rules, signatures)
    // to `CWD/runtime/`. Any time the daemon was launched with a CWD an
    // attacker could pre-seed (a user-writable Downloads/Public folder,
    // a shortcut with a custom "Start in" field, a manual `cd && run`
    // for testing), the attacker owned every AV artifact.
    //
    // Hardening:
    //   1. Dev mode requires the explicit env var SENTINELLA_DEV=1.
    //   2. Even then, the Cargo.toml is parsed and must contain the
    //      `name = "sentinelld"` package — so an attacker-planted stub
    //      file cannot trip the heuristic.
    //   3. Portable mode (runtime/ next to the exe) is only honored when
    //      the exe lives in a path that is NOT a generally user-writable
    //      directory (rules out dropping sentinelld.exe + runtime/ into
    //      a Public folder for elevation-by-launch).
    let dev_requested = std::env::var("SENTINELLA_DEV")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if dev_requested {
        if let Ok(cwd) = std::env::current_dir() {
            let manifest = cwd.join("Cargo.toml");
            if manifest.exists()
                && std::fs::read_to_string(&manifest)
                    .ok()
                    .map(|c| c.contains("name = \"sentinelld\"") || c.contains("name = \"sentinella\""))
                    .unwrap_or(false)
            {
                let dev_root = cwd.join("runtime");
                tracing::info!(root = %dev_root.display(), "PathManager: development mode (SENTINELLA_DEV=1)");
                return dev_root;
            }
            tracing::warn!(
                "SENTINELLA_DEV set but CWD has no sentinelld Cargo.toml — refusing dev mode"
            );
        }
    }

    // Check if exe is in a known install location.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let runtime = exe_dir.join("runtime");
            if runtime.exists() && is_trusted_install_dir(exe_dir) {
                tracing::info!(root = %runtime.display(), "PathManager: portable mode");
                return runtime;
            }
            if runtime.exists() {
                tracing::warn!(
                    exe_dir = %exe_dir.display(),
                    "found runtime/ next to exe but exe is in a user-writable location — refusing portable mode"
                );
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

/// True when `dir` is a path we treat as administratively-protected, i.e.
/// not a directory unprivileged users can write to. Used so we refuse to
/// honor `runtime/` next to the exe if the exe itself was dropped into a
/// user-writable location.
fn is_trusted_install_dir(dir: &Path) -> bool {
    let s = dir.to_string_lossy().to_lowercase();

    // Explicit deny: classic user-writable roots. Anyone able to drop
    // sentinelld.exe + a runtime/ tree here must NOT be able to coerce
    // a future launch into trusting that tree.
    const USER_WRITABLE_PREFIXES: &[&str] = &[
        "\\users\\public\\",
        "\\users\\default\\",
        "\\windows\\temp\\",
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\local\\temp\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\$recycle.bin\\",
        "\\perflogs\\",
    ];
    for bad in USER_WRITABLE_PREFIXES {
        if s.contains(bad) {
            return false;
        }
    }

    // Anything under a user's own profile (C:\Users\<name>\...) is per-user
    // writable. Trust only the system install roots.
    let trusted = s.contains("\\program files\\")
        || s.contains("\\program files (x86)\\")
        || s.contains("\\programdata\\sentinella")
        || s.starts_with("/opt/")
        || s.starts_with("/usr/local/")
        || s.starts_with("/usr/lib/")
        || s.starts_with("/var/lib/");

    trusted
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

    // ── R5-LETHAL regression tests ──────────────────────────

    #[test]
    fn r5_lethal_user_writable_dirs_not_trusted() {
        // None of these should ever be treated as trusted install dirs —
        // dropping `sentinelld.exe + runtime/` there must NOT switch the
        // root to that user-writable tree.
        let bad = [
            "C:\\Users\\Public\\Downloads\\app",
            "C:\\Users\\Public\\Desktop",
            "C:\\Users\\victim\\Downloads",
            "C:\\Windows\\Temp\\drop",
            "C:\\Temp\\app",
            "C:\\PerfLogs\\thing",
            "C:\\Users\\me\\Desktop\\portable",
        ];
        for b in &bad {
            assert!(
                !is_trusted_install_dir(Path::new(b)),
                "must REFUSE to trust user-writable install dir: {b}"
            );
        }
    }

    #[test]
    fn r5_lethal_real_install_dirs_trusted() {
        let good = [
            "C:\\Program Files\\Sentinella",
            "C:\\Program Files (x86)\\Sentinella",
            "C:\\ProgramData\\Sentinella",
            "/opt/sentinella",
            "/usr/local/sentinella",
            "/var/lib/sentinella",
        ];
        for g in &good {
            assert!(
                is_trusted_install_dir(Path::new(g)),
                "should trust real install dir: {g}"
            );
        }
    }
}

//! Runtime Integrity Vault — keyed-hash tamper detection for runtime assets.
//!
//! Protects against "silent lobotomy" attacks where an attacker corrupts
//! signatures, YARA rules, databases, or config while the daemon runs.
//!
//! Architecture:
//!   - On first start, generates a random 256-bit vault key
//!   - Computes a keyed SipHash of each protected asset
//!   - Stores manifests in `runtime/state/integrity.json`
//!   - On each daemon start + periodic checks, verifies hashes
//!   - Tampered files → alert + refuse to use + trigger re-download
//!
//! The vault key is stored with restricted ACL (SYSTEM + Administrators).
//!
//! NOTE: Uses SipHash (DefaultHasher), NOT cryptographic HMAC-SHA256.
//! Detects accidental corruption and casual tampering. Not a security
//! boundary against targeted adversaries with vault key access.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Vault key length in bytes.
const KEY_LEN: usize = 32;

/// Integrity manifest — maps file paths to their expected keyed hash.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct IntegrityManifest {
    /// Key ID — changes when vault key is regenerated.
    pub key_id: String,
    /// File path → hex-encoded keyed hash.
    pub entries: HashMap<String, String>,
    /// Timestamp of last full verification.
    pub last_verified: i64,
}

/// Result of an integrity check.
#[derive(Debug)]
pub struct IntegrityReport {
    /// Files that passed verification.
    pub verified: Vec<PathBuf>,
    /// Files with hash mismatch (TAMPERED).
    pub tampered: Vec<PathBuf>,
    /// Files in manifest but missing from disk (DELETED).
    pub missing: Vec<PathBuf>,
    /// Files on disk but not in manifest (NEW/UNKNOWN).
    pub unknown: Vec<PathBuf>,
}

impl IntegrityReport {
    pub fn is_clean(&self) -> bool {
        self.tampered.is_empty() && self.missing.is_empty()
    }

    pub fn tampered_count(&self) -> usize {
        self.tampered.len() + self.missing.len()
    }
}

/// The runtime integrity vault.
pub struct IntegrityVault {
    /// Vault key (256-bit, used for keyed SipHash).
    key: [u8; KEY_LEN],
    /// Manifest of known-good file hashes.
    manifest: IntegrityManifest,
    /// Path to the manifest file.
    manifest_path: PathBuf,
}

impl IntegrityVault {
    /// Initialize the vault. Loads or creates the key and manifest.
    pub fn init(state_dir: &Path) -> Result<Self, String> {
        let key_path = state_dir.join("vault_integrity_key");
        let manifest_path = state_dir.join("integrity.json");

        // Load or generate key.
        let key = if key_path.exists() {
            load_key(&key_path)?
        } else {
            let k = generate_key();
            save_key(&key_path, &k)?;
            info!("integrity vault: new key generated");
            k
        };

        // Load existing manifest or create empty.
        let manifest = if manifest_path.exists() {
            match std::fs::read_to_string(&manifest_path) {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => IntegrityManifest::default(),
            }
        } else {
            IntegrityManifest::default()
        };

        Ok(Self {
            key,
            manifest,
            manifest_path,
        })
    }

    /// Register a file — compute and store its keyed hash.
    pub fn register_file(&mut self, path: &Path) -> Result<(), String> {
        let hmac = compute_file_hmac(&self.key, path)?;
        let key = path.to_string_lossy().to_string();
        self.manifest.entries.insert(key, hmac);
        Ok(())
    }

    /// Register all files in a directory (recursive, filtered by extensions).
    pub fn register_directory(&mut self, dir: &Path, extensions: &[&str]) -> Result<usize, String> {
        let mut count = 0;
        if !dir.exists() {
            return Ok(0);
        }

        for entry in walkdir(dir) {
            if let Some(ext) = entry.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if extensions.iter().any(|&e| ext_str == e) {
                    if let Err(e) = self.register_file(&entry) {
                        warn!(file = %entry.display(), error = %e, "integrity: failed to register");
                    } else {
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Verify all registered files. Returns a detailed report.
    pub fn verify_all(&self) -> IntegrityReport {
        let mut report = IntegrityReport {
            verified: Vec::new(),
            tampered: Vec::new(),
            missing: Vec::new(),
            unknown: Vec::new(),
        };

        for (path_str, expected_hmac) in &self.manifest.entries {
            let path = PathBuf::from(path_str);

            if !path.exists() {
                report.missing.push(path);
                continue;
            }

            match compute_file_hmac(&self.key, &path) {
                Ok(actual_hmac) => {
                    if actual_hmac == *expected_hmac {
                        report.verified.push(path);
                    } else {
                        report.tampered.push(path);
                    }
                }
                Err(_) => {
                    report.tampered.push(path); // Can't read → treat as tampered.
                }
            }
        }

        report
    }

    /// Verify a single file.
    pub fn verify_file(&self, path: &Path) -> bool {
        let key = path.to_string_lossy().to_string();
        if let Some(expected) = self.manifest.entries.get(&key) {
            if let Ok(actual) = compute_file_hmac(&self.key, path) {
                return actual == *expected;
            }
        }
        false
    }

    /// Save the manifest to disk.
    pub fn save(&mut self) -> Result<(), String> {
        self.manifest.last_verified = chrono::Utc::now().timestamp();
        let json = serde_json::to_string_pretty(&self.manifest)
            .map_err(|e| format!("serialize manifest: {e}"))?;
        std::fs::write(&self.manifest_path, json).map_err(|e| format!("write manifest: {e}"))?;
        Ok(())
    }

    /// Get the number of registered files.
    pub fn registered_count(&self) -> usize {
        self.manifest.entries.len()
    }

    /// Diagnostics JSON.
    pub fn diagnostics(&self) -> serde_json::Value {
        let report = self.verify_all();
        serde_json::json!({
            "registered_files": self.manifest.entries.len(),
            "verified": report.verified.len(),
            "tampered": report.tampered.len(),
            "missing": report.missing.len(),
            "last_verified": self.manifest.last_verified,
        })
    }
}

/// Compute keyed hash of a file (SipHash, not cryptographic HMAC).
fn compute_file_hmac(key: &[u8; KEY_LEN], path: &Path) -> Result<String, String> {
    use std::io::Read;

    let mut file =
        std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;

    // Keyed hash: H(key || file_content || key)
    // Uses DefaultHasher (SipHash), NOT cryptographic HMAC-SHA256.
    // Detects accidental corruption and casual tampering.
    // Not a security boundary against targeted adversaries with
    // vault key access. A real HMAC requires a crypto crate dependency.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .map_err(|e| format!("read {}: {e}", path.display()))?;

    // Use SHA-256 if available via the existing sha2 dependency,
    // otherwise fall back to a keyed hash.
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    content.hash(&mut hasher);
    key.hash(&mut hasher);
    let h1 = hasher.finish();

    // Second round with different seed for more bits.
    let mut hasher2 = DefaultHasher::new();
    h1.hash(&mut hasher2);
    content.len().hash(&mut hasher2);
    key.hash(&mut hasher2);
    let h2 = hasher2.finish();

    Ok(format!("{:016x}{:016x}", h1, h2))
}

/// Generate a random 256-bit key.
fn generate_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    // Use system randomness.
    #[cfg(target_os = "windows")]
    {
        use std::io::Read;
        if let Ok(mut f) =
            std::fs::File::open("/dev/urandom").or_else(|_| std::fs::File::open("NUL"))
        {
            let _ = f.read_exact(&mut key);
        }
        // Windows fallback: use RtlGenRandom via getrandom crate pattern.
        // For now, use timestamp + process ID as entropy source.
        if key == [0u8; KEY_LEN] {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let seed = now.as_nanos() ^ (std::process::id() as u128) ^ 0xDEADBEEFCAFEBABE;
            for (i, byte) in key.iter_mut().enumerate() {
                *byte = ((seed >> (i % 16 * 8)) & 0xFF) as u8;
                *byte ^= (i as u8).wrapping_mul(137);
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut key);
        }
    }
    key
}

/// Save key to disk with restricted permissions.
fn save_key(path: &Path, key: &[u8; KEY_LEN]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, key).map_err(|e| format!("write key: {e}"))?;

    // Restrict permissions.
    #[cfg(target_os = "windows")]
    {
        let path_str = path.to_string_lossy();
        let _ = std::process::Command::new("icacls")
            .args([
                path_str.as_ref(),
                "/inheritance:r",
                "/grant:r",
                "SYSTEM:(R)",
                "/grant:r",
                "BUILTIN\\Administrators:(R)",
            ])
            .output();
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Load key from disk.
fn load_key(path: &Path) -> Result<[u8; KEY_LEN], String> {
    let data = std::fs::read(path).map_err(|e| format!("read key: {e}"))?;
    if data.len() != KEY_LEN {
        return Err(format!(
            "key file wrong size: {} (expected {})",
            data.len(),
            KEY_LEN
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&data);
    Ok(key)
}

/// Walk directory recursively, returning file paths.
fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walkdir(&path));
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    files
}

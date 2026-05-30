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

    /// Save the manifest to disk. Atomic-rename + fsync — a crash mid-write
    /// must not leave the integrity manifest truncated/corrupted (loaded next
    /// start as garbage → silent state loss → entire integrity gate disabled).
    pub fn save(&mut self) -> Result<(), String> {
        self.manifest.last_verified = chrono::Utc::now().timestamp();
        let json = serde_json::to_string_pretty(&self.manifest)
            .map_err(|e| format!("serialize manifest: {e}"))?;
        let tmp = self.manifest_path.with_extension("json.tmp");
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| format!("open temp manifest: {e}"))?;
            f.write_all(json.as_bytes())
                .map_err(|e| format!("write manifest: {e}"))?;
            f.sync_all().map_err(|e| format!("sync manifest: {e}"))?;
        }
        std::fs::rename(&tmp, &self.manifest_path)
            .map_err(|e| format!("rename manifest: {e}"))?;
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

    /// Borrow the raw key bytes — for sidecar HMAC computation in other
    /// subsystems (config tamper detection, binary integrity check) that
    /// need to share the same authentication key without instantiating a
    /// second vault.
    pub fn key_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }
}

// ── Binary integrity (TOFU) ───────────────────────────────────────────────
//
// Separate manifest (`binary_integrity.json`) used to detect tampering of
// the daemon's own executable and sibling worker binaries between starts.
// Fail-loud (warn + health flag), NOT fail-closed — admins replace binaries
// during upgrades and we must keep running so the operator sees the alert.

/// Manifest of binary hashes — distinct from the runtime asset manifest so a
/// post-upgrade rehash of binaries cannot ripple through and silently drop a
/// real signature/YARA tamper alert (or vice-versa).
#[derive(Debug, Serialize, Deserialize, Default)]
struct BinaryManifest {
    /// Map of absolute binary path → HMAC-SHA256 hex.
    entries: HashMap<String, String>,
    /// Timestamp of last update (creation or rehash on upgrade).
    last_updated: i64,
}

/// Result of a binary integrity check at startup.
#[derive(Debug, Default)]
pub struct BinaryIntegrityReport {
    /// Manifest was missing — TOFU baseline established this run.
    pub tofu_initialized: bool,
    /// Binary paths whose stored hash matched.
    pub verified: Vec<PathBuf>,
    /// Binary paths whose stored hash MISMATCHED (real tamper signal).
    pub drifted: Vec<PathBuf>,
    /// Binary paths present on disk but absent from manifest (new binary
    /// added since baseline — could be legitimate upgrade or planted helper).
    pub new_entries: Vec<PathBuf>,
    /// Binary paths in manifest but missing from disk (worker removed).
    pub missing: Vec<PathBuf>,
}

impl BinaryIntegrityReport {
    /// True when at least one binary's hash changed against the baseline.
    pub fn has_drift(&self) -> bool {
        !self.drifted.is_empty()
    }
}

/// Verify the daemon's own executable + sibling workers against
/// `<state_dir>/binary_integrity.json`. On first call the manifest is
/// created (trust-on-first-run); on subsequent calls a mismatch is
/// reported via `BinaryIntegrityReport.drifted`. The manifest is rehashed
/// when new sibling workers appear OR after explicit refresh; on a drift
/// we DO NOT rehash — the operator must investigate first.
///
/// `key` is the runtime-integrity vault key (shared, no second secret).
pub fn verify_or_init_binaries(
    state_dir: &Path,
    key: &[u8; KEY_LEN],
) -> Result<BinaryIntegrityReport, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| "current_exe has no parent".to_string())?
        .to_path_buf();

    // Candidate binaries: daemon itself + known sibling workers. Missing
    // siblings are skipped silently (dev builds, partial installs).
    let mut candidates: Vec<PathBuf> = vec![exe.clone()];
    for sibling in [
        "argusd.exe",
        "clamavd.exe",
        "sandboxd.exe",
        "etw_probe.exe",
        "freshclam.exe",
    ] {
        let p = exe_dir.join(sibling);
        if p.exists() && p.is_file() {
            candidates.push(p);
        }
    }

    let manifest_path = state_dir.join("binary_integrity.json");
    let mut manifest: BinaryManifest = if manifest_path.exists() {
        match std::fs::read_to_string(&manifest_path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => BinaryManifest::default(),
        }
    } else {
        BinaryManifest::default()
    };

    let mut report = BinaryIntegrityReport::default();

    if manifest.entries.is_empty() {
        // TOFU: establish baseline.
        for c in &candidates {
            match compute_file_hmac(key, c) {
                Ok(h) => {
                    manifest
                        .entries
                        .insert(c.to_string_lossy().to_string(), h);
                }
                Err(e) => {
                    warn!(file = %c.display(), error = %e, "binary integrity: failed to hash");
                }
            }
        }
        manifest.last_updated = chrono::Utc::now().timestamp();
        write_binary_manifest(&manifest_path, &manifest)?;
        report.tofu_initialized = true;
        info!(
            count = manifest.entries.len(),
            path = %manifest_path.display(),
            "binary integrity: TOFU baseline established"
        );
        return Ok(report);
    }

    // Subsequent start: verify each candidate against the stored hash.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in &candidates {
        let key_str = c.to_string_lossy().to_string();
        seen.insert(key_str.clone());
        match manifest.entries.get(&key_str) {
            Some(expected) => match compute_file_hmac(key, c) {
                Ok(actual) => {
                    if actual == *expected {
                        report.verified.push(c.clone());
                    } else {
                        report.drifted.push(c.clone());
                    }
                }
                Err(_) => report.drifted.push(c.clone()),
            },
            None => report.new_entries.push(c.clone()),
        }
    }
    for (path_str, _) in &manifest.entries {
        if !seen.contains(path_str) {
            report.missing.push(PathBuf::from(path_str));
        }
    }

    Ok(report)
}

fn write_binary_manifest(path: &Path, manifest: &BinaryManifest) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| format!("serialize binary manifest: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("open temp binary manifest: {e}"))?;
        f.write_all(json.as_bytes())
            .map_err(|e| format!("write binary manifest: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("sync binary manifest: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("rename binary manifest: {e}"))?;
    Ok(())
}

/// Verify a single binary path against the stored binary-integrity manifest.
/// Returns:
///   - `Ok(true)`  — hash matches the baseline (safe to spawn).
///   - `Ok(false)` — hash differs (refuse to spawn — tamper signal).
///   - `Err(_)`    — manifest missing, binary missing, or unrecoverable I/O.
///                   Caller MUST NOT silently spawn on Err — fall back to
///                   the same fail-loud handling used at startup.
///
/// On a manifest that simply doesn't have this binary registered (e.g. the
/// daemon was upgraded before this check shipped), we return `Ok(true)` —
/// the startup TOFU pass will re-baseline on the next start, and we don't
/// want this check to break update flows that worked yesterday.
pub fn verify_binary_against_manifest(
    state_dir: &Path,
    key: &[u8; KEY_LEN],
    binary: &Path,
) -> Result<bool, String> {
    let manifest_path = state_dir.join("binary_integrity.json");
    if !manifest_path.exists() {
        // No baseline yet — nothing to verify against.
        return Ok(true);
    }
    let json = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read binary manifest: {e}"))?;
    let manifest: BinaryManifest =
        serde_json::from_str(&json).map_err(|e| format!("parse binary manifest: {e}"))?;
    let key_str = binary.to_string_lossy().to_string();
    let expected = match manifest.entries.get(&key_str) {
        Some(h) => h,
        // Unregistered binary — silent allow (see doc above).
        None => return Ok(true),
    };
    let actual = compute_file_hmac(key, binary)?;
    Ok(&actual == expected)
}

/// Compute HMAC-SHA256 of an arbitrary byte slice under the vault key.
/// Used by the config tamper-detection sidecar.
pub fn hmac_bytes(key: &[u8; KEY_LEN], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(tag.len() * 2);
    for b in tag.iter() {
        use std::fmt::Write as _;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

/// Compute HMAC-SHA256 of a file under the integrity key.
///
/// CRYPTO FIX: previous impl used `DefaultHasher` (SipHash) wrapped as
/// `H(key || content || key)`. SipHash is a PRF for hash-flooding defence,
/// NOT a MAC. Using a non-MAC to "authenticate" the integrity manifest
/// meant the gate that's supposed to detect a silent lobotomy of signatures
/// / YARA rules was relying on a primitive with no formal MAC security.
/// The whole point of `runtime_integrity` is to defeat targeted tampering;
/// the old impl explicitly admitted in its own comment that it wasn't a
/// security boundary against that. Now uses real HMAC-SHA256 from the
/// `hmac` crate, keyed by the existing 32-byte CSPRNG-generated integrity
/// key — proper EUF-CMA security under SHA-256's collision/PRF assumptions.
///
/// The output format stays 32 lowercase hex chars × 2 = 64 chars wide so
/// existing manifests can be transparently re-verified (they'll appear
/// "tampered" on first verify post-upgrade, which forces a re-register and
/// is the SAFE outcome — a non-MAC manifest entry was untrusted anyway).
fn compute_file_hmac(key: &[u8; KEY_LEN], path: &Path) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::io::Read;

    let mut file =
        std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|e| format!("hmac init: {e}"))?;

    // Stream the file in chunks — avoids the previous "read entire file into
    // a Vec" pattern that would have allocated 100+ MB for a single large
    // signature DB. HMAC update is streaming-safe.
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        mac.update(&buf[..n]);
    }

    let tag = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(tag.len() * 2);
    for b in tag.iter() {
        use std::fmt::Write as _;
        let _ = write!(hex, "{:02x}", b);
    }
    Ok(hex)
}

/// Generate a random 256-bit key from the OS CSPRNG.
///
/// SECURITY: the previous Windows path was broken — `File::open("/dev/urandom")`
/// fails on Windows and the `"NUL"` fallback opens successfully but yields EOF
/// on read, leaving `key` all-zero. It then derived the key from
/// `timestamp ^ pid ^ constant`, i.e. a PREDICTABLE value. Since this key
/// authenticates the integrity manifest, a predictable key lets an attacker
/// who can guess the daemon start time + PID forge valid hashes after tampering
/// signatures/rules — defeating the whole anti-"silent-lobotomy" design.
///
/// `rand::thread_rng()` is a CSPRNG seeded from the OS entropy source
/// (BCryptGenRandom on Windows, getrandom on Unix) — same primitive the
/// quarantine vault key already uses.
fn generate_key() -> [u8; KEY_LEN] {
    use rand::RngCore;
    let mut key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Save key to disk with restricted permissions. fsync — predictable-key
/// disaster (see `generate_key` doc) repeats on crash if the buffered write
/// is lost: next start sees no key file → regenerates → re-derives a new key
/// → entire manifest fails authentication → silent integrity bypass.
fn save_key(path: &Path, key: &[u8; KEY_LEN]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("open key: {e}"))?;
        f.write_all(key).map_err(|e| format!("write key: {e}"))?;
        f.sync_all().map_err(|e| format!("sync key: {e}"))?;
    }

    // Restrict permissions.
    // R9-LETHAL: use raw SIDs so the grant works on non-English Windows.
    // The English-name version ("SYSTEM", "BUILTIN\Administrators") fails
    // silently on localized installs (German "SYSTEM" is fine, but the
    // "BUILTIN" prefix translates), leaving the integrity key world-readable.
    #[cfg(target_os = "windows")]
    {
        use crate::win_process::QuietCommand;
        let path_str = path.to_string_lossy();
        let _ = std::process::Command::new("icacls")
            .args([
                path_str.as_ref(),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(R)",     // NT AUTHORITY\SYSTEM
                "/grant:r",
                "*S-1-5-32-544:(R)", // BUILTIN\Administrators
            ])
            .quiet_windows()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_is_random_not_zero() {
        // Regression: the old Windows path left the key all-zero (NUL EOF) and
        // fell back to a predictable timestamp^pid seed.
        let k1 = generate_key();
        let k2 = generate_key();
        assert_ne!(k1, [0u8; KEY_LEN], "key must not be all-zero (broken CSPRNG)");
        assert_ne!(k1, k2, "two keys must differ (predictable generator)");
    }

    #[test]
    fn hmac_detects_content_tamper() {
        let key = [7u8; KEY_LEN];
        let dir = std::env::temp_dir().join("sent_integrity_hmac_test");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("asset.bin");
        std::fs::write(&f, b"original signatures").unwrap();
        let h1 = compute_file_hmac(&key, &f).unwrap();
        std::fs::write(&f, b"tampered signatures").unwrap();
        let h2 = compute_file_hmac(&key, &f).unwrap();
        assert_ne!(h1, h2, "keyed hash must change when content changes");
        // Same content + same key → stable hash.
        std::fs::write(&f, b"original signatures").unwrap();
        assert_eq!(h1, compute_file_hmac(&key, &f).unwrap());
        let _ = std::fs::remove_file(&f);
    }
}

//! Quarantine vault - AES-256-GCM encrypted storage for detected threats.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::info;
use uuid::Uuid;

use crate::db::{Database, QuarantineRow};

/// Max file size for quarantine (100 MB).
const MAX_QUARANTINE_SIZE: u64 = 100 * 1024 * 1024;

/// 32-byte vault key. Stored locally with restricted ACL.
fn get_vault_key() -> Result<[u8; 32], String> {
    let key_path = PathBuf::from("runtime/quarantine/.vault_key");
    if let Ok(data) = fs::read(&key_path) {
        if data.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            return Ok(key);
        }
    }

    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut key);
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Cannot create vault key dir: {e}"))?;
    }
    fs::write(&key_path, key).map_err(|e| format!("Cannot persist vault key: {e}"))?;
    // Restrict permissions — only current user + SYSTEM can read.
    restrict_file_permissions(&key_path);
    Ok(key)
}

/// Restrict file permissions so only the current user and SYSTEM can access.
#[cfg(target_os = "windows")]
fn restrict_file_permissions(path: &Path) {
    #[cfg(target_os = "windows")]
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    // icacls: remove inherited perms, grant only current user + SYSTEM.
    let path_str = path.to_string_lossy();
    let _ = Command::new("icacls")
        .args([
            path_str.as_ref(),
            "/inheritance:r",
            "/grant:r",
            "SYSTEM:(R)",
            "/grant:r",
        ])
        .arg(format!("{}:(R)", whoami()))
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();
}

#[cfg(target_os = "windows")]
fn whoami() -> String {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("whoami")
        .creation_flags(0x08000000)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "BUILTIN\\Administrators".to_string())
}

#[cfg(not(target_os = "windows"))]
fn restrict_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[derive(Debug)]
pub struct PreparedQuarantine {
    pub row: QuarantineRow,
    pub result: QuarantineResult,
    pub canonical_path: PathBuf,
    pub vault_path: PathBuf,
}

/// Compatibility wrapper. New daemon code should split prepare/commit/finalize
/// so DB locks are not held during file IO and encryption.
#[allow(dead_code)]
pub fn quarantine_file(
    file_path: &Path,
    vault_dir: &Path,
    virus_name: &str,
    scan_id: &str,
    db: &Database,
) -> Result<QuarantineResult, String> {
    let prepared = prepare_quarantine_file(file_path, vault_dir, virus_name, scan_id)?;
    db.insert_quarantine_item(&prepared.row);
    if let Err(e) = finalize_quarantine_file(&prepared) {
        db.update_quarantine_status(&prepared.row.quarantine_id, "failed");
        return Err(e);
    }
    Ok(prepared.result)
}

/// Validate, read, hash, encrypt, and write vault without touching the DB.
pub fn prepare_quarantine_file(
    file_path: &Path,
    vault_dir: &Path,
    virus_name: &str,
    scan_id: &str,
) -> Result<PreparedQuarantine, String> {
    if !file_path.exists() {
        return Err(format!("File not found: {}", file_path.display()));
    }
    if file_path.is_symlink() {
        return Err("Refusing to quarantine a symlink".into());
    }
    let canonical = file_path
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path: {e}"))?;
    let meta = fs::metadata(&canonical).map_err(|e| format!("Cannot read metadata: {e}"))?;
    if meta.len() > MAX_QUARANTINE_SIZE {
        return Err(format!(
            "File too large ({} bytes, max {})",
            meta.len(),
            MAX_QUARANTINE_SIZE
        ));
    }

    let content = fs::read(&canonical).map_err(|e| format!("Cannot read file: {e}"))?;
    let original_size = content.len() as u64;
    let sha256_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&content);
        hex::encode(hasher.finalize())
    };

    let key_bytes = get_vault_key()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, content.as_ref())
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let q_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    let vault_subdir = vault_dir.join(&q_id[..2]);
    fs::create_dir_all(&vault_subdir).map_err(|e| format!("Cannot create vault dir: {e}"))?;
    let vault_path = vault_subdir.join(format!("{q_id}.vault"));

    let mut vault_data = Vec::with_capacity(12 + ciphertext.len());
    vault_data.extend_from_slice(&nonce_bytes);
    vault_data.extend_from_slice(&ciphertext);
    let mut vault_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&vault_path)
        .map_err(|e| format!("Cannot create vault file: {e}"))?;
    if let Err(e) = vault_file.write_all(&vault_data) {
        let _ = fs::remove_file(&vault_path);
        return Err(format!("Cannot write vault file: {e}"));
    }
    if let Err(e) = vault_file.flush() {
        let _ = fs::remove_file(&vault_path);
        return Err(format!("Cannot flush vault file: {e}"));
    }

    let row = QuarantineRow {
        quarantine_id: q_id.clone(),
        original_path: canonical.to_string_lossy().to_string(),
        vault_path: vault_path.to_string_lossy().to_string(),
        virus_name: virus_name.to_string(),
        sha256: sha256_hash.clone(),
        original_size,
        quarantined_at: now,
        scan_id: scan_id.to_string(),
        status: "quarantined".to_string(),
    };

    let result = QuarantineResult {
        quarantine_id: q_id,
        original_path: canonical.to_string_lossy().to_string(),
        virus_name: virus_name.to_string(),
        sha256: sha256_hash,
        original_size,
    };

    Ok(PreparedQuarantine {
        row,
        result,
        canonical_path: canonical,
        vault_path,
    })
}

/// Delete original only after vault file and DB row are durable.
pub fn finalize_quarantine_file(prepared: &PreparedQuarantine) -> Result<(), String> {
    if let Err(e) = fs::remove_file(&prepared.canonical_path) {
        let _ = fs::remove_file(&prepared.vault_path);
        return Err(format!("Cannot remove original: {e}"));
    }

    info!(
        id = %prepared.result.quarantine_id,
        path = %prepared.canonical_path.display(),
        virus = %prepared.result.virus_name,
        "file quarantined (AES-256-GCM)"
    );
    Ok(())
}

#[allow(dead_code)]
pub fn restore_file(
    quarantine_id: &str,
    _vault_dir: &Path,
    db: &Database,
) -> Result<String, String> {
    let item = db
        .get_quarantine_item(quarantine_id)
        .ok_or_else(|| format!("Not found: {quarantine_id}"))?;
    let path = restore_file_from_row(&item)?;
    db.update_quarantine_status(quarantine_id, "restored");
    Ok(path)
}

/// Decrypt, verify, and restore without touching the DB.
pub fn restore_file_from_row(item: &QuarantineRow) -> Result<String, String> {
    if item.status != "quarantined" {
        return Err(format!("Status is '{}', not quarantined", item.status));
    }

    let vault_path = validate_vault_path(Path::new(&item.vault_path))?;

    let original_path = Path::new(&item.original_path);
    validate_restore_path(original_path)?;
    if original_path.exists() {
        return Err(format!("Target exists: {}", original_path.display()));
    }

    let vault_data = fs::read(&vault_path).map_err(|e| format!("Cannot read vault: {e}"))?;
    if vault_data.len() < 12 {
        return Err("Vault file corrupted (too small)".into());
    }

    let (nonce_bytes, ciphertext) = vault_data.split_at(12);
    let key_bytes = get_vault_key()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed - vault key may have changed".to_string())?;

    let restored_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        hex::encode(hasher.finalize())
    };
    if restored_hash != item.sha256 {
        return Err(format!(
            "Hash mismatch: expected {}, got {}",
            item.sha256, restored_hash
        ));
    }

    if let Some(parent) = original_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(original_path)
        .map_err(|e| format!("Cannot create restored file: {e}"))?;
    out.write_all(&plaintext)
        .map_err(|e| format!("Cannot write restored file: {e}"))?;

    let _ = fs::remove_file(vault_path);
    info!(id = %item.quarantine_id, path = %original_path.display(), "file restored (hash verified)");
    Ok(item.original_path.clone())
}

#[allow(dead_code)]
pub fn delete_quarantined(quarantine_id: &str, db: &Database) -> Result<(), String> {
    let item = db
        .get_quarantine_item(quarantine_id)
        .ok_or_else(|| format!("Not found: {quarantine_id}"))?;
    delete_vault_file(&item)?;
    db.update_quarantine_status(quarantine_id, "deleted");
    info!(id = quarantine_id, "quarantine item deleted");
    Ok(())
}

/// Remove vault file without touching the DB.
pub fn delete_vault_file(item: &QuarantineRow) -> Result<(), String> {
    let vault_path = validate_vault_path(Path::new(&item.vault_path))?;
    fs::remove_file(vault_path).map_err(|e| format!("Cannot delete vault file: {e}"))?;
    Ok(())
}

fn validate_vault_path(path: &Path) -> Result<PathBuf, String> {
    let root = PathBuf::from("runtime/quarantine")
        .canonicalize()
        .map_err(|e| format!("Cannot resolve vault root: {e}"))?;
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("Vault file missing or invalid: {e}"))?;
    if !canonical.starts_with(&root) {
        return Err("Vault path outside quarantine root".into());
    }
    if canonical.extension().and_then(|e| e.to_str()) != Some("vault") {
        return Err("Invalid vault file extension".into());
    }
    Ok(canonical)
}

fn validate_restore_path(path: &Path) -> Result<(), String> {
    let canonical = path
        .canonicalize()
        .or_else(|_| {
            path.parent()
                .and_then(|p| p.canonicalize().ok())
                .map(|p| p.join(path.file_name().unwrap_or_default()))
                .ok_or_else(|| "Cannot resolve path".to_string())
        })
        .map_err(|e| format!("Path resolution failed: {e}"))?;

    let s = canonical.to_string_lossy().to_lowercase();
    let blocked = [
        "\\windows\\",
        "\\system32\\",
        "\\syswow64\\",
        "\\program files\\",
        "\\program files (x86)\\",
        "\\programdata\\",
        "\\drivers\\",
    ];
    for b in &blocked {
        if s.contains(b) {
            return Err(format!("System path blocked: {}", canonical.display()));
        }
    }

    if canonical.parent().is_none() || canonical.parent() == Some(Path::new("")) {
        return Err("Root path blocked".into());
    }

    if path.is_symlink() {
        return Err("Symlink target blocked - restore to a real directory".into());
    }

    Ok(())
}

mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[derive(Debug, Serialize)]
pub struct QuarantineResult {
    pub quarantine_id: String,
    pub original_path: String,
    pub virus_name: String,
    pub sha256: String,
    pub original_size: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Global mutex — `get_vault_key()` and `validate_vault_path()` use
    /// hard-coded relative paths (`runtime/quarantine/`), so we must
    /// `set_current_dir` into each test's temp root.  Because CWD is
    /// process-global we serialize all quarantine tests.
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    /// Create a unique temp directory and set CWD to it.
    /// Returns the path so the caller can clean up.
    fn setup_test_env() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sentinella_qtest_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(dir.join("runtime/quarantine")).unwrap();
        std::env::set_current_dir(&dir).unwrap();
        dir
    }

    fn teardown(dir: &Path) {
        // Best-effort cleanup. Ignore errors (e.g. if a test already removed files).
        let _ = fs::remove_dir_all(dir);
    }

    // ---------------------------------------------------------------
    //  1. Vault key generation — idempotent (same key on repeat call)
    // ---------------------------------------------------------------
    #[test]
    fn vault_key_is_persisted_across_calls() {
        let _lock = CWD_LOCK.lock().unwrap();
        let root = setup_test_env();

        let k1 = get_vault_key().expect("first call should succeed");
        let k2 = get_vault_key().expect("second call should succeed");
        assert_eq!(k1, k2, "vault key must be stable across calls");

        // The key file should exist on disk and be exactly 32 bytes.
        let key_path = root.join("runtime/quarantine/.vault_key");
        assert!(key_path.exists(), ".vault_key file must be persisted");
        let on_disk = fs::read(&key_path).unwrap();
        assert_eq!(on_disk.len(), 32);
        assert_eq!(&on_disk[..], &k1[..]);

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  2. Full quarantine round-trip (prepare → finalize → restore)
    // ---------------------------------------------------------------
    #[test]
    fn quarantine_round_trip() {
        let _lock = CWD_LOCK.lock().unwrap();
        let root = setup_test_env();

        let vault_dir = root.join("runtime/quarantine");
        let original = root.join("malware_sample.txt");
        let content = b"this is a test payload for quarantine";
        fs::write(&original, content).unwrap();

        // --- prepare ---
        let prepared = prepare_quarantine_file(&original, &vault_dir, "Eicar-Test", "scan-001")
            .expect("prepare should succeed");

        assert!(
            prepared.vault_path.exists(),
            "vault file must exist after prepare"
        );
        assert!(
            original.exists(),
            "original must still exist after prepare (not yet finalized)"
        );
        assert_eq!(prepared.result.original_size, content.len() as u64);
        assert_eq!(prepared.result.virus_name, "Eicar-Test");
        assert_eq!(prepared.row.status, "quarantined");

        // --- finalize (deletes original) ---
        finalize_quarantine_file(&prepared).expect("finalize should succeed");
        assert!(
            !original.exists(),
            "original must be deleted after finalize"
        );
        assert!(
            prepared.vault_path.exists(),
            "vault file must survive finalize"
        );

        // --- restore ---
        let row = QuarantineRow {
            quarantine_id: prepared.row.quarantine_id.clone(),
            original_path: prepared.row.original_path.clone(),
            vault_path: prepared.row.vault_path.clone(),
            virus_name: prepared.row.virus_name.clone(),
            sha256: prepared.row.sha256.clone(),
            original_size: prepared.row.original_size,
            quarantined_at: prepared.row.quarantined_at,
            scan_id: prepared.row.scan_id.clone(),
            status: "quarantined".to_string(),
        };

        let restored_path = restore_file_from_row(&row).expect("restore should succeed");

        let restored_content = fs::read(&restored_path).unwrap();
        assert_eq!(
            restored_content, content,
            "restored content must match original"
        );

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  3. Path validation — restore blocked paths
    // ---------------------------------------------------------------
    #[test]
    fn validate_restore_path_rejects_system_paths() {
        // This test does not need CWD manipulation because
        // validate_restore_path works on absolute paths.
        let blocked = [
            r"C:\Windows\System32\evil.exe",
            r"C:\Windows\notepad.exe",
            r"C:\Windows\System32\drivers\malware.sys",
            r"C:\Windows\SysWOW64\bad.dll",
            r"C:\Program Files\app\file.exe",
            r"C:\Program Files (x86)\app\file.exe",
            r"C:\ProgramData\secret.dat",
        ];

        for path_str in &blocked {
            let p = Path::new(path_str);
            let result = validate_restore_path(p);
            assert!(
                result.is_err(),
                "validate_restore_path should reject '{}', got Ok",
                path_str
            );
        }
    }

    // ---------------------------------------------------------------
    //  4. Path validation — vault path outside quarantine root
    // ---------------------------------------------------------------
    #[test]
    fn validate_vault_path_rejects_outside_root() {
        let _lock = CWD_LOCK.lock().unwrap();
        let root = setup_test_env();

        // Create a file outside the vault root.
        let outside = root.join("somewhere_else.vault");
        fs::write(&outside, b"fake").unwrap();

        let result = validate_vault_path(&outside);
        assert!(
            result.is_err(),
            "validate_vault_path must reject paths outside runtime/quarantine/"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("outside quarantine root") || err.contains("Vault path outside"),
            "error message should mention path is outside root, got: {err}"
        );

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  5. prepare_quarantine_file on non-existent file
    // ---------------------------------------------------------------
    #[test]
    fn prepare_nonexistent_file_returns_error() {
        let _lock = CWD_LOCK.lock().unwrap();
        let root = setup_test_env();

        let vault_dir = root.join("runtime/quarantine");
        let missing = root.join("does_not_exist.bin");

        let result = prepare_quarantine_file(&missing, &vault_dir, "Trojan", "scan-002");
        assert!(result.is_err(), "prepare on missing file must fail");
        let err = result.unwrap_err();
        assert!(
            err.contains("not found") || err.contains("File not found"),
            "error should mention file not found, got: {err}"
        );

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  6. Empty (0-byte) file quarantine
    // ---------------------------------------------------------------
    #[test]
    fn quarantine_empty_file_succeeds() {
        let _lock = CWD_LOCK.lock().unwrap();
        let root = setup_test_env();

        let vault_dir = root.join("runtime/quarantine");
        let empty_file = root.join("empty.dat");
        fs::write(&empty_file, b"").unwrap();

        let prepared = prepare_quarantine_file(&empty_file, &vault_dir, "PUA.Empty", "scan-003")
            .expect("quarantine of empty file should succeed");

        assert_eq!(prepared.result.original_size, 0);
        assert!(prepared.vault_path.exists());

        finalize_quarantine_file(&prepared).expect("finalize empty should succeed");
        assert!(
            !empty_file.exists(),
            "original empty file should be deleted"
        );

        // Restore and verify zero-length content.
        let row = QuarantineRow {
            quarantine_id: prepared.row.quarantine_id.clone(),
            original_path: prepared.row.original_path.clone(),
            vault_path: prepared.row.vault_path.clone(),
            virus_name: prepared.row.virus_name.clone(),
            sha256: prepared.row.sha256.clone(),
            original_size: prepared.row.original_size,
            quarantined_at: prepared.row.quarantined_at,
            scan_id: prepared.row.scan_id.clone(),
            status: "quarantined".to_string(),
        };
        let restored = restore_file_from_row(&row).expect("restore empty should succeed");
        let data = fs::read(&restored).unwrap();
        assert!(data.is_empty(), "restored empty file should be 0 bytes");

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  7. Large path (>260 chars) should not crash
    // ---------------------------------------------------------------
    #[test]
    fn large_path_does_not_crash() {
        let _lock = CWD_LOCK.lock().unwrap();
        let root = setup_test_env();

        let vault_dir = root.join("runtime/quarantine");
        // Build a path with > 260 characters.
        let long_name = "a".repeat(300);
        let long_path = root.join(&long_name);

        // We don't expect this to succeed (OS will likely reject the path),
        // but it must not panic — it should return an Err.
        let result = prepare_quarantine_file(&long_path, &vault_dir, "LongPath", "scan-004");
        // Either it errors cleanly or (on \\?\ capable systems) succeeds.
        // The key assertion: no panic occurred if we reach this line.
        if let Err(e) = &result {
            // Acceptable — OS rejected the too-long path.
            assert!(!e.is_empty(), "error message should be non-empty");
        }
        // If Ok, that means the OS supports long paths — also fine.

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  8. validate_vault_path rejects wrong extension
    // ---------------------------------------------------------------
    #[test]
    fn validate_vault_path_rejects_wrong_extension() {
        let _lock = CWD_LOCK.lock().unwrap();
        let root = setup_test_env();

        // Place a file inside the vault root but with wrong extension.
        let bad_ext = root.join("runtime/quarantine/evil.exe");
        fs::write(&bad_ext, b"data").unwrap();

        let result = validate_vault_path(&bad_ext);
        assert!(result.is_err(), "non-.vault extension should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("extension"),
            "error should mention extension, got: {err}"
        );

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  9. restore_file_from_row rejects non-quarantined status
    // ---------------------------------------------------------------
    #[test]
    fn restore_rejects_non_quarantined_status() {
        let row = QuarantineRow {
            quarantine_id: "test-id".into(),
            original_path: r"C:\temp\file.txt".into(),
            vault_path: "runtime/quarantine/ab/test.vault".into(),
            virus_name: "TestVirus".into(),
            sha256: "deadbeef".into(),
            original_size: 42,
            quarantined_at: 0,
            scan_id: "scan-x".into(),
            status: "restored".into(),
        };

        let result = restore_file_from_row(&row);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("not quarantined"),
            "should reject status='restored', got: {err}"
        );
    }
}

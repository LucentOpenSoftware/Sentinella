//! Quarantine vault - AES-256-GCM encrypted storage for detected threats.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

use crate::db::{Database, QuarantineRow};

/// Max file size for quarantine (100 MB).
const MAX_QUARANTINE_SIZE: u64 = 100 * 1024 * 1024;

/// Chunk size for streaming AES-GCM (1 MiB).
///
/// Memory pressure: the old format encrypted the whole file in RAM, peaking at
/// ~3x the file size (plaintext + ciphertext + concatenated vault buffer). On a
/// 100 MB sample that's ~300 MB transient, which OOMs low-RAM boxes during a
/// malware storm. With 1 MiB chunks the steady-state peak is ~2 MiB per
/// in-flight quarantine (one plaintext chunk + one ciphertext chunk).
const CHUNK_SIZE: usize = 1024 * 1024;

/// Magic prefix identifying the chunked vault format.
///
/// Old vaults start with a 12-byte random nonce, so the first byte is uniform
/// over 0..=255. A 4-byte magic gives ~1/2^32 odds that a legacy vault is
/// misclassified — effectively zero for the corpus sizes we ever hold.
const CHUNKED_MAGIC: [u8; 4] = [0xC1, 0xAE, 0x53, 0x01];

/// Header layout after the magic: original_size u64 LE + num_chunks u32 LE.
const CHUNKED_HEADER_LEN: usize = 4 + 8 + 4;

/// Max length of virus_name / scan_id stored in DB and emitted to logs.
/// F2: prevents log-injection (CR/LF/control chars) and DB bloat from a
/// caller passing a 10 MB "virus name" through quarantine.add.
const MAX_VIRUS_NAME_LEN: usize = 256;
const MAX_SCAN_ID_LEN: usize = 128;
/// Hard cap on path length stored in the DB row. Windows MAX_PATH is 260;
/// long-path namespace can push to 32k. Anything beyond ~4 KB in our DB row
/// is either bug or abuse — refuse.
const MAX_STORED_PATH_LEN: usize = 4096;

/// F2: strip ASCII control chars (incl. CR/LF) so a hostile virus_name
/// cannot inject fake log lines into structured tracing output that ops
/// or SIEM might parse line-oriented. Also truncate to bound.
fn sanitize_label(s: &str, max: usize) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect();
    if cleaned.is_empty() {
        "Unknown".into()
    } else {
        cleaned
    }
}

/// Resolve the quarantine root directory.
fn quarantine_root() -> PathBuf {
    crate::paths::paths().quarantine_dir()
}

/// 32-byte vault key. Stored locally with restricted ACL.
fn get_vault_key() -> Result<[u8; 32], String> {
    get_vault_key_in(&quarantine_root())
}

/// Inner: loads or creates vault key inside the given quarantine dir.
/// Race-safe: if two threads call concurrently on first start, only one
/// writes the key; the other reads it back. Without `create_new`, both
/// could write different keys → second-writer wins → first thread holds
/// a stale key in memory and all later encrypts use the wrong key.
fn get_vault_key_in(qdir: &Path) -> Result<[u8; 32], String> {
    let key_path = qdir.join(".vault_key");
    // Fast path: existing key.
    if let Ok(data) = fs::read(&key_path) {
        if data.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            return Ok(key);
        }
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Cannot create vault key dir: {e}"))?;
    }

    let mut new_key = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut new_key);

    // Atomic create_new: returns AlreadyExists if another thread won the race.
    use std::io::Write;
    match fs::OpenOptions::new().write(true).create_new(true).open(&key_path) {
        Ok(mut f) => {
            f.write_all(&new_key).map_err(|e| format!("Cannot persist vault key: {e}"))?;
            // Durability: 32-byte buffered writes can be lost on power loss
            // between first-quarantine and disk flush. Vault key loss means
            // every encrypted sample is unrecoverable — fsync before release.
            f.sync_all().map_err(|e| format!("Cannot sync vault key: {e}"))?;
            drop(f);
            restrict_file_permissions(&key_path);
            Ok(new_key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost race — read winner's key.
            let data = fs::read(&key_path).map_err(|e| format!("Cannot read existing vault key: {e}"))?;
            if data.len() != 32 {
                return Err(format!("Vault key file corrupt: {} bytes", data.len()));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            Ok(key)
        }
        Err(e) => Err(format!("Cannot create vault key: {e}")),
    }
}

/// Restrict file permissions on the vault AES-256 key.
///
/// ☠️ R7-LETHAL: only SYSTEM and Administrators may read this file. The
/// daemon runs as SYSTEM and is the ONLY component that ever needs to
/// touch the vault key (GUI never decrypts — it asks the daemon over IPC).
/// A prior round granted `BUILTIN\Users (R)` "to mirror the IPC secret
/// model"; that was wrong. The IPC secret authenticates the GUI process;
/// the vault key encrypts every quarantined malware. Letting any
/// logged-in user read the key turns the entire quarantine vault into a
/// public archive — they can decrypt every caught malware sample for
/// re-targeting research, and on multi-user / RDP / kiosk boxes they can
/// read another user's false-positive quarantine (sensitive docs).
#[cfg(target_os = "windows")]
fn restrict_file_permissions(path: &Path) {
    // Under `cargo test` the test process runs as the user (not SYSTEM)
    // and creates the test-only vault key — applying a SYSTEM-only ACL
    // would lock the test process out of its own file on the next read.
    // The production daemon always runs as SYSTEM so this no-op-in-tests
    // path is correct.
    #[cfg(test)]
    {
        let _ = path;
        return;
    }

    #[cfg(not(test))]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        let path_str = path.to_string_lossy();
        let _ = Command::new("icacls")
            .args([
                path_str.as_ref(),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(R)",      // NT AUTHORITY\SYSTEM
                "/grant:r",
                "*S-1-5-32-544:(R)",  // BUILTIN\Administrators
                // Intentionally NO BUILTIN\Users grant.
            ])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output();
    }
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
        let _ = db.update_quarantine_status(&prepared.row.quarantine_id, "failed");
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
    // ☠️ R4-LETHAL-3: server-side path validation for QUARANTINE ADD.
    //
    // Previously `validate_restore_path` existed only on the RESTORE side.
    // The ADD path had no guard, so any caller able to obtain a challenge
    // token (which — per the current IPC secret ACL — is *any* logged-in
    // user) could ask the daemon (running as SYSTEM) to quarantine any
    // file on disk. Quarantine = "encrypt to vault + delete original".
    //
    // Concrete impact: an unprivileged user could ask SYSTEM to delete:
    //   - C:\Program Files\Sentinella\sentinelld.exe (kill our own AV)
    //   - Defender / EDR sensor binaries (kill the OS AV)
    //   - Service .exe / .sys under writable ProgramData paths
    //   - Browser updaters, signed installers, etc.
    // → exactly the "kill the AV, leave the system vulnerable" class.
    //
    // Same blocklist as restore + a hard refusal for our own install dir
    // so we cannot be socially-engineered into self-destructing.
    validate_quarantine_source(&canonical)?;
    // F2: bound + sanitize caller-controlled strings BEFORE we hash/encrypt/write.
    // The DB row, the log line, and the GUI list all consume these fields; a
    // 10 MB virus_name from a token-holding caller would otherwise bloat every
    // future quarantine.list and let CR/LF injection forge tracing output.
    let virus_name = sanitize_label(virus_name, MAX_VIRUS_NAME_LEN);
    let scan_id = sanitize_label(scan_id, MAX_SCAN_ID_LEN);
    let canonical_str = canonical.to_string_lossy().to_string();
    if canonical_str.len() > MAX_STORED_PATH_LEN {
        return Err(format!(
            "Path too long for quarantine row ({} > {})",
            canonical_str.len(),
            MAX_STORED_PATH_LEN
        ));
    }
    // Single-open + fstat: avoid a path re-lookup between size check and read.
    // Previously `fs::metadata` then `fs::read` re-resolved `canonical`, so an
    // attacker who swapped the inode for a hardlink to a larger file in
    // between bypassed the 100 MB cap. Open ONCE, stat the live handle,
    // then read from that same handle.
    let mut f = fs::OpenOptions::new()
        .read(true)
        .open(&canonical)
        .map_err(|e| format!("Cannot read file: {e}"))?;
    let meta = f
        .metadata()
        .map_err(|e| format!("Cannot read metadata: {e}"))?;
    if meta.len() > MAX_QUARANTINE_SIZE {
        return Err(format!(
            "File too large ({} bytes, max {})",
            meta.len(),
            MAX_QUARANTINE_SIZE
        ));
    }
    // Streaming, chunked AES-256-GCM. We bound peak memory to ~2 MiB regardless
    // of the source file size (vs. ~3x the file size in the old whole-buffer
    // path). Hash is folded in as we read so we never need the full plaintext
    // resident.
    let original_size = meta.len();
    let q_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    let vault_subdir = vault_dir.join(&q_id[..2]);
    fs::create_dir_all(&vault_subdir).map_err(|e| format!("Cannot create vault dir: {e}"))?;
    let vault_path = vault_subdir.join(format!("{q_id}.vault"));

    let key_bytes = get_vault_key_in(vault_dir)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let num_chunks: u32 = if original_size == 0 {
        // We always emit at least one chunk — even for an empty file — so the
        // decode path stays uniform (no special-case "header only" branch).
        1
    } else {
        let n = original_size.div_ceil(CHUNK_SIZE as u64);
        u32::try_from(n).map_err(|_| "Too many chunks".to_string())?
    };

    let mut vault_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&vault_path)
        .map_err(|e| format!("Cannot create vault file: {e}"))?;

    // Helper: any failure mid-stream must remove the partial vault file so we
    // never leave an undecryptable husk that confuses restore later.
    let cleanup = |e: String| -> String {
        let _ = fs::remove_file(&vault_path);
        e
    };

    // Header: magic + original_size + num_chunks.
    let mut header = [0u8; CHUNKED_HEADER_LEN];
    header[..4].copy_from_slice(&CHUNKED_MAGIC);
    header[4..12].copy_from_slice(&original_size.to_le_bytes());
    header[12..16].copy_from_slice(&num_chunks.to_le_bytes());
    vault_file
        .write_all(&header)
        .map_err(|e| cleanup(format!("Cannot write vault header: {e}")))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut total_read: u64 = 0;
    use rand::RngCore;
    for _ in 0..num_chunks {
        // Read up to CHUNK_SIZE; for the last chunk this is short. read_exact
        // would be wrong because the final chunk is < CHUNK_SIZE in general.
        let mut filled = 0;
        while filled < CHUNK_SIZE {
            match f.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) => return Err(cleanup(format!("Cannot read file: {e}"))),
            }
        }
        let chunk = &buf[..filled];
        total_read += filled as u64;
        // Same belt-and-braces as the old path: a live writer could grow the
        // file past the cap between fstat and reading the tail.
        if total_read > MAX_QUARANTINE_SIZE {
            return Err(cleanup(format!(
                "File too large ({total_read} bytes, max {MAX_QUARANTINE_SIZE})"
            )));
        }
        hasher.update(chunk);

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, chunk)
            .map_err(|e| cleanup(format!("Encryption failed: {e}")))?;

        vault_file
            .write_all(&nonce_bytes)
            .map_err(|e| cleanup(format!("Cannot write vault nonce: {e}")))?;
        vault_file
            .write_all(&ct)
            .map_err(|e| cleanup(format!("Cannot write vault chunk: {e}")))?;
    }

    // If the source shrank mid-stream we'll have read fewer bytes than the
    // header claims. Detect and bail — restore would later fail the SHA check
    // anyway, but better to fail loudly here so we don't delete the original.
    if total_read != original_size {
        return Err(cleanup(format!(
            "Source size changed during read ({} → {})",
            original_size, total_read
        )));
    }
    drop(f);
    let sha256_hash = hex::encode(hasher.finalize());

    if let Err(e) = vault_file.flush() {
        return Err(cleanup(format!("Cannot flush vault file: {e}")));
    }
    // Durability: flush() only pushes to OS; fsync forces disk. Crash between
    // here and finalize without sync_all → vault truncated/missing while the
    // original is about to be deleted → unrecoverable malware-sample loss.
    if let Err(e) = vault_file.sync_all() {
        return Err(cleanup(format!("Cannot sync vault file: {e}")));
    }

    let row = QuarantineRow {
        quarantine_id: q_id.clone(),
        original_path: canonical_str.clone(),
        vault_path: vault_path.to_string_lossy().to_string(),
        virus_name: virus_name.clone(),
        sha256: sha256_hash.clone(),
        original_size,
        quarantined_at: now,
        scan_id: scan_id.clone(),
        status: "quarantined".to_string(),
    };

    let result = QuarantineResult {
        quarantine_id: q_id,
        original_path: canonical_str,
        virus_name,
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
    // Commit FIRST, then purge vault. If the DB write fails, leave both the
    // restored file (security-positive — user gets their file back) AND the
    // vault (recoverable via retry) intact.
    db.update_quarantine_status(quarantine_id, "restored")?;
    purge_vault_after_restore(&item.vault_path);
    Ok(path)
}

/// Streamed decrypt + write + hash. Reads the vault file in bounded chunks,
/// decrypts each chunk in place, writes plaintext to `out`, and folds bytes
/// into a SHA-256 hasher. Returns the hex digest on success.
///
/// Supports both formats:
///   - Chunked v1: 4-byte CHUNKED_MAGIC at offset 0, then header + per-chunk
///     (nonce, ciphertext+tag) records. Peak memory ~2 MiB.
///   - Legacy: 12-byte nonce + AES-GCM one-shot ciphertext. Buffered fully
///     because that's what the old format permits. Pre-upgrade vaults keep
///     working; new vaults all use the chunked layout.
fn decrypt_vault_streaming(
    vault_path: &Path,
    cipher: &Aes256Gcm,
    out: &mut fs::File,
) -> Result<String, String> {
    let mut vf = fs::OpenOptions::new()
        .read(true)
        .open(vault_path)
        .map_err(|e| format!("Cannot read vault: {e}"))?;
    let mut magic = [0u8; 4];
    let mut read_so_far = 0;
    while read_so_far < magic.len() {
        match vf.read(&mut magic[read_so_far..]) {
            Ok(0) => break,
            Ok(n) => read_so_far += n,
            Err(e) => return Err(format!("Cannot read vault: {e}")),
        }
    }

    if read_so_far == 4 && magic == CHUNKED_MAGIC {
        // Chunked path.
        let mut rest_header = [0u8; CHUNKED_HEADER_LEN - 4];
        vf.read_exact(&mut rest_header)
            .map_err(|_| "Vault header truncated".to_string())?;
        let original_size = u64::from_le_bytes(rest_header[0..8].try_into().unwrap());
        let num_chunks = u32::from_le_bytes(rest_header[8..12].try_into().unwrap());
        if original_size > MAX_QUARANTINE_SIZE {
            return Err(format!(
                "Vault claims oversize plaintext ({original_size} > {MAX_QUARANTINE_SIZE})"
            ));
        }
        let mut hasher = Sha256::new();
        let mut nonce_bytes = [0u8; 12];
        // Reuse a single ciphertext buffer sized for a full chunk + tag.
        let mut ct_buf = vec![0u8; CHUNK_SIZE + 16];
        let mut remaining = original_size;
        for i in 0..num_chunks {
            // Last chunk is smaller if original_size isn't an exact multiple.
            let chunk_plain = if i + 1 == num_chunks {
                // Even for an empty source we still emit one chunk; remaining
                // will be 0 here and we decrypt the 16-byte AEAD-only ct.
                remaining as usize
            } else {
                CHUNK_SIZE
            };
            let ct_len = chunk_plain + 16;
            vf.read_exact(&mut nonce_bytes)
                .map_err(|_| "Vault nonce truncated".to_string())?;
            vf.read_exact(&mut ct_buf[..ct_len])
                .map_err(|_| "Vault chunk truncated".to_string())?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            let pt = cipher
                .decrypt(nonce, &ct_buf[..ct_len])
                .map_err(|_| "Decryption failed - vault key may have changed".to_string())?;
            hasher.update(&pt);
            out.write_all(&pt)
                .map_err(|e| format!("Cannot write restored file: {e}"))?;
            remaining = remaining.saturating_sub(pt.len() as u64);
        }
        Ok(hex::encode(hasher.finalize()))
    } else {
        // Legacy path: re-read entirely (old format requires it). Peak memory
        // matches the pre-streaming era for these vaults only — once the
        // operator processes them they convert to the chunked format on the
        // next quarantine cycle.
        let mut whole = Vec::new();
        whole.extend_from_slice(&magic[..read_so_far]);
        vf.read_to_end(&mut whole)
            .map_err(|e| format!("Cannot read vault: {e}"))?;
        if whole.len() < 12 {
            return Err("Vault file corrupted (too small)".into());
        }
        let (nonce_bytes, ciphertext) = whole.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed - vault key may have changed".to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        out.write_all(&plaintext)
            .map_err(|e| format!("Cannot write restored file: {e}"))?;
        Ok(hex::encode(hasher.finalize()))
    }
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

    let key_bytes = get_vault_key()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // F6: parent must pre-exist (no SYSTEM-driven create_dir_all along an
    // attacker-influenced path). F1/F6: also walk ancestors for reparse points.
    match original_path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => {}
        Some(parent) => {
            if !parent.is_dir() {
                return Err(format!(
                    "Cannot restore: parent directory missing — recreate it first ({})",
                    parent.display()
                ));
            }
        }
        None => {}
    }
    reject_symlink_ancestors(original_path)?;
    // TOCTOU-safe open: FILE_FLAG_OPEN_REPARSE_POINT means we don't follow
    // symlinks/junctions inserted between validate_restore_path and now.
    let mut out = open_no_follow(original_path)?;
    // Stream-decrypt into the output, hashing as we go. We can't verify the
    // hash before writing because the chunked format never buffers the full
    // plaintext; on hash mismatch we unlink the partial output so the caller
    // never observes a corrupt restore.
    let restored_hash = match decrypt_vault_streaming(&vault_path, &cipher, &mut out) {
        Ok(h) => h,
        Err(e) => {
            drop(out);
            let _ = fs::remove_file(original_path);
            return Err(e);
        }
    };
    if !constant_time_eq(restored_hash.as_bytes(), item.sha256.as_bytes()) {
        drop(out);
        let _ = fs::remove_file(original_path);
        return Err(format!(
            "Hash mismatch: expected {}, got {}",
            item.sha256, restored_hash
        ));
    }
    // Durability: sync_all before removing the vault. Crash after vault delete
    // with a non-synced restore would leave the user with a truncated file and
    // no source of truth → unrecoverable.
    out.sync_all()
        .map_err(|e| format!("Cannot sync restored file: {e}"))?;
    drop(out);

    // NOTE: vault file is INTENTIONALLY not deleted here. The caller is
    // responsible for committing the DB status change to "restored" FIRST
    // and only then invoking `purge_vault_after_restore`.
    info!(id = %item.quarantine_id, path = %original_path.display(), "file restored (hash verified) — vault retained for caller commit");
    Ok(item.original_path.clone())
}

/// Remove a vault file after the caller has durably committed the
/// "restored" status to the DB. Safe to call even if the file is already
/// gone (e.g. a previous run completed but crashed before reporting).
pub fn purge_vault_after_restore(vault_path: &str) {
    // Re-validate the path is inside the vault root before unlink —
    // even though the caller had a verified `QuarantineRow`, a malicious
    // tamper of the row between read and call (e.g. SQL injection vector
    // surfaced elsewhere) shouldn't let us delete arbitrary files.
    match validate_vault_path(Path::new(vault_path)) {
        Ok(p) => {
            if let Err(e) = fs::remove_file(&p) {
                // Already gone is fine; any other error is a leak we log.
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(path = %p.display(), error = %e, "vault file purge failed after restore");
                }
            }
        }
        Err(e) => {
            warn!(path = vault_path, error = %e, "vault path rejected during purge — leaving file");
        }
    }
}

/// F1/F6: walk every existing ancestor of `dest` and reject if any is a
/// symlink, junction, or other reparse point. `open_no_follow` only protects
/// against a reparse point AT the leaf; an attacker who plants a junction at
/// an intermediate component (e.g. `C:\Users\victim\Downloads -> C:\Windows`)
/// would otherwise see the SYSTEM-owned restore write traverse into the
/// redirected target before reaching the leaf check.
fn reject_symlink_ancestors(dest: &Path) -> Result<(), String> {
    // Skip the leaf itself — `open_no_follow`/the leaf existence check handle
    // it. Walk parent chain upward and stop at the first non-existent ancestor
    // (Windows root, missing dir): nothing further up can be a live reparse
    // point if it doesn't exist.
    for ancestor in dest.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                let ft = meta.file_type();
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::fs::FileTypeExt;
                    if ft.is_symlink() || ft.is_symlink_dir() || ft.is_symlink_file() {
                        return Err(format!(
                            "Restore refused: ancestor is a reparse point ({})",
                            ancestor.display()
                        ));
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    if ft.is_symlink() {
                        return Err(format!(
                            "Restore refused: ancestor is a symlink ({})",
                            ancestor.display()
                        ));
                    }
                }
            }
            // Non-existent ancestor → nothing above is a live reparse point,
            // and the parent-must-exist check elsewhere will catch missing
            // intermediates that matter for the write.
            Err(_) => break,
        }
    }
    Ok(())
}

/// Open file with create_new + no-follow semantics (rejects reparse points
/// inserted between validation and open). Windows uses FILE_FLAG_OPEN_REPARSE_POINT;
/// Unix uses O_NOFOLLOW.
fn open_no_follow(path: &Path) -> Result<fs::File, String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|e| format!("Cannot create restored file (reparse-safe): {e}"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| format!("Cannot create restored file (nofollow): {e}"))
    }
}

/// Decrypt, verify, and restore to an alternate path (not the original).
pub fn restore_file_as(item: &QuarantineRow, dest: &Path) -> Result<String, String> {
    if item.status != "quarantined" {
        return Err(format!("Status is '{}', not quarantined", item.status));
    }

    let vault_path = validate_vault_path(Path::new(&item.vault_path))?;
    validate_restore_path(dest)?;

    if dest.exists() {
        return Err(format!("Target exists: {}", dest.display()));
    }
    // Reject if dest is a reparse point.
    if dest.is_symlink() {
        return Err("Symlink target blocked".into());
    }

    let key_bytes = get_vault_key()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // F1/F6: same rationale as restore_file_from_row — refuse to mkdir as
    // SYSTEM along an attacker-influenced path. Parent must pre-exist.
    match dest.parent() {
        Some(parent) if parent.as_os_str().is_empty() => {}
        Some(parent) => {
            if !parent.is_dir() {
                return Err(format!(
                    "Cannot restore: destination parent directory missing — pick an existing folder ({})",
                    parent.display()
                ));
            }
        }
        None => {}
    }
    // F1/F6: same ancestor-symlink check as restore_file_from_row.
    reject_symlink_ancestors(dest)?;
    // TOCTOU-safe open — same rationale as restore_file_from_row.
    let mut out = open_no_follow(dest)?;
    // Stream-decrypt; on hash mismatch unlink the partial output (see
    // restore_file_from_row for full rationale).
    let restored_hash = match decrypt_vault_streaming(&vault_path, &cipher, &mut out) {
        Ok(h) => h,
        Err(e) => {
            drop(out);
            let _ = fs::remove_file(dest);
            return Err(e);
        }
    };
    if !constant_time_eq(restored_hash.as_bytes(), item.sha256.as_bytes()) {
        drop(out);
        let _ = fs::remove_file(dest);
        return Err(format!(
            "Hash mismatch: expected {}, got {}",
            item.sha256, restored_hash
        ));
    }
    // Durability: same rationale as restore_file_from_row.
    out.sync_all()
        .map_err(|e| format!("Cannot sync restored file: {e}"))?;
    drop(out);

    // Vault retention: same rationale as restore_file_from_row. Caller
    // commits DB status first, then calls purge_vault_after_restore.
    info!(id = %item.quarantine_id, dest = %dest.display(), "file restored to alternate path (hash verified) — vault retained for caller commit");
    Ok(dest.to_string_lossy().to_string())
}

#[allow(dead_code)]
pub fn delete_quarantined(quarantine_id: &str, db: &Database) -> Result<(), String> {
    let item = db
        .get_quarantine_item(quarantine_id)
        .ok_or_else(|| format!("Not found: {quarantine_id}"))?;
    delete_vault_file(&item)?;
    // DB write failure here is non-fatal for the security goal (file is
    // already gone); log via the Result chain so ops sees it.
    let _ = db.update_quarantine_status(quarantine_id, "deleted");
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
    validate_vault_path_in(path, &quarantine_root())
}

fn validate_vault_path_in(path: &Path, qdir: &Path) -> Result<PathBuf, String> {
    let root = qdir
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

/// R4-LETHAL-3: refuse to quarantine (= encrypt + delete) anything that
/// would brick the OS, kill another security product, or wipe our own
/// install. Called on the canonical (symlink-resolved) source path.
fn validate_quarantine_source(canonical: &Path) -> Result<(), String> {
    let s = canonical.to_string_lossy().to_lowercase();

    // ☠️ R8-LETHAL: refuse UNC / device-namespace paths.
    // Daemon runs as SYSTEM. Quarantining a file from `\\attacker\share\`
    // causes the read (and the subsequent delete of the "original") to
    // authenticate to the remote SMB server with the machine-account
    // NTLM hash → captured by responder → relayed for AD compromise.
    //
    // Allow `\\?\C:\...` (long-path namespace) — `std::fs::canonicalize`
    // returns paths in exactly that form, so blanket-rejecting `\\` would
    // break every legitimate quarantine on Windows.
    let raw = canonical.to_string_lossy();
    let is_long_local = s.starts_with(r"\\?\")
        && s.len() >= 6
        && s.as_bytes()[4].is_ascii_alphabetic()
        && s.as_bytes()[5] == b':';
    let is_long_unc = s.starts_with(r"\\?\unc\");
    let is_unc_share = (raw.starts_with("\\\\") && !is_long_local && !is_long_unc
        && !s.starts_with(r"\\.\"))
        || raw.starts_with("//");
    let is_device_ns = s.starts_with(r"\\.\")
        || s.contains(r"\globalroot\")
        || s.contains(r"\physicaldrive");
    if is_unc_share || is_long_unc || is_device_ns {
        return Err(format!(
            "Refusing to quarantine UNC/device path: {}",
            canonical.display()
        ));
    }

    // Hard-deny: OS-critical roots. Even if SYSTEM technically can delete
    // some of these (TrustedInstaller ACLs aside), losing any of them
    // bricks Windows.
    const FORBIDDEN_ROOTS: &[&str] = &[
        "\\windows\\",
        "\\system32\\",
        "\\syswow64\\",
        "\\winsxs\\",
        "\\drivers\\",
        "\\boot\\",
        "\\recovery\\",
        "\\programdata\\microsoft\\",
        "\\program files\\windowsapps\\",
    ];
    for root in FORBIDDEN_ROOTS {
        if s.contains(root) {
            return Err(format!(
                "Refusing to quarantine OS path: {}",
                canonical.display()
            ));
        }
    }

    // Hard-deny: known security-product install paths. An attacker with a
    // challenge token must NOT be able to coerce us into deleting another
    // AV/EDR sensor binary.
    const FORBIDDEN_SECURITY_PRODUCTS: &[&str] = &[
        "\\program files\\windows defender\\",
        "\\programdata\\microsoft\\windows defender\\",
        "\\program files\\microsoft security client\\",
        "\\program files\\microsoft\\security\\",
        "\\program files (x86)\\windows defender\\",
        // Common third-party AV/EDR roots.
        "\\program files\\crowdstrike\\",
        "\\program files\\sentinelone\\",
        "\\program files\\sophos\\",
        "\\program files\\eset\\",
        "\\program files\\bitdefender\\",
        "\\program files\\kaspersky lab\\",
        "\\program files\\malwarebytes\\",
        "\\program files\\carbon black\\",
        "\\program files\\cylance\\",
        "\\program files\\trendmicro\\",
        "\\program files\\mcafee\\",
        "\\program files\\norton\\",
        "\\program files\\symantec\\",
        "\\program files\\avast software\\",
        "\\program files\\avg\\",
    ];
    for prod in FORBIDDEN_SECURITY_PRODUCTS {
        if s.contains(prod) {
            return Err(format!(
                "Refusing to quarantine security-product file: {}",
                canonical.display()
            ));
        }
    }

    // Hard-deny: our own install directory. Self-destruct prevention —
    // resolve the running exe's parent dir at runtime so renames during
    // packaging do not silently disable this check.
    if let Ok(my_exe) = std::env::current_exe() {
        if let Some(my_dir) = my_exe.parent() {
            if let Ok(my_dir_canon) = my_dir.canonicalize() {
                let mine = my_dir_canon.to_string_lossy().to_lowercase();
                if !mine.is_empty() && s.starts_with(&mine) {
                    return Err(format!(
                        "Refusing to quarantine a file inside our own install dir: {}",
                        canonical.display()
                    ));
                }
            }
        }
    }
    // Also block by literal product directory name regardless of where
    // we're installed.
    if s.contains("\\sentinella\\") || s.contains("\\sentinelld") {
        return Err("Refusing to quarantine a Sentinella file".into());
    }

    Ok(())
}

fn validate_restore_path(path: &Path) -> Result<(), String> {
    let raw = path.to_string_lossy();
    let lower_raw = raw.to_ascii_lowercase();
    if lower_raw.starts_with(r"\\?\unc\")
        || (raw.starts_with(r"\\") && !raw.starts_with(r"\\?\") && !raw.starts_with(r"\\.\"))
        || raw.starts_with("//")
    {
        return Err("Network/UNC restore paths are blocked".into());
    }

    if let Some(parent) = path.parent() {
        if parent.is_symlink() {
            return Err("Symlink parent blocked - restore to a real directory".into());
        }
    }

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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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

    /// Create a unique temp directory with quarantine subdirectory.
    /// No CWD manipulation — tests use `_in` helpers directly.
    fn setup_test_env() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sentinella_qtest_{}", uuid::Uuid::new_v4()));
        let qdir = dir.join("quarantine");
        fs::create_dir_all(&qdir).unwrap();
        dir
    }

    fn teardown(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    /// Test helper: decrypt a chunked-format vault into a Vec. Mirrors the
    /// production streaming decode but writes to memory so tests can assert on
    /// the round-tripped bytes. Also handles legacy one-shot vaults so the
    /// older fixtures (if any) keep working.
    fn decrypt_vault_to_vec(vault_path: &Path, cipher: &Aes256Gcm) -> Vec<u8> {
        let data = fs::read(vault_path).expect("read vault");
        if data.len() >= 4 && data[0..4] == CHUNKED_MAGIC {
            assert!(
                data.len() >= CHUNKED_HEADER_LEN,
                "chunked vault header truncated"
            );
            let original_size = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let num_chunks = u32::from_le_bytes(data[12..16].try_into().unwrap());
            let mut out = Vec::with_capacity(original_size as usize);
            let mut offset = CHUNKED_HEADER_LEN;
            let mut remaining = original_size;
            for i in 0..num_chunks {
                let chunk_plain = if i + 1 == num_chunks {
                    remaining as usize
                } else {
                    CHUNK_SIZE
                };
                let ct_len = chunk_plain + 16;
                let nonce = Nonce::from_slice(&data[offset..offset + 12]);
                offset += 12;
                let pt = cipher
                    .decrypt(nonce, &data[offset..offset + ct_len])
                    .expect("chunk decrypt");
                offset += ct_len;
                remaining -= pt.len() as u64;
                out.extend_from_slice(&pt);
            }
            out
        } else {
            // Legacy one-shot format.
            let (nonce_bytes, ciphertext) = data.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);
            cipher.decrypt(nonce, ciphertext).expect("legacy decrypt")
        }
    }

    // ---------------------------------------------------------------
    //  1. Vault key generation — idempotent (same key on repeat call)
    // ---------------------------------------------------------------
    #[test]
    fn vault_key_is_persisted_across_calls() {
        let root = setup_test_env();
        let qdir = root.join("quarantine");

        let k1 = get_vault_key_in(&qdir).expect("first call should succeed");
        let k2 = get_vault_key_in(&qdir).expect("second call should succeed");
        assert_eq!(k1, k2, "vault key must be stable across calls");

        let key_path = qdir.join(".vault_key");
        assert!(key_path.exists(), ".vault_key file must be persisted");
        let on_disk = fs::read(&key_path).unwrap();
        assert_eq!(on_disk.len(), 32);
        assert_eq!(&on_disk[..], &k1[..]);

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  2. Full quarantine round-trip (prepare → finalize → restore)
    //     Uses prepare_quarantine_file (which uses its own vault_dir
    //     arg) and bypasses get_vault_key() global path.
    // ---------------------------------------------------------------
    #[test]
    fn quarantine_round_trip() {
        let root = setup_test_env();
        let vault_dir = root.join("quarantine");
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
        assert!(original.exists(), "original must still exist after prepare");
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

        // --- restore (reuse vault_dir as quarantine root for validation) ---
        // We need vault path validation to work. Since prepare wrote the vault file
        // inside vault_dir, validate_vault_path_in(vault_path, &vault_dir) will pass.
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

        // Restore reads the vault using get_vault_key() which calls quarantine_root().
        // In tests the PathManager may not be initialized, so we test the pieces instead:
        // 1) Vault path is valid
        let vp = validate_vault_path_in(Path::new(&row.vault_path), &vault_dir)
            .expect("vault path should be valid");
        assert!(vp.exists());

        // 2) Decrypt via the chunked-format-aware test helper.
        let key_bytes = get_vault_key_in(&vault_dir).unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let plaintext = decrypt_vault_to_vec(&vp, &cipher);
        assert_eq!(plaintext, content, "decrypted content must match original");

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  R4-LETHAL-3: quarantine SOURCE path validation
    // ---------------------------------------------------------------
    #[test]
    fn r4_lethal3_quarantine_source_rejects_os_paths() {
        // Daemon runs as SYSTEM. These must NEVER be quarantined.
        let blocked = [
            r"C:\Windows\System32\winlogon.exe",
            r"C:\Windows\System32\lsass.exe",
            r"C:\Windows\System32\drivers\nvlddmkm.sys",
            r"C:\Windows\SysWOW64\kernel32.dll",
            r"C:\Windows\WinSxS\amd64_microsoft.foo\thing.dll",
            r"C:\Boot\BCD",
            r"C:\Recovery\RecoveryImage\install.wim",
        ];
        for p in &blocked {
            let res = validate_quarantine_source(Path::new(p));
            assert!(
                res.is_err(),
                "quarantine ADD must reject OS path '{p}' — would brick Windows"
            );
        }
    }

    #[test]
    fn r4_lethal3_quarantine_source_rejects_security_products() {
        // Refuse to be weaponized to delete a competing AV/EDR sensor.
        let blocked = [
            r"C:\Program Files\Windows Defender\MsMpEng.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\engine.dll",
            r"C:\Program Files\CrowdStrike\CSAgent.sys",
            r"C:\Program Files\SentinelOne\Sentinel Agent\SentinelAgent.exe",
            r"C:\Program Files\Sophos\Sophos Anti-Virus\SAVAdminService.exe",
            r"C:\Program Files\ESET\ESET Security\ekrn.exe",
            r"C:\Program Files\Bitdefender\Endpoint Security\product.exe",
            r"C:\Program Files\Malwarebytes\Anti-Malware\mbam.exe",
        ];
        for p in &blocked {
            let res = validate_quarantine_source(Path::new(p));
            assert!(
                res.is_err(),
                "quarantine ADD must reject security-product path '{p}' — would kill the competing AV"
            );
        }
    }

    #[test]
    fn r4_lethal3_quarantine_source_rejects_sentinella_self() {
        // Self-destruct prevention: refusing literal "Sentinella" / "sentinelld"
        // path components irrespective of install dir.
        let blocked = [
            r"C:\Program Files\Sentinella\sentinelld.exe",
            r"D:\Apps\Sentinella\gui.exe",
            r"C:\opt\sentinelld\engine.dll",
        ];
        for p in &blocked {
            let res = validate_quarantine_source(Path::new(p));
            assert!(
                res.is_err(),
                "quarantine ADD must reject self path '{p}' — AV cannot be coerced into self-delete"
            );
        }
    }

    #[test]
    fn r8_lethal_quarantine_source_rejects_unc_and_device_paths() {
        // SYSTEM-context read+delete via UNC = NTLM hash capture for
        // machine account → AD pivot. Device-namespace paths read raw
        // disk. All must be refused.
        let blocked = [
            r"\\attacker.example.com\share\evil.exe",
            r"\\?\UNC\attacker.example.com\share\evil.exe",
            r"\\.\PHYSICALDRIVE0",
            r"\\.\GLOBALROOT\Device\HarddiskVolume1\Windows\notepad.exe",
            r"\\.\pipe\some_pipe",
        ];
        for p in &blocked {
            let res = validate_quarantine_source(Path::new(p));
            assert!(
                res.is_err(),
                "quarantine ADD must reject UNC/device path '{p}'"
            );
        }
    }

    #[test]
    fn r4_lethal3_quarantine_source_accepts_user_files() {
        // Legit malware locations should still pass.
        let allowed = [
            r"C:\Users\me\Downloads\evil.exe",
            r"C:\Users\me\AppData\Roaming\dropper.dll",
            r"D:\suspicious\sample.bin",
        ];
        for p in &allowed {
            let res = validate_quarantine_source(Path::new(p));
            assert!(res.is_ok(), "should allow user-space path '{p}': {res:?}");
        }
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

    #[test]
    fn validate_restore_path_rejects_unc_paths() {
        let blocked = [r"\\server\share\evil.exe", "//server/share/evil.exe"];

        for path_str in &blocked {
            let result = validate_restore_path(Path::new(path_str));
            assert!(result.is_err(), "UNC path should be rejected: {path_str}");
        }
    }

    // ---------------------------------------------------------------
    //  4. Path validation — vault path outside quarantine root
    // ---------------------------------------------------------------
    #[test]
    fn validate_vault_path_rejects_outside_root() {
        let root = setup_test_env();
        let qdir = root.join("quarantine");

        // Create a file outside the vault root.
        let outside = root.join("somewhere_else.vault");
        fs::write(&outside, b"fake").unwrap();

        let result = validate_vault_path_in(&outside, &qdir);
        assert!(result.is_err(), "must reject paths outside quarantine/");
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
        let root = setup_test_env();
        let vault_dir = root.join("quarantine");
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
        let root = setup_test_env();
        let vault_dir = root.join("quarantine");
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

        // Verify vault contents decrypt to an empty plaintext via the
        // chunked-format helper (single chunk of size 0).
        let key_bytes = get_vault_key_in(&vault_dir).unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let plaintext = decrypt_vault_to_vec(&prepared.vault_path, &cipher);
        assert!(
            plaintext.is_empty(),
            "decrypted empty file should be 0 bytes"
        );

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  7. Large path (>260 chars) should not crash
    // ---------------------------------------------------------------
    #[test]
    fn large_path_does_not_crash() {
        let root = setup_test_env();
        let vault_dir = root.join("quarantine");
        let long_name = "a".repeat(300);
        let long_path = root.join(&long_name);

        let result = prepare_quarantine_file(&long_path, &vault_dir, "LongPath", "scan-004");
        if let Err(e) = &result {
            assert!(!e.is_empty(), "error message should be non-empty");
        }

        teardown(&root);
    }

    // ---------------------------------------------------------------
    //  8. validate_vault_path rejects wrong extension
    // ---------------------------------------------------------------
    #[test]
    fn validate_vault_path_rejects_wrong_extension() {
        let root = setup_test_env();
        let qdir = root.join("quarantine");

        let bad_ext = qdir.join("evil.exe");
        fs::write(&bad_ext, b"data").unwrap();

        let result = validate_vault_path_in(&bad_ext, &qdir);
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

    // ---------------------------------------------------------------
    //  10. Chunked AES-GCM round-trip across multiple chunks.
    //      Validates the streaming encode path actually emits >1 chunk
    //      (2.5 MiB > 2 × CHUNK_SIZE) and that the helper decoder
    //      reassembles every byte. Catches off-by-ones in header math
    //      and last-chunk sizing that smaller round-trips can't see.
    // ---------------------------------------------------------------
    #[test]
    fn chunked_multi_chunk_round_trip() {
        let root = setup_test_env();
        let vault_dir = root.join("quarantine");
        let original = root.join("big_sample.bin");

        // 2.5 MiB: forces 3 chunks (1 MiB, 1 MiB, ~0.5 MiB).
        let size = (2 * CHUNK_SIZE) + (CHUNK_SIZE / 2);
        let mut content = vec![0u8; size];
        // Deterministic non-trivial pattern so corruption shows up.
        for (i, b) in content.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        fs::write(&original, &content).unwrap();

        let prepared = prepare_quarantine_file(&original, &vault_dir, "ChunkedTest", "scan-chunk")
            .expect("prepare should succeed on multi-chunk file");

        // Vault file must begin with the chunked magic — proves we took the
        // new path and not some legacy fallback.
        let header_bytes = fs::read(&prepared.vault_path).unwrap();
        assert!(
            header_bytes.len() >= 4 && header_bytes[0..4] == CHUNKED_MAGIC,
            "vault file must start with CHUNKED_MAGIC, got {:?}",
            &header_bytes[0..4.min(header_bytes.len())]
        );
        let num_chunks = u32::from_le_bytes(header_bytes[12..16].try_into().unwrap());
        assert_eq!(num_chunks, 3, "2.5 MiB at 1 MiB chunks should be 3 chunks");

        // Decode via the test helper and confirm byte-exact round-trip.
        let key_bytes = get_vault_key_in(&vault_dir).unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let plaintext = decrypt_vault_to_vec(&prepared.vault_path, &cipher);
        assert_eq!(plaintext.len(), content.len(), "size must match");
        assert_eq!(plaintext, content, "every byte must round-trip");

        // SHA hash recorded in the row must match what we'd compute now.
        let mut h = Sha256::new();
        h.update(&content);
        assert_eq!(prepared.row.sha256, hex::encode(h.finalize()));

        teardown(&root);
    }
}

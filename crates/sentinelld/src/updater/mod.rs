//! Signature database updater — wraps freshclam as a sidecar process.
//!
//! Runs freshclam with the configured mirror and database directory.
//! Reports progress via activity events.

use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, info, warn};

use crate::win_process::QuietCommand;

/// Run freshclam to update the signature database.
/// Returns (success, output_message).
#[allow(dead_code)]
pub fn run_freshclam(freshclam_path: &Path, config_path: &Path, _db_dir: &Path) -> (bool, String) {
    run_freshclam_with_progress(freshclam_path, config_path, _db_dir, |_| {})
}

/// Run freshclam with a progress callback that receives each output line.
/// The callback fires in real-time as freshclam produces output, enabling
/// the daemon to track download phases and filenames.
pub fn run_freshclam_with_progress<F>(
    freshclam_path: &Path,
    config_path: &Path,
    _db_dir: &Path,
    mut on_line: F,
) -> (bool, String)
where
    F: FnMut(&str),
{
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const FRESHCLAM_TIMEOUT: Duration = Duration::from_secs(10 * 60);
    const MAX_FRESHCLAM_OUTPUT_BYTES: usize = 256 * 1024;

    if !freshclam_path.exists() {
        return (
            false,
            format!("freshclam not found at {}", freshclam_path.display()),
        );
    }

    // Tamper-check freshclam against the binary-integrity manifest before
    // spawning. An attacker who can swap freshclam.exe for a poisoned copy
    // can otherwise smuggle arbitrary code in under our daemon's network/FS
    // privileges every update cycle. Fail CLOSED here (refuse to spawn) —
    // this differs from the startup self-check (fail-loud) because a bad
    // freshclam runs adversary code with our privileges, whereas a bad
    // self-binary already has whatever access the running daemon has.
    {
        let state_dir = crate::paths::paths().state_dir();
        let key_path = crate::paths::paths().vault_integrity_key();
        if let Ok(key_bytes) = std::fs::read(&key_path) {
            if key_bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                match crate::runtime_integrity::verify_binary_against_manifest(
                    &state_dir,
                    &key,
                    freshclam_path,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        error!(
                            path = %freshclam_path.display(),
                            "freshclam binary HMAC mismatch — refusing to spawn (tamper signal)"
                        );
                        return (
                            false,
                            "freshclam binary failed integrity check — refusing to spawn".into(),
                        );
                    }
                    Err(e) => {
                        warn!(%e, "freshclam integrity check inconclusive — allowing spawn");
                    }
                }
            }
        }
    }

    info!(path = %freshclam_path.display(), "starting freshclam update");

    // Resolve relative paths in config to absolute paths.
    // freshclam on Windows requires absolute paths with backslashes.
    let effective_config = resolve_freshclam_config(config_path);
    let config_arg = effective_config.as_deref().unwrap_or(config_path);

    // Spawn with piped stdout/stderr for real-time reading.
    // v0.1.7 Phase 1: `.quiet_windows()` adds CREATE_NO_WINDOW so the
    // freshclam console no longer flashes on every signature reload —
    // the primary "ghost CMD window" source the user reported.
    let mut child = match Command::new(freshclam_path)
        .arg("--config-file")
        .arg(config_arg)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .quiet_windows()
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            error!(%e, "failed to start freshclam");
            return (false, format!("Failed to execute: {e}"));
        }
    };

    let mut output_lines = Vec::new();
    let mut output_bytes = 0usize;
    let (tx, rx) = mpsc::channel::<String>();
    let mut readers = Vec::new();

    if let Some(stdout) = child.stdout.take() {
        let tx = tx.clone();
        readers.push(std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                let _ = tx.send(line);
            }
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let tx = tx.clone();
        readers.push(std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                let _ = tx.send(line);
            }
        }));
    }
    drop(tx);

    let started = Instant::now();
    let status = loop {
        while let Ok(line) = rx.try_recv() {
            on_line(&line);
            push_capped_output(
                &mut output_lines,
                &mut output_bytes,
                line,
                MAX_FRESHCLAM_OUTPUT_BYTES,
            );
        }

        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                error!(%e, "failed waiting for freshclam");
                return (false, format!("Process error: {e}"));
            }
        }

        if started.elapsed() > FRESHCLAM_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            warn!("freshclam timed out and was killed");
            return (false, "freshclam timed out".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    for reader in readers {
        let _ = reader.join();
    }
    while let Ok(line) = rx.try_recv() {
        on_line(&line);
        push_capped_output(
            &mut output_lines,
            &mut output_bytes,
            line,
            MAX_FRESHCLAM_OUTPUT_BYTES,
        );
    }

    let combined = output_lines.join("\n");

    if status.success() {
        info!("freshclam update completed successfully");
        (true, combined)
    } else {
        let code = status.code().unwrap_or(-1);
        warn!(code, "freshclam exited with error");
        (false, format!("Exit code {code}: {combined}"))
    }
}

fn push_capped_output(
    output_lines: &mut Vec<String>,
    output_bytes: &mut usize,
    line: String,
    max_bytes: usize,
) {
    if *output_bytes >= max_bytes {
        return;
    }
    let remaining = max_bytes - *output_bytes;
    if line.len() <= remaining {
        *output_bytes = (*output_bytes + line.len() + 1).min(max_bytes);
        output_lines.push(line);
    } else {
        let mut cut = remaining;
        while cut > 0 && !line.is_char_boundary(cut) {
            cut -= 1;
        }
        output_lines.push(line[..cut].to_string());
        *output_bytes = max_bytes;
    }
}

/// Find freshclam binary in common locations.
///
/// ☠️ R9-LETHAL: never resolve relative paths against CWD. The daemon
/// runs as SYSTEM and invokes whatever this function returns; a
/// CWD-relative candidate (`"build/clamav/.../freshclam.exe"`) is a
/// SYSTEM-exec hijack waiting for any moment the daemon's working
/// directory ends up under attacker control (portable invocation,
/// shortcut "Start in" field, manual `cd && run`). Resolve only against
/// the daemon's own exe directory (write-protected install path).
pub fn find_freshclam() -> Option<PathBuf> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))?;

    // Trusted candidates — all anchored to the daemon's install dir.
    let candidates = [
        exe_dir.join("freshclam.exe"),
        exe_dir.join("build").join("clamav").join("freshclam").join("Release").join("freshclam.exe"),
        exe_dir.join("third_party").join("clamav").join("build").join("freshclam").join("Release").join("freshclam.exe"),
    ];
    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
    }

    // PATH fallback is acceptable: PATH for a Windows service is
    // %SystemRoot%\system32 etc. — directories ordinary users cannot write to.
    if let Ok(output) = Command::new("where").arg("freshclam.exe").quiet_windows().output() {
        let path = String::from_utf8_lossy(&output.stdout);
        let first = path.lines().next().unwrap_or("").trim();
        if !first.is_empty() && Path::new(first).exists() {
            return Some(PathBuf::from(first));
        }
    }

    None
}

/// Resolve relative paths in freshclam.conf to absolute paths.
/// Returns path to a temp config file with resolved paths, or None if
/// the original config already uses absolute paths.
///
/// ☠️ R9-LETHAL pattern: anchor relatives to the daemon's data root (via
/// `PathManager`), NEVER to CWD. CWD drift between manual-trigger and
/// scheduled/auto-trigger code paths was the suspected cause of the tray
/// update failing while the same update succeeded from the GUI's Update page
/// (the daemon would write the resolved temp config + signatures under a
/// directory that didn't exist or wasn't writable from that CWD).
fn resolve_freshclam_config(config_path: &Path) -> Option<PathBuf> {
    let content = std::fs::read_to_string(config_path).ok()?;
    let base = crate::paths::paths().root().to_path_buf();

    let mut rewritten = String::new();
    let mut changed = false;

    for line in content.lines() {
        let trimmed = line.trim();
        // Resolve DatabaseDirectory and UpdateLogFile paths.
        if let Some(rest) = trimmed.strip_prefix("DatabaseDirectory") {
            let val = rest.trim();
            if !val.is_empty() && !Path::new(val).is_absolute() {
                let abs = base.join(val);
                let _ = std::fs::create_dir_all(&abs);
                rewritten.push_str(&format!("DatabaseDirectory {}\n", abs.display()));
                changed = true;
                continue;
            }
        } else if let Some(rest) = trimmed.strip_prefix("UpdateLogFile") {
            let val = rest.trim();
            if !val.is_empty() && !Path::new(val).is_absolute() {
                let abs = base.join(val);
                if let Some(parent) = abs.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                rewritten.push_str(&format!("UpdateLogFile {}\n", abs.display()));
                changed = true;
                continue;
            }
        }
        rewritten.push_str(line);
        rewritten.push('\n');
    }

    if !changed {
        return None;
    }

    // Write resolved config under the daemon's own config dir (CWD-independent).
    let cfg_dir = crate::paths::paths().config_dir();
    let _ = std::fs::create_dir_all(&cfg_dir);
    let tmp = cfg_dir.join("freshclam.resolved.conf");
    std::fs::write(&tmp, &rewritten).ok()?;
    info!(path = %tmp.display(), "freshclam config resolved to absolute paths");
    Some(tmp)
}

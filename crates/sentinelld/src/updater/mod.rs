//! Signature database updater — wraps freshclam as a sidecar process.
//!
//! Runs freshclam with the configured mirror and database directory.
//! Reports progress via activity events.

use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, info, warn};

use crate::win_process::QuietCommand;

/// Attempts per update cycle, and the pause between them.
///
/// WHY THIS EXISTS. Before this, a single freshclam failure ended the cycle
/// and surfaced as a user-facing "signature update failed" toast. But the
/// overwhelmingly common causes — a slow mirror, Wi-Fi that dropped, the
/// machine suspending mid-download — are transient and fix themselves. The
/// user could do nothing useful with that notification, and with a 4-hour
/// update interval a single miss leaves signatures at most 4 hours old.
///
/// Three attempts covers the transient cases without turning a genuinely
/// unreachable mirror into a long stall: worst case here is one timeout
/// plus two short waits, and the cycle then ends quietly and waits for the
/// next scheduled run.
const ATTEMPTS_PER_CYCLE: usize = 3;
const RETRY_BACKOFF: [std::time::Duration; 2] = [
    std::time::Duration::from_secs(30),
    std::time::Duration::from_secs(120),
];

/// Is this failure worth retrying inside the same cycle?
///
/// Transient means "the same command might succeed in two minutes":
/// timeouts, connection failures, DNS resolution, a mirror returning 5xx.
/// A 403, a bad config, or a missing binary will fail identically on every
/// retry, so retrying just delays the inevitable — those end the cycle
/// immediately and wait for the next scheduled run like everything else.
fn is_transient(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    [
        "timed out",
        "timeout",
        "connection",
        "connect",
        "network",
        "temporarily",
        "resolve",
        "unreachable",
        "reset",
        "refused",
        "503",
        "502",
        "504",
    ]
    .iter()
    .any(|needle| m.contains(needle))
}

/// Run freshclam to update the signature database.
/// Returns (success, output_message).
#[allow(dead_code)]
pub fn run_freshclam(freshclam_path: &Path, config_path: &Path, _db_dir: &Path) -> (bool, String) {
    run_freshclam_with_retry(freshclam_path, config_path, _db_dir, |_| {})
}

/// One update CYCLE: run freshclam, retrying transient failures quietly.
///
/// The returned message is the LAST attempt's, and the caller still records
/// it for diagnostics. What changed is that a failure here is no longer an
/// event worth interrupting the user for — see the module note on
/// ATTEMPTS_PER_CYCLE. The user-facing signal is signature AGE, which is a
/// fact they can act on, not a failed fetch, which is not.
pub fn run_freshclam_with_retry<F>(
    freshclam_path: &Path,
    config_path: &Path,
    db_dir: &Path,
    mut on_line: F,
) -> (bool, String)
where
    F: FnMut(&str),
{
    let mut last = (false, String::new());
    for attempt in 0..ATTEMPTS_PER_CYCLE {
        if attempt > 0 {
            let pause = RETRY_BACKOFF[(attempt - 1).min(RETRY_BACKOFF.len() - 1)];
            info!(
                attempt = attempt + 1,
                of = ATTEMPTS_PER_CYCLE,
                backoff_secs = pause.as_secs(),
                "retrying signature update after a transient failure"
            );
            std::thread::sleep(pause);
        }
        last = run_freshclam_with_progress(freshclam_path, config_path, db_dir, &mut on_line);
        if last.0 {
            return last;
        }
        if !is_transient(&last.1) {
            // Retrying will produce the same answer; stop wasting the time.
            warn!(
                detail = last.1.as_str(),
                "signature update failed for a non-transient reason - not retrying this cycle"
            );
            return last;
        }
    }
    warn!(
        attempts = ATTEMPTS_PER_CYCLE,
        detail = last.1.as_str(),
        "signature update did not succeed this cycle - will retry on the next scheduled run"
    );
    last
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
        match std::fs::read(&key_path) {
            Ok(key_bytes) if key_bytes.len() == 32 => {
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
                    // verify_binary_against_manifest returns Ok(true) when no
                    // manifest exists yet (first boot), so an Err here means a
                    // manifest EXISTS but verification itself failed — honor
                    // the fail-closed contract instead of spawning anyway.
                    Err(e) => {
                        error!(
                            %e,
                            path = %freshclam_path.display(),
                            "freshclam integrity check errored — refusing to spawn (fail closed)"
                        );
                        return (
                            false,
                            format!("freshclam integrity check failed: {e} — refusing to spawn"),
                        );
                    }
                }
            }
            _ => {
                // No (valid) vault key yet — first boot before the TOFU
                // baseline exists. Skip the check, but say so loudly.
                warn!(
                    key = %key_path.display(),
                    "freshclam integrity check skipped — vault key missing or invalid (pre-baseline)"
                );
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
    // ☠️ R9-LETHAL: resolve `where` itself against System32 — a bare name
    // would search the (potentially attacker-influenced) process PATH.
    let where_exe = crate::win_process::system32_tool("where.exe");
    if let Ok(output) = Command::new(where_exe).arg("freshclam.exe").quiet_windows().output() {
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
        // Require whitespace after the keyword — bare strip_prefix would
        // also match a hypothetical directive starting with the same string
        // (e.g. `DatabaseDirectoryExtra`).
        let directive_value = |keyword: &str| -> Option<&str> {
            trimmed
                .strip_prefix(keyword)
                .filter(|rest| rest.starts_with(char::is_whitespace))
        };
        // Resolve DatabaseDirectory and UpdateLogFile paths.
        if let Some(rest) = directive_value("DatabaseDirectory") {
            let val = rest.trim();
            if !val.is_empty() && !Path::new(val).is_absolute() {
                let abs = base.join(val);
                let _ = std::fs::create_dir_all(&abs);
                rewritten.push_str(&format!("DatabaseDirectory {}\n", abs.display()));
                changed = true;
                continue;
            }
        } else if let Some(rest) = directive_value("UpdateLogFile") {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_failure_that_started_this_is_transient() {
        // The literal message the user saw as a toast. If this ever stops
        // classifying as transient, the silent-retry behaviour is gone.
        assert!(is_transient("freshclam timed out"));
    }

    #[test]
    fn network_shaped_failures_retry() {
        for m in [
            "freshclam timed out and was killed",
            "ERROR: Can't connect to database.clamav.net",
            "Connection refused",
            "could not resolve host",
            "Network is unreachable",
            "connection reset by peer",
            "HTTP 503 Service Unavailable",
            "Temporarily unavailable",
        ] {
            assert!(is_transient(m), "should retry: {m}");
        }
    }

    #[test]
    fn permanent_failures_do_not_retry() {
        // Retrying these wastes RETRY_BACKOFF seconds to reach the same
        // answer; the cycle should end immediately and wait for the next.
        for m in [
            "freshclam binary not found",
            "freshclam.conf not found",
            "ERROR: 403 Forbidden",
            "Can't create temporary directory",
            "Permission denied",
            "mirrors.dat is corrupt",
        ] {
            assert!(!is_transient(m), "should NOT retry: {m}");
        }
    }

    #[test]
    fn classification_is_case_insensitive() {
        assert!(is_transient("TIMED OUT"));
        assert!(is_transient("Connection Refused"));
    }

    #[test]
    fn backoff_covers_every_retry() {
        // Indexing RETRY_BACKOFF[attempt - 1] must stay in bounds for every
        // attempt the loop can take.
        assert!(RETRY_BACKOFF.len() >= ATTEMPTS_PER_CYCLE - 1);
        // And the pauses must be ordered, or "backoff" is a lie.
        assert!(RETRY_BACKOFF.windows(2).all(|w| w[0] < w[1]));
    }
}

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
/// unreachable mirror into a long stall, because the attempts SHARE one
/// deadline (`CYCLE_BUDGET`) rather than each starting a fresh clock. The
/// cycle then ends quietly and waits for the next scheduled run.
///
/// The shared deadline is load-bearing, not tidiness. `update_running` is
/// held for the whole cycle, so its duration is the window in which every
/// other update — scheduled or user-pressed — is rejected as "already in
/// progress", and it is how long a user watching the Update page waits.
/// With a per-attempt timeout, three 10-minute timeouts plus the backoffs
/// reached 32.5 minutes; freshclam's own ConnectTimeout/ReceiveTimeout do
/// not bound this, because libfreshclam maps ReceiveTimeout to curl's
/// LOW_SPEED_TIME, which a slow-but-progressing transfer never trips.
const ATTEMPTS_PER_CYCLE: usize = 3;
const RETRY_BACKOFF: [std::time::Duration; 2] = [
    std::time::Duration::from_secs(30),
    std::time::Duration::from_secs(120),
];
/// Wall-clock ceiling for one cycle, sleeps included. Chosen so a stuck
/// mirror costs roughly one old-style timeout in total instead of three:
/// main.cvd is large, so a single attempt still needs most of it, and the
/// point of the retries is a mirror that fails FAST and recovers.
const CYCLE_BUDGET: std::time::Duration = std::time::Duration::from_secs(10 * 60);
/// Below this there is no point starting another attempt — freshclam would
/// be killed mid-handshake and the kill costs another orphaned temp dir.
const MIN_ATTEMPT_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);

/// What the retry loop does next, decided BEFORE any sleeping.
struct Attempt {
    /// Backoff to take before running. Zero on the first attempt.
    pause: std::time::Duration,
    /// How long freshclam may then run.
    budget: std::time::Duration,
}

/// Plan attempt `attempt` of a cycle that has already spent `elapsed`.
///
/// `None` means the cycle is out of time and must stop **without sleeping**.
/// That ordering is the whole point of this function. The backoff used to be
/// taken first and the budget checked after, so the last attempt of a stuck
/// cycle slept the full 120 s and only then discovered there was no time
/// left to use it: a cycle documented as a 10-minute ceiling ran 12 minutes,
/// two of them pure dead time. `update_running` is held for all of it, so
/// every scheduled and user-pressed update in that window is rejected as
/// "already in progress" and the Update page just spins.
fn plan_attempt(attempt: usize, elapsed: std::time::Duration) -> Option<Attempt> {
    let pause = if attempt == 0 {
        std::time::Duration::ZERO
    } else {
        RETRY_BACKOFF[(attempt - 1).min(RETRY_BACKOFF.len() - 1)]
    };
    // The pause is charged to the budget HERE, before it is taken.
    let budget = CYCLE_BUDGET.saturating_sub(elapsed.saturating_add(pause));
    if budget < MIN_ATTEMPT_BUDGET {
        return None;
    }
    Some(Attempt { pause, budget })
}

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

/// A `tmp.<hex>` staging directory younger than this may belong to a
/// freshclam that is running RIGHT NOW, so it is never swept.
///
/// This guard is the whole safety argument. The daemon serialises its own
/// updates behind `update_running`, but nothing stops an administrator
/// running `freshclam.exe` by hand, and deleting a live download's staging
/// directory would corrupt it. An hour is far longer than any run this
/// updater permits (`CYCLE_BUDGET`), so anything older is provably dead.
const ORPHAN_TEMP_MIN_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Delete `tmp.<hex>` staging directories left behind by killed freshclam runs.
///
/// freshclam stages every download into `<db_dir>/tmp.<hex>/` and moves the
/// files out only on a clean finish. We kill it when it exceeds its budget,
/// and on Windows that is a `TerminateProcess` — no cleanup handler runs, so
/// the directory survives with a partial CVD inside it. `main.cvd` alone is
/// ~170 MB, and nothing else in the daemon ever removed these, so a machine
/// on a slow link accrued one per timed-out attempt until the disk noticed.
///
/// Is this directory entry one of freshclam's abandoned staging directories?
///
/// Split out from the walk so the decision is testable without backdating
/// files on disk, which needs an OS-specific call to do to a DIRECTORY on
/// Windows. `age` is `None` when the mtime could not be read.
fn is_sweepable(name: &str, is_dir: bool, age: Option<std::time::Duration>) -> bool {
    // Anchored: a directory merely CONTAINING "tmp." is not freshclam's.
    if !name.starts_with("tmp.") || !is_dir {
        return false;
    }
    match age {
        Some(age) => age >= ORPHAN_TEMP_MIN_AGE,
        // Unreadable or future-dated mtime. Treat as young and leave it: the
        // cost of skipping is one stale directory, the cost of guessing wrong
        // the other way is a corrupted live download.
        None => false,
    }
}

/// Best-effort throughout: this is housekeeping, and a failure to tidy up
/// must never turn into a failed update. Errors are logged at debug.
fn sweep_orphaned_temp_dirs(db_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(db_dir) else {
        return;
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0u32;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let age = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| now.duration_since(m).ok());
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        if !is_sweepable(name, is_dir, age) {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) => tracing::debug!(path = %entry.path().display(), %e,
                "could not remove an orphaned freshclam staging directory"),
        }
    }
    if removed > 0 {
        info!(
            count = removed,
            "removed orphaned freshclam staging directories left by killed update runs"
        );
    }
}

/// Run freshclam to update the signature database.
/// Returns (success, output_message).
#[allow(dead_code)]
pub fn run_freshclam(freshclam_path: &Path, config_path: &Path, db_dir: &Path) -> (bool, String) {
    run_freshclam_with_retry(freshclam_path, config_path, db_dir, |_| {})
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
    // Sweep BEFORE the run, not after. After would only ever catch the
    // directories this cycle just made, and those are younger than
    // ORPHAN_TEMP_MIN_AGE by construction, so they would always be skipped
    // and nothing would ever be collected. Sweeping first collects the ones
    // previous cycles abandoned, which is the actual leak.
    sweep_orphaned_temp_dirs(db_dir);

    let cycle_started = std::time::Instant::now();
    let mut last = (false, String::new());
    for attempt in 0..ATTEMPTS_PER_CYCLE {
        // The backoff sleeps come out of the same budget as the downloads, so
        // the ceiling covers the whole cycle and not just the time freshclam
        // was running - and the sleep is only taken once we know there will
        // be time left to use it.
        let Some(plan) = plan_attempt(attempt, cycle_started.elapsed()) else {
            warn!(
                attempt = attempt + 1,
                budget_secs = CYCLE_BUDGET.as_secs(),
                "signature update cycle is out of time - waiting for the next scheduled run"
            );
            if last.1.is_empty() {
                last.1 = "signature update cycle exceeded its time budget".into();
            }
            return last;
        };
        if !plan.pause.is_zero() {
            info!(
                attempt = attempt + 1,
                of = ATTEMPTS_PER_CYCLE,
                backoff_secs = plan.pause.as_secs(),
                "retrying signature update after a transient failure"
            );
            std::thread::sleep(plan.pause);
        }
        last = run_freshclam_bounded(
            freshclam_path,
            config_path,
            db_dir,
            plan.budget,
            &mut on_line,
        );
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

/// One freshclam invocation, killed after `budget`.
///
/// The progress callback fires in real-time as freshclam produces output,
/// letting the daemon track download phases and filenames.
///
/// The budget is a PARAMETER rather than a per-call constant because the
/// retry loop divides one cycle budget across its attempts. When it was a
/// local const, every attempt started a fresh 10-minute clock and three
/// attempts could occupy the updater for 32.5 minutes.
fn run_freshclam_bounded<F>(
    freshclam_path: &Path,
    config_path: &Path,
    _db_dir: &Path,
    budget: std::time::Duration,
    mut on_line: F,
) -> (bool, String)
where
    F: FnMut(&str),
{
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let freshclam_timeout = budget;
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

        if started.elapsed() > freshclam_timeout {
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
    fn the_sweep_collects_dead_staging_dirs_and_spares_live_ones() {
        use std::time::Duration;
        let old = Some(ORPHAN_TEMP_MIN_AGE + Duration::from_secs(60));
        let recent = Some(Duration::from_secs(30));

        // The leak this closes: a killed freshclam's staging directory, with
        // a partial CVD inside, that nothing ever removed.
        assert!(is_sweepable("tmp.deadbeef01", true, old));

        // The dangerous direction. `recent` stands for a freshclam running
        // RIGHT NOW — ours, or one an admin started by hand. Dropping the age
        // guard deletes a live download's staging directory mid-write.
        assert!(!is_sweepable("tmp.cafebabe02", true, recent));

        // An unreadable or future-dated mtime is not evidence of death.
        assert!(!is_sweepable("tmp.deadbeef01", true, None));

        // Only freshclam's own naming, and only directories.
        assert!(!is_sweepable("quarantine-staging", true, old));
        assert!(!is_sweepable("my-tmp.stuff", true, old));
        assert!(!is_sweepable("tmp.notadirectory", false, old));
        // Exactly at the threshold counts as dead — the boundary has to fall
        // somewhere, and an hour is already far past any run we permit.
        assert!(is_sweepable("tmp.x", true, Some(ORPHAN_TEMP_MIN_AGE)));
    }

    #[test]
    fn the_sweep_walks_a_real_directory_and_removes_nothing_it_should_not() {
        // The predicate above owns the decision; this owns the walk. Every
        // entry here is RECENT, so a correct sweep removes none of them —
        // which is also the regression guard for a sweep that ignored the
        // predicate and deleted by name alone.
        let root = std::env::temp_dir().join(format!("sentinella-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let live = root.join("tmp.cafebabe02");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("daily.cvd.partial"), b"xx").unwrap();
        let keep = root.join("enhanced");
        std::fs::create_dir_all(&keep).unwrap();

        sweep_orphaned_temp_dirs(&root);

        assert!(live.exists(), "a live download must survive the sweep");
        assert!(keep.exists(), "unrelated directories are not ours to touch");

        // And it must not panic or complain on a directory that is not there.
        sweep_orphaned_temp_dirs(&root.join("does-not-exist"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_cycle_ceiling_is_the_ceiling_not_a_per_attempt_one() {
        // The defect this pins: ATTEMPTS_PER_CYCLE's doc comment describes
        // the worst case as one timeout plus the backoffs. That is only true
        // while the attempts SHARE a deadline. If someone reverts
        // run_freshclam_bounded to a per-call constant, the real worst case
        // becomes ATTEMPTS_PER_CYCLE * CYCLE_BUDGET and the comment silently
        // becomes a lie again.
        //
        // Asserted as a property of the constants: the sleeps must fit inside
        // the cycle budget with room for at least one real attempt, or the
        // retry loop can only ever run the first attempt.
        let backoff_total: std::time::Duration = RETRY_BACKOFF.iter().sum();
        assert!(
            backoff_total + MIN_ATTEMPT_BUDGET < CYCLE_BUDGET,
            "backoffs ({backoff_total:?}) leave no room for a retry inside CYCLE_BUDGET ({CYCLE_BUDGET:?})"
        );
        // And the floor must be small enough that a retry is actually
        // reachable after the first attempt has consumed most of the budget.
        assert!(MIN_ATTEMPT_BUDGET < CYCLE_BUDGET / 2);
    }

    #[test]
    fn backoff_covers_every_retry() {
        // Indexing RETRY_BACKOFF[attempt - 1] must stay in bounds for every
        // attempt the loop can take.
        assert!(RETRY_BACKOFF.len() >= ATTEMPTS_PER_CYCLE - 1);
        // And the pauses must be ordered, or "backoff" is a lie.
        assert!(RETRY_BACKOFF.windows(2).all(|w| w[0] < w[1]));
    }

    /// REGRESSION. The worst case walked through by hand, with the shipped
    /// constants: attempt 0 fails fast, attempt 1 runs to its budget and
    /// times out at t=10m00s, attempt 2 is refused. The old loop slept the
    /// 120 s backoff BEFORE testing the budget, so the cycle ran 12 minutes
    /// against a documented 10-minute ceiling with `update_running` held —
    /// two minutes of sleeping toward an attempt it had already decided to
    /// refuse.
    #[test]
    fn a_dead_cycle_is_not_padded_by_a_backoff_it_will_not_use() {
        let spent = std::time::Duration::from_secs(10 * 60);
        assert!(
            plan_attempt(2, spent).is_none(),
            "an exhausted cycle must stop instead of sleeping first"
        );
        // The same at the boundary: 120 s of backoff plus the 45 s floor
        // does not fit in what is left, so there is nothing to sleep for.
        let almost = CYCLE_BUDGET - std::time::Duration::from_secs(160);
        assert!(plan_attempt(2, almost).is_none());
    }

    /// The ceiling is wall-clock, "sleeps included" — so NO sequence the
    /// loop can walk may exceed it. Every combination of "failed fast" and
    /// "burned its whole budget" is simulated through the same planner the
    /// loop uses, summing sleeps and run time exactly as the loop spends
    /// them. Charging the backoff to the budget only AFTER taking it (the
    /// shape this replaced) pushes the fast-then-slow sequences over.
    #[test]
    fn no_cycle_sequence_can_exceed_the_wall_clock_ceiling() {
        let fast = std::time::Duration::from_secs(1);
        // Bit i of `pattern` = attempt i fails fast rather than timing out.
        for pattern in 0..(1u32 << ATTEMPTS_PER_CYCLE) {
            let mut elapsed = std::time::Duration::ZERO;
            let mut ran = 0;
            for attempt in 0..ATTEMPTS_PER_CYCLE {
                let Some(plan) = plan_attempt(attempt, elapsed) else {
                    break;
                };
                let ran_for = if pattern & (1 << attempt) != 0 {
                    fast
                } else {
                    plan.budget
                };
                elapsed += plan.pause + ran_for;
                ran += 1;
            }
            assert!(ran > 0, "the first attempt must always be allowed to run");
            assert!(
                elapsed <= CYCLE_BUDGET,
                "pattern {pattern:b} occupies {elapsed:?}, past the {CYCLE_BUDGET:?} ceiling"
            );
        }
    }

    /// ...and the ceiling must not be bought by refusing to retry: a fast
    /// first failure has to leave room for the later attempts.
    #[test]
    fn a_fast_first_failure_still_gets_every_attempt() {
        let mut elapsed = std::time::Duration::from_secs(1);
        for attempt in 1..ATTEMPTS_PER_CYCLE {
            let plan = plan_attempt(attempt, elapsed)
                .unwrap_or_else(|| panic!("attempt {attempt} refused after {elapsed:?}"));
            assert!(plan.budget >= MIN_ATTEMPT_BUDGET);
            // A quick transient failure, not a full-budget burn.
            elapsed += plan.pause + std::time::Duration::from_secs(1);
        }
    }
}

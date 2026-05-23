//! Signature database updater — wraps freshclam as a sidecar process.
//!
//! Runs freshclam with the configured mirror and database directory.
//! Reports progress via activity events.

use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, info, warn};

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

    info!(path = %freshclam_path.display(), "starting freshclam update");

    // Spawn with piped stdout/stderr for real-time reading.
    let mut child = match Command::new(freshclam_path)
        .arg("--config-file")
        .arg(config_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
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
pub fn find_freshclam() -> Option<PathBuf> {
    // Check relative to the exe's directory first.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let mut candidates = vec![
        PathBuf::from("build/clamav/freshclam/Release/freshclam.exe"),
        PathBuf::from("third_party/clamav/build/freshclam/Release/freshclam.exe"),
    ];
    if let Some(ref dir) = exe_dir {
        candidates.push(dir.join("freshclam.exe"));
    }

    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
    }

    // Try PATH.
    if let Ok(output) = Command::new("where").arg("freshclam.exe").output() {
        let path = String::from_utf8_lossy(&output.stdout);
        let first = path.lines().next().unwrap_or("").trim();
        if !first.is_empty() && Path::new(first).exists() {
            return Some(PathBuf::from(first));
        }
    }

    None
}

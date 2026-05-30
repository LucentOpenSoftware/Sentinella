//! Optional external ClamAV worker invocation.
//!
//! Spawns `clamavd.exe` as a subprocess for isolated ClamAV scanning.
//! If clamavd crashes (e.g., CVE in libclamav), only the worker dies.
//! The daemon survives and can respawn a new worker.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::Deserialize;

const MAX_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MB max stdout
/// Max concurrent clamavd subprocesses (each loads ~400MB of sigs).
const MAX_CONCURRENT_WORKERS: usize = 2;

static ACTIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

/// Simple RAII guard — runs closure on drop.
struct Guard<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for Guard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}
fn scopeguard<F: FnOnce()>(f: F) -> Guard<F> {
    Guard(Some(f))
}

#[derive(Clone, Debug)]
pub struct ClamWorkerSettings {
    pub enabled: bool,
    pub dll_dir: PathBuf,
    pub db_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
pub struct ClamWorkerOutput {
    pub path: String,
    pub infected: bool,
    pub virus_name: Option<String>,
    pub scanned_bytes: u64,
    pub error: Option<String>,
    pub signature_count: u64,
    pub scan_time_ms: u64,
}

/// Scan a file using the isolated clamavd subprocess.
/// Limits concurrent workers to MAX_CONCURRENT_WORKERS to prevent RAM explosion.
pub fn scan_file(
    settings: &ClamWorkerSettings,
    path: &Path,
    cancel: &AtomicBool,
) -> Result<ClamWorkerOutput, String> {
    // Concurrency gate — each clamavd loads ~400MB of signatures.
    let active = ACTIVE_WORKERS.fetch_add(1, Ordering::Relaxed);
    if active >= MAX_CONCURRENT_WORKERS {
        ACTIVE_WORKERS.fetch_sub(1, Ordering::Relaxed);
        return Err("clamavd concurrency limit reached — falling back to in-process".into());
    }
    let _guard = scopeguard(|| {
        ACTIVE_WORKERS.fetch_sub(1, Ordering::Relaxed);
    });

    let worker = find_clamavd();
    let worker_path = worker.ok_or_else(|| "clamavd.exe not found".to_string())?;

    let mut child = std::process::Command::new(&worker_path)
        .arg(path)
        .arg("--dll-dir")
        .arg(&settings.dll_dir)
        .arg("--db-dir")
        .arg(&settings.db_dir)
        .arg("--json")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("clamavd spawn failed: {e}"))?;

    // Real leak fix: Rust's `Child` Drop is a no-op — it does NOT kill or
    // wait the spawned process. The previous `child.stdout.take().ok_or("no stdout")?`
    // early-returned, dropping `child` and orphaning the clamavd process. On
    // a busy realtime watcher that compounds quickly. Kill+wait before
    // bubbling up if take() fails.
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("no stdout".into());
        }
    };
    let reader = std::thread::spawn(move || read_limited(stdout, MAX_OUTPUT_BYTES));
    let stderr_reader = child
        .stderr
        .take()
        .map(|stderr| std::thread::spawn(move || read_limited(stderr, MAX_OUTPUT_BYTES)));

    // Wait with timeout + cancellation.
    let start = Instant::now();
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("cancelled".into());
        }
        if start.elapsed() > settings.timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "clamavd timeout after {}s",
                settings.timeout.as_secs()
            ));
        }
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("clamavd wait error: {e}"));
            }
        }
    }

    let stdout_data = reader
        .join()
        .map_err(|_| "stdout reader panicked".to_string())?
        .map_err(|e| format!("stdout read: {e}"))?;
    if let Some(reader) = stderr_reader {
        let _ = reader
            .join()
            .map_err(|_| "stderr reader panicked".to_string())?;
    }

    if stdout_data.is_empty() {
        return Err("clamavd produced empty output".into());
    }

    let output: ClamWorkerOutput =
        serde_json::from_slice(&stdout_data).map_err(|e| format!("clamavd JSON parse: {e}"))?;

    Ok(output)
}

fn read_limited<R: Read>(mut reader: R, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        if out.len() + n > limit {
            return Err("output too large".into());
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn find_clamavd() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("clamavd.exe");
            if candidate.exists() {
                return Some(candidate);
            }
            // Dev layout.
            for ancestor in dir.ancestors().skip(1) {
                let rel = ancestor.join("target").join("release").join("clamavd.exe");
                if rel.exists() {
                    return Some(rel);
                }
                let dbg = ancestor.join("target").join("debug").join("clamavd.exe");
                if dbg.exists() {
                    return Some(dbg);
                }
            }
        }
    }
    None
}

//! Behavioral sandbox worker invocation.
//!
//! Spawns `sandboxd.exe` as subprocess to detonate suspicious files.
//! Only triggered for ARGUS scores in the configurable range (default 26-75).
//! Disabled by default — experimental feature.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::config::SandboxConfig;

const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENT: usize = 1; // Only 1 detonation at a time.

static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// Simple RAII guard.
struct Guard<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for Guard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SandboxOutput {
    pub engine: String,
    pub status: String,
    pub sample_path: String,
    pub sample_sha256: String,
    pub detonation_time_ms: u64,
    #[serde(default)]
    pub monitor_duration_ms: u64,
    #[serde(default)]
    pub backend_used: Option<String>,
    pub findings: Vec<SandboxFinding>,
    pub score_delta: i32,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SandboxFinding {
    pub kind: String,
    pub severity: String,
    pub detail: String,
    #[serde(default = "default_confidence")]
    pub confidence: String,
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_confidence() -> String {
    "observed".into()
}

fn default_source() -> String {
    "sandboxd".into()
}

/// Check if a file should be sent to sandbox based on ARGUS score.
pub fn should_sandbox(score: u32, config: &SandboxConfig) -> bool {
    config.enabled && score >= config.min_score && score <= config.max_score
}

/// Detonate a file in the sandbox worker subprocess.
pub fn detonate(
    path: &Path,
    config: &SandboxConfig,
    cancel: &AtomicBool,
) -> Result<SandboxOutput, String> {
    // Concurrency gate.
    let active = ACTIVE.fetch_add(1, Ordering::Relaxed);
    if active >= MAX_CONCURRENT {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        return Err("sandbox busy — only 1 concurrent detonation allowed".into());
    }
    let _guard = Guard(Some(|| {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }));

    let worker = find_sandboxd().ok_or("sandboxd.exe not found")?;

    let mut child = std::process::Command::new(&worker)
        .arg(path)
        .arg("--timeout")
        .arg(config.timeout_sec.to_string())
        .arg("--json")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("sandboxd spawn: {e}"))?;

    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stdout_reader = std::thread::spawn(move || read_limited(stdout, MAX_OUTPUT_BYTES));
    let stderr_reader = child
        .stderr
        .take()
        .map(|stderr| std::thread::spawn(move || read_limited(stderr, MAX_OUTPUT_BYTES)));

    // Wait with timeout + cancellation.
    let timeout = Duration::from_secs(config.timeout_sec + 5); // Extra buffer beyond detonation timeout.
    let start = Instant::now();
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("cancelled".into());
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err("sandboxd process timeout".into());
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("sandboxd wait: {e}"));
            }
        }
    }

    let stdout_data = stdout_reader
        .join()
        .map_err(|_| "stdout reader panicked")?
        .map_err(|e| format!("stdout: {e}"))?;
    if let Some(reader) = stderr_reader {
        let _ = reader.join().map_err(|_| "stderr reader panicked")?;
    }

    if stdout_data.is_empty() {
        return Err("sandboxd produced empty output".into());
    }

    serde_json::from_slice(&stdout_data).map_err(|e| format!("sandboxd JSON: {e}"))
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

/// Check if sandboxd binary exists (for startup validation).
pub fn find_sandboxd_public() -> Option<PathBuf> {
    find_sandboxd()
}

fn find_sandboxd() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let c = dir.join("sandboxd.exe");
            if c.exists() {
                return Some(c);
            }
            for ancestor in dir.ancestors().skip(1) {
                let r = ancestor.join("target").join("release").join("sandboxd.exe");
                if r.exists() {
                    return Some(r);
                }
                let d = ancestor.join("target").join("debug").join("sandboxd.exe");
                if d.exists() {
                    return Some(d);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_finding_keeps_evidence_contract() {
        let finding: SandboxFinding = serde_json::from_str(
            r#"{"kind":"network_connection","severity":"high","detail":"TCP connect","confidence":"observed","source":"etw_kernel_tcpip"}"#,
        )
        .unwrap();

        assert_eq!(finding.confidence, "observed");
        assert_eq!(finding.source, "etw_kernel_tcpip");
    }

    #[test]
    fn sandbox_finding_defaults_legacy_fields() {
        let finding: SandboxFinding =
            serde_json::from_str(r#"{"kind":"timeout","severity":"medium","detail":"timeout"}"#)
                .unwrap();

        assert_eq!(finding.confidence, "observed");
        assert_eq!(finding.source, "sandboxd");
    }
}

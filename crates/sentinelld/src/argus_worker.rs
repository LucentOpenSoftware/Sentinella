//! Optional external ARGUS worker invocation.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Deserialize;

const MAX_WORKER_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_WORKER_STDERR_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct ArgusWorkerSettings {
    pub enabled: bool,
    pub path: String,
    pub timeout: Duration,
}

impl ArgusWorkerSettings {
    pub fn from_config(config: &crate::config::Config) -> Self {
        let enabled = config.scan.argus_worker_enabled || config.argus_worker_enabled;
        let path = if config.scan.argus_worker_enabled {
            config.scan.argus_worker_path.clone()
        } else {
            config.argus_worker_path.clone()
        };
        let timeout_sec = if config.scan.argus_worker_enabled {
            config.scan.argus_worker_timeout_sec
        } else {
            config.argus_worker_timeout_sec
        };

        Self {
            enabled,
            path,
            timeout: Duration::from_secs(timeout_sec.max(1)),
        }
    }
}

#[derive(Debug, Deserialize)]
struct WorkerOutput {
    path: String,
    file_size: u64,
    sha256: String,
    mime_type: Option<String>,
    score: u32,
    verdict: argus::verdict::Verdict,
    confidence_label: argus::verdict::ConfidenceLabel,
    threat_maturity: argus::verdict::ThreatMaturity,
    framework: Option<String>,
    strategy: Option<argus::verdict::ScanStrategy>,
    findings: Vec<argus::Finding>,
    analysis_time_us: u64,
    timestamp: i64,
    explanation: argus::verdict::VerdictExplanation,
    timing: Option<argus::verdict::ScanTiming>,
    #[serde(default)]
    errors: Vec<String>,
}

pub fn scan_file(
    settings: &ArgusWorkerSettings,
    path: &Path,
    cancel: &AtomicBool,
) -> Result<argus::ArgusVerdict, String> {
    let worker = resolve_worker_path(&settings.path);
    let mut child = Command::new(&worker)
        .arg("scan-file")
        .arg(path)
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("ARGUS worker spawn failed ({}): {e}", worker.display()))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "ARGUS worker stdout unavailable".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "ARGUS worker stderr unavailable".to_string())?;

    let stdout_reader =
        std::thread::spawn(move || read_limited(stdout, MAX_WORKER_JSON_BYTES, "stdout"));
    let stderr_reader =
        std::thread::spawn(move || read_limited(stderr, MAX_WORKER_STDERR_BYTES, "stderr"));

    let status = wait_child(&mut child, settings.timeout, cancel)?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| "ARGUS worker stdout reader panicked".to_string())??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "ARGUS worker stderr reader panicked".to_string())??;

    let code = status.code().unwrap_or(-1);
    if code >= 3 || code < 0 {
        let stderr = String::from_utf8_lossy(&stderr).trim().to_string();
        return Err(format!(
            "ARGUS worker exit {}{}",
            code,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            },
        ));
    }

    if stdout.is_empty() {
        return Err("ARGUS worker produced empty JSON".into());
    }

    let parsed: WorkerOutput = serde_json::from_slice(&stdout)
        .map_err(|e| format!("ARGUS worker JSON parse failed: {e}"))?;
    validate_worker_output(&parsed)?;
    if !parsed.errors.is_empty() {
        return Err(parsed.errors.join("; "));
    }

    Ok(argus::ArgusVerdict {
        path: parsed.path,
        file_size: parsed.file_size,
        sha256: parsed.sha256,
        mime_type: parsed.mime_type,
        score: parsed.score,
        verdict: parsed.verdict,
        findings: parsed.findings,
        analysis_time_us: parsed.analysis_time_us,
        engine_version: argus::ENGINE_VERSION,
        timestamp: parsed.timestamp,
        explanation: parsed.explanation,
        timing: parsed.timing,
    })
}

fn wait_child(
    child: &mut Child,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<std::process::ExitStatus, String> {
    let start = Instant::now();
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("ARGUS worker cancelled".into());
        }

        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("ARGUS worker timeout after {}s", timeout.as_secs()));
        }

        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("ARGUS worker wait failed: {e}"));
            }
        }
    }
}

fn read_limited<R: Read>(mut reader: R, limit: usize, name: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("ARGUS worker {name} read failed: {e}"))?;
        if n == 0 {
            break;
        }
        if out.len() < limit {
            let remaining = limit - out.len();
            out.extend_from_slice(&buf[..n.min(remaining)]);
            if n > remaining {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    if truncated {
        return Err(format!("ARGUS worker {name} exceeded {limit} bytes"));
    }
    Ok(out)
}

fn validate_worker_output(parsed: &WorkerOutput) -> Result<(), String> {
    if parsed.path.trim().is_empty() {
        return Err("ARGUS worker JSON missing path".into());
    }
    if parsed.score > 100 {
        return Err(format!("ARGUS worker JSON invalid score {}", parsed.score));
    }
    if parsed.sha256.len() != 64 || !parsed.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("ARGUS worker JSON invalid sha256".into());
    }
    if parsed.explanation.final_score > 100 || parsed.explanation.final_score != parsed.score {
        return Err("ARGUS worker JSON inconsistent final score".into());
    }
    if parsed.explanation.confidence_label != parsed.confidence_label {
        return Err("ARGUS worker JSON inconsistent confidence label".into());
    }
    if parsed.explanation.threat_maturity != parsed.threat_maturity {
        return Err("ARGUS worker JSON inconsistent threat maturity".into());
    }
    if parsed.explanation.framework != parsed.framework {
        return Err("ARGUS worker JSON inconsistent framework".into());
    }
    let timing_strategy = parsed.timing.as_ref().and_then(|t| t.strategy);
    if timing_strategy != parsed.strategy {
        return Err("ARGUS worker JSON inconsistent strategy".into());
    }
    Ok(())
}

fn resolve_worker_path(configured: &str) -> PathBuf {
    let raw = PathBuf::from(configured);
    if raw.components().count() > 1 || raw.is_absolute() {
        return raw;
    }

    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(&raw));
            if let Some(root) = project_root_from_target_dir(dir) {
                candidates.push(root.join("target").join("release").join(&raw));
                candidates.push(root.join("target").join("debug").join(&raw));
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(&raw));
        candidates.push(cwd.join("target").join("release").join(&raw));
        candidates.push(cwd.join("target").join("debug").join(&raw));
    }

    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }

    raw
}

fn project_root_from_target_dir(dir: &Path) -> Option<PathBuf> {
    let name = dir.file_name()?.to_string_lossy().to_ascii_lowercase();
    if name == "debug" || name == "release" {
        let target = dir.parent()?;
        if target
            .file_name()?
            .to_string_lossy()
            .eq_ignore_ascii_case("target")
        {
            return target.parent().map(Path::to_path_buf);
        }
    }
    None
}

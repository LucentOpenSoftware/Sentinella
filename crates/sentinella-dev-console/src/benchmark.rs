//! Spawn `argusd.exe benchmark --json …` and parse the report.
//!
//! Identical CLI to what the daemon shells out to via the `benchmark.run`
//! IPC method — so the numbers we render here are the same numbers a
//! Developer-Mode GUI run would show.

use crate::daemon::quiet_command;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Stdio;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchmarkReport {
    #[serde(default)]
    pub engine_version: String,
    #[serde(default)]
    pub passes: u32,
    #[serde(default)]
    pub corpus_files: u64,
    #[serde(default)]
    pub corpus_bytes: u64,
    #[serde(default)]
    pub files_per_sec: f64,
    #[serde(default)]
    pub mb_per_sec: f64,
    #[serde(default)]
    pub p50_us: u64,
    #[serde(default)]
    pub p95_us: u64,
    #[serde(default)]
    pub max_us: u64,
    #[serde(default)]
    pub mean_us: u64,
    #[serde(default)]
    pub performance_index: f64,
    #[serde(default)]
    pub logical_cores: u32,
    #[serde(default)]
    pub simd: Vec<String>,
    /// Everything else the argusd report emits — surfaced verbatim in a
    /// raw-JSON view so we never lose data the parser doesn't model yet.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
pub enum BenchmarkOutcome {
    Ok(BenchmarkReport),
    Failed { stderr: String, exit: Option<i32> },
}

pub fn run_benchmark(
    argusd: &Path,
    passes: u32,
    dir: Option<&Path>,
) -> Result<BenchmarkOutcome, String> {
    let mut cmd = quiet_command(argusd);
    cmd.arg("benchmark")
        .arg("--json")
        .arg("--passes")
        .arg(passes.clamp(1, 10).to_string());
    if let Some(d) = dir {
        cmd.arg("--dir").arg(d);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let out = cmd
        .output()
        .map_err(|e| format!("spawn {} benchmark: {e}", argusd.display()))?;
    if !out.status.success() {
        return Ok(BenchmarkOutcome::Failed {
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit: out.status.code(),
        });
    }
    let report: BenchmarkReport = serde_json::from_slice(&out.stdout)
        .map_err(|e| {
            format!(
                "parse benchmark JSON ({} bytes): {e}\n--- raw ---\n{}",
                out.stdout.len(),
                String::from_utf8_lossy(&out.stdout)
            )
        })?;
    Ok(BenchmarkOutcome::Ok(report))
}

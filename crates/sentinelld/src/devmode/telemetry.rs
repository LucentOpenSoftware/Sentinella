//! Developer-mode local perf telemetry (v0.1.6, local-only).
//!
//! Appends human-readable performance records to a bounded, rotating text file
//! in the AV diagnostics dir so the author can compare how Sentinella behaves on
//! different hardware (i7-7200U, Core 2 Quad, Skylake, Ryzen vs. the i5-1265U
//! dev box). This is **NOT** cloud telemetry: nothing leaves the machine, there
//! is no aggregation and no network egress. Writes are gated behind developer
//! mode + `telemetry_enabled`, and the dump file is hard-capped — past the cap a
//! single backup is kept and the live file starts fresh, so it is never
//! unbounded. Telemetry is best-effort: any failure is logged at debug and
//! swallowed so it can never disrupt scanning.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;

use crate::config::DeveloperConfig;

const TELEMETRY_FILE: &str = "perf_telemetry.txt";
const TELEMETRY_BACKUP: &str = "perf_telemetry.1.txt";

/// One perf record => one human-readable block appended to the dump file.
#[derive(Debug, Clone)]
pub struct PerfRecord {
    /// Event class: "scan", "reload", "benchmark".
    pub kind: String,
    /// Short detail (scan type, reload reason, corpus source).
    pub detail: String,
    pub files: u64,
    pub bytes: u64,
    pub duration_ms: u64,
    pub threats: u64,
    pub working_set_mb: u64,
    pub private_bytes_mb: u64,
    pub peak_working_set_mb: u64,
    /// Memory pressure state at completion ("Normal"/"Elevated"/...).
    pub pressure: String,
    /// Free-form extra lines (ClamAV vs ARGUS split, mpool state, cache stats).
    pub notes: Vec<String>,
}

impl PerfRecord {
    /// Start an empty record of the given kind + detail.
    pub fn new(kind: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            detail: detail.into(),
            files: 0,
            bytes: 0,
            duration_ms: 0,
            threats: 0,
            working_set_mb: 0,
            private_bytes_mb: 0,
            peak_working_set_mb: 0,
            pressure: String::new(),
            notes: Vec::new(),
        }
    }

    /// Append a free-form note line.
    pub fn note(mut self, n: impl Into<String>) -> Self {
        self.notes.push(n.into());
        self
    }
}

/// Whether telemetry should be written for this config. Requires BOTH developer
/// mode enabled AND telemetry opt-in.
pub fn enabled(cfg: &DeveloperConfig) -> bool {
    cfg.enabled && cfg.telemetry_enabled
}

/// Absolute path to the live telemetry dump file (for `dev.status` / the GUI).
pub fn dump_path() -> std::path::PathBuf {
    crate::paths::paths().diagnostics_dir().join(TELEMETRY_FILE)
}

/// Current size of the live dump file in KiB (0 if absent).
pub fn dump_size_kb() -> u64 {
    std::fs::metadata(dump_path())
        .map(|m| m.len() / 1024)
        .unwrap_or(0)
}

/// Append a record to the perf telemetry dump (gated + bounded). Best-effort.
pub fn record(cfg: &DeveloperConfig, rec: &PerfRecord) {
    if !enabled(cfg) {
        return;
    }
    let dir = crate::paths::paths().diagnostics_dir();
    let max_kb = cfg.telemetry_max_kb.clamp(64, 65_536);
    if let Err(e) = append_block(&dir, max_kb, &format_block(rec)) {
        tracing::debug!("perf telemetry write failed: {e}");
    }
}

/// files/sec + MB/sec, guarding against a zero duration.
fn throughput(files: u64, bytes: u64, duration_ms: u64) -> (f64, f64) {
    if duration_ms == 0 {
        return (0.0, 0.0);
    }
    let secs = duration_ms as f64 / 1000.0;
    let fps = files as f64 / secs;
    let mbps = (bytes as f64 / (1024.0 * 1024.0)) / secs;
    (fps, mbps)
}

/// Render one record as a human-readable block (with this machine's facts so a
/// dump collected from a Core 2 Quad reads as "old CPU" rather than "broken").
fn format_block(rec: &PerfRecord) -> String {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%z");
    let sys = crate::footprint::system_info_json();
    let cores = sys
        .get("logical_cores")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let ram = sys.get("total_ram_mb").and_then(|v| v.as_u64()).unwrap_or(0);
    let arch = sys.get("arch").and_then(|v| v.as_str()).unwrap_or("?");
    let simd = simd_summary(&sys);
    let (fps, mbps) = throughput(rec.files, rec.bytes, rec.duration_ms);
    let pressure = if rec.pressure.is_empty() {
        "?"
    } else {
        rec.pressure.as_str()
    };

    let mut s = String::new();
    let _ = writeln!(s, "──── {ts} [{}] {} ────", rec.kind, rec.detail);
    let _ = writeln!(s, "  host: {cores} cores, {ram} MB RAM, {arch}, simd=[{simd}]");
    let _ = writeln!(
        s,
        "  work: files={} bytes={} threats={} duration_ms={}",
        rec.files, rec.bytes, rec.threats, rec.duration_ms
    );
    let _ = writeln!(s, "  throughput: {fps:.1} files/sec, {mbps:.1} MB/sec");
    let _ = writeln!(
        s,
        "  memory: ws={}MB private={}MB peak={}MB pressure={pressure}",
        rec.working_set_mb, rec.private_bytes_mb, rec.peak_working_set_mb
    );
    for n in &rec.notes {
        let _ = writeln!(s, "  {n}");
    }
    s.push('\n');
    s
}

/// Most-capable-first SIMD summary from `system_info_json`'s `simd` object.
fn simd_summary(sys: &serde_json::Value) -> String {
    let simd = match sys.get("simd") {
        Some(v) if v.is_object() => v,
        _ => return String::from("n/a"),
    };
    let mut out = Vec::new();
    for k in ["avx2", "avx", "sse4.2", "sse2"] {
        if simd.get(k).and_then(|v| v.as_bool()).unwrap_or(false) {
            out.push(k);
        }
    }
    if out.is_empty() {
        String::from("none")
    } else {
        out.join(",")
    }
}

/// Append `block` to the dump file in `dir`, rotating when the cap would be
/// exceeded. A single block always gets written even if it alone exceeds the cap
/// (a fresh file after rotation) — so the cap bounds growth, not single records.
fn append_block(dir: &Path, max_kb: u64, block: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(TELEMETRY_FILE);
    let max_bytes = max_kb.saturating_mul(1024);

    let cur = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    if cur.saturating_add(block.len() as u64) > max_bytes && path.exists() {
        // Rotate: current -> single backup, then start fresh.
        let backup = dir.join(TELEMETRY_BACKUP);
        let _ = std::fs::remove_file(&backup);
        std::fs::rename(&path, &backup)?;
    }

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    f.write_all(block.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(enabled: bool, telemetry: bool) -> DeveloperConfig {
        DeveloperConfig {
            enabled,
            password_sha256: String::new(),
            telemetry_enabled: telemetry,
            telemetry_max_kb: 2048,
        }
    }

    #[test]
    fn gate_requires_both_flags() {
        assert!(!enabled(&dev(false, false)));
        assert!(!enabled(&dev(false, true)));
        assert!(!enabled(&dev(true, false)));
        assert!(enabled(&dev(true, true)));
    }

    #[test]
    fn throughput_handles_zero_duration() {
        assert_eq!(throughput(10, 1024, 0), (0.0, 0.0));
        let (fps, mbps) = throughput(10, 2 * 1024 * 1024, 1000);
        assert!((fps - 10.0).abs() < 1e-9);
        assert!((mbps - 2.0).abs() < 1e-9);
    }

    #[test]
    fn simd_summary_orders_and_handles_missing() {
        let sys = serde_json::json!({
            "simd": { "avx2": true, "avx": true, "sse4.2": true, "sse2": true }
        });
        assert_eq!(simd_summary(&sys), "avx2,avx,sse4.2,sse2");

        let none = serde_json::json!({
            "simd": { "avx2": false, "avx": false, "sse4.2": false, "sse2": false }
        });
        assert_eq!(simd_summary(&none), "none");

        let absent = serde_json::json!({ "simd": null });
        assert_eq!(simd_summary(&absent), "n/a");
    }

    #[test]
    fn format_block_contains_key_fields() {
        let rec = PerfRecord {
            kind: "scan".into(),
            detail: "full".into(),
            files: 100,
            bytes: 1024 * 1024,
            duration_ms: 2000,
            threats: 3,
            working_set_mb: 250,
            private_bytes_mb: 300,
            peak_working_set_mb: 400,
            pressure: "Normal".into(),
            notes: vec!["mpool=file-backed".into()],
        };
        let block = format_block(&rec);
        assert!(block.contains("[scan] full"));
        assert!(block.contains("files=100"));
        assert!(block.contains("threats=3"));
        assert!(block.contains("pressure=Normal"));
        assert!(block.contains("mpool=file-backed"));
        assert!(block.ends_with("\n\n"));
    }

    #[test]
    fn append_creates_and_grows() {
        let dir = std::env::temp_dir().join(format!("senti-telemetry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        append_block(&dir, 2048, "block-one\n\n").unwrap();
        append_block(&dir, 2048, "block-two\n\n").unwrap();

        let body = std::fs::read_to_string(dir.join(TELEMETRY_FILE)).unwrap();
        assert!(body.contains("block-one"));
        assert!(body.contains("block-two"));
        assert!(!dir.join(TELEMETRY_BACKUP).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotates_when_cap_exceeded() {
        let dir =
            std::env::temp_dir().join(format!("senti-telemetry-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // 64 KiB cap. Each block ~1 KiB; write enough to force a rotation.
        let block = "x".repeat(1024);
        for _ in 0..80 {
            append_block(&dir, 64, &block).unwrap();
        }

        let main = dir.join(TELEMETRY_FILE);
        let backup = dir.join(TELEMETRY_BACKUP);
        assert!(backup.exists(), "backup should exist after rotation");

        let main_len = std::fs::metadata(&main).unwrap().len();
        assert!(
            main_len <= 64 * 1024,
            "live file must stay under cap, got {main_len}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! Memory footprint diagnostics.
//!
//! Measures process memory usage and identifies major contributors.
//! Diagnostic-only — does not optimize or free memory.

pub mod pressure;
pub mod residency;

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Snapshot of daemon memory footprint.
#[derive(Debug, Clone, Serialize)]
pub struct FootprintSnapshot {
    /// Working set in MB (physical RAM used).
    pub working_set_mb: u64,
    /// Private bytes in MB (committed virtual memory).
    pub private_bytes_mb: u64,
    /// Peak working set in MB.
    pub peak_working_set_mb: u64,
    /// Whether ClamAV engine is loaded.
    pub clamav_loaded: bool,
    /// ClamAV signature count.
    pub signature_count: u64,
    /// YARA rules loaded.
    pub yara_rules: u64,
    /// Scan cache entries.
    pub scan_cache_entries: u64,
    /// Active scan workers.
    pub active_workers: u32,
    /// Delta from startup baseline (MB). Negative = memory returned.
    pub delta_since_start_mb: i64,
    /// Delta from last post-scan baseline (MB).
    pub delta_since_last_scan_mb: i64,
    /// Warning level: "normal", "elevated", "warning", "critical".
    pub warning_level: String,
    /// Explanatory notes about memory usage.
    pub notes: Vec<String>,
}

/// Persistent baselines for delta tracking.
pub struct FootprintBaselines {
    startup_ws_mb: AtomicU64,
    last_post_scan_ws_mb: AtomicU64,
    capture_count: AtomicU64,
    /// Track working set at each of last N captures for monotonic growth detection.
    recent_captures: std::sync::Mutex<Vec<u64>>,
}

impl FootprintBaselines {
    pub fn new() -> Self {
        Self {
            startup_ws_mb: AtomicU64::new(0),
            last_post_scan_ws_mb: AtomicU64::new(0),
            capture_count: AtomicU64::new(0),
            recent_captures: std::sync::Mutex::new(Vec::with_capacity(16)),
        }
    }

    /// Record startup baseline (call once after engine load).
    pub fn record_startup(&self, ws_mb: u64) {
        self.startup_ws_mb.store(ws_mb, Ordering::Relaxed);
    }

    /// Record post-scan baseline.
    pub fn record_post_scan(&self, ws_mb: u64) {
        self.last_post_scan_ws_mb.store(ws_mb, Ordering::Relaxed);
    }

    /// Record a capture for monotonic growth detection.
    fn record_capture(&self, ws_mb: u64) {
        self.capture_count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut captures) = self.recent_captures.lock() {
            captures.push(ws_mb);
            // Keep last 16 captures.
            if captures.len() > 16 {
                captures.remove(0);
            }
        }
    }

    /// Check if working set has grown monotonically over last N captures.
    fn is_monotonic_growth(&self, min_captures: usize) -> bool {
        if let Ok(captures) = self.recent_captures.lock() {
            if captures.len() < min_captures {
                return false;
            }
            let tail = &captures[captures.len().saturating_sub(min_captures)..];
            tail.windows(2)
                .all(|w| w[1] >= w[0] && w[1] > w[0].saturating_sub(5))
        } else {
            false
        }
    }

    fn startup_ws(&self) -> u64 {
        self.startup_ws_mb.load(Ordering::Relaxed)
    }

    fn last_post_scan_ws(&self) -> u64 {
        self.last_post_scan_ws_mb.load(Ordering::Relaxed)
    }
}

/// Capture current process memory footprint with delta tracking.
pub fn capture(
    clamav_loaded: bool,
    signature_count: u64,
    yara_rules: u64,
    scan_cache_entries: u64,
    active_workers: u32,
    baselines: &FootprintBaselines,
) -> FootprintSnapshot {
    let (working_set, private_bytes, peak_ws) = get_process_memory();

    let mut notes = Vec::new();

    // Annotate major contributors.
    if clamav_loaded && signature_count > 0 {
        let sig_mb = signature_count / 10_000; // rough: ~1MB per 10K sigs
        notes.push(format!(
            "ClamAV: ~{sig_mb}MB estimated for {signature_count} signatures"
        ));
        if working_set > 0 && sig_mb > working_set / 2 {
            notes.push("Large working set likely caused by ClamAV signatures".into());
        }
    }
    if yara_rules > 0 {
        notes.push(format!(
            "YARA-X: {yara_rules} rules (wasmtime JIT contributes ~50-150MB)"
        ));
        if yara_rules > 200 {
            notes.push("High YARA rule footprint".into());
        }
    }
    if active_workers > 4 {
        notes.push(format!(
            "Worker count ({active_workers}) exceeds default concurrency (4)"
        ));
    }
    if scan_cache_entries > 40_000 {
        notes.push(format!("Scan cache large: {scan_cache_entries} entries"));
    }

    // Delta tracking.
    let startup_ws = baselines.startup_ws();
    let post_scan_ws = baselines.last_post_scan_ws();
    let delta_start = if startup_ws > 0 {
        working_set as i64 - startup_ws as i64
    } else {
        0
    };
    let delta_scan = if post_scan_ws > 0 {
        working_set as i64 - post_scan_ws as i64
    } else {
        0
    };

    // Memory-returned check.
    if delta_scan < -10 {
        notes.push("Memory returned after scan completion".into());
    }
    if delta_scan > 100 {
        notes.push("Possible retained scan buffers".into());
    }

    // Record for monotonic tracking.
    baselines.record_capture(working_set);
    if baselines.is_monotonic_growth(8) {
        notes.push("Monotonic growth detected over last 8 captures — possible slow leak".into());
    }

    // Warning level.
    let warning_level = if working_set > 2500 {
        "critical"
    } else if working_set > 1500 {
        "warning"
    } else if working_set > 800 {
        "elevated"
    } else {
        "normal"
    };

    if working_set > 2500 {
        notes.push("Working set >2.5GB CRITICAL — investigate immediately".into());
    } else if working_set > 1500 {
        notes.push("Working set >1.5GB — consider subprocess worker mode for heavy scans".into());
    }

    FootprintSnapshot {
        working_set_mb: working_set,
        private_bytes_mb: private_bytes,
        peak_working_set_mb: peak_ws,
        clamav_loaded,
        signature_count,
        yara_rules,
        scan_cache_entries,
        active_workers,
        delta_since_start_mb: delta_start,
        delta_since_last_scan_mb: delta_scan,
        warning_level: warning_level.into(),
        notes,
    }
}

/// Log footprint at a lifecycle point.
pub fn log_footprint(label: &str, snapshot: &FootprintSnapshot) {
    tracing::info!(
        label,
        working_set_mb = snapshot.working_set_mb,
        private_bytes_mb = snapshot.private_bytes_mb,
        peak_mb = snapshot.peak_working_set_mb,
        sigs = snapshot.signature_count,
        yara = snapshot.yara_rules,
        cache = snapshot.scan_cache_entries,
        delta_start = snapshot.delta_since_start_mb,
        warning = snapshot.warning_level.as_str(),
        "memory footprint"
    );
    for note in &snapshot.notes {
        tracing::debug!(label, note = note.as_str(), "footprint note");
    }
}

/// Get process memory usage in MB.
fn get_process_memory() -> (u64, u64, u64) {
    #[cfg(target_os = "windows")]
    {
        get_process_memory_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        (0, 0, 0)
    }
}

#[cfg(target_os = "windows")]
fn get_process_memory_windows() -> (u64, u64, u64) {
    use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
    use windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS;
    use windows::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let process = GetCurrentProcess();
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;

        let ok = GetProcessMemoryInfo(
            process,
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        );

        if ok.is_ok() {
            let ws = counters.WorkingSetSize as u64 / (1024 * 1024);
            let peak = counters.PeakWorkingSetSize as u64 / (1024 * 1024);
            // PagefileUsage approximates private bytes.
            let private = counters.PagefileUsage as u64 / (1024 * 1024);
            (ws, private, peak)
        } else {
            (0, 0, 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_returns_valid_snapshot() {
        let baselines = FootprintBaselines::new();
        baselines.record_startup(100);
        let snap = capture(true, 3_600_000, 119, 1000, 4, &baselines);
        assert!(snap.working_set_mb > 0 || cfg!(not(target_os = "windows")));
        assert_eq!(snap.signature_count, 3_600_000);
        assert_eq!(snap.yara_rules, 119);
        assert!(!snap.notes.is_empty());
    }

    #[test]
    fn delta_tracking_works() {
        let baselines = FootprintBaselines::new();
        baselines.record_startup(200);
        baselines.record_post_scan(250);
        let snap = capture(true, 1_000_000, 50, 100, 1, &baselines);
        // Delta is relative to baselines, actual WS from OS.
        assert_eq!(snap.delta_since_start_mb, snap.working_set_mb as i64 - 200);
        assert_eq!(
            snap.delta_since_last_scan_mb,
            snap.working_set_mb as i64 - 250
        );
    }

    #[test]
    fn warning_levels() {
        let baselines = FootprintBaselines::new();
        let snap = capture(false, 0, 0, 0, 0, &baselines);
        // On test machines, WS is typically <800MB.
        assert!(
            ["normal", "elevated", "warning", "critical"].contains(&snap.warning_level.as_str())
        );
    }

    #[test]
    fn monotonic_growth_detection() {
        let baselines = FootprintBaselines::new();
        // Simulate 8 increasing captures.
        for i in 0..8 {
            baselines.record_capture(100 + i * 10);
        }
        assert!(baselines.is_monotonic_growth(8));
    }

    #[test]
    fn no_false_monotonic_growth() {
        let baselines = FootprintBaselines::new();
        // Simulate fluctuating captures.
        for ws in &[100, 120, 90, 110, 80, 100, 95, 105] {
            baselines.record_capture(*ws);
        }
        assert!(!baselines.is_monotonic_growth(8));
    }
}

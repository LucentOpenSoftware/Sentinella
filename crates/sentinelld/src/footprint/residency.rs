//! Working Set Residency Manager — quiet re-trim policy.
//!
//! Principle: realtime protection wins. Trimming only after quiet periods.
//!
//! The engine naturally warms (WS grows) when the watcher scans files.
//! When the system becomes quiet, unused signature pages are trimmed
//! back to standby — reducing Task Manager visible memory.
//!
//! Safety: never trims during active scans, reloads, or updates.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info};

/// RAII guard for active scan tracking.
/// Increments active_scan_count on creation, decrements on drop.
/// Prevents stuck counters from early returns, panics, or errors.
pub struct ScanGuard {
    tracker: Arc<ActivityTracker>,
}

impl ScanGuard {
    pub fn new(tracker: &Arc<ActivityTracker>) -> Self {
        tracker.inc_active_scans();
        Self {
            tracker: Arc::clone(tracker),
        }
    }
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        self.tracker.dec_active_scans();
    }
}

/// Residency policy configuration.
pub struct ResidencyConfig {
    /// Enable quiet re-trim.
    pub enabled: bool,
    /// Minutes of quiet before re-trim.
    pub quiet_minutes: u64,
    /// WS threshold (MB) above which trim is considered.
    pub threshold_mb: u64,
    /// Minimum minutes between trims.
    pub cooldown_minutes: u64,
}

impl Default for ResidencyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            quiet_minutes: 5,
            threshold_mb: 350,
            cooldown_minutes: 10,
        }
    }
}

/// Activity tracker — records when subsystems were last active.
pub struct ActivityTracker {
    pub last_realtime_scan: AtomicU64, // unix timestamp
    pub last_manual_scan: AtomicU64,
    pub last_idle_scan: AtomicU64,
    pub last_reload: AtomicU64,
    pub last_update: AtomicU64,
    pub active_scan_count: AtomicU64,
    pub realtime_scan_count: AtomicU64,
}

impl ActivityTracker {
    pub fn new() -> Self {
        let now = now_secs();
        Self {
            last_realtime_scan: AtomicU64::new(now),
            last_manual_scan: AtomicU64::new(0),
            last_idle_scan: AtomicU64::new(0),
            last_reload: AtomicU64::new(now),
            last_update: AtomicU64::new(0),
            active_scan_count: AtomicU64::new(0),
            realtime_scan_count: AtomicU64::new(0),
        }
    }

    pub fn record_realtime_scan(&self) {
        self.last_realtime_scan.store(now_secs(), Ordering::Relaxed);
        self.realtime_scan_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_manual_scan(&self) {
        self.last_manual_scan.store(now_secs(), Ordering::Relaxed);
    }

    pub fn record_idle_scan(&self) {
        self.last_idle_scan.store(now_secs(), Ordering::Relaxed);
    }

    pub fn record_reload(&self) {
        self.last_reload.store(now_secs(), Ordering::Relaxed);
    }

    pub fn record_update(&self) {
        self.last_update.store(now_secs(), Ordering::Relaxed);
    }

    pub fn inc_active_scans(&self) {
        self.active_scan_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_scans(&self) {
        self.active_scan_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Check if the system has been quiet for at least `quiet_secs`.
    pub fn is_quiet(&self, quiet_secs: u64) -> bool {
        let now = now_secs();
        let cutoff = now.saturating_sub(quiet_secs);

        // Any active scans → not quiet.
        if self.active_scan_count.load(Ordering::Relaxed) > 0 {
            return false;
        }

        // Check all activity timestamps.
        let timestamps = [
            self.last_realtime_scan.load(Ordering::Relaxed),
            self.last_manual_scan.load(Ordering::Relaxed),
            self.last_idle_scan.load(Ordering::Relaxed),
            self.last_reload.load(Ordering::Relaxed),
            self.last_update.load(Ordering::Relaxed),
        ];

        timestamps.iter().all(|&ts| ts < cutoff)
    }

    /// Seconds since last activity of any type.
    pub fn quiet_for_secs(&self) -> u64 {
        let now = now_secs();
        let latest = [
            self.last_realtime_scan.load(Ordering::Relaxed),
            self.last_manual_scan.load(Ordering::Relaxed),
            self.last_idle_scan.load(Ordering::Relaxed),
            self.last_reload.load(Ordering::Relaxed),
            self.last_update.load(Ordering::Relaxed),
        ]
        .into_iter()
        .max()
        .unwrap_or(0);

        now.saturating_sub(latest)
    }
}

/// The residency manager — runs as a background check.
pub struct ResidencyManager {
    config: ResidencyConfig,
    last_trim: AtomicU64, // unix timestamp of last trim
    trim_count: AtomicU64,
    last_reduction_mb: AtomicU64,
}

impl ResidencyManager {
    pub fn new(config: ResidencyConfig) -> Self {
        Self {
            config,
            last_trim: AtomicU64::new(0),
            trim_count: AtomicU64::new(0),
            last_reduction_mb: AtomicU64::new(0),
        }
    }

    /// Check if a trim should happen and perform it if conditions are met.
    /// Call this periodically (e.g., every 60 seconds from scheduler).
    pub fn check_and_trim(&self, activity: &ActivityTracker) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check quiet period.
        let quiet_secs = self.config.quiet_minutes * 60;
        if !activity.is_quiet(quiet_secs) {
            return false;
        }

        // Check cooldown.
        let now = now_secs();
        let last = self.last_trim.load(Ordering::Relaxed);
        let cooldown_secs = self.config.cooldown_minutes * 60;
        if last > 0 && now.saturating_sub(last) < cooldown_secs {
            return false;
        }

        // Check WS threshold.
        let ws_mb = get_working_set_mb();
        if ws_mb < self.config.threshold_mb {
            debug!(
                ws_mb,
                threshold = self.config.threshold_mb,
                "residency: below threshold, skip trim"
            );
            return false;
        }

        // Perform trim.
        let ws_before = ws_mb;
        perform_trim();
        let ws_after = get_working_set_mb();
        let reduction = ws_before.saturating_sub(ws_after);

        self.last_trim.store(now, Ordering::Relaxed);
        self.trim_count.fetch_add(1, Ordering::Relaxed);
        self.last_reduction_mb.store(reduction, Ordering::Relaxed);

        info!(
            ws_before_mb = ws_before,
            ws_after_mb = ws_after,
            reduction_mb = reduction,
            quiet_secs = activity.quiet_for_secs(),
            "residency: quiet re-trim applied"
        );

        true
    }

    /// Diagnostics JSON.
    pub fn diagnostics(&self, activity: &ActivityTracker) -> serde_json::Value {
        let quiet_secs = activity.quiet_for_secs();
        let ws_mb = get_working_set_mb();

        serde_json::json!({
            "strategy": if self.config.enabled { "quiet_retrim" } else { "none" },
            "enabled": self.config.enabled,
            "working_set_mb": ws_mb,
            "private_bytes_mb": get_private_bytes_mb(),
            "quiet": activity.is_quiet(self.config.quiet_minutes * 60),
            "quiet_for_secs": quiet_secs,
            "retrim_threshold_mb": self.config.threshold_mb,
            "last_trim_at": self.last_trim.load(Ordering::Relaxed),
            "trim_count": self.trim_count.load(Ordering::Relaxed),
            "last_trim_reduction_mb": self.last_reduction_mb.load(Ordering::Relaxed),
            "active_scan_count": activity.active_scan_count.load(Ordering::Relaxed),
            "realtime_scan_count": activity.realtime_scan_count.load(Ordering::Relaxed),
            "last_realtime_scan_at": activity.last_realtime_scan.load(Ordering::Relaxed),
            "cooldown_minutes": self.config.cooldown_minutes,
            "mode": if activity.active_scan_count.load(Ordering::Relaxed) > 0 {
                "active_scan"
            } else if ws_mb < 100 {
                "trimmed_standby"
            } else if activity.is_quiet(60) {
                "quiet_idle"
            } else {
                "engine_warm"
            },
        })
    }
}

// ── Helper functions ──────────────────────────────────────

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn get_working_set_mb() -> u64 {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
        use windows::Win32::System::Threading::GetCurrentProcess;
        unsafe {
            let mut c: windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS =
                std::mem::zeroed();
            c.cb = std::mem::size_of_val(&c) as u32;
            let _ = GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb);
            c.WorkingSetSize as u64 / (1024 * 1024)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        0
    }
}

fn get_private_bytes_mb() -> u64 {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
        use windows::Win32::System::Threading::GetCurrentProcess;
        unsafe {
            let mut c: windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS =
                std::mem::zeroed();
            c.cb = std::mem::size_of_val(&c) as u32;
            let _ = GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb);
            c.PagefileUsage as u64 / (1024 * 1024)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        0
    }
}

fn perform_trim() {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
        unsafe {
            let _ = SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn active_scan_blocks_quiet() {
        let tracker = ActivityTracker::new();
        // Set all timestamps far in the past.
        tracker.last_realtime_scan.store(0, Ordering::Relaxed);
        tracker.last_manual_scan.store(0, Ordering::Relaxed);
        tracker.last_idle_scan.store(0, Ordering::Relaxed);
        tracker.last_reload.store(0, Ordering::Relaxed);
        tracker.last_update.store(0, Ordering::Relaxed);

        // No active scans → quiet.
        assert!(tracker.is_quiet(1));

        // Active scan → not quiet.
        tracker.inc_active_scans();
        assert!(!tracker.is_quiet(1));

        // Dec back → quiet again.
        tracker.dec_active_scans();
        assert!(tracker.is_quiet(1));
    }

    #[test]
    fn recent_activity_blocks_quiet() {
        let tracker = ActivityTracker::new();
        // Record recent scan.
        tracker.record_realtime_scan();

        // quiet_secs=300 → NOT quiet (just happened).
        assert!(!tracker.is_quiet(300));

        // quiet_secs=0 → always quiet (threshold is now).
        // Actually 0 means cutoff = now, timestamps must be < now which they are.
        // But just-recorded timestamp ≈ now, so ts < now might fail.
        // Skip edge case — the meaningful test is above.
    }

    #[test]
    fn quiet_for_secs_reports_elapsed() {
        let tracker = ActivityTracker::new();
        // Set all timestamps far in the past.
        tracker.last_realtime_scan.store(0, Ordering::Relaxed);
        tracker.last_manual_scan.store(0, Ordering::Relaxed);
        tracker.last_idle_scan.store(0, Ordering::Relaxed);
        tracker.last_reload.store(0, Ordering::Relaxed);
        tracker.last_update.store(0, Ordering::Relaxed);

        let quiet = tracker.quiet_for_secs();
        // All timestamps at epoch → quiet_for_secs ≈ now (huge number).
        assert!(quiet > 1_000_000);
    }

    #[test]
    fn scan_guard_raii_releases() {
        let tracker = Arc::new(ActivityTracker::new());
        assert_eq!(tracker.active_scan_count.load(Ordering::Relaxed), 0);

        {
            let _g1 = ScanGuard::new(&tracker);
            assert_eq!(tracker.active_scan_count.load(Ordering::Relaxed), 1);

            {
                let _g2 = ScanGuard::new(&tracker);
                assert_eq!(tracker.active_scan_count.load(Ordering::Relaxed), 2);
            }
            // g2 dropped.
            assert_eq!(tracker.active_scan_count.load(Ordering::Relaxed), 1);
        }
        // g1 dropped.
        assert_eq!(tracker.active_scan_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn trim_respects_cooldown() {
        let mgr = ResidencyManager::new(ResidencyConfig {
            enabled: true,
            quiet_minutes: 0,      // no quiet requirement
            threshold_mb: 0,       // always above threshold
            cooldown_minutes: 999, // huge cooldown
        });
        let tracker = ActivityTracker::new();
        // Clear all timestamps.
        tracker.last_realtime_scan.store(0, Ordering::Relaxed);
        tracker.last_manual_scan.store(0, Ordering::Relaxed);
        tracker.last_idle_scan.store(0, Ordering::Relaxed);
        tracker.last_reload.store(0, Ordering::Relaxed);
        tracker.last_update.store(0, Ordering::Relaxed);

        // First trim should succeed.
        let first = mgr.check_and_trim(&tracker);
        assert!(first);

        // Second trim immediately → blocked by cooldown.
        let second = mgr.check_and_trim(&tracker);
        assert!(!second);
    }

    #[test]
    fn disabled_config_skips_trim() {
        let mgr = ResidencyManager::new(ResidencyConfig {
            enabled: false,
            quiet_minutes: 0,
            threshold_mb: 0,
            cooldown_minutes: 0,
        });
        let tracker = ActivityTracker::new();
        tracker.last_realtime_scan.store(0, Ordering::Relaxed);
        tracker.last_reload.store(0, Ordering::Relaxed);

        assert!(!mgr.check_and_trim(&tracker));
    }

    #[test]
    fn diagnostics_contains_expected_fields() {
        let mgr = ResidencyManager::new(ResidencyConfig::default());
        let tracker = ActivityTracker::new();
        let diag = mgr.diagnostics(&tracker);

        assert!(diag.get("strategy").is_some());
        assert!(diag.get("enabled").is_some());
        assert!(diag.get("working_set_mb").is_some());
        assert!(diag.get("private_bytes_mb").is_some());
        assert!(diag.get("quiet").is_some());
        assert!(diag.get("quiet_for_secs").is_some());
        assert!(diag.get("mode").is_some());
        assert!(diag.get("trim_count").is_some());
        assert!(diag.get("active_scan_count").is_some());
    }

    #[test]
    fn activity_timestamps_change_mode() {
        let mgr = ResidencyManager::new(ResidencyConfig::default());
        let tracker = ActivityTracker::new();
        // All timestamps at epoch, no active scans → quiet_idle or trimmed_standby.
        tracker.last_realtime_scan.store(0, Ordering::Relaxed);
        tracker.last_reload.store(0, Ordering::Relaxed);

        let diag = mgr.diagnostics(&tracker);
        let mode = diag["mode"].as_str().unwrap();
        // WS on test runner is low → trimmed_standby most likely.
        assert!(
            mode == "trimmed_standby" || mode == "quiet_idle",
            "expected trimmed_standby or quiet_idle, got {mode}"
        );

        // Active scan → mode = active_scan.
        tracker.inc_active_scans();
        let diag2 = mgr.diagnostics(&tracker);
        assert_eq!(diag2["mode"].as_str().unwrap(), "active_scan");
        tracker.dec_active_scans();
    }

    #[test]
    fn record_helpers_update_timestamps() {
        let tracker = ActivityTracker::new();
        tracker.last_realtime_scan.store(0, Ordering::Relaxed);
        tracker.last_manual_scan.store(0, Ordering::Relaxed);
        tracker.last_idle_scan.store(0, Ordering::Relaxed);
        tracker.last_reload.store(0, Ordering::Relaxed);
        tracker.last_update.store(0, Ordering::Relaxed);

        tracker.record_realtime_scan();
        assert!(tracker.last_realtime_scan.load(Ordering::Relaxed) > 0);
        assert_eq!(tracker.realtime_scan_count.load(Ordering::Relaxed), 1);

        tracker.record_manual_scan();
        assert!(tracker.last_manual_scan.load(Ordering::Relaxed) > 0);

        tracker.record_idle_scan();
        assert!(tracker.last_idle_scan.load(Ordering::Relaxed) > 0);

        tracker.record_reload();
        assert!(tracker.last_reload.load(Ordering::Relaxed) > 0);

        tracker.record_update();
        assert!(tracker.last_update.load(Ordering::Relaxed) > 0);
    }
}

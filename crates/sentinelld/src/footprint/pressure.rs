//! Memory pressure policy — classifies daemon memory state and drives
//! adaptive behavior (external worker routing, idle scanner pausing, etc.).
//!
//! No optimization logic here — only classification and policy decisions.

use serde::Serialize;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::config::PerformanceConfig;

/// Memory pressure state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureState {
    /// < 800 MB working set. Normal operation.
    Normal,
    /// 800–1500 MB. Monitor, no action yet.
    Elevated,
    /// 1500–2500 MB. Route heavy work to external workers.
    Warning,
    /// > 2500 MB. Emergency: pause idle scanner, reduce concurrency.
    Critical,
}

impl PressureState {
    fn as_u8(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Elevated => 1,
            Self::Warning => 2,
            Self::Critical => 3,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Normal,
            1 => Self::Elevated,
            2 => Self::Warning,
            _ => Self::Critical,
        }
    }
}

/// Policy actions recommended at each pressure level.
#[derive(Debug, Clone, Serialize)]
pub struct PressurePolicy {
    pub state: PressureState,
    pub working_set_mb: u64,
    /// Whether to prefer external ARGUS worker for manual scans.
    pub prefer_external_argus: bool,
    /// Whether to pause the idle scanner.
    pub pause_idle_scanner: bool,
    /// Whether to reject new full scans.
    pub reject_full_scans: bool,
    /// Max in-process workers (0 = use default).
    pub max_resident_workers: u32,
    /// Human-readable action list for diagnostics.
    pub actions: Vec<String>,
}

impl PressurePolicy {
    /// Evaluate policy from current working set and config.
    pub fn evaluate(working_set_mb: u64, config: &PerformanceConfig) -> Self {
        let state = classify(working_set_mb, config);
        let mut actions = Vec::new();

        let prefer_external = match state {
            PressureState::Warning | PressureState::Critical => {
                if config.external_argus_under_pressure {
                    actions.push("route_argus_to_external_worker".into());
                    true
                } else {
                    false
                }
            }
            _ => false,
        };

        let pause_idle = matches!(state, PressureState::Critical);
        if pause_idle {
            actions.push("pause_idle_scanner".into());
        }

        let reject_full = matches!(state, PressureState::Critical);
        if reject_full {
            actions.push("reject_new_full_scans".into());
        }

        let max_workers = match state {
            PressureState::Warning | PressureState::Critical => {
                let w = config.max_resident_workers_on_pressure;
                if w > 0 {
                    actions.push(format!("reduce_resident_workers_to_{w}"));
                }
                w
            }
            _ => 0, // 0 = use default
        };

        Self {
            state,
            working_set_mb,
            prefer_external_argus: prefer_external,
            pause_idle_scanner: pause_idle,
            reject_full_scans: reject_full,
            max_resident_workers: max_workers,
            actions,
        }
    }
}

/// Classify working set into pressure state.
fn classify(working_set_mb: u64, config: &PerformanceConfig) -> PressureState {
    if working_set_mb > config.memory_critical_mb {
        PressureState::Critical
    } else if working_set_mb > config.memory_warning_mb {
        PressureState::Warning
    } else if working_set_mb > 800 {
        PressureState::Elevated
    } else {
        PressureState::Normal
    }
}

/// The working-set entry threshold (MB) for a given state — the value the
/// working set must exceed to reach it.
fn entry_threshold(state: PressureState, config: &PerformanceConfig) -> u64 {
    match state {
        PressureState::Normal => 0,
        PressureState::Elevated => 800,
        PressureState::Warning => config.memory_warning_mb,
        PressureState::Critical => config.memory_critical_mb,
    }
}

/// Hysteresis margin (MB): a working set hovering at a threshold must drop
/// this far below it before we step down a level, preventing rapid
/// flapping (and the log/behaviour thrash that came with it).
const HYSTERESIS_MARGIN_MB: u64 = 128;

/// Atomic pressure state for lock-free reads from any thread.
pub struct PressureTracker {
    state: AtomicU8,
}

impl PressureTracker {
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(PressureState::Normal.as_u8()),
        }
    }

    /// Update pressure state from latest footprint.
    pub fn update(&self, working_set_mb: u64, config: &PerformanceConfig) -> PressureState {
        let raw = classify(working_set_mb, config);
        let prev = self.current();
        // Hysteresis: only step DOWN a level once the working set has fallen
        // a clear margin below the current level's entry threshold. Stepping
        // UP is immediate (respond to pressure fast). Prevents Warning↔Critical
        // flapping when the working set hovers at a boundary.
        let state = if (raw.as_u8()) < (prev.as_u8()) {
            let entry = entry_threshold(prev, config);
            if working_set_mb + HYSTERESIS_MARGIN_MB > entry {
                prev // not far enough below — hold current level
            } else {
                raw
            }
        } else {
            raw
        };
        self.state.store(state.as_u8(), Ordering::Relaxed);
        if state != prev {
            match state {
                PressureState::Normal => {
                    tracing::info!("memory pressure: normal ({working_set_mb}MB)");
                }
                PressureState::Elevated => {
                    tracing::info!("memory pressure: elevated ({working_set_mb}MB)");
                }
                PressureState::Warning => {
                    tracing::warn!(
                        "memory pressure: WARNING ({working_set_mb}MB) — routing heavy work to external workers"
                    );
                }
                PressureState::Critical => {
                    tracing::error!(
                        "memory pressure: CRITICAL ({working_set_mb}MB) — pausing idle scanner, reducing concurrency"
                    );
                }
            }
        }
        state
    }

    /// Get current pressure state (lock-free).
    pub fn current(&self) -> PressureState {
        PressureState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// Whether external ARGUS is preferred at current pressure.
    pub fn prefer_external_argus(&self) -> bool {
        matches!(
            self.current(),
            PressureState::Warning | PressureState::Critical
        )
    }

    /// Whether idle scanner should be paused at current pressure.
    pub fn should_pause_idle(&self) -> bool {
        matches!(self.current(), PressureState::Critical)
    }
}

/// Derive memory-pressure thresholds (warning_mb, critical_mb) from total
/// physical RAM and the configured `memory_profile`.
///
/// Why: the static defaults (1500/2500 MB) are an absolute footprint that does
/// NOT mean the same thing across hardware. On a 4 GB Core 2 Quad, 2500 MB
/// "critical" is 62% of RAM — it fires only after the box is already swapping
/// (libclamav mpool ~970 MB + scan buffers). On a 32 GB box it's trivially low
/// and pauses the idle scanner needlessly. Scaling by total RAM gives the same
/// *behavioral* trust across an i7-7200U, a Core 2 Quad, Skylake, Ryzen, and an
/// i5-1265U: "back off at roughly the same fraction of this machine's memory."
pub fn ram_relative_thresholds(total_ram_mb: u64, profile: &str) -> (u64, u64) {
    let (warn_pct, crit_pct) = match profile {
        "low" => (0.12, 0.22),        // conserve aggressively on constrained boxes
        "aggressive" => (0.30, 0.50), // allow more footprint for speed
        _ => (0.20, 0.35),            // "normal"
    };
    // Floors keep tiny-RAM boxes from absurdly low caps; ceilings stop a huge-RAM
    // box from letting the AV balloon (its real footprint is < 1 GB anyway).
    let warning = ((total_ram_mb as f64 * warn_pct) as u64).clamp(512, 3072);
    let mut critical = ((total_ram_mb as f64 * crit_pct) as u64).clamp(1024, 4096);
    if critical <= warning {
        critical = warning + 256;
    }
    (warning, critical)
}

/// Total physical RAM in MiB, or `None` if it can't be determined (caller keeps
/// the static absolute defaults). Fail-safe: never panics.
#[cfg(target_os = "windows")]
pub fn detect_total_ram_mb() -> Option<u64> {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    unsafe { GlobalMemoryStatusEx(&mut status).ok()? };
    Some(status.ullTotalPhys / (1024 * 1024))
}

#[cfg(not(target_os = "windows"))]
pub fn detect_total_ram_mb() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_perf() -> PerformanceConfig {
        PerformanceConfig::default()
    }

    #[test]
    fn ram_relative_scales_across_hardware() {
        // 4 GB Core 2 Quad (normal): critical must be FAR below the old 2500 MB
        // absolute so it fires before the box swaps.
        let (w4, c4) = ram_relative_thresholds(4096, "normal");
        assert!(c4 < 1500, "4GB critical {c4} should be well under the old 2500");
        assert!(w4 < c4);

        // 8 GB i7-7200U (normal).
        let (_w8, c8) = ram_relative_thresholds(8192, "normal");
        assert!(c8 > c4, "more RAM → higher critical");

        // 32 GB i5-1265U (normal): capped, not absurd.
        let (w32, c32) = ram_relative_thresholds(32768, "normal");
        assert!(c32 <= 4096 && w32 <= 3072, "huge RAM is ceiling-capped");
        assert!(w32 < c32);

        // 2 GB ancient box: floors apply, still ordered.
        let (w2, c2) = ram_relative_thresholds(2048, "normal");
        assert!(w2 >= 512 && c2 >= 1024 && w2 < c2);

        // Profile ordering: low < normal < aggressive critical for same RAM.
        // Use 8 GB so the values sit below the high-RAM ceiling that would
        // otherwise flatten normal/aggressive to the same cap.
        let lo = ram_relative_thresholds(8192, "low").1;
        let no = ram_relative_thresholds(8192, "normal").1;
        let ag = ram_relative_thresholds(8192, "aggressive").1;
        assert!(lo < no && no <= ag);
    }

    #[test]
    fn classify_normal() {
        assert_eq!(classify(300, &default_perf()), PressureState::Normal);
        assert_eq!(classify(799, &default_perf()), PressureState::Normal);
    }

    #[test]
    fn classify_elevated() {
        assert_eq!(classify(800, &default_perf()), PressureState::Normal); // boundary: <= 800 is normal
        assert_eq!(classify(801, &default_perf()), PressureState::Elevated);
        assert_eq!(classify(1200, &default_perf()), PressureState::Elevated);
    }

    #[test]
    fn classify_warning() {
        assert_eq!(classify(1501, &default_perf()), PressureState::Warning);
        assert_eq!(classify(2000, &default_perf()), PressureState::Warning);
    }

    #[test]
    fn classify_critical() {
        assert_eq!(classify(2501, &default_perf()), PressureState::Critical);
        assert_eq!(classify(4000, &default_perf()), PressureState::Critical);
    }

    #[test]
    fn policy_normal_no_actions() {
        let policy = PressurePolicy::evaluate(400, &default_perf());
        assert_eq!(policy.state, PressureState::Normal);
        assert!(!policy.prefer_external_argus);
        assert!(!policy.pause_idle_scanner);
        assert!(!policy.reject_full_scans);
        assert!(policy.actions.is_empty());
    }

    #[test]
    fn policy_warning_routes_external() {
        let policy = PressurePolicy::evaluate(1800, &default_perf());
        assert_eq!(policy.state, PressureState::Warning);
        assert!(policy.prefer_external_argus);
        assert!(!policy.pause_idle_scanner);
        assert_eq!(policy.max_resident_workers, 1);
    }

    #[test]
    fn policy_critical_pauses_idle() {
        let policy = PressurePolicy::evaluate(3000, &default_perf());
        assert_eq!(policy.state, PressureState::Critical);
        assert!(policy.prefer_external_argus);
        assert!(policy.pause_idle_scanner);
        assert!(policy.reject_full_scans);
    }

    #[test]
    fn policy_respects_disabled_external() {
        let mut perf = default_perf();
        perf.external_argus_under_pressure = false;
        let policy = PressurePolicy::evaluate(1800, &perf);
        assert!(!policy.prefer_external_argus);
    }

    #[test]
    fn tracker_atomic_updates() {
        let tracker = PressureTracker::new();
        assert_eq!(tracker.current(), PressureState::Normal);

        tracker.update(1800, &default_perf());
        assert_eq!(tracker.current(), PressureState::Warning);
        assert!(tracker.prefer_external_argus());

        tracker.update(400, &default_perf());
        assert_eq!(tracker.current(), PressureState::Normal);
        assert!(!tracker.prefer_external_argus());
    }

    #[test]
    fn custom_thresholds() {
        let perf = PerformanceConfig {
            memory_warning_mb: 500,
            memory_critical_mb: 1000,
            ..default_perf()
        };
        assert_eq!(classify(400, &perf), PressureState::Normal);
        assert_eq!(classify(600, &perf), PressureState::Warning);
        assert_eq!(classify(1100, &perf), PressureState::Critical);
    }
}

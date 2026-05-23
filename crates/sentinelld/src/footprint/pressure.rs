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
        let state = classify(working_set_mb, config);
        let prev = PressureState::from_u8(self.state.swap(state.as_u8(), Ordering::Relaxed));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn default_perf() -> PerformanceConfig {
        PerformanceConfig::default()
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

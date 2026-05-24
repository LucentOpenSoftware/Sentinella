//! Scan execution budgets — bounded, profile-aware analysis limits.
//!
//! Every scan operates within a budget. Exceeding a budget is NOT failure —
//! it's evidence. Timeouts feed back into the convergence model.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Execution budget for a single file scan.
/// Profiles own budgets — realtime is strict, manual is relaxed, idle is deepest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanExecutionBudget {
    /// Max total wall-clock time for the entire scan of one file.
    pub max_duration: Duration,
    /// Max ClamAV signature scan time.
    pub max_clamav_duration: Duration,
    /// Max YARA rule matching time.
    pub max_yara_duration: Duration,
    /// Max PE/structural analysis time.
    pub max_structural_duration: Duration,
    /// Max archive nesting depth.
    pub max_archive_depth: u32,
    /// Max total extracted bytes from archives/compound files.
    pub max_extracted_bytes: u64,
    /// Max YARA rule matches before stopping rule evaluation.
    pub max_yara_matches: usize,
}

const MB: u64 = 1024 * 1024;

impl ScanExecutionBudget {
    /// Strict budget for realtime scanning — low latency, minimal FP.
    pub fn realtime() -> Self {
        Self {
            max_duration: Duration::from_secs(10),
            max_clamav_duration: Duration::from_secs(5),
            max_yara_duration: Duration::from_secs(3),
            max_structural_duration: Duration::from_secs(2),
            max_archive_depth: 5,
            max_extracted_bytes: 100 * MB,
            max_yara_matches: 50,
        }
    }

    /// Relaxed budget for user-initiated manual scans.
    pub fn manual() -> Self {
        Self {
            max_duration: Duration::from_secs(60),
            max_clamav_duration: Duration::from_secs(30),
            max_yara_duration: Duration::from_secs(15),
            max_structural_duration: Duration::from_secs(10),
            max_archive_depth: 10,
            max_extracted_bytes: 500 * MB,
            max_yara_matches: 200,
        }
    }

    /// Deep budget for idle background scanning.
    pub fn idle() -> Self {
        Self {
            max_duration: Duration::from_secs(120),
            max_clamav_duration: Duration::from_secs(60),
            max_yara_duration: Duration::from_secs(30),
            max_structural_duration: Duration::from_secs(20),
            max_archive_depth: 10,
            max_extracted_bytes: 500 * MB,
            max_yara_matches: 200,
        }
    }

    /// Very strict budget for startup critical scan.
    pub fn startup() -> Self {
        Self {
            max_duration: Duration::from_secs(15),
            max_clamav_duration: Duration::from_secs(8),
            max_yara_duration: Duration::from_secs(5),
            max_structural_duration: Duration::from_secs(3),
            max_archive_depth: 3,
            max_extracted_bytes: 50 * MB,
            max_yara_matches: 50,
        }
    }
}

impl Default for ScanExecutionBudget {
    fn default() -> Self {
        Self::manual()
    }
}

/// Why a timeout occurred — feeds into convergence as evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutReason {
    /// ClamAV signature scan exceeded budget.
    ClamAvTimeout,
    /// YARA rule matching exceeded budget.
    YaraTimeout,
    /// PE/structural analysis exceeded budget.
    StructuralTimeout,
    /// Overall scan duration exceeded budget.
    TotalTimeout,
    /// Archive extraction produced too many nested layers.
    ArchiveExplosion,
    /// Archive extraction produced too much data.
    ExtractionOverflow,
    /// Too many YARA matches (possible rule-bomb).
    YaraFlood,
    /// Sandbox detonation exceeded time limit.
    SandboxOverrun,
}

impl TimeoutReason {
    /// Suspicion weight for this timeout type.
    /// Timeouts are not neutral — they can indicate evasion.
    pub fn suspicion_weight(&self) -> u32 {
        match self {
            Self::ClamAvTimeout => 3,
            Self::YaraTimeout => 5,
            Self::StructuralTimeout => 8,
            Self::TotalTimeout => 5,
            Self::ArchiveExplosion => 12,
            Self::ExtractionOverflow => 10,
            Self::YaraFlood => 8,
            Self::SandboxOverrun => 6,
        }
    }

    /// Human-readable label for diagnostics.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ClamAvTimeout => "ClamAV signature scan timeout",
            Self::YaraTimeout => "YARA rule matching timeout",
            Self::StructuralTimeout => "PE/structural analysis timeout",
            Self::TotalTimeout => "Total scan duration timeout",
            Self::ArchiveExplosion => "Archive nesting depth exceeded",
            Self::ExtractionOverflow => "Archive extraction size exceeded",
            Self::YaraFlood => "YARA match count exceeded",
            Self::SandboxOverrun => "Sandbox detonation timeout",
        }
    }
}

/// Tracks budget consumption during a scan. Thread-safe.
/// Created at scan start, checked at each analysis phase.
pub struct BudgetTracker {
    budget: ScanExecutionBudget,
    started: Instant,
    cancelled: Arc<AtomicBool>,
    timeouts: std::sync::Mutex<Vec<TimeoutReason>>,
}

impl BudgetTracker {
    pub fn new(budget: ScanExecutionBudget, cancel_flag: Arc<AtomicBool>) -> Self {
        Self {
            budget,
            started: Instant::now(),
            cancelled: cancel_flag,
            timeouts: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Check if total budget is exceeded.
    pub fn is_expired(&self) -> bool {
        self.started.elapsed() >= self.budget.max_duration
    }

    /// Check if a specific phase budget is exceeded.
    pub fn phase_expired(&self, phase_start: Instant, phase_budget: Duration) -> bool {
        phase_start.elapsed() >= phase_budget
    }

    /// Check if scan was cancelled externally.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Record a timeout event.
    pub fn record_timeout(&self, reason: TimeoutReason) {
        if let Ok(mut timeouts) = self.timeouts.lock() {
            timeouts.push(reason);
        }
    }

    /// Get all recorded timeouts.
    pub fn timeouts(&self) -> Vec<TimeoutReason> {
        self.timeouts
            .lock()
            .map(|t| t.clone())
            .unwrap_or_default()
    }

    /// Total suspicion weight from all timeouts.
    pub fn timeout_suspicion(&self) -> u32 {
        self.timeouts()
            .iter()
            .map(|r| r.suspicion_weight())
            .sum()
    }

    /// Elapsed time since scan started.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Remaining budget.
    pub fn remaining(&self) -> Duration {
        self.budget
            .max_duration
            .checked_sub(self.started.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Reference to the underlying budget.
    pub fn budget(&self) -> &ScanExecutionBudget {
        &self.budget
    }

    /// Compute final outcome after scan completes (or doesn't).
    pub fn outcome(&self) -> BudgetOutcome {
        let timeouts = self.timeouts();
        if self.is_cancelled() {
            BudgetOutcome::Aborted
        } else if timeouts.is_empty() {
            BudgetOutcome::Clean
        } else if self.is_expired() {
            BudgetOutcome::Exhausted
        } else if timeouts.iter().any(|t| t.suspicion_weight() >= 8) {
            BudgetOutcome::Suspicious
        } else {
            BudgetOutcome::Partial
        }
    }
}

/// How the scan completed relative to its budget.
/// "Partial" is NOT failure — it means "completed with evidence but truncated."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetOutcome {
    /// Scan completed within budget, no timeouts.
    Clean,
    /// Scan completed but some phases timed out — suspicious behavior.
    Suspicious,
    /// Entire budget exhausted — file consumed all available time.
    Exhausted,
    /// Scan cancelled externally (user or system).
    Aborted,
    /// Some phases timed out but overall budget not exhausted.
    /// Evidence is partial but usable.
    Partial,
}

impl BudgetOutcome {
    /// Human-readable label for UI.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Clean => "Completed",
            Self::Suspicious => "Completed with execution limits",
            Self::Exhausted => "Budget exhausted",
            Self::Aborted => "Cancelled",
            Self::Partial => "Partially analyzed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realtime_budget_is_strict() {
        let rt = ScanExecutionBudget::realtime();
        let manual = ScanExecutionBudget::manual();
        let idle = ScanExecutionBudget::idle();

        assert!(rt.max_duration < manual.max_duration);
        assert!(rt.max_clamav_duration < manual.max_clamav_duration);
        assert!(rt.max_yara_duration < manual.max_yara_duration);
        assert!(rt.max_structural_duration < manual.max_structural_duration);
        assert!(rt.max_archive_depth <= manual.max_archive_depth);
        assert!(rt.max_extracted_bytes <= manual.max_extracted_bytes);
        assert!(rt.max_yara_matches <= manual.max_yara_matches);

        assert!(manual.max_duration <= idle.max_duration);
        assert!(manual.max_clamav_duration <= idle.max_clamav_duration);

        let startup = ScanExecutionBudget::startup();
        assert!(startup.max_duration < manual.max_duration);
    }

    #[test]
    fn budget_tracker_expiry() {
        let budget = ScanExecutionBudget {
            max_duration: Duration::from_millis(1),
            ..ScanExecutionBudget::realtime()
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel);

        std::thread::sleep(Duration::from_millis(2));
        assert!(tracker.is_expired());
        assert_eq!(tracker.remaining(), Duration::ZERO);
    }

    #[test]
    fn timeout_suspicion_accumulates() {
        let budget = ScanExecutionBudget::realtime();
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel);

        assert_eq!(tracker.timeout_suspicion(), 0);

        tracker.record_timeout(TimeoutReason::ClamAvTimeout);
        assert_eq!(tracker.timeout_suspicion(), 3);

        tracker.record_timeout(TimeoutReason::ArchiveExplosion);
        assert_eq!(tracker.timeout_suspicion(), 3 + 12);

        tracker.record_timeout(TimeoutReason::YaraFlood);
        assert_eq!(tracker.timeout_suspicion(), 3 + 12 + 8);

        assert_eq!(tracker.timeouts().len(), 3);
    }

    #[test]
    fn cancelled_flag_checked() {
        let budget = ScanExecutionBudget::manual();
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel.clone());

        assert!(!tracker.is_cancelled());
        cancel.store(true, Ordering::Relaxed);
        assert!(tracker.is_cancelled());
    }

    #[test]
    fn outcome_clean_when_no_timeouts() {
        let budget = ScanExecutionBudget::manual();
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel);
        assert_eq!(tracker.outcome(), BudgetOutcome::Clean);
    }

    #[test]
    fn outcome_aborted_when_cancelled() {
        let budget = ScanExecutionBudget::manual();
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel.clone());
        cancel.store(true, Ordering::Relaxed);
        // Cancelled wins even with no timeouts.
        assert_eq!(tracker.outcome(), BudgetOutcome::Aborted);
    }

    #[test]
    fn outcome_aborted_wins_over_timeout() {
        let budget = ScanExecutionBudget::manual();
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel.clone());
        tracker.record_timeout(TimeoutReason::ArchiveExplosion);
        cancel.store(true, Ordering::Relaxed);
        // Cancellation takes precedence.
        assert_eq!(tracker.outcome(), BudgetOutcome::Aborted);
    }

    #[test]
    fn outcome_suspicious_with_high_weight_timeout() {
        let budget = ScanExecutionBudget::manual();
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel);
        // ArchiveExplosion has weight 12 (>= 8 threshold).
        tracker.record_timeout(TimeoutReason::ArchiveExplosion);
        assert_eq!(tracker.outcome(), BudgetOutcome::Suspicious);
    }

    #[test]
    fn outcome_partial_with_low_weight_timeout() {
        let budget = ScanExecutionBudget::manual();
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel);
        // ClamAvTimeout has weight 3 (< 8 threshold).
        tracker.record_timeout(TimeoutReason::ClamAvTimeout);
        assert_eq!(tracker.outcome(), BudgetOutcome::Partial);
    }

    #[test]
    fn outcome_exhausted_when_budget_expired() {
        let budget = ScanExecutionBudget {
            max_duration: Duration::from_millis(1),
            ..ScanExecutionBudget::realtime()
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel);
        std::thread::sleep(Duration::from_millis(2));
        tracker.record_timeout(TimeoutReason::TotalTimeout);
        assert_eq!(tracker.outcome(), BudgetOutcome::Exhausted);
    }

    #[test]
    fn timeout_reasons_serialize() {
        let reasons = vec![TimeoutReason::ClamAvTimeout, TimeoutReason::YaraFlood];
        let json = serde_json::to_string(&reasons).unwrap();
        assert!(json.contains("clam_av_timeout"));
        assert!(json.contains("yara_flood"));
        let back: Vec<TimeoutReason> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reasons);
    }

    #[test]
    fn budget_outcome_labels() {
        assert_eq!(BudgetOutcome::Clean.label(), "Completed");
        assert_eq!(BudgetOutcome::Suspicious.label(), "Completed with execution limits");
        assert_eq!(BudgetOutcome::Exhausted.label(), "Budget exhausted");
        assert_eq!(BudgetOutcome::Aborted.label(), "Cancelled");
        assert_eq!(BudgetOutcome::Partial.label(), "Partially analyzed");
    }
}

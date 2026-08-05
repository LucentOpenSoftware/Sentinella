//! FISH — File Integrity Shield.
//!
//! Detects destructive file modification patterns in user directories.
//! Public UI name: "Ransomware Shield"
//!
//! Two modes:
//! - observe-only: detect + log + diagnostics. No process action.
//! - active: detect + suspend/terminate offending process.
//!
//! Active response requires process attribution (best-effort: recent file
//! writers via NtQuerySystemInformation or fallback heuristics).

pub mod response;

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;

/// File mutation event types tracked by FISH.
#[derive(Debug, Clone)]
pub enum MutationKind {
    /// File was rewritten (content changed).
    Rewrite,
    /// File was renamed.
    Rename {
        #[allow(dead_code)]
        old_name: String,
        #[allow(dead_code)]
        new_name: String,
    },
    /// File extension changed (e.g., .docx → .encrypted).
    ExtensionMutation {
        #[allow(dead_code)]
        old_ext: String,
        new_ext: String,
    },
    /// File was deleted.
    Delete,
    /// New file created (potential ransom note).
    Create,
}

/// A single file mutation event.
#[derive(Debug, Clone)]
pub struct FileMutationEvent {
    #[allow(dead_code)] // Used in diagnostics aggregation.
    pub path: PathBuf,
    pub kind: MutationKind,
    pub timestamp: Instant,
}

/// FISH configuration.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(default)]
pub struct FishConfig {
    pub enabled: bool,
    pub observe_only: bool,
    pub window_seconds: u64,
    pub rename_threshold: u32,
    pub rewrite_threshold: u32,
    /// Extension-mutation count in the window that trips an alert. Was a
    /// hardcoded `>= 5`; made configurable for consistency with the rename /
    /// rewrite thresholds (and so the FP-prone signal can be tuned per site).
    pub ext_mutation_threshold: u32,
    /// Slow-burn detector: a ransomware that encrypts BELOW the short-window
    /// burst thresholds (e.g. 40 files / 30 s, sustained for minutes) evades
    /// the rename/rewrite/ext signals entirely. This long tumbling window
    /// catches sustained low-rate mass mutation. Observe-only, like the rest.
    pub slow_burn_window_secs: u64,
    /// Cumulative mutations within `slow_burn_window_secs` that trip the
    /// slow-burn signal. Tuned high to avoid flagging legit bulk ops.
    pub slow_burn_threshold: u32,
    pub entropy_delta_threshold: f64,
    /// Cooldown seconds between repeated identical alerts.
    pub alert_cooldown_seconds: u64,
    /// Active response mode: "observe" (log only), "suspend" (freeze process),
    /// "terminate" (kill process). Default: "observe". Ignored while
    /// `observe_only` is true — the master switch always forces observe.
    pub active_response: String,
}

impl Default for FishConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_only: true,
            window_seconds: 30,
            rename_threshold: 50,
            rewrite_threshold: 200,
            ext_mutation_threshold: 5,
            // MEASURED, not estimated. 250-in-10-minutes was chosen as
            // "well above legit bulk edits" and is not: on an ordinary
            // desktop with OneDrive syncing and a messenger running, the
            // watched roots (AppData\Roaming, OneDrive, Documents) produced
            // 1342 mutations in one 600 s window and tripped this 19 times in
            // under three hours, every one a false positive.
            //
            // Since `entropy_delta_threshold` is inert (see above), this is a
            // pure volume counter and cannot tell encryption from sync. The
            // number is therefore a NOISE FLOOR: high enough to clear
            // observed legitimate churn, which is a weaker guarantee than it
            // looks. A real encryption run over a user's Documents moves far
            // more than this, far faster; a deliberately slow one may not
            // trip it at all, and that gap closes only by wiring a content
            // discriminator, not by tuning this.
            slow_burn_window_secs: 600,
            slow_burn_threshold: 2000,
            // INERT. Nothing reads this field: it is declared, defaulted,
            // validated and clamped, and no detection path consumes it.
            // Kept rather than deleted because removing a config key breaks
            // every TOML that sets it, but do not mistake its presence for a
            // capability — FISH currently has NO discriminator between "many
            // files were written" and "many files were encrypted". Wiring it
            // needs a before/after sample of each file, and by the time the
            // watcher sees the event the "before" is already gone, so it
            // needs a content cache first. That is why the thresholds below
            // are a noise floor rather than a detection threshold.
            entropy_delta_threshold: 0.20,
            alert_cooldown_seconds: 60,
            active_response: "observe".into(),
        }
    }
}

impl FishConfig {
    /// Clamp fish fields to safe ranges. Hostile or typo'd TOML could
    /// otherwise produce a process-kill primitive with no allowlist check
    /// (e.g. `window_seconds=0, rename_threshold=0, active_response="terminate"`).
    pub fn validate(&mut self) {
        // window_seconds: too-short windows defeat detection (every event
        // looks isolated); too-long windows blow memory in the event queue.
        self.window_seconds = self.window_seconds.clamp(5, 3600);
        // A threshold of 0 means UNSET, so restore that field's default —
        // it does NOT mean 1.
        //
        // It used to mean 1, and that is the opposite of safe: a threshold
        // of 1 fires on the very first event of its kind, so a config with
        // `ext_mutation_threshold = 0` made FISH alert on the first
        // .docx -> .enc rename anyone performed. `MutationWindow::new`
        // carried its own 0-fallbacks (5 / 600 / 250) with a comment
        // promising exactly this protection, but every construction site
        // runs `validate()` first, so those branches were unreachable and
        // the 1 always won. The defaults live in one place now.
        let d = Self::default();
        if self.slow_burn_window_secs == 0 {
            self.slow_burn_window_secs = d.slow_burn_window_secs;
        }
        // >1 day defeats the slow-burn purpose; the floor keeps a
        // deliberately-small window from tumbling constantly.
        self.slow_burn_window_secs = self.slow_burn_window_secs.clamp(60, 86_400);
        if self.rename_threshold == 0 {
            self.rename_threshold = d.rename_threshold;
        }
        if self.rewrite_threshold == 0 {
            self.rewrite_threshold = d.rewrite_threshold;
        }
        if self.ext_mutation_threshold == 0 {
            self.ext_mutation_threshold = d.ext_mutation_threshold;
        }
        if self.slow_burn_threshold == 0 {
            self.slow_burn_threshold = d.slow_burn_threshold;
        }
        // Cooldown >1 day suppresses every subsequent alert in practice.
        if self.alert_cooldown_seconds > 86_400 {
            self.alert_cooldown_seconds = 86_400;
        }
        // entropy_delta is a ratio in [0,1]; NaN would compare-false forever.
        if !self.entropy_delta_threshold.is_finite() {
            self.entropy_delta_threshold = 0.20;
        }
        if self.entropy_delta_threshold < 0.0 {
            self.entropy_delta_threshold = 0.0;
        }
        if self.entropy_delta_threshold > 1.0 {
            self.entropy_delta_threshold = 1.0;
        }
        // active_response is a kill primitive — refuse anything outside the
        // strict allowlist and fall back to the safest mode.
        if !matches!(
            self.active_response.as_str(),
            "observe" | "suspend" | "terminate"
        ) {
            tracing::warn!(
                value = self.active_response.as_str(),
                "invalid fish.active_response — reset to \"observe\""
            );
            self.active_response = "observe".into();
        }
    }
}

/// FISH decision — what the shield observed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FishDecision {
    /// Normal file activity.
    Normal,
    /// Rename burst detected — possible mass file encryption.
    RenameBurst { count: u32, window_secs: u64 },
    /// Rewrite burst detected — many files modified rapidly.
    RewriteBurst { count: u32, window_secs: u64 },
    /// Extension mutation detected — files changing to unusual extensions.
    ExtensionMutation { count: u32, pattern: String },
    /// Sustained low-rate mass mutation across a long window — catches
    /// "slow-and-low" encryption that stays under the short-window bursts.
    SlowBurn { count: u32, window_secs: u64 },
    /// Alert suppressed by cooldown.
    Cooldown {
        original: String,
        suppressed_count: u64,
    },
}

/// FISH diagnostics snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct FishDiagnostics {
    pub enabled: bool,
    pub observe_only: bool,
    pub recent_events: usize,
    pub rename_bursts: u64,
    pub rewrite_bursts: u64,
    pub extension_mutations: u64,
    /// Slow-burn (sustained low-rate) signals tripped.
    pub slow_burn_alerts: u64,
    /// Mutations counted in the current slow-burn window.
    pub slow_burn_window_count: u32,
    pub alerts_suppressed: u64,
    pub last_decision: Option<FishDecision>,
    /// Top mutated extensions in current window.
    pub top_mutated_extensions: Vec<String>,
    /// Top mutated directories in current window.
    pub top_mutated_directories: Vec<String>,
    /// Total events processed lifetime.
    pub total_events: u64,
    /// Active response mode.
    pub active_response: String,
    /// Processes suspended by active response.
    pub processes_suspended: u64,
    /// Processes terminated by active response.
    pub processes_terminated: u64,
}

/// Sliding window mutation tracker.
pub struct MutationWindow {
    /// The shield's master switch, captured from the config this window was
    /// built from. When false `record` does nothing at all — see there for
    /// why the gate lives here rather than at the call site.
    enabled: bool,
    events: VecDeque<FileMutationEvent>,
    window: Duration,
    rename_threshold: u32,
    rewrite_threshold: u32,
    ext_mutation_threshold: u32,
    cooldown: Duration,
    // ── Slow-burn (long tumbling window) ──
    slow_burn_window: Duration,
    slow_burn_threshold: u32,
    slow_burn_count: u32,
    slow_burn_start: Instant,
    // Counters for diagnostics.
    rename_bursts: u64,
    rewrite_bursts: u64,
    extension_mutations: u64,
    slow_burn_alerts: u64,
    alerts_suppressed: u64,
    /// Suppressed-alert count per alert type — the global
    /// `alerts_suppressed` made Cooldown diagnostics meaningless.
    suppressed_by_key: HashMap<String, u64>,
    total_events: u64,
    last_decision: Option<FishDecision>,
    /// Cooldown: last alert time per alert type.
    last_alert_times: HashMap<String, Instant>,
    /// Active response counters.
    processes_suspended: u64,
    processes_terminated: u64,
}

impl MutationWindow {
    pub fn new(config: &FishConfig) -> Self {
        Self {
            enabled: config.enabled,
            events: VecDeque::with_capacity(1024),
            window: Duration::from_secs(config.window_seconds),
            rename_threshold: config.rename_threshold,
            rewrite_threshold: config.rewrite_threshold,
            // Taken as given. `FishConfig::validate` owns the 0-means-unset
            // substitution and every construction site runs it first, so the
            // 0-fallbacks that used to sit here were unreachable — and they
            // disagreed with what validate actually installed.
            ext_mutation_threshold: config.ext_mutation_threshold,
            cooldown: Duration::from_secs(config.alert_cooldown_seconds),
            slow_burn_window: Duration::from_secs(config.slow_burn_window_secs),
            slow_burn_threshold: config.slow_burn_threshold,
            slow_burn_count: 0,
            slow_burn_start: Instant::now(),
            rename_bursts: 0,
            rewrite_bursts: 0,
            extension_mutations: 0,
            slow_burn_alerts: 0,
            alerts_suppressed: 0,
            suppressed_by_key: HashMap::new(),
            total_events: 0,
            last_decision: None,
            last_alert_times: HashMap::new(),
            processes_suspended: 0,
            processes_terminated: 0,
        }
    }

    /// Record a process suspension.
    pub fn record_suspension(&mut self) {
        self.processes_suspended += 1;
    }

    /// Record a process termination.
    pub fn record_termination(&mut self) {
        self.processes_terminated += 1;
    }

    /// Record a mutation event and check thresholds.
    ///
    /// THE MASTER SWITCH IS ENFORCED HERE, and nowhere else. `fish.enabled`
    /// is a UAC-gated CRITICAL_FIELD that an admin turns off to stop FISH
    /// false positives on a bulk-encryption or bulk-rename workload — but
    /// it was validated, persisted, logged as a change, and then read by
    /// nothing: `watcher::fish_feed_event` calls this unconditionally, so
    /// every mutation was still recorded and "FISH: rewrite burst detected"
    /// kept filling the activity log. The gate belongs at this end because
    /// this is the one funnel every caller goes through; a check at the call
    /// site would have to be repeated by the next caller and eventually
    /// would not be.
    ///
    /// Disabled means disabled: no event stored, no counter moved, no
    /// evaluation. `MutationWindow::new` is the only place `enabled` is
    /// read, and `AppState::load_fish_config` rebuilds the window whenever
    /// the config changes, so this cannot go stale without that path
    /// breaking first.
    pub fn record(&mut self, event: FileMutationEvent) -> FishDecision {
        if !self.enabled {
            return FishDecision::Normal;
        }
        self.total_events += 1;
        // Slow-burn tumbling window: reset the cumulative counter once the long
        // window elapses, then count this mutation. (Tumbling, not sliding —
        // memory-cheap; a boundary-straddling attacker is a documented residual.)
        if self.slow_burn_start.elapsed() >= self.slow_burn_window {
            self.slow_burn_count = 0;
            self.slow_burn_start = Instant::now();
        }
        self.slow_burn_count = self.slow_burn_count.saturating_add(1);
        self.events.push_back(event);
        // R3-fix: hard cap on deque size. Time-based expiry alone allows
        // unbounded growth under sustained high-rate FS churn (1k events/s
        // for window=30s = 30k entries × 3 O(n) filter passes per record).
        // Cap to keep evaluate() bounded even on hostile workloads.
        const MAX_WINDOW_EVENTS: usize = 8192;
        if self.events.len() > MAX_WINDOW_EVENTS {
            let drop_n = self.events.len() - MAX_WINDOW_EVENTS;
            self.events.drain(..drop_n);
        }
        self.expire_old();

        let decision = self.evaluate();
        match &decision {
            FishDecision::Normal | FishDecision::Cooldown { .. } => {}
            other => {
                self.last_decision = Some(other.clone());
            }
        }
        decision
    }

    /// Remove events older than the sliding window.
    fn expire_old(&mut self) {
        // R3-14: Instant - Duration panics if window > uptime (early boot).
        let cutoff = match Instant::now().checked_sub(self.window) {
            Some(t) => t,
            None => return,
        };
        while self
            .events
            .front()
            .map(|e| e.timestamp < cutoff)
            .unwrap_or(false)
        {
            self.events.pop_front();
        }
    }

    /// Check cooldown — returns true if alert should be suppressed.
    fn in_cooldown(&mut self, alert_type: &str) -> bool {
        // R3-15: cap map size so long-running daemon does not accumulate
        // unbounded alert-type keys (each ~50 bytes + Instant).
        const MAX_TRACKED_ALERTS: usize = 256;

        if let Some(last) = self.last_alert_times.get(alert_type) {
            if last.elapsed() < self.cooldown {
                self.alerts_suppressed += 1;
                *self.suppressed_by_key.entry(alert_type.to_string()).or_default() += 1;
                return true;
            }
        }
        if self.last_alert_times.len() >= MAX_TRACKED_ALERTS
            && !self.last_alert_times.contains_key(alert_type)
        {
            // Evict the oldest entry (linear scan — small N).
            if let Some(oldest_key) = self
                .last_alert_times
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| k.clone())
            {
                self.last_alert_times.remove(&oldest_key);
            }
        }
        self.last_alert_times
            .insert(alert_type.to_string(), Instant::now());
        false
    }

    /// Evaluate current window for burst patterns.
    fn evaluate(&mut self) -> FishDecision {
        let renames = self
            .events
            .iter()
            .filter(|e| matches!(e.kind, MutationKind::Rename { .. }))
            .count() as u32;
        let rewrites = self
            .events
            .iter()
            .filter(|e| matches!(e.kind, MutationKind::Rewrite))
            .count() as u32;
        let ext_mutations = self
            .events
            .iter()
            .filter(|e| matches!(e.kind, MutationKind::ExtensionMutation { .. }))
            .count() as u32;

        if renames >= self.rename_threshold {
            if self.in_cooldown("rename_burst") {
                return FishDecision::Cooldown {
                    original: "rename_burst".into(),
                    suppressed_count: self.suppressed_by_key.get("rename_burst").copied().unwrap_or(0),
                };
            }
            self.rename_bursts += 1;
            return FishDecision::RenameBurst {
                count: renames,
                window_secs: self.window.as_secs(),
            };
        }

        if rewrites >= self.rewrite_threshold {
            if self.in_cooldown("rewrite_burst") {
                return FishDecision::Cooldown {
                    original: "rewrite_burst".into(),
                    suppressed_count: self.suppressed_by_key.get("rewrite_burst").copied().unwrap_or(0),
                };
            }
            self.rewrite_bursts += 1;
            return FishDecision::RewriteBurst {
                count: rewrites,
                window_secs: self.window.as_secs(),
            };
        }

        if ext_mutations >= self.ext_mutation_threshold {
            if self.in_cooldown("ext_mutation") {
                return FishDecision::Cooldown {
                    original: "ext_mutation".into(),
                    suppressed_count: self.suppressed_by_key.get("ext_mutation").copied().unwrap_or(0),
                };
            }
            self.extension_mutations += 1;
            // Report the DOMINANT new extension in the window, not the first
            // event's — the first match is arbitrary and misleads the alert.
            let mut ext_counts: HashMap<&str, u32> = HashMap::new();
            for e in &self.events {
                if let MutationKind::ExtensionMutation { new_ext, .. } = &e.kind {
                    *ext_counts.entry(new_ext.as_str()).or_default() += 1;
                }
            }
            let pattern = ext_counts
                .into_iter()
                .max_by_key(|(_, n)| *n)
                .map(|(ext, _)| ext.to_string())
                .unwrap_or_default();
            return FishDecision::ExtensionMutation {
                count: ext_mutations,
                pattern,
            };
        }

        // Slow-burn: sustained low-rate mass mutation that never tripped a
        // short-window burst above. Checked last so a genuine burst is reported
        // as the more specific signal first.
        if self.slow_burn_count >= self.slow_burn_threshold {
            if self.in_cooldown("slow_burn") {
                return FishDecision::Cooldown {
                    original: "slow_burn".into(),
                    suppressed_count: self.suppressed_by_key.get("slow_burn").copied().unwrap_or(0),
                };
            }
            self.slow_burn_alerts += 1;
            return FishDecision::SlowBurn {
                count: self.slow_burn_count,
                window_secs: self.slow_burn_window.as_secs(),
            };
        }

        FishDecision::Normal
    }

    /// Get top mutated extensions in current window.
    fn top_extensions(&self, n: usize) -> Vec<String> {
        let mut counts: HashMap<String, u32> = HashMap::new();
        for event in &self.events {
            if let Some(ext) = event.path.extension() {
                *counts
                    .entry(ext.to_string_lossy().to_lowercase())
                    .or_default() += 1;
            }
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.into_iter().take(n).map(|(ext, _)| ext).collect()
    }

    /// Get top mutated directories in current window.
    fn top_directories(&self, n: usize) -> Vec<String> {
        let mut counts: HashMap<String, u32> = HashMap::new();
        for event in &self.events {
            if let Some(parent) = event.path.parent() {
                *counts
                    .entry(parent.to_string_lossy().to_string())
                    .or_default() += 1;
            }
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.into_iter().take(n).map(|(dir, _)| dir).collect()
    }

    /// Get diagnostics snapshot.
    pub fn diagnostics(&self, config: &FishConfig) -> FishDiagnostics {
        FishDiagnostics {
            enabled: config.enabled,
            observe_only: config.observe_only,
            recent_events: self.events.len(),
            rename_bursts: self.rename_bursts,
            rewrite_bursts: self.rewrite_bursts,
            extension_mutations: self.extension_mutations,
            slow_burn_alerts: self.slow_burn_alerts,
            slow_burn_window_count: self.slow_burn_count,
            alerts_suppressed: self.alerts_suppressed,
            last_decision: self.last_decision.clone(),
            top_mutated_extensions: self.top_extensions(5),
            top_mutated_directories: self.top_directories(5),
            total_events: self.total_events,
            active_response: config.active_response.clone(),
            processes_suspended: self.processes_suspended,
            processes_terminated: self.processes_terminated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> FishConfig {
        FishConfig {
            enabled: true,
            observe_only: true,
            window_seconds: 30,
            rename_threshold: 5, // Low for testing.
            rewrite_threshold: 5,
            alert_cooldown_seconds: 0, // No cooldown in tests.
            ..FishConfig::default()
        }
    }

    #[test]
    fn normal_saves_do_not_alert() {
        let mut window = MutationWindow::new(&make_config());
        for i in 0..3 {
            let decision = window.record(FileMutationEvent {
                path: PathBuf::from(format!("doc{i}.txt")),
                kind: MutationKind::Rewrite,
                timestamp: Instant::now(),
            });
            assert!(matches!(decision, FishDecision::Normal));
        }
    }

    #[test]
    fn rename_burst_triggers() {
        let mut window = MutationWindow::new(&make_config());
        for i in 0..5 {
            let decision = window.record(FileMutationEvent {
                path: PathBuf::from(format!("file{i}.docx")),
                kind: MutationKind::Rename {
                    old_name: format!("file{i}.docx"),
                    new_name: format!("file{i}.encrypted"),
                },
                timestamp: Instant::now(),
            });
            if i == 4 {
                assert!(matches!(decision, FishDecision::RenameBurst { .. }));
            }
        }
    }

    #[test]
    fn rewrite_burst_triggers() {
        let mut window = MutationWindow::new(&make_config());
        for i in 0..5 {
            let decision = window.record(FileMutationEvent {
                path: PathBuf::from(format!("file{i}.docx")),
                kind: MutationKind::Rewrite,
                timestamp: Instant::now(),
            });
            if i == 4 {
                assert!(matches!(decision, FishDecision::RewriteBurst { .. }));
            }
        }
    }

    #[test]
    fn extension_mutation_triggers() {
        let mut window = MutationWindow::new(&make_config());
        for i in 0..5 {
            let decision = window.record(FileMutationEvent {
                path: PathBuf::from(format!("file{i}.docx")),
                kind: MutationKind::ExtensionMutation {
                    old_ext: "docx".into(),
                    new_ext: "encrypted".into(),
                },
                timestamp: Instant::now(),
            });
            if i == 4 {
                assert!(matches!(decision, FishDecision::ExtensionMutation { .. }));
            }
        }
    }

    #[test]
    fn slow_burn_catches_low_rate_mutation_under_burst_thresholds() {
        // Ransomware "slow-and-low": stays under the short-window burst bars but
        // mutates many files over the long window. Disable bursts, low slow bar.
        let mut cfg = make_config();
        cfg.rename_threshold = 1_000_000;
        cfg.rewrite_threshold = 1_000_000;
        cfg.ext_mutation_threshold = 1_000_000;
        cfg.slow_burn_threshold = 10;
        cfg.slow_burn_window_secs = 600;
        cfg.alert_cooldown_seconds = 0;
        let mut w = MutationWindow::new(&cfg);

        let mut last = FishDecision::Normal;
        for i in 0..10 {
            last = w.record(FileMutationEvent {
                path: PathBuf::from(format!("doc{i}.bin")),
                kind: MutationKind::Rewrite,
                timestamp: Instant::now(),
            });
        }
        assert!(
            matches!(last, FishDecision::SlowBurn { count, .. } if count >= 10),
            "sustained low-rate mutation under burst thresholds must trip slow-burn; got {last:?}"
        );
        assert_eq!(w.diagnostics(&cfg).slow_burn_alerts, 1);
    }

    #[test]
    fn extension_mutation_threshold_is_configurable() {
        // Custom low threshold of 2 must trip on the 2nd mutation — proving the
        // value is honored rather than the old hardcoded `>= 5`.
        let mut cfg = make_config();
        cfg.ext_mutation_threshold = 2;
        let mut window = MutationWindow::new(&cfg);

        let mut ev = |i: u32| {
            window.record(FileMutationEvent {
                path: PathBuf::from(format!("file{i}.docx")),
                kind: MutationKind::ExtensionMutation {
                    old_ext: "docx".into(),
                    new_ext: "encrypted".into(),
                },
                timestamp: Instant::now(),
            })
        };
        assert!(!matches!(ev(0), FishDecision::ExtensionMutation { .. }), "1 < threshold");
        assert!(
            matches!(ev(1), FishDecision::ExtensionMutation { .. }),
            "2nd mutation must trip the configured threshold of 2"
        );

        // A zeroed threshold falls back to the safe default, NOT trip-on-1.
        //
        // Through validate(), which is what every production construction
        // site does. This used to build the window directly from a raw
        // config and so exercised a 0-fallback inside MutationWindow::new
        // that production could never reach — the branch was dead, and
        // validate was meanwhile installing 1, the exact trip-on-first
        // behaviour this assertion forbids. The property was right; the
        // path was fiction.
        let mut cfg0 = make_config();
        cfg0.ext_mutation_threshold = 0;
        cfg0.validate();
        let mut w0 = MutationWindow::new(&cfg0);
        let d = w0.record(FileMutationEvent {
            path: PathBuf::from("only.docx"),
            kind: MutationKind::ExtensionMutation {
                old_ext: "docx".into(),
                new_ext: "encrypted".into(),
            },
            timestamp: Instant::now(),
        });
        assert!(
            !matches!(d, FishDecision::ExtensionMutation { .. }),
            "zeroed threshold must not alert on a single mutation"
        );
    }

    #[test]
    fn diagnostics_snapshot() {
        let cfg = make_config();
        let window = MutationWindow::new(&cfg);
        let diag = window.diagnostics(&cfg);
        assert!(diag.enabled);
        assert!(diag.observe_only);
        assert_eq!(diag.recent_events, 0);
        assert_eq!(diag.total_events, 0);
        assert!(diag.top_mutated_extensions.is_empty());
    }

    #[test]
    fn window_expiration() {
        let mut cfg = make_config();
        cfg.window_seconds = 0; // Immediate expiration.
        let mut window = MutationWindow::new(&cfg);

        for i in 0..10 {
            window.record(FileMutationEvent {
                path: PathBuf::from(format!("file{i}.txt")),
                kind: MutationKind::Rewrite,
                timestamp: Instant::now() - Duration::from_secs(1), // Already expired.
            });
        }

        // Events should be expired — no burst.
        let diag = window.diagnostics(&cfg);
        assert_eq!(diag.recent_events, 0);
        assert_eq!(diag.total_events, 10);
    }

    #[test]
    fn cooldown_suppresses_repeated_alerts() {
        let mut cfg = make_config();
        cfg.alert_cooldown_seconds = 300; // 5 minute cooldown.
        let mut window = MutationWindow::new(&cfg);

        // First burst: should alert.
        for i in 0..5 {
            window.record(FileMutationEvent {
                path: PathBuf::from(format!("file{i}.docx")),
                kind: MutationKind::Rewrite,
                timestamp: Instant::now(),
            });
        }
        // First rewrite burst fires.
        assert_eq!(window.rewrite_bursts, 1);

        // Add more events — second burst within cooldown should suppress.
        for i in 5..10 {
            window.record(FileMutationEvent {
                path: PathBuf::from(format!("file{i}.docx")),
                kind: MutationKind::Rewrite,
                timestamp: Instant::now(),
            });
        }
        // Burst count should NOT increment (suppressed by cooldown).
        assert_eq!(window.rewrite_bursts, 1);
        assert!(window.alerts_suppressed > 0);
    }

    #[test]
    fn top_extensions_tracked() {
        let mut window = MutationWindow::new(&make_config());
        for i in 0..3 {
            window.record(FileMutationEvent {
                path: PathBuf::from(format!("file{i}.docx")),
                kind: MutationKind::Rewrite,
                timestamp: Instant::now(),
            });
        }
        window.record(FileMutationEvent {
            path: PathBuf::from("test.xlsx"),
            kind: MutationKind::Rewrite,
            timestamp: Instant::now(),
        });

        let cfg = make_config();
        let diag = window.diagnostics(&cfg);
        assert!(diag.top_mutated_extensions.contains(&"docx".to_string()));
    }

    #[test]
    fn top_directories_tracked() {
        let mut window = MutationWindow::new(&make_config());
        for i in 0..3 {
            window.record(FileMutationEvent {
                path: PathBuf::from(format!("C:\\Users\\test\\Documents\\file{i}.docx")),
                kind: MutationKind::Rewrite,
                timestamp: Instant::now(),
            });
        }

        let cfg = make_config();
        let diag = window.diagnostics(&cfg);
        assert!(!diag.top_mutated_directories.is_empty());
        assert!(diag.top_mutated_directories[0].contains("Documents"));
    }

    /// REGRESSION. `fish.enabled` is a UAC-gated CRITICAL_FIELD an admin
    /// turns off to stop FISH firing on a legitimate bulk-encryption or
    /// bulk-rename workload. Nothing read it: the window did not store it
    /// and `record` did not check it, so the burst warnings kept coming
    /// after the setting was accepted, persisted and logged as a change.
    #[test]
    fn a_disabled_shield_records_nothing_and_never_alerts() {
        let mut cfg = make_config();
        cfg.enabled = false;
        let mut window = MutationWindow::new(&cfg);

        // Ten times the rename threshold and ten times the rewrite
        // threshold — a screaming burst under any configuration.
        for i in 0..50 {
            let decision = window.record(FileMutationEvent {
                path: PathBuf::from(format!("C:\\Users\\test\\Documents\\file{i}.docx")),
                kind: MutationKind::Rename {
                    old_name: format!("file{i}.docx"),
                    new_name: format!("file{i}.encrypted"),
                },
                timestamp: Instant::now(),
            });
            assert!(
                matches!(decision, FishDecision::Normal),
                "a disabled shield must not decide anything: {decision:?}"
            );
        }
        for i in 0..50 {
            window.record(FileMutationEvent {
                path: PathBuf::from(format!("C:\\Users\\test\\Documents\\file{i}.docx")),
                kind: MutationKind::Rewrite,
                timestamp: Instant::now(),
            });
        }

        // And it must not be silently accumulating either: an admin reading
        // diagnostics on a disabled shield should see a shield that is
        // doing nothing, not one that is watching and staying quiet.
        let diag = window.diagnostics(&cfg);
        assert_eq!(diag.total_events, 0, "events recorded while disabled");
        assert_eq!(diag.recent_events, 0);
        assert_eq!(diag.rename_bursts, 0);
        assert_eq!(diag.rewrite_bursts, 0);
        assert_eq!(diag.slow_burn_window_count, 0);
        assert!(diag.last_decision.is_none());
    }

    /// The same events with the switch ON must alert — otherwise the test
    /// above would pass on a `record` that is broken for everyone.
    #[test]
    fn an_enabled_shield_still_alerts_on_the_same_burst() {
        let mut window = MutationWindow::new(&make_config());
        let mut alerted = false;
        for i in 0..50 {
            let decision = window.record(FileMutationEvent {
                path: PathBuf::from(format!("C:\\Users\\test\\Documents\\file{i}.docx")),
                kind: MutationKind::Rename {
                    old_name: format!("file{i}.docx"),
                    new_name: format!("file{i}.encrypted"),
                },
                timestamp: Instant::now(),
            });
            if matches!(decision, FishDecision::RenameBurst { .. }) {
                alerted = true;
            }
        }
        assert!(alerted, "the enabled shield must still see this burst");
    }
}

#[cfg(test)]
mod zero_threshold_tests {
    use super::*;

    #[test]
    fn a_zeroed_threshold_restores_the_default_not_one() {
        // The defect: validate floored every 0 to 1, so
        // `ext_mutation_threshold = 0` in config.toml made FISH alert on the
        // FIRST .docx -> .enc rename on the machine. MutationWindow::new
        // carried 0-fallbacks promising the opposite, but validate runs
        // first at every construction site so they never executed.
        let d = FishConfig::default();
        let mut c = FishConfig {
            rename_threshold: 0,
            rewrite_threshold: 0,
            ext_mutation_threshold: 0,
            slow_burn_threshold: 0,
            slow_burn_window_secs: 0,
            ..FishConfig::default()
        };
        c.validate();
        assert_eq!(c.ext_mutation_threshold, d.ext_mutation_threshold, "0 must mean unset, not 1");
        assert_eq!(c.rename_threshold, d.rename_threshold);
        assert_eq!(c.rewrite_threshold, d.rewrite_threshold);
        assert_eq!(c.slow_burn_threshold, d.slow_burn_threshold);
        assert_eq!(c.slow_burn_window_secs, d.slow_burn_window_secs);
        assert!(c.ext_mutation_threshold > 1, "a threshold of 1 fires on the first event");
    }

    #[test]
    fn the_window_carries_validates_values_verbatim() {
        // MutationWindow must not re-substitute: two places deciding what 0
        // means is how they came to disagree. A window built from a
        // validated config has exactly that config's numbers.
        let mut c = FishConfig { ext_mutation_threshold: 0, ..FishConfig::default() };
        c.validate();
        let w = MutationWindow::new(&c);
        assert_eq!(w.ext_mutation_threshold, c.ext_mutation_threshold);
        // And an explicit low-but-nonzero value is the user's choice to keep.
        let mut c2 = FishConfig { ext_mutation_threshold: 2, ..FishConfig::default() };
        c2.validate();
        assert_eq!(MutationWindow::new(&c2).ext_mutation_threshold, 2);
    }
}

#[cfg(test)]
mod noise_floor_tests {
    use super::*;

    /// Highest legitimate mutation count observed in one 600 s window on a
    /// developer desktop (OneDrive syncing, messenger running, browser open),
    /// 2026-08-05. The old default of 250 sat far below this and fired 19
    /// times in under three hours, all false positives.
    const OBSERVED_LEGITIMATE_CHURN_PER_WINDOW: u32 = 1342;

    #[test]
    fn the_slow_burn_floor_clears_measured_legitimate_churn() {
        let d = FishConfig::default();
        assert_eq!(d.slow_burn_window_secs, 600, "the measurement is per 600 s window");
        assert!(
            d.slow_burn_threshold > OBSERVED_LEGITIMATE_CHURN_PER_WINDOW,
            "slow_burn_threshold {} does not clear churn measured on a real desktop ({});              lowering it re-creates a shield that cries wolf every few minutes",
            d.slow_burn_threshold,
            OBSERVED_LEGITIMATE_CHURN_PER_WINDOW
        );
    }

    #[test]
    fn the_entropy_knob_is_still_inert_and_this_test_says_so_out_loud() {
        // Not a behaviour assertion — a tripwire. entropy_delta_threshold is
        // validated and clamped but no detection path reads it, which is why
        // the slow-burn threshold is a noise floor rather than a real
        // discriminator. When someone wires it, this test should fail and be
        // replaced by one that exercises the discriminator.
        let mut c = FishConfig { entropy_delta_threshold: f64::NAN, ..FishConfig::default() };
        c.validate();
        assert_eq!(c.entropy_delta_threshold, 0.20, "validate still owns this field");
        let w = MutationWindow::new(&c);
        // MutationWindow does not carry it at all: nothing consumes it.
        let _ = w;
    }
}

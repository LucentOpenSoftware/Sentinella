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
    pub entropy_delta_threshold: f64,
    /// Cooldown seconds between repeated identical alerts.
    pub alert_cooldown_seconds: u64,
    /// Active response mode: "observe" (log only), "suspend" (freeze process),
    /// "terminate" (kill process). Default: "observe".
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
            entropy_delta_threshold: 0.20,
            alert_cooldown_seconds: 60,
            active_response: "observe".into(),
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
    events: VecDeque<FileMutationEvent>,
    window: Duration,
    rename_threshold: u32,
    rewrite_threshold: u32,
    cooldown: Duration,
    // Counters for diagnostics.
    rename_bursts: u64,
    rewrite_bursts: u64,
    extension_mutations: u64,
    alerts_suppressed: u64,
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
            events: VecDeque::with_capacity(1024),
            window: Duration::from_secs(config.window_seconds),
            rename_threshold: config.rename_threshold,
            rewrite_threshold: config.rewrite_threshold,
            cooldown: Duration::from_secs(config.alert_cooldown_seconds),
            rename_bursts: 0,
            rewrite_bursts: 0,
            extension_mutations: 0,
            alerts_suppressed: 0,
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
    pub fn record(&mut self, event: FileMutationEvent) -> FishDecision {
        self.total_events += 1;
        self.events.push_back(event);
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
        let cutoff = Instant::now() - self.window;
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
        if let Some(last) = self.last_alert_times.get(alert_type) {
            if last.elapsed() < self.cooldown {
                self.alerts_suppressed += 1;
                return true;
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
                    suppressed_count: self.alerts_suppressed,
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
                    suppressed_count: self.alerts_suppressed,
                };
            }
            self.rewrite_bursts += 1;
            return FishDecision::RewriteBurst {
                count: rewrites,
                window_secs: self.window.as_secs(),
            };
        }

        if ext_mutations >= 5 {
            if self.in_cooldown("ext_mutation") {
                return FishDecision::Cooldown {
                    original: "ext_mutation".into(),
                    suppressed_count: self.alerts_suppressed,
                };
            }
            self.extension_mutations += 1;
            let pattern = self
                .events
                .iter()
                .filter_map(|e| match &e.kind {
                    MutationKind::ExtensionMutation { new_ext, .. } => Some(new_ext.clone()),
                    _ => None,
                })
                .next()
                .unwrap_or_default();
            return FishDecision::ExtensionMutation {
                count: ext_mutations,
                pattern,
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
}

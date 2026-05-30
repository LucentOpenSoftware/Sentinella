//! ARGUS Threat Profiles — per-module scan behavior configuration.
//!
//! Each scan context (realtime, manual, idle, startup) owns a profile
//! that controls: execution budget, YARA aggressiveness, archive handling,
//! convergence thresholds, and heuristic sensitivity.
//!
//! Profiles are the boundary between "scanner" and "intelligence engine."
//! The same file may get different analysis depth depending on context.

use serde::{Deserialize, Serialize};

use crate::budget::ScanExecutionBudget;
use crate::verdict::ScanStrategy;

/// Named scan profile — determines analysis behavior per context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    /// Realtime watcher: fast, low-FP, never stalls the user.
    Realtime,
    /// User-initiated scan: deep, thorough, user expects to wait.
    Manual,
    /// Idle background scan: opportunistic, deepest analysis, lowest priority.
    Idle,
    /// Post-boot critical areas: fast, persistence-focused.
    Startup,
    /// Archive/compound file: focused on nested content extraction.
    Archive,
    /// Document scan: office, PDF, HTML — macro/exploit focused.
    Document,
}

impl ProfileKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Realtime => "Realtime",
            Self::Manual => "Manual",
            Self::Idle => "Idle",
            Self::Startup => "Startup",
            Self::Archive => "Archive",
            Self::Document => "Document",
        }
    }
}

/// Full scan profile — owns budget + analysis behavior controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    /// Which named profile this is.
    pub kind: ProfileKind,

    /// Execution budget for this profile.
    pub budget: ScanExecutionBudget,

    // ── YARA behavior ────────────────────────────────────
    /// Enable YARA rule matching.
    pub yara_enabled: bool,
    /// Max YARA matches before stopping (prevents rule floods).
    pub yara_max_matches: usize,

    // ── Heuristic sensitivity ────────────────────────────
    /// Enable PE structural heuristics.
    pub pe_heuristics_enabled: bool,
    /// Enable reputation layer.
    pub reputation_enabled: bool,
    /// Enable context layer (path/name analysis).
    pub context_enabled: bool,
    /// Enable IOC hash matching.
    pub ioc_enabled: bool,
    /// Enable packer/protector detection.
    pub packer_detection_enabled: bool,

    // ── Convergence tuning ───────────────────────────────
    /// Minimum score to trigger convergence chain analysis.
    /// Lower = more sensitive, higher = fewer false positives.
    pub convergence_threshold: u32,
    /// Score at which auto-quarantine triggers.
    pub quarantine_threshold: u32,

    // ── Archive behavior ─────────────────────────────────
    /// Max archive nesting depth for this profile.
    pub max_archive_depth: u32,
    /// Max extracted bytes from compound files.
    pub max_extracted_bytes: u64,

    // ── Strategy overrides ───────────────────────────────
    /// If true, transient/temp artifacts get SignatureOnly instead of FullAnalysis.
    pub downgrade_transient: bool,
    /// Minimum file size (bytes) for full PE heuristic analysis.
    /// Smaller files skip heavy PE parsing.
    pub pe_min_size_bytes: u64,
}

impl ScanProfile {
    /// Realtime profile: fast, low-FP, never stalls.
    pub fn realtime() -> Self {
        Self {
            kind: ProfileKind::Realtime,
            budget: ScanExecutionBudget::realtime(),
            yara_enabled: true,
            yara_max_matches: 50,
            pe_heuristics_enabled: true,
            reputation_enabled: true,
            context_enabled: true,
            ioc_enabled: true,
            packer_detection_enabled: true,
            convergence_threshold: 30,
            quarantine_threshold: 76,
            max_archive_depth: 5,
            max_extracted_bytes: 100 * 1024 * 1024,
            downgrade_transient: true,
            pe_min_size_bytes: 1024,
        }
    }

    /// Manual profile: deep, user expects to wait.
    pub fn manual() -> Self {
        Self {
            kind: ProfileKind::Manual,
            budget: ScanExecutionBudget::manual(),
            yara_enabled: true,
            yara_max_matches: 200,
            pe_heuristics_enabled: true,
            reputation_enabled: true,
            context_enabled: true,
            ioc_enabled: true,
            packer_detection_enabled: true,
            convergence_threshold: 20,
            quarantine_threshold: 76,
            max_archive_depth: 10,
            max_extracted_bytes: 500 * 1024 * 1024,
            downgrade_transient: false,
            pe_min_size_bytes: 512,
        }
    }

    /// Idle profile: deepest, opportunistic, all layers active.
    pub fn idle() -> Self {
        Self {
            kind: ProfileKind::Idle,
            budget: ScanExecutionBudget::idle(),
            yara_enabled: true,
            yara_max_matches: 200,
            pe_heuristics_enabled: true,
            reputation_enabled: true,
            context_enabled: true,
            ioc_enabled: true,
            packer_detection_enabled: true,
            convergence_threshold: 15, // Most sensitive.
            quarantine_threshold: 76,
            max_archive_depth: 10,
            max_extracted_bytes: 500 * 1024 * 1024,
            downgrade_transient: false,
            pe_min_size_bytes: 256,
        }
    }

    /// Startup profile: fast, persistence-focused.
    pub fn startup() -> Self {
        Self {
            kind: ProfileKind::Startup,
            budget: ScanExecutionBudget::startup(),
            yara_enabled: true,
            yara_max_matches: 50,
            pe_heuristics_enabled: true,
            reputation_enabled: true,
            context_enabled: true,
            ioc_enabled: true,
            packer_detection_enabled: true,
            convergence_threshold: 25,
            quarantine_threshold: 76,
            max_archive_depth: 3,
            max_extracted_bytes: 50 * 1024 * 1024,
            downgrade_transient: true,
            pe_min_size_bytes: 1024,
        }
    }

    /// Archive profile: focused on nested content.
    pub fn archive() -> Self {
        Self {
            kind: ProfileKind::Archive,
            budget: ScanExecutionBudget::manual(),
            yara_enabled: true,
            yara_max_matches: 100,
            pe_heuristics_enabled: true,
            reputation_enabled: false, // Extracted files have no meaningful path reputation.
            context_enabled: false,
            ioc_enabled: true,
            packer_detection_enabled: true,
            convergence_threshold: 25,
            quarantine_threshold: 76,
            max_archive_depth: 10,
            max_extracted_bytes: 500 * 1024 * 1024,
            downgrade_transient: false,
            pe_min_size_bytes: 512,
        }
    }

    /// Document profile: macro/exploit focused.
    pub fn document() -> Self {
        Self {
            kind: ProfileKind::Document,
            budget: ScanExecutionBudget::manual(),
            yara_enabled: true,
            yara_max_matches: 100,
            pe_heuristics_enabled: false, // Documents aren't PE files.
            reputation_enabled: true,
            context_enabled: true,
            ioc_enabled: true,
            packer_detection_enabled: false,
            convergence_threshold: 20,
            quarantine_threshold: 76,
            max_archive_depth: 5,
            max_extracted_bytes: 100 * 1024 * 1024,
            downgrade_transient: false,
            pe_min_size_bytes: 0,
        }
    }

    /// Determine the effective scan strategy for a file under this profile.
    pub fn effective_strategy(
        &self,
        path: &str,
        file_size: u64,
        is_transient: bool,
    ) -> ScanStrategy {
        // Transient artifacts → downgrade if profile says so.
        if is_transient && self.downgrade_transient {
            return ScanStrategy::SignatureOnly;
        }

        // Large non-executable files (>50MB) are downgraded inside
        // `ScanStrategy::classify` itself — no profile-level override needed.
        ScanStrategy::classify(path, file_size)
    }

    /// Select the right profile for a scan context string.
    pub fn for_context(context: &str) -> Self {
        match context {
            "realtime" | "watcher" => Self::realtime(),
            "quick" | "startup" | "startup-critical" => Self::startup(),
            "folder" | "full" | "manual" | "file" => Self::manual(),
            "idle" | "background" => Self::idle(),
            _ => Self::manual(), // Safe default.
        }
    }
}

impl Default for ScanProfile {
    fn default() -> Self {
        Self::manual()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_kinds_serialize() {
        let json = serde_json::to_string(&ProfileKind::Realtime).unwrap();
        assert_eq!(json, "\"realtime\"");
        let back: ProfileKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ProfileKind::Realtime);
    }

    #[test]
    fn realtime_is_strictest() {
        let rt = ScanProfile::realtime();
        let manual = ScanProfile::manual();
        let idle = ScanProfile::idle();

        assert!(rt.budget.max_duration < manual.budget.max_duration);
        assert!(manual.budget.max_duration < idle.budget.max_duration);
        assert!(rt.convergence_threshold > idle.convergence_threshold);
        assert!(rt.downgrade_transient);
        assert!(!manual.downgrade_transient);
    }

    #[test]
    fn for_context_maps_correctly() {
        assert_eq!(
            ScanProfile::for_context("realtime").kind,
            ProfileKind::Realtime
        );
        assert_eq!(
            ScanProfile::for_context("watcher").kind,
            ProfileKind::Realtime
        );
        assert_eq!(ScanProfile::for_context("quick").kind, ProfileKind::Startup);
        assert_eq!(ScanProfile::for_context("folder").kind, ProfileKind::Manual);
        assert_eq!(ScanProfile::for_context("idle").kind, ProfileKind::Idle);
        assert_eq!(
            ScanProfile::for_context("unknown").kind,
            ProfileKind::Manual
        );
    }

    #[test]
    fn transient_downgrade_in_realtime() {
        let rt = ScanProfile::realtime();
        let strategy = rt.effective_strategy("test.exe", 1024, true);
        assert_eq!(strategy, ScanStrategy::SignatureOnly);
    }

    #[test]
    fn no_downgrade_in_manual() {
        let manual = ScanProfile::manual();
        let strategy = manual.effective_strategy("test.exe", 1024, true);
        // Manual doesn't downgrade transient.
        assert_eq!(strategy, ScanStrategy::FullAnalysis);
    }

    #[test]
    fn large_non_exe_downgraded() {
        let rt = ScanProfile::realtime();
        // 60MB PDF in realtime → SignatureOnly.
        let strategy = rt.effective_strategy("report.pdf", 60 * 1024 * 1024, false);
        assert_eq!(strategy, ScanStrategy::SignatureOnly);
    }

    #[test]
    fn large_exe_not_downgraded() {
        let rt = ScanProfile::realtime();
        // 60MB EXE in realtime → still FullAnalysis (executables always get full treatment).
        let strategy = rt.effective_strategy("setup.exe", 60 * 1024 * 1024, false);
        assert_eq!(strategy, ScanStrategy::FullAnalysis);
    }

    #[test]
    fn document_profile_disables_pe() {
        let doc = ScanProfile::document();
        assert!(!doc.pe_heuristics_enabled);
        assert!(!doc.packer_detection_enabled);
        assert!(doc.yara_enabled);
    }

    #[test]
    fn archive_profile_disables_reputation() {
        let arch = ScanProfile::archive();
        assert!(!arch.reputation_enabled);
        assert!(!arch.context_enabled);
        assert!(arch.ioc_enabled);
    }
}

//! `settings.full_config` — complete daemon configuration exposed to the GUI.
//!
//! v0.1.8 added a "full" mirror of the daemon's `Config` struct so the
//! Settings page can render every TOML knob with proper types, not just
//! the ~12 keys the old [`crate::settings::Settings`] surface exposed.
//!
//! # Design
//!
//! - Mirrors the daemon's `crate::config::Config` field-by-field.
//!   Conversions live on the daemon side (`impl From<&Config> for FullConfig`).
//! - `#[serde(default)]` everywhere — newer daemon versions can add fields
//!   without breaking older GUIs (and vice-versa).
//! - `developer.password_sha256` is **deliberately not mirrored** — the
//!   wire schema cannot carry it at all. Provisioning is out-of-band.
//! - Nested config structs (`FullFishConfig`, `FullSandboxConfig`, etc.)
//!   carry the configuration knobs only — never runtime stats.
//!
//! # Security: critical fields
//!
//! The settings.set_full handler MUST refuse to mutate the fields listed in
//! [`CRITICAL_FIELDS`]. Those are kill-vector fields (exclusions,
//! watched roots, trusted hashes, etc.) and travel via the elevated
//! `protection.set_critical` IPC method, which the GUI gates behind a UAC
//! prompt + challenge token.
//!
//! # Restart requirements
//!
//! Not every field can be applied while the daemon is running. The GUI
//! calls `settings.restart_requirements` to learn which keys flip a
//! "needs restart" pill. Three buckets — see [`RestartRequirement`].

use serde::{Deserialize, Serialize};

// ─── Restart requirements ───────────────────────────────────────────

/// What action is required for a config field change to take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RestartRequirement {
    /// Applies immediately on save (most threshold/timing knobs).
    #[default]
    None,
    /// Requires the daemon to recompile the ClamAV engine.
    /// (exclusions, signature-provider switch, trusted hashes)
    EngineReload,
    /// Requires `sc stop SentinellaDaemon && sc start SentinellaDaemon`.
    /// (log_level, clamav_isolation, powershell bridge, scheduler enable)
    DaemonRestart,
}

/// Static lookup: field path (top-level or `nested.field`) → restart requirement.
///
/// GUI uses this to render the per-field "needs restart" pill and to
/// batch the "Restart now" footer button. The field paths match the
/// FullConfig serde names exactly.
pub fn restart_requirement(field_path: &str) -> RestartRequirement {
    use RestartRequirement::*;
    match field_path {
        // ── EngineReload (mpool rebuild required) ─────
        "excluded_paths"
        | "excluded_extensions"
        | "excluded_detections"
        | "trusted_hashes"
        | "enhanced_signature_provider"
        | "max_file_size_mb"
        | "scan_archives"
        | "heuristic_alerts" => EngineReload,

        // ── DaemonRestart (process-lifecycle state) ───
        "log_level"
        | "clamav_isolation"
        | "powershell_bridge_enabled"
        | "powershell_poll_seconds"
        | "scheduled_scan_enabled"
        | "argus_worker_enabled"
        | "scan.argus_worker_enabled"
        | "fish.enabled"
        | "sandbox.enabled" => DaemonRestart,

        // Everything else is hot-applied.
        _ => None,
    }
}

// ─── Critical fields (kill-vector defense) ──────────────────────────

/// Field paths that `settings.set_full` MUST NOT mutate. Mutation requires
/// the elevated `protection.set_critical` IPC method, which itself
/// requires a challenge token plus (GUI-side) a UAC prompt.
///
/// Adding to this list = strictly more locked down. Removing from this list
/// is a security regression — don't, without a written rationale.
pub const CRITICAL_FIELDS: &[&str] = &[
    // ── Protection state (existing) ─────────────────
    "realtime_enabled",
    "auto_quarantine",
    // ── Worker hijack vectors ───────────────────────
    "argus_worker_enabled",
    "argus_worker_path",
    "scan.argus_worker_enabled",
    "scan.argus_worker_path",
    // ── Detection-suppression kill vectors ──────────
    // (excluded_detections=[""] silences ALL detections; an empty
    //  realtime_roots blinds the watcher; trusted_hashes whitelists
    //  specific malware; etc.)
    "excluded_paths",
    "excluded_extensions",
    "excluded_detections",
    "trusted_hashes",
    "realtime_roots",
    "heuristic_alerts",
    "idle_scan_enabled",
    "scheduled_scan_enabled",
    "enhanced_signature_provider",
];

/// True if the given field path is in [`CRITICAL_FIELDS`].
pub fn is_critical(field_path: &str) -> bool {
    CRITICAL_FIELDS.contains(&field_path)
}

// ─── FullConfig — full daemon config mirror ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FullConfig {
    // ── Real-time protection ─────────────────────────
    pub realtime_enabled: bool,
    pub realtime_roots: Vec<String>,

    // ── Scan limits ──────────────────────────────────
    pub max_file_size_mb: u64,
    pub scan_archives: bool,
    pub heuristic_alerts: bool,

    // ── Updates ──────────────────────────────────────
    pub auto_update: bool,
    pub update_interval_hours: u32,
    pub signature_stale_days: u32,
    pub update_mirror: String,

    // ── Quarantine ───────────────────────────────────
    pub quarantine_retention_days: u32,
    pub auto_quarantine: bool,

    // ── Exclusions ───────────────────────────────────
    pub excluded_paths: Vec<String>,
    pub excluded_extensions: Vec<String>,
    pub excluded_detections: Vec<String>,
    pub trusted_hashes: Vec<String>,

    // ── Enhanced signature provider ──────────────────
    pub enhanced_signature_provider: String,

    // ── Logging ──────────────────────────────────────
    pub log_level: String,

    // ── Scheduler ────────────────────────────────────
    pub scheduled_scan_enabled: bool,
    pub scheduled_scan_hour: u32,
    pub scheduled_scan_type: String,

    // ── Startup ──────────────────────────────────────
    pub startup_critical_scan: bool,

    // ── PowerShell bridge ────────────────────────────
    pub powershell_bridge_enabled: bool,
    pub powershell_poll_seconds: u64,

    // ── Idle scanner ─────────────────────────────────
    pub idle_scan_enabled: bool,
    pub idle_scan_start_delay_secs: u64,
    pub idle_scan_on_battery: bool,
    pub idle_scan_cpu_pause_threshold: u32,
    pub idle_scan_max_file_size_mb: u64,
    pub idle_scan_fullscreen_pause: bool,
    pub idle_scan_disk_latency_pause_ms: u64,
    pub idle_scan_max_files_per_session: u64,
    pub idle_scan_slow_delay_min_ms: u64,
    pub idle_scan_slow_delay_max_ms: u64,
    pub idle_scan_normal_delay_min_ms: u64,
    pub idle_scan_normal_delay_max_ms: u64,
    pub idle_scan_fast_delay_min_ms: u64,
    pub idle_scan_fast_delay_max_ms: u64,

    // ── ARGUS worker (top-level) ─────────────────────
    pub argus_worker_enabled: bool,
    pub argus_worker_path: String,
    pub argus_worker_timeout_sec: u64,

    // ── ClamAV isolation ─────────────────────────────
    pub clamav_isolation: String,
    pub clamav_worker_timeout_sec: u64,

    // ── Nested sub-configs ───────────────────────────
    pub scan: FullScanConfig,
    pub performance: FullPerformanceConfig,
    pub fish: FullFishConfig,
    pub sandbox: FullSandboxConfig,
    pub developer: DeveloperConfigPublic,
}

impl Default for FullConfig {
    fn default() -> Self {
        Self {
            realtime_enabled: true,
            realtime_roots: Vec::new(),

            max_file_size_mb: 512,
            scan_archives: true,
            heuristic_alerts: true,

            auto_update: true,
            update_interval_hours: 4,
            signature_stale_days: 3,
            update_mirror: "database.clamav.net".into(),

            quarantine_retention_days: 90,
            auto_quarantine: true,

            excluded_paths: Vec::new(),
            excluded_extensions: Vec::new(),
            excluded_detections: Vec::new(),
            trusted_hashes: Vec::new(),

            enhanced_signature_provider: "none".into(),

            log_level: "info".into(),

            scheduled_scan_enabled: true,
            scheduled_scan_hour: 3,
            scheduled_scan_type: "quick".into(),

            startup_critical_scan: true,

            powershell_bridge_enabled: false,
            powershell_poll_seconds: 5,

            idle_scan_enabled: true,
            idle_scan_start_delay_secs: 300,
            idle_scan_on_battery: false,
            idle_scan_cpu_pause_threshold: 50,
            idle_scan_max_file_size_mb: 256,
            idle_scan_fullscreen_pause: true,
            idle_scan_disk_latency_pause_ms: 50,
            idle_scan_max_files_per_session: 10_000,
            idle_scan_slow_delay_min_ms: 1500,
            idle_scan_slow_delay_max_ms: 2500,
            idle_scan_normal_delay_min_ms: 400,
            idle_scan_normal_delay_max_ms: 1000,
            idle_scan_fast_delay_min_ms: 100,
            idle_scan_fast_delay_max_ms: 300,

            argus_worker_enabled: false,
            argus_worker_path: "argusd.exe".into(),
            argus_worker_timeout_sec: 15,

            clamav_isolation: "in_process".into(),
            clamav_worker_timeout_sec: 30,

            scan: FullScanConfig::default(),
            performance: FullPerformanceConfig::default(),
            fish: FullFishConfig::default(),
            sandbox: FullSandboxConfig::default(),
            developer: DeveloperConfigPublic::default(),
        }
    }
}

// ─── Nested sub-configs ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FullScanConfig {
    pub argus_worker_enabled: bool,
    pub argus_worker_path: String,
    pub argus_worker_timeout_sec: u64,
    pub orchestrator_file_scan_enabled: bool,
    pub orchestrator_folder_scan_enabled: bool,
    pub orchestrator_quick_scan_enabled: bool,
    pub orchestrator_full_scan_enabled: bool,
}

impl Default for FullScanConfig {
    fn default() -> Self {
        Self {
            argus_worker_enabled: false,
            argus_worker_path: "argusd.exe".into(),
            argus_worker_timeout_sec: 15,
            orchestrator_file_scan_enabled: false,
            orchestrator_folder_scan_enabled: false,
            orchestrator_quick_scan_enabled: false,
            orchestrator_full_scan_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FullPerformanceConfig {
    pub memory_profile: String,
    pub memory_warning_mb: u64,
    pub memory_critical_mb: u64,
    pub external_argus_under_pressure: bool,
    pub max_resident_workers_on_pressure: u32,
}

impl Default for FullPerformanceConfig {
    fn default() -> Self {
        Self {
            memory_profile: "normal".into(),
            memory_warning_mb: 1500,
            memory_critical_mb: 2500,
            external_argus_under_pressure: true,
            max_resident_workers_on_pressure: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FullFishConfig {
    pub enabled: bool,
    pub observe_only: bool,
    pub window_seconds: u64,
    pub rename_threshold: u32,
    pub rewrite_threshold: u32,
    pub ext_mutation_threshold: u32,
    pub slow_burn_window_secs: u64,
    pub slow_burn_threshold: u32,
    pub entropy_delta_threshold: f64,
    pub alert_cooldown_seconds: u64,
    /// "observe" | "suspend" | "terminate"
    pub active_response: String,
}

impl Default for FullFishConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_only: true,
            window_seconds: 30,
            rename_threshold: 50,
            rewrite_threshold: 200,
            ext_mutation_threshold: 5,
            slow_burn_window_secs: 600,
            slow_burn_threshold: 250,
            entropy_delta_threshold: 0.20,
            alert_cooldown_seconds: 60,
            active_response: "observe".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FullSandboxConfig {
    pub enabled: bool,
    /// "experimental" | "production"
    pub mode: String,
    pub timeout_sec: u64,
    pub min_score: u32,
    pub max_score: u32,
}

impl Default for FullSandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "experimental".into(),
            timeout_sec: 10,
            min_score: 26,
            max_score: 75,
        }
    }
}

/// Public projection of `DeveloperConfig`. Deliberately omits
/// `password_sha256` — provisioning is out-of-band only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeveloperConfigPublic {
    pub enabled: bool,
    pub telemetry_enabled: bool,
    pub telemetry_max_kb: u64,
}

impl Default for DeveloperConfigPublic {
    fn default() -> Self {
        Self {
            enabled: false,
            telemetry_enabled: true,
            telemetry_max_kb: 2048,
        }
    }
}

// ─── Restart-requirement map endpoint payload ────────────────────────

/// Response for `settings.restart_requirements` — maps every field path
/// to its [`RestartRequirement`]. Returned as a flat object keyed by
/// the same paths used in [`restart_requirement`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartRequirementMap {
    pub fields: std::collections::HashMap<String, RestartRequirement>,
}

impl RestartRequirementMap {
    /// Build the map by enumerating every known FullConfig field path.
    /// Adding a new field here is the single place to update — keeps
    /// the GUI's pill rendering in sync with the actual restart story.
    pub fn build() -> Self {
        let paths: &[&str] = &[
            // Top-level
            "realtime_enabled",
            "realtime_roots",
            "max_file_size_mb",
            "scan_archives",
            "heuristic_alerts",
            "auto_update",
            "update_interval_hours",
            "signature_stale_days",
            "update_mirror",
            "quarantine_retention_days",
            "auto_quarantine",
            "excluded_paths",
            "excluded_extensions",
            "excluded_detections",
            "trusted_hashes",
            "enhanced_signature_provider",
            "log_level",
            "scheduled_scan_enabled",
            "scheduled_scan_hour",
            "scheduled_scan_type",
            "startup_critical_scan",
            "powershell_bridge_enabled",
            "powershell_poll_seconds",
            "idle_scan_enabled",
            "idle_scan_start_delay_secs",
            "idle_scan_on_battery",
            "idle_scan_cpu_pause_threshold",
            "idle_scan_max_file_size_mb",
            "idle_scan_fullscreen_pause",
            "idle_scan_disk_latency_pause_ms",
            "idle_scan_max_files_per_session",
            "idle_scan_slow_delay_min_ms",
            "idle_scan_slow_delay_max_ms",
            "idle_scan_normal_delay_min_ms",
            "idle_scan_normal_delay_max_ms",
            "idle_scan_fast_delay_min_ms",
            "idle_scan_fast_delay_max_ms",
            "argus_worker_enabled",
            "argus_worker_path",
            "argus_worker_timeout_sec",
            "clamav_isolation",
            "clamav_worker_timeout_sec",
            // scan.*
            "scan.argus_worker_enabled",
            "scan.argus_worker_path",
            "scan.argus_worker_timeout_sec",
            "scan.orchestrator_file_scan_enabled",
            "scan.orchestrator_folder_scan_enabled",
            "scan.orchestrator_quick_scan_enabled",
            "scan.orchestrator_full_scan_enabled",
            // performance.*
            "performance.memory_profile",
            "performance.memory_warning_mb",
            "performance.memory_critical_mb",
            "performance.external_argus_under_pressure",
            "performance.max_resident_workers_on_pressure",
            // fish.*
            "fish.enabled",
            "fish.observe_only",
            "fish.window_seconds",
            "fish.rename_threshold",
            "fish.rewrite_threshold",
            "fish.ext_mutation_threshold",
            "fish.slow_burn_window_secs",
            "fish.slow_burn_threshold",
            "fish.entropy_delta_threshold",
            "fish.alert_cooldown_seconds",
            "fish.active_response",
            // sandbox.*
            "sandbox.enabled",
            "sandbox.mode",
            "sandbox.timeout_sec",
            "sandbox.min_score",
            "sandbox.max_score",
            // developer.* (public projection only)
            "developer.enabled",
            "developer.telemetry_enabled",
            "developer.telemetry_max_kb",
        ];
        let mut fields = std::collections::HashMap::with_capacity(paths.len());
        for p in paths {
            fields.insert((*p).to_string(), restart_requirement(p));
        }
        Self { fields }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_roundtrip_through_json() {
        let cfg = FullConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: FullConfig = serde_json::from_str(&json).expect("deserialize");
        // Spot-check a few representative fields.
        assert_eq!(parsed.realtime_enabled, true);
        assert_eq!(parsed.max_file_size_mb, 512);
        assert_eq!(parsed.fish.window_seconds, 30);
        assert_eq!(parsed.sandbox.min_score, 26);
        assert_eq!(parsed.performance.memory_profile, "normal");
        assert_eq!(parsed.developer.telemetry_max_kb, 2048);
    }

    #[test]
    fn restart_requirement_classification() {
        assert_eq!(
            restart_requirement("excluded_paths"),
            RestartRequirement::EngineReload
        );
        assert_eq!(
            restart_requirement("log_level"),
            RestartRequirement::DaemonRestart
        );
        assert_eq!(
            restart_requirement("idle_scan_cpu_pause_threshold"),
            RestartRequirement::None
        );
        assert_eq!(
            restart_requirement("fish.rename_threshold"),
            RestartRequirement::None
        );
        // Unknown field → safe default (no restart needed).
        assert_eq!(
            restart_requirement("not_a_real_field"),
            RestartRequirement::None
        );
    }

    #[test]
    fn critical_fields_cover_known_kill_vectors() {
        // These are the kill-vector fields the old settings.set handler
        // already pinned — they MUST all be in CRITICAL_FIELDS so the
        // new settings.set_full handler refuses to mutate them too.
        for field in [
            "realtime_enabled",
            "auto_quarantine",
            "excluded_paths",
            "excluded_extensions",
            "excluded_detections",
            "trusted_hashes",
            "realtime_roots",
            "heuristic_alerts",
            "idle_scan_enabled",
            "scheduled_scan_enabled",
            "enhanced_signature_provider",
            "argus_worker_path",
            "argus_worker_enabled",
        ] {
            assert!(
                is_critical(field),
                "{field} must be in CRITICAL_FIELDS — kill-vector regression"
            );
        }
    }

    #[test]
    fn restart_requirement_map_is_well_formed() {
        let map = RestartRequirementMap::build();
        // Sanity: covers at least 60 fields.
        assert!(
            map.fields.len() >= 60,
            "restart_requirements map missing fields: {}",
            map.fields.len()
        );
        // Spot-check a few entries.
        assert_eq!(
            map.fields.get("excluded_paths").copied(),
            Some(RestartRequirement::EngineReload)
        );
        assert_eq!(
            map.fields.get("log_level").copied(),
            Some(RestartRequirement::DaemonRestart)
        );
        assert_eq!(
            map.fields.get("idle_scan_cpu_pause_threshold").copied(),
            Some(RestartRequirement::None)
        );
    }

    #[test]
    fn developer_public_excludes_password_hash() {
        // Compile-time guarantee: DeveloperConfigPublic has no `password_sha256`
        // field. This test exists as documentation — if someone adds the field
        // back, the assertion fails on the field-list check below.
        let cfg = FullConfig::default();
        let json = serde_json::to_string(&cfg.developer).unwrap();
        assert!(
            !json.contains("password_sha256"),
            "DeveloperConfigPublic must NEVER carry the password hash on the wire"
        );
    }
}

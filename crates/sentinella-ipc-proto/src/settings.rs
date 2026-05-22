//! `settings.*` — daemon configuration methods.

use serde::{Deserialize, Serialize};

/// Full daemon settings, returned by `settings.get` and sent via `settings.set`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    // ── Scan defaults ────────────────────────────────────────
    pub default_scan_archives: bool,
    pub default_max_filesize_mb: u64,
    pub default_max_scansize_mb: u64,
    pub default_max_recursion: u32,
    pub default_max_files: u32,
    pub default_heuristic_alerts: bool,

    // ── Real-time protection ─────────────────────────────────
    pub realtime_enabled: bool,
    pub realtime_roots: Vec<String>,

    // ── Updates ──────────────────────────────────────────────
    pub update_interval_hours: u32,
    pub update_mirror: Option<String>,
    pub proxy_url: Option<String>,

    // ── Quarantine ──────────────────────────────────────────
    pub quarantine_retention_days: u32,
    pub quarantine_auto: bool,

    // ── Exclusions ──────────────────────────────────────────
    pub excluded_paths: Vec<String>,
    pub excluded_signatures: Vec<String>,

    // ── Scheduled scans ─────────────────────────────────────
    pub scheduled_scans: Vec<ScheduledScan>,

    // ── Logging ─────────────────────────────────────────────
    pub log_level: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_scan_archives: true,
            default_max_filesize_mb: 100,
            default_max_scansize_mb: 400,
            default_max_recursion: 17,
            default_max_files: 10_000,
            default_heuristic_alerts: true,

            realtime_enabled: true,
            realtime_roots: default_watch_roots(),

            update_interval_hours: 4,
            update_mirror: None,
            proxy_url: None,

            quarantine_retention_days: 90,
            quarantine_auto: true,

            excluded_paths: Vec::new(),
            excluded_signatures: Vec::new(),
            scheduled_scans: Vec::new(),

            log_level: "info".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScan {
    pub id: String,
    pub label: String,
    /// Cron expression (5-field: min hour dom month dow).
    pub cron: String,
    pub targets: Vec<String>,
    pub enabled: bool,
}

/// Response to `settings.set`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetResult {
    pub ok: bool,
    pub reload_required: bool,
}

#[cfg(target_os = "windows")]
fn default_watch_roots() -> Vec<String> {
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    if home.is_empty() {
        return vec![];
    }
    vec![
        format!(r"{home}\Downloads"),
        format!(r"{home}\Desktop"),
        format!(r"{home}\Documents"),
        std::env::var("TEMP").unwrap_or_else(|_| format!(r"{home}\AppData\Local\Temp")),
    ]
}

#[cfg(not(target_os = "windows"))]
fn default_watch_roots() -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        return vec!["/tmp".into()];
    }
    vec![
        format!("{home}/Downloads"),
        format!("{home}/Desktop"),
        "/tmp".into(),
    ]
}

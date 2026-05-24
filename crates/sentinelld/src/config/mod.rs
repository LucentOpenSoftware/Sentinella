//! Daemon configuration — persistent TOML with validation.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub realtime_enabled: bool,
    pub realtime_roots: Vec<String>,
    pub max_file_size_mb: u64,
    pub scan_archives: bool,
    pub heuristic_alerts: bool,
    pub auto_update: bool,
    pub update_interval_hours: u32,
    pub update_mirror: String,
    pub quarantine_retention_days: u32,
    pub auto_quarantine: bool,
    pub excluded_paths: Vec<String>,
    pub excluded_extensions: Vec<String>,
    /// Detection names to ignore (e.g., "Win.Test.EICAR_HDB-1", "ARGUS/Suspicious.Generic").
    /// Matching is case-insensitive substring. Use exact names from scan results.
    pub excluded_detections: Vec<String>,
    /// SHA-256 hashes of files to always allow (manual whitelist).
    /// Use full 64-character lowercase hex hashes from scan results.
    pub trusted_hashes: Vec<String>,
    pub log_level: String,
    pub scheduled_scan_enabled: bool,
    pub scheduled_scan_hour: u32,
    pub scheduled_scan_type: String,
    // ── Idle background scanner ─────────────────────────
    pub startup_critical_scan: bool,
    pub idle_scan_enabled: bool,
    pub idle_scan_on_battery: bool,
    pub idle_scan_cpu_pause_threshold: u32, // percent 0-100
    pub idle_scan_max_file_size_mb: u64,
    pub idle_scan_fullscreen_pause: bool,
    pub idle_scan_disk_latency_pause_ms: u64, // pause if read >N ms
    pub idle_scan_max_files_per_session: u64,
    pub idle_scan_slow_delay_min_ms: u64,
    pub idle_scan_slow_delay_max_ms: u64,
    pub idle_scan_normal_delay_min_ms: u64,
    pub idle_scan_normal_delay_max_ms: u64,
    pub idle_scan_fast_delay_min_ms: u64,
    pub idle_scan_fast_delay_max_ms: u64,
    pub scan: ScanConfig,
    pub argus_worker_enabled: bool,
    pub argus_worker_path: String,
    pub argus_worker_timeout_sec: u64,
    // ── ClamAV isolation ───────────────────────────────
    /// Run ClamAV in isolated subprocess ("in_process" or "subprocess").
    pub clamav_isolation: String,
    /// Timeout for subprocess ClamAV scans (seconds).
    pub clamav_worker_timeout_sec: u64,
    // ── Memory pressure management ─────────────────────
    pub performance: PerformanceConfig,
    // ── FISH (Ransomware Shield) ──────────────────────
    pub fish: crate::fish::FishConfig,
    // ── Behavioral sandbox (experimental) ────────────
    pub sandbox: SandboxConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    /// Enable behavioral sandbox detonation.
    pub enabled: bool,
    /// Mode: "experimental" (default), "production".
    pub mode: String,
    /// Detonation timeout in seconds.
    pub timeout_sec: u64,
    /// Minimum ARGUS score to trigger sandbox (inclusive).
    pub min_score: u32,
    /// Maximum ARGUS score to trigger sandbox (inclusive). Above this = direct threat.
    pub max_score: u32,
}

impl Default for SandboxConfig {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PerformanceConfig {
    /// Memory profile: "low" (aggressive conservation), "normal" (default),
    /// "aggressive" (allow higher memory for faster scans).
    pub memory_profile: String,
    /// Working set MB threshold for "warning" pressure state.
    pub memory_warning_mb: u64,
    /// Working set MB threshold for "critical" pressure state.
    pub memory_critical_mb: u64,
    /// Route ARGUS analysis to external worker when pressure >= warning.
    pub external_argus_under_pressure: bool,
    /// Max in-process scan workers when pressure >= warning.
    pub max_resident_workers_on_pressure: u32,
}

impl Default for PerformanceConfig {
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
pub struct ScanConfig {
    pub argus_worker_enabled: bool,
    pub argus_worker_path: String,
    pub argus_worker_timeout_sec: u64,
    pub orchestrator_file_scan_enabled: bool,
    pub orchestrator_folder_scan_enabled: bool,
    pub orchestrator_quick_scan_enabled: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            argus_worker_enabled: false,
            argus_worker_path: "argusd.exe".into(),
            argus_worker_timeout_sec: 15,
            orchestrator_file_scan_enabled: false,
            orchestrator_folder_scan_enabled: false,
            orchestrator_quick_scan_enabled: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_default();
        let temp =
            std::env::var("TEMP").unwrap_or_else(|_| format!("{home}\\AppData\\Local\\Temp"));
        Self {
            realtime_enabled: true,
            realtime_roots: vec![
                format!("{home}\\Downloads"),
                format!("{home}\\Desktop"),
                temp,
            ],
            max_file_size_mb: 512,
            scan_archives: true,
            heuristic_alerts: true,
            auto_update: true,
            update_interval_hours: 4,
            update_mirror: "database.clamav.net".into(),
            quarantine_retention_days: 90,
            auto_quarantine: true,
            excluded_paths: vec![],
            excluded_extensions: vec![],
            excluded_detections: vec![],
            trusted_hashes: vec![],
            log_level: "info".into(),
            scheduled_scan_enabled: true,
            scheduled_scan_hour: 3,
            scheduled_scan_type: "quick".into(),
            // Idle scanner defaults.
            startup_critical_scan: true,
            idle_scan_enabled: true,
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
            scan: ScanConfig::default(),
            argus_worker_enabled: false,
            argus_worker_path: "argusd.exe".into(),
            argus_worker_timeout_sec: 15,
            clamav_isolation: "in_process".into(),
            clamav_worker_timeout_sec: 30,
            performance: PerformanceConfig::default(),
            fish: crate::fish::FishConfig::default(),
            sandbox: SandboxConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let config_path = path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("runtime/config/sentinelld.toml"));

        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            match toml::from_str::<Config>(&content) {
                Ok(config) => {
                    tracing::debug!(path = %config_path.display(), "configuration loaded");
                    Ok(config.expanded())
                }
                Err(e) => {
                    warn!(path = %config_path.display(), %e, "config parse error, using defaults");
                    // Backup the bad config.
                    let backup = config_path.with_extension("toml.bad");
                    let _ = std::fs::copy(&config_path, &backup);
                    warn!(backup = %backup.display(), "bad config backed up");
                    let config = Config::default();
                    let _ = config.save(&config_path);
                    Ok(config)
                }
            }
        } else {
            info!(path = %config_path.display(), "config not found, creating defaults");
            let config = Config::default();
            let _ = config.save(&config_path);
            Ok(config)
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
        }
        let content = toml::to_string_pretty(self).map_err(|e| format!("serialize: {e}"))?;
        std::fs::write(path, content).map_err(|e| format!("write: {e}"))?;
        info!(path = %path.display(), "configuration saved");
        Ok(())
    }

    fn expanded(mut self) -> Self {
        expand_vec(&mut self.realtime_roots);
        expand_vec(&mut self.excluded_paths);
        self.argus_worker_path = expand_vars(&self.argus_worker_path);
        self.scan.argus_worker_path = expand_vars(&self.scan.argus_worker_path);
        self
    }

    /// Validate config values — clamp to safe ranges.
    pub fn validate(&mut self) {
        if self.max_file_size_mb == 0 {
            self.max_file_size_mb = 512;
        }
        if self.max_file_size_mb > 4096 {
            self.max_file_size_mb = 4096;
        }
        if self.update_interval_hours == 0 {
            self.update_interval_hours = 1;
        }
        if self.update_interval_hours > 168 {
            self.update_interval_hours = 168;
        }
        if self.quarantine_retention_days > 365 {
            self.quarantine_retention_days = 365;
        }
        if self.update_mirror.is_empty() {
            self.update_mirror = "database.clamav.net".into();
        }
        if self.argus_worker_path.trim().is_empty() {
            self.argus_worker_path = "argusd.exe".into();
        }
        if self.argus_worker_timeout_sec == 0 {
            self.argus_worker_timeout_sec = 15;
        }
        if self.argus_worker_timeout_sec > 300 {
            self.argus_worker_timeout_sec = 300;
        }
        if self.scan.argus_worker_path.trim().is_empty() {
            self.scan.argus_worker_path = "argusd.exe".into();
        }
        if self.scan.argus_worker_timeout_sec == 0 {
            self.scan.argus_worker_timeout_sec = 15;
        }
        if self.scan.argus_worker_timeout_sec > 300 {
            self.scan.argus_worker_timeout_sec = 300;
        }
        // ClamAV isolation mode validation.
        if !matches!(self.clamav_isolation.as_str(), "in_process" | "subprocess") {
            warn!(
                value = self.clamav_isolation.as_str(),
                "invalid clamav_isolation — defaulting to in_process"
            );
            self.clamav_isolation = "in_process".into();
        }
        if self.clamav_worker_timeout_sec == 0 {
            self.clamav_worker_timeout_sec = 30;
        }
        if self.clamav_worker_timeout_sec > 300 {
            self.clamav_worker_timeout_sec = 300;
        }
        // Sandbox validation.
        if self.sandbox.timeout_sec < 5 {
            self.sandbox.timeout_sec = 5;
        }
        if self.sandbox.timeout_sec > 120 {
            self.sandbox.timeout_sec = 120;
        }
        if self.sandbox.min_score > self.sandbox.max_score {
            warn!("sandbox min_score > max_score — swapping");
            std::mem::swap(&mut self.sandbox.min_score, &mut self.sandbox.max_score);
        }
        if self.sandbox.max_score > 100 {
            self.sandbox.max_score = 100;
        }
        if !matches!(self.sandbox.mode.as_str(), "experimental" | "production") {
            self.sandbox.mode = "experimental".into();
        }
    }
}

fn expand_vec(values: &mut [String]) {
    for value in values {
        *value = expand_vars(value);
    }
}

fn expand_vars(value: &str) -> String {
    let mut out = value.to_string();
    for (key, fallback) in [
        ("USERPROFILE", ""),
        ("HOME", ""),
        ("TEMP", ""),
        ("PROGRAMDATA", r"C:\ProgramData"),
    ] {
        if let Ok(env) = std::env::var(key) {
            out = out.replace(&format!("%{key}%"), &env);
            out = out.replace(&format!("${key}"), &env);
        } else if !fallback.is_empty() {
            out = out.replace(&format!("%{key}%"), fallback);
            out = out.replace(&format!("${key}"), fallback);
        }
    }
    out
}

pub fn load(path: Option<&str>) -> anyhow::Result<Config> {
    let mut config = Config::load(path)?;
    config.validate();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_programdata_path() {
        let expected = std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into());
        let config = Config {
            excluded_paths: vec![r"%PROGRAMDATA%\Sentinella".into()],
            ..Config::default()
        }
        .expanded();

        assert_eq!(config.excluded_paths[0], format!(r"{expected}\Sentinella"));
    }
}

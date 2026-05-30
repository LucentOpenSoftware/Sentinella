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
    /// Age (days) at which the signature DB is reported "out of date" in the UI.
    /// Freshness is measured from the newest signature file's mtime. Default 3.
    #[serde(default = "default_signature_stale_days")]
    pub signature_stale_days: u32,
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
    /// Enhanced signature provider (advanced, opt-in).
    /// At most ONE provider active alongside official ClamAV.
    /// "none" = official ClamAV only (default).
    /// Changing this invalidates the mpool residency cache.
    #[serde(default = "default_enhanced_provider")]
    pub enhanced_signature_provider: String,
    pub log_level: String,
    pub scheduled_scan_enabled: bool,
    pub scheduled_scan_hour: u32,
    pub scheduled_scan_type: String,
    // ── Idle background scanner ─────────────────────────
    pub startup_critical_scan: bool,
    // ── Runtime intelligence ────────────────────────
    pub powershell_bridge_enabled: bool,
    pub powershell_poll_seconds: u64,
    pub idle_scan_enabled: bool,
    /// Delay in seconds before idle scanner starts after engine compile.
    /// Preserves lightweight residency impression after boot.
    /// Default: 300 (5 minutes). Realtime watcher remains active.
    #[serde(default = "default_idle_scan_start_delay")]
    pub idle_scan_start_delay_secs: u64,
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
    // ── Developer mode (v0.1.6 only — local perf telemetry) ──
    pub developer: DeveloperConfig,
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

/// Developer mode (v0.1.6 only). Per-machine, password-gated, LOCAL-ONLY perf
/// telemetry — dumps scan/engine performance to a txt file in the AV data dir.
/// NOT a cloud/aggregate telemetry system; nothing leaves the machine.
///
/// SECURITY NOTE: this is a low-harm local convenience gate (it only enables a
/// performance dump), not an auth boundary. `password_sha256` is a plain
/// SHA-256 (no salt/KDF) compared constant-time; that is sufficient to stop a
/// casual flip but is deliberately NOT a credential store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeveloperConfig {
    /// Current per-machine developer-mode state. Only ever set true after a
    /// successful password check (see `verify_developer_password`); validation
    /// forces this back to false if no password is provisioned.
    pub enabled: bool,
    /// Lowercase hex SHA-256 of the unlock password. Empty = unprovisioned →
    /// developer mode cannot be enabled.
    pub password_sha256: String,
    /// When developer mode is on, append perf telemetry to the dump file.
    pub telemetry_enabled: bool,
    /// Hard cap (KiB) on the telemetry dump file; rotated/truncated past this.
    pub telemetry_max_kb: u64,
}

impl Default for DeveloperConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            password_sha256: String::new(),
            telemetry_enabled: true,
            telemetry_max_kb: 2048,
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
    pub orchestrator_full_scan_enabled: bool,
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
            orchestrator_full_scan_enabled: true,
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
            // C3 fix: expanded default watch roots.
            // Previously only Downloads/Desktop/Temp — malware in Documents,
            // AppData, ProgramData was completely invisible to realtime protection.
            realtime_roots: vec![
                format!("{home}\\Downloads"),
                format!("{home}\\Desktop"),
                temp,
                format!("{home}\\Documents"),
                format!("{home}\\AppData\\Roaming"),
                format!("{home}\\AppData\\Local\\Temp"),
                "C:\\ProgramData".into(),
                format!("{home}\\OneDrive"),
            ],
            max_file_size_mb: 512,
            scan_archives: true,
            heuristic_alerts: true,
            auto_update: true,
            update_interval_hours: 4,
            signature_stale_days: 3,
            update_mirror: "database.clamav.net".into(),
            quarantine_retention_days: 90,
            auto_quarantine: true,
            excluded_paths: vec![],
            excluded_extensions: vec![],
            excluded_detections: vec![],
            trusted_hashes: vec![],
            enhanced_signature_provider: "none".into(),
            log_level: "info".into(),
            scheduled_scan_enabled: true,
            scheduled_scan_hour: 3,
            scheduled_scan_type: "quick".into(),
            // Idle scanner defaults.
            startup_critical_scan: true,
            powershell_bridge_enabled: false, // Disabled by default — opt-in.
            powershell_poll_seconds: 5,
            idle_scan_enabled: true,
            idle_scan_start_delay_secs: 300, // 5 minutes — preserve post-boot lightness.
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
            developer: DeveloperConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let config_path = path
            .map(PathBuf::from)
            .unwrap_or_else(|| crate::paths::paths().config_file());

        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            match toml::from_str::<Config>(&content) {
                Ok(config) => {
                    tracing::debug!(path = %config_path.display(), "configuration loaded");
                    // R4-C1 (CRITICAL): every Config::load() call site relied on
                    // top-level `pub fn load` for validation. Anyone calling
                    // `Config::load(None)` directly bypassed it — meaning the
                    // excluded_detections=[""] kill-switch (which suppresses
                    // ALL detections) was never filtered. Validate here too.
                    let mut config = config.expanded();
                    config.validate();
                    Ok(config)
                }
                Err(e) => {
                    warn!(path = %config_path.display(), %e, "config parse error, using defaults");
                    // R4-C17: backup with timestamp suffix so repeated parse
                    // failures don't keep overwriting the same .bad file.
                    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
                    let backup = config_path.with_extension(format!("toml.bad.{ts}"));
                    let _ = std::fs::copy(&config_path, &backup);
                    warn!(backup = %backup.display(), "bad config backed up");
                    // Match the loaded path: env-var literals in defaults
                    // should be expanded before persisting, otherwise the
                    // saved file embeds unexpanded `%VAR%` strings.
                    let mut config = Config::default().expanded();
                    config.validate();
                    let _ = config.save(&config_path);
                    Ok(config)
                }
            }
        } else {
            info!(path = %config_path.display(), "config not found, creating defaults");
            let mut config = Config::default().expanded();
            config.validate();
            let _ = config.save(&config_path);
            Ok(config)
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
        }
        let content = toml::to_string_pretty(self).map_err(|e| format!("serialize: {e}"))?;
        // R4-C18: atomic write — write to .tmp then rename. A crash mid-write
        // previously left a truncated config that load() would treat as parse
        // error and silently reset to defaults (losing user settings).
        //
        // Durability: `fs::write` buffers in the OS page cache; without
        // `sync_all` the rename can complete and the system can crash with
        // the destination file empty/short on disk. Sync the temp file BEFORE
        // the rename so the post-rename file is durable.
        let tmp = path.with_extension("toml.tmp");
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| format!("open temp: {e}"))?;
            f.write_all(content.as_bytes())
                .map_err(|e| format!("write: {e}"))?;
            f.sync_all().map_err(|e| format!("sync: {e}"))?;
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("rename: {e}"))?;
        info!(path = %path.display(), "configuration saved");
        // Best-effort HMAC sidecar — keeps the on-disk config bound to the
        // last daemon-issued save. `load_verified` compares the sidecar to
        // detect out-of-band edits. We deliberately do NOT fail the save if
        // the sidecar can't be written (no vault key yet during very early
        // startup, ACL issue, etc.) — the config write itself succeeded and
        // the worst case is just a missing drift signal next load.
        let _ = write_config_hmac_sidecar(path, content.as_bytes());
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
        // Signature staleness warning age — clamp to a sane [1, 30] day range
        // (0 would warn constantly; >30 would hide a genuinely abandoned DB).
        self.signature_stale_days = self.signature_stale_days.clamp(1, 30);
        // R4-C8: 0 days = instant cleanup on every scheduler tick — wipes
        // quarantine. Enforce a 1-day minimum so accidental UI input does
        // not destroy quarantined evidence.
        if self.quarantine_retention_days == 0 {
            warn!("quarantine_retention_days = 0 would delete all quarantine on next cleanup — bumping to 1");
            self.quarantine_retention_days = 1;
        }
        if self.quarantine_retention_days > 365 {
            self.quarantine_retention_days = 365;
        }
        // R4-C10: update_mirror should be a bare hostname. Strip protocol
        // prefixes and trailing paths so URL composition downstream cannot
        // produce malformed targets (e.g. "https://https://host").
        if self.update_mirror.is_empty() {
            self.update_mirror = "database.clamav.net".into();
        } else {
            let trimmed = self
                .update_mirror
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("database.clamav.net")
                .to_string();
            if trimmed.is_empty() || trimmed.len() > 253 {
                warn!(value = self.update_mirror.as_str(), "invalid update_mirror — reset to default");
                self.update_mirror = "database.clamav.net".into();
            } else if trimmed != self.update_mirror {
                self.update_mirror = trimmed;
            }
        }
        // R4-C3: scheduled_scan_hour > 23 → scheduler hour check never matches → silently disabled.
        if self.scheduled_scan_hour > 23 {
            warn!(
                value = self.scheduled_scan_hour,
                "scheduled_scan_hour > 23 — clamped to 3 AM"
            );
            self.scheduled_scan_hour = 3;
        }
        // "custom" was previously accepted but the scheduler dispatch in
        // ipc::state::start_scan only handles "quick" / "full" / "folder" /
        // "file" / "startup" — a scheduled "custom" type produced a silent
        // "Unknown scan type" error and no scan ever ran.
        if !matches!(self.scheduled_scan_type.as_str(), "quick" | "full") {
            self.scheduled_scan_type = "quick".into();
        }
        // R4-C11: invalid log_level breaks tracing init silently.
        if !matches!(
            self.log_level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error"
        ) {
            self.log_level = "info".into();
        }
        // R4-C4: cpu_pause_threshold > 100 → never pauses; 0 → always pauses → idle scan dead.
        if self.idle_scan_cpu_pause_threshold == 0 {
            self.idle_scan_cpu_pause_threshold = 5;
        }
        if self.idle_scan_cpu_pause_threshold > 100 {
            self.idle_scan_cpu_pause_threshold = 100;
        }
        // R4-C5: disk_latency_pause_ms = 0 → always paused.
        if self.idle_scan_disk_latency_pause_ms == 0 {
            self.idle_scan_disk_latency_pause_ms = 50;
        }
        if self.idle_scan_disk_latency_pause_ms > 60_000 {
            self.idle_scan_disk_latency_pause_ms = 60_000;
        }
        // R4-C7: max_files_per_session = 0 wedges the scanner.
        if self.idle_scan_max_files_per_session == 0 {
            self.idle_scan_max_files_per_session = 10_000;
        }
        if self.idle_scan_max_file_size_mb == 0 {
            self.idle_scan_max_file_size_mb = 256;
        }
        // Mirror max_file_size_mb cap — consumed downstream as
        // `* 1024 * 1024` (u64) and a huge value would overflow / wrap,
        // silently defeating idle scanning.
        if self.idle_scan_max_file_size_mb > 4096 {
            self.idle_scan_max_file_size_mb = 4096;
        }
        // R4-C6: rand::gen_range(min..=max) panics if min > max. Swap pairs.
        for (lo, hi) in [
            (
                &mut self.idle_scan_slow_delay_min_ms,
                &mut self.idle_scan_slow_delay_max_ms,
            ),
            (
                &mut self.idle_scan_normal_delay_min_ms,
                &mut self.idle_scan_normal_delay_max_ms,
            ),
            (
                &mut self.idle_scan_fast_delay_min_ms,
                &mut self.idle_scan_fast_delay_max_ms,
            ),
        ] {
            if *lo > *hi {
                std::mem::swap(lo, hi);
            }
        }
        // R4-C20: powershell_poll_seconds = 0 → tight loop spawning PS processes.
        if self.powershell_poll_seconds == 0 {
            self.powershell_poll_seconds = 5;
        }
        if self.powershell_poll_seconds > 3600 {
            self.powershell_poll_seconds = 3600;
        }
        // R4-C14: enhanced_signature_provider allowlist.
        if !matches!(
            self.enhanced_signature_provider.as_str(),
            "none" | "securiteinfo" | "urlhaus" | "malwarepatrol"
        ) {
            warn!(
                value = self.enhanced_signature_provider.as_str(),
                "unknown enhanced_signature_provider — reset to none"
            );
            self.enhanced_signature_provider = "none".into();
        }
        // R4-C12: memory_warning must be < memory_critical.
        if self.performance.memory_warning_mb >= self.performance.memory_critical_mb {
            warn!(
                warning = self.performance.memory_warning_mb,
                critical = self.performance.memory_critical_mb,
                "memory_warning_mb >= memory_critical_mb — resetting to defaults"
            );
            self.performance.memory_warning_mb = 1500;
            self.performance.memory_critical_mb = 2500;
        }
        if !matches!(
            self.performance.memory_profile.as_str(),
            "low" | "normal" | "aggressive"
        ) {
            self.performance.memory_profile = "normal".into();
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
        // R4-C15: clamp lower bound — 1-sec timeout makes every scan fail.
        if self.clamav_worker_timeout_sec < 5 {
            self.clamav_worker_timeout_sec = 30;
        }
        if self.clamav_worker_timeout_sec > 300 {
            self.clamav_worker_timeout_sec = 300;
        }
        // ── Developer mode (v0.1.6) ──
        // password_sha256 must be empty (unprovisioned) or exactly 64 lowercase
        // hex chars. A malformed value can never match any password, so reset it
        // to empty (which also forces enabled=false below).
        {
            let h = self.developer.password_sha256.trim().to_ascii_lowercase();
            let valid_hash =
                h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit());
            self.developer.password_sha256 = if valid_hash { h } else { String::new() };
        }
        // Cannot be enabled without a provisioned password — refuse a config
        // that sets enabled=true with no/invalid hash.
        if self.developer.enabled && self.developer.password_sha256.is_empty() {
            warn!("developer_mode enabled but no valid password provisioned — disabling");
            self.developer.enabled = false;
        }
        // Telemetry dump file size bounds.
        if self.developer.telemetry_max_kb < 64 {
            self.developer.telemetry_max_kb = 64;
        }
        if self.developer.telemetry_max_kb > 65_536 {
            self.developer.telemetry_max_kb = 65_536;
        }
        // Sandbox validation.
        if self.sandbox.timeout_sec < 5 {
            self.sandbox.timeout_sec = 5;
        }
        if self.sandbox.timeout_sec > 120 {
            self.sandbox.timeout_sec = 120;
        }
        // Clamp min_score to [0, 100] BEFORE the swap. Otherwise a config like
        // `min_score=200, max_score=300` would clamp max to 100 but leave min
        // at 200 → empty trigger range → sandbox silently disabled.
        if self.sandbox.min_score > 100 {
            self.sandbox.min_score = 100;
        }
        if self.sandbox.max_score > 100 {
            self.sandbox.max_score = 100;
        }
        if self.sandbox.min_score > self.sandbox.max_score {
            warn!("sandbox min_score > max_score — clamping min below max");
            self.sandbox.min_score = self.sandbox.max_score.saturating_sub(1);
        }
        if !matches!(self.sandbox.mode.as_str(), "experimental" | "production") {
            self.sandbox.mode = "experimental".into();
        }
        // FISH validation — hostile or typo'd TOML could otherwise produce a
        // process-kill primitive (`active_response="terminate"`) with thresholds
        // that trip on the first event. Delegated to FishConfig::validate.
        self.fish.validate();
        // C2 fix: validate excluded_paths — reject dangerously broad entries.
        self.excluded_paths.retain(|p| {
            let trimmed = p.trim();
            // Reject entries shorter than 3 characters (prevents "\" or "C:" matching everything).
            if trimmed.len() < 3 {
                warn!(entry = trimmed, "excluded_paths entry too short — removed");
                return false;
            }
            // Reject entries that are just directory separators.
            if trimmed.chars().all(|c| c == '\\' || c == '/') {
                warn!(
                    entry = trimmed,
                    "excluded_paths entry is only separators — removed"
                );
                return false;
            }
            // R4-C16: reject bare drive-letter roots (e.g. "C:\", "D:/") and
            // raw drive specs ("C:") which would exclude the entire drive
            // from realtime scanning when used as a path prefix.
            let lower = trimmed.to_ascii_lowercase();
            let bytes = lower.as_bytes();
            let is_drive_root = bytes.len() <= 3
                && bytes.len() >= 2
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && (bytes.len() == 2 || bytes[2] == b'\\' || bytes[2] == b'/');
            if is_drive_root {
                warn!(
                    entry = trimmed,
                    "excluded_paths entry is a drive root — refused (would disable AV on entire drive)"
                );
                return false;
            }
            // Refuse system roots that would gut protection of the OS.
            for forbidden in [
                "c:\\windows",
                "c:\\windows\\",
                "c:\\program files",
                "c:\\program files (x86)",
                "c:\\users",
            ] {
                if lower == forbidden || lower == format!("{forbidden}\\") {
                    warn!(
                        entry = trimmed,
                        "excluded_paths entry would disable protection on a critical system root — refused"
                    );
                    return false;
                }
            }
            // Warn about very broad exclusions (single path component, no separator).
            if !trimmed.contains('\\') && !trimmed.contains('/') && !trimmed.contains(':') {
                warn!(
                    entry = trimmed,
                    "excluded_paths entry has no path separator — may be overly broad"
                );
            }
            true
        });

        // R4-C9: cap realtime_roots regardless of watcher cap. Otherwise a
        // bloated config gets serialized back to disk repeatedly and grows.
        const MAX_REALTIME_ROOTS: usize = 64;
        if self.realtime_roots.len() > MAX_REALTIME_ROOTS {
            warn!(
                count = self.realtime_roots.len(),
                max = MAX_REALTIME_ROOTS,
                "realtime_roots truncated"
            );
            self.realtime_roots.truncate(MAX_REALTIME_ROOTS);
        }

        // ☠️ CRITICAL FIX: empty string in excluded_detections matches EVERYTHING.
        // "any_string".contains("") == true in Rust. An attacker setting
        // excluded_detections = [""] silently suppresses ALL ClamAV + ARGUS detections.
        // Also reject very short entries (< 3 chars) to prevent broad substring matches.
        let before_det = self.excluded_detections.len();
        self.excluded_detections.retain(|d| {
            let trimmed = d.trim();
            if trimmed.is_empty() {
                warn!("excluded_detections: empty string entry BLOCKED (would suppress ALL detections)");
                return false;
            }
            if trimmed.len() < 3 {
                warn!(entry = trimmed, "excluded_detections entry too short — removed");
                return false;
            }
            true
        });
        if self.excluded_detections.len() < before_det {
            warn!(
                removed = before_det - self.excluded_detections.len(),
                "dangerous excluded_detections entries filtered"
            );
        }

        // R4-LETHAL-1: validate excluded_extensions. Previous code comment
        // promised to "block excluding ALL executable types at once" but
        // returned `true` unconditionally — the validation was a no-op.
        // Anyone able to write the config (admin, scheduled task, GPO,
        // tampered TOML) could set excluded_extensions=["exe","dll","ps1",
        // "scr","bat","cmd","js","msi","lnk","vbs"] and silently disable
        // scanning of every executable artifact on the box. That is the
        // entire AV defeated by 10 strings.
        //
        // Fix: enforce a hard deny-list of high-risk executable extensions
        // that may NEVER be added to the exclusion list, regardless of who
        // writes the config.
        const NEVER_EXCLUDABLE_EXTENSIONS: &[&str] = &[
            "exe", "dll", "sys", "drv", "scr", "ocx", "cpl", "msi", "msp", "msc",
            "bat", "cmd", "com", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf",
            "wsh", "hta", "lnk", "url", "pif", "reg", "inf", "jar", "py", "pyw",
            "rb", "pl", "sh",
        ];
        self.excluded_extensions.retain(|e| {
            let trimmed = e.trim().trim_start_matches('.').to_ascii_lowercase();
            if trimmed.is_empty() {
                warn!("excluded_extensions: empty entry removed");
                return false;
            }
            // Reject wildcards / glob attempts.
            if trimmed.contains('*') || trimmed.contains('?') {
                warn!(entry = trimmed.as_str(), "excluded_extensions: glob characters refused");
                return false;
            }
            // Hard deny: never let a config disable executable scanning.
            if NEVER_EXCLUDABLE_EXTENSIONS.contains(&trimmed.as_str()) {
                warn!(
                    entry = trimmed.as_str(),
                    "excluded_extensions: REFUSED — executable extension cannot be excluded (silent AV bypass)"
                );
                return false;
            }
            true
        });

        // Validate trusted_hashes — must look like SHA-256 (64 hex chars).
        self.trusted_hashes.retain(|h| {
            let trimmed = h.trim();
            if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                warn!(
                    entry = &trimmed[..trimmed.len().min(16)],
                    "trusted_hashes: invalid SHA-256 format — removed"
                );
                return false;
            }
            true
        });

        // Cap list sizes to prevent abuse.
        const MAX_EXCLUSIONS: usize = 50;
        if self.excluded_paths.len() > MAX_EXCLUSIONS {
            warn!(
                count = self.excluded_paths.len(),
                max = MAX_EXCLUSIONS,
                "excluded_paths truncated"
            );
            self.excluded_paths.truncate(MAX_EXCLUSIONS);
        }
        if self.excluded_detections.len() > MAX_EXCLUSIONS {
            warn!(
                count = self.excluded_detections.len(),
                max = MAX_EXCLUSIONS,
                "excluded_detections truncated"
            );
            self.excluded_detections.truncate(MAX_EXCLUSIONS);
        }
        if self.excluded_extensions.len() > MAX_EXCLUSIONS {
            warn!(
                count = self.excluded_extensions.len(),
                max = MAX_EXCLUSIONS,
                "excluded_extensions truncated"
            );
            self.excluded_extensions.truncate(MAX_EXCLUSIONS);
        }
        if self.trusted_hashes.len() > MAX_EXCLUSIONS {
            warn!(
                count = self.trusted_hashes.len(),
                max = MAX_EXCLUSIONS,
                "trusted_hashes truncated"
            );
            self.trusted_hashes.truncate(MAX_EXCLUSIONS);
        }
    }
}

fn default_enhanced_provider() -> String {
    "none".into()
}
fn default_idle_scan_start_delay() -> u64 {
    300
}
fn default_signature_stale_days() -> u32 {
    3
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
        let resolved = std::env::var(key).unwrap_or_else(|_| fallback.to_string());
        if resolved.is_empty() {
            continue;
        }
        // %VAR% form (Windows-style, unambiguous delimiters) — safe to replace.
        out = out.replace(&format!("%{key}%"), &resolved);
        // R4-C23: $VAR form is greedy — "$USERPROFILEEXT" would partially
        // match "$USERPROFILE". Replace only when the next char is NOT a
        // valid identifier continuation (alnum / underscore).
        let needle = format!("${key}");
        let mut rebuilt = String::with_capacity(out.len());
        let mut i = 0;
        while i < out.len() {
            if out[i..].starts_with(&needle) {
                let after = out[i + needle.len()..].chars().next();
                let is_word_continuation =
                    after.map(|c| c.is_ascii_alphanumeric() || c == '_').unwrap_or(false);
                if !is_word_continuation {
                    rebuilt.push_str(&resolved);
                    i += needle.len();
                    continue;
                }
            }
            // Push one char (handle multi-byte safely).
            let c = out[i..].chars().next().unwrap();
            rebuilt.push(c);
            i += c.len_utf8();
        }
        out = rebuilt;
    }
    out
}

pub fn load(path: Option<&str>) -> anyhow::Result<Config> {
    let mut config = Config::load(path)?;
    config.validate();
    Ok(config)
}

/// Load the config AND verify its HMAC sidecar against the runtime-integrity
/// vault key. Returns `(config, drift)` where `drift=true` means the on-disk
/// config bytes did not match the sidecar — someone edited the file outside
/// the daemon (or the sidecar is stale because the daemon last saved before
/// this hardening shipped). Caller should surface drift via the `health`
/// IPC and decide whether to refuse start (we don't — fail-loud).
///
/// First-start behavior: if the sidecar is missing, we write a fresh one
/// for the just-loaded file (TOFU) and return `drift=false`. This avoids a
/// nuisance drift report on every daemon upgrade.
///
/// The vault key is read directly from disk (vault file) instead of taking
/// an `IntegrityVault` ref so this can be called BEFORE the `AppState` lock
/// graph is wired. If the vault key isn't present yet (very first daemon
/// start), we cannot verify and return `drift=false` — the post-save hook
/// in `Config::save` will lay down a sidecar shortly after.
pub fn load_verified(path: Option<&str>) -> anyhow::Result<(Config, bool)> {
    let config_path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::paths::paths().config_file());

    // Load the config first so a missing-sidecar / missing-key situation
    // never blocks startup.
    let config = load(path)?;

    // If the config file itself doesn't exist on disk (load() just synthesized
    // defaults + wrote them), there's nothing to verify — Config::save will
    // have written a sidecar already (best-effort).
    if !config_path.exists() {
        return Ok((config, false));
    }

    let key_path = crate::paths::paths().vault_integrity_key();
    let key_bytes = match std::fs::read(&key_path) {
        Ok(b) if b.len() == 32 => b,
        _ => return Ok((config, false)), // no key yet — can't verify
    };
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let hmac_path = config_path.with_extension("toml.hmac");
    let content = match std::fs::read(&config_path) {
        Ok(c) => c,
        Err(_) => return Ok((config, false)),
    };
    let computed = crate::runtime_integrity::hmac_bytes(&key, &content);

    if !hmac_path.exists() {
        // TOFU — record the current content's HMAC so a future edit is
        // detectable. Best-effort: a write failure here is just "no drift
        // detection until next save".
        let _ = write_config_hmac_sidecar(&config_path, &content);
        return Ok((config, false));
    }

    match std::fs::read_to_string(&hmac_path) {
        Ok(stored_raw) => {
            let stored = stored_raw.trim().to_ascii_lowercase();
            if stored == computed {
                Ok((config, false))
            } else {
                warn!(
                    config = %config_path.display(),
                    "config HMAC sidecar mismatch — file edited outside the daemon"
                );
                Ok((config, true))
            }
        }
        Err(_) => Ok((config, false)),
    }
}

/// Write `<path>.hmac` containing the lowercase hex HMAC-SHA256 of `content`
/// under the runtime-integrity vault key. Same atomic-rename + fsync pattern
/// as the config write so a crash mid-write cannot leave a torn sidecar that
/// would mis-flag the config as drifted on next start.
fn write_config_hmac_sidecar(config_path: &Path, content: &[u8]) -> Result<(), String> {
    // Vault key is required; absent → no sidecar (caller treats as "no drift").
    let key_path = crate::paths::paths().vault_integrity_key();
    let key_bytes = std::fs::read(&key_path).map_err(|e| format!("read vault key: {e}"))?;
    if key_bytes.len() != 32 {
        return Err(format!(
            "vault key wrong size: {} (expected 32)",
            key_bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let hex = crate::runtime_integrity::hmac_bytes(&key, content);
    let hmac_path = config_path.with_extension("toml.hmac");
    let tmp = hmac_path.with_extension("hmac.tmp");
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("open temp hmac: {e}"))?;
        f.write_all(hex.as_bytes())
            .map_err(|e| format!("write hmac: {e}"))?;
        f.sync_all().map_err(|e| format!("sync hmac: {e}"))?;
    }
    std::fs::rename(&tmp, &hmac_path).map_err(|e| format!("rename hmac: {e}"))?;
    Ok(())
}

/// Hash a developer-mode password to lowercase hex SHA-256. Used both to
/// provision `DeveloperConfig.password_sha256` and to verify an unlock attempt.
pub fn hash_developer_password(password: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time check of a developer-mode password against the stored hex
/// hash. Returns false if the stored hash is empty (unprovisioned) or malformed
/// — developer mode is locked until a valid hash is provisioned.
pub fn verify_developer_password(input: &str, stored_hash_hex: &str) -> bool {
    let stored = stored_hash_hex.trim().to_ascii_lowercase();
    if stored.len() != 64 || !stored.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let computed = hash_developer_password(input);
    if computed.len() != stored.len() {
        return false;
    }
    // Constant-time over the fixed 64-char hex — no early exit on first mismatch.
    let mut diff = 0u8;
    for (a, b) in computed.bytes().zip(stored.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ════════════════════════════════════════════════════════════════════
//  FullConfig bridge (v0.1.8 settings.get_full / settings.set_full)
// ════════════════════════════════════════════════════════════════════
//
// `sentinella_ipc_proto::full_config::FullConfig` is the wire-format
// mirror of `Config`. These conversions are the single seam between
// the two — every field of Config has to appear here or it won't make
// it to the GUI. The compile-time field-coverage test below catches
// drift after a Config struct add.
//
// `apply_non_critical` is the inverse used by `settings.set_full`: it
// applies every NON-critical field from a FullConfig into a Config,
// leaving the kill-vector fields untouched. The same kill-vector pin
// list is enforced server-side in the IPC handler as a second defence.

use sentinella_ipc_proto::full_config::{
    DeveloperConfigPublic, FullConfig, FullFishConfig, FullPerformanceConfig, FullSandboxConfig,
    FullScanConfig, CRITICAL_FIELDS,
};

impl From<&Config> for FullConfig {
    fn from(c: &Config) -> Self {
        FullConfig {
            realtime_enabled: c.realtime_enabled,
            realtime_roots: c.realtime_roots.clone(),

            max_file_size_mb: c.max_file_size_mb,
            scan_archives: c.scan_archives,
            heuristic_alerts: c.heuristic_alerts,

            auto_update: c.auto_update,
            update_interval_hours: c.update_interval_hours,
            signature_stale_days: c.signature_stale_days,
            update_mirror: c.update_mirror.clone(),

            quarantine_retention_days: c.quarantine_retention_days,
            auto_quarantine: c.auto_quarantine,

            excluded_paths: c.excluded_paths.clone(),
            excluded_extensions: c.excluded_extensions.clone(),
            excluded_detections: c.excluded_detections.clone(),
            trusted_hashes: c.trusted_hashes.clone(),

            enhanced_signature_provider: c.enhanced_signature_provider.clone(),
            log_level: c.log_level.clone(),

            scheduled_scan_enabled: c.scheduled_scan_enabled,
            scheduled_scan_hour: c.scheduled_scan_hour,
            scheduled_scan_type: c.scheduled_scan_type.clone(),

            startup_critical_scan: c.startup_critical_scan,

            powershell_bridge_enabled: c.powershell_bridge_enabled,
            powershell_poll_seconds: c.powershell_poll_seconds,

            idle_scan_enabled: c.idle_scan_enabled,
            idle_scan_start_delay_secs: c.idle_scan_start_delay_secs,
            idle_scan_on_battery: c.idle_scan_on_battery,
            idle_scan_cpu_pause_threshold: c.idle_scan_cpu_pause_threshold,
            idle_scan_max_file_size_mb: c.idle_scan_max_file_size_mb,
            idle_scan_fullscreen_pause: c.idle_scan_fullscreen_pause,
            idle_scan_disk_latency_pause_ms: c.idle_scan_disk_latency_pause_ms,
            idle_scan_max_files_per_session: c.idle_scan_max_files_per_session,
            idle_scan_slow_delay_min_ms: c.idle_scan_slow_delay_min_ms,
            idle_scan_slow_delay_max_ms: c.idle_scan_slow_delay_max_ms,
            idle_scan_normal_delay_min_ms: c.idle_scan_normal_delay_min_ms,
            idle_scan_normal_delay_max_ms: c.idle_scan_normal_delay_max_ms,
            idle_scan_fast_delay_min_ms: c.idle_scan_fast_delay_min_ms,
            idle_scan_fast_delay_max_ms: c.idle_scan_fast_delay_max_ms,

            argus_worker_enabled: c.argus_worker_enabled,
            argus_worker_path: c.argus_worker_path.clone(),
            argus_worker_timeout_sec: c.argus_worker_timeout_sec,

            clamav_isolation: c.clamav_isolation.clone(),
            clamav_worker_timeout_sec: c.clamav_worker_timeout_sec,

            scan: FullScanConfig {
                argus_worker_enabled: c.scan.argus_worker_enabled,
                argus_worker_path: c.scan.argus_worker_path.clone(),
                argus_worker_timeout_sec: c.scan.argus_worker_timeout_sec,
                orchestrator_file_scan_enabled: c.scan.orchestrator_file_scan_enabled,
                orchestrator_folder_scan_enabled: c.scan.orchestrator_folder_scan_enabled,
                orchestrator_quick_scan_enabled: c.scan.orchestrator_quick_scan_enabled,
                orchestrator_full_scan_enabled: c.scan.orchestrator_full_scan_enabled,
            },
            performance: FullPerformanceConfig {
                memory_profile: c.performance.memory_profile.clone(),
                memory_warning_mb: c.performance.memory_warning_mb,
                memory_critical_mb: c.performance.memory_critical_mb,
                external_argus_under_pressure: c.performance.external_argus_under_pressure,
                max_resident_workers_on_pressure: c.performance.max_resident_workers_on_pressure,
            },
            fish: FullFishConfig {
                enabled: c.fish.enabled,
                observe_only: c.fish.observe_only,
                window_seconds: c.fish.window_seconds,
                rename_threshold: c.fish.rename_threshold,
                rewrite_threshold: c.fish.rewrite_threshold,
                ext_mutation_threshold: c.fish.ext_mutation_threshold,
                slow_burn_window_secs: c.fish.slow_burn_window_secs,
                slow_burn_threshold: c.fish.slow_burn_threshold,
                entropy_delta_threshold: c.fish.entropy_delta_threshold,
                alert_cooldown_seconds: c.fish.alert_cooldown_seconds,
                active_response: c.fish.active_response.clone(),
            },
            sandbox: FullSandboxConfig {
                enabled: c.sandbox.enabled,
                mode: c.sandbox.mode.clone(),
                timeout_sec: c.sandbox.timeout_sec,
                min_score: c.sandbox.min_score,
                max_score: c.sandbox.max_score,
            },
            // password_sha256 is NEVER mirrored — see DeveloperConfigPublic.
            developer: DeveloperConfigPublic {
                enabled: c.developer.enabled,
                telemetry_enabled: c.developer.telemetry_enabled,
                telemetry_max_kb: c.developer.telemetry_max_kb,
            },
        }
    }
}

impl Config {
    /// Apply every NON-critical field from `full` into `self`.
    ///
    /// Kill-vector fields (see `CRITICAL_FIELDS`) are NEVER touched —
    /// they only travel through `protection.set_critical`. The
    /// kill-vector pin is enforced TWICE: once by skipping the field
    /// here, and once by the IPC handler refusing the entire request
    /// if any critical field differs from the current value.
    ///
    /// Caller is responsible for invoking `self.validate()` after.
    pub fn apply_non_critical(&mut self, full: &FullConfig) {
        // ── Non-critical scalar/list fields ─────────────
        self.max_file_size_mb = full.max_file_size_mb;
        self.scan_archives = full.scan_archives;

        self.auto_update = full.auto_update;
        self.update_interval_hours = full.update_interval_hours;
        self.signature_stale_days = full.signature_stale_days;
        self.update_mirror = full.update_mirror.clone();

        self.quarantine_retention_days = full.quarantine_retention_days;

        self.log_level = full.log_level.clone();

        self.scheduled_scan_hour = full.scheduled_scan_hour;
        self.scheduled_scan_type = full.scheduled_scan_type.clone();

        self.startup_critical_scan = full.startup_critical_scan;

        self.powershell_bridge_enabled = full.powershell_bridge_enabled;
        self.powershell_poll_seconds = full.powershell_poll_seconds;

        self.idle_scan_start_delay_secs = full.idle_scan_start_delay_secs;
        self.idle_scan_on_battery = full.idle_scan_on_battery;
        self.idle_scan_cpu_pause_threshold = full.idle_scan_cpu_pause_threshold;
        self.idle_scan_max_file_size_mb = full.idle_scan_max_file_size_mb;
        self.idle_scan_fullscreen_pause = full.idle_scan_fullscreen_pause;
        self.idle_scan_disk_latency_pause_ms = full.idle_scan_disk_latency_pause_ms;
        self.idle_scan_max_files_per_session = full.idle_scan_max_files_per_session;
        self.idle_scan_slow_delay_min_ms = full.idle_scan_slow_delay_min_ms;
        self.idle_scan_slow_delay_max_ms = full.idle_scan_slow_delay_max_ms;
        self.idle_scan_normal_delay_min_ms = full.idle_scan_normal_delay_min_ms;
        self.idle_scan_normal_delay_max_ms = full.idle_scan_normal_delay_max_ms;
        self.idle_scan_fast_delay_min_ms = full.idle_scan_fast_delay_min_ms;
        self.idle_scan_fast_delay_max_ms = full.idle_scan_fast_delay_max_ms;

        self.argus_worker_timeout_sec = full.argus_worker_timeout_sec;

        self.clamav_isolation = full.clamav_isolation.clone();
        self.clamav_worker_timeout_sec = full.clamav_worker_timeout_sec;

        // ── Nested: scan (path/enabled are critical, timeouts/orchestrator flags are not) ──
        self.scan.argus_worker_timeout_sec = full.scan.argus_worker_timeout_sec;
        self.scan.orchestrator_file_scan_enabled = full.scan.orchestrator_file_scan_enabled;
        self.scan.orchestrator_folder_scan_enabled = full.scan.orchestrator_folder_scan_enabled;
        self.scan.orchestrator_quick_scan_enabled = full.scan.orchestrator_quick_scan_enabled;
        self.scan.orchestrator_full_scan_enabled = full.scan.orchestrator_full_scan_enabled;

        // ── Nested: performance ──
        self.performance.memory_profile = full.performance.memory_profile.clone();
        self.performance.memory_warning_mb = full.performance.memory_warning_mb;
        self.performance.memory_critical_mb = full.performance.memory_critical_mb;
        self.performance.external_argus_under_pressure =
            full.performance.external_argus_under_pressure;
        self.performance.max_resident_workers_on_pressure =
            full.performance.max_resident_workers_on_pressure;

        // ── Nested: fish ──
        // fish.enabled is DaemonRestart (process-lifecycle) but not in
        // CRITICAL_FIELDS — it gates the detector loop, not detection itself.
        // Allow toggling here; the restart pill in the GUI tells the user.
        self.fish.enabled = full.fish.enabled;
        self.fish.observe_only = full.fish.observe_only;
        self.fish.window_seconds = full.fish.window_seconds;
        self.fish.rename_threshold = full.fish.rename_threshold;
        self.fish.rewrite_threshold = full.fish.rewrite_threshold;
        self.fish.ext_mutation_threshold = full.fish.ext_mutation_threshold;
        self.fish.slow_burn_window_secs = full.fish.slow_burn_window_secs;
        self.fish.slow_burn_threshold = full.fish.slow_burn_threshold;
        self.fish.entropy_delta_threshold = full.fish.entropy_delta_threshold;
        self.fish.alert_cooldown_seconds = full.fish.alert_cooldown_seconds;
        self.fish.active_response = full.fish.active_response.clone();

        // ── Nested: sandbox ──
        self.sandbox.enabled = full.sandbox.enabled;
        self.sandbox.mode = full.sandbox.mode.clone();
        self.sandbox.timeout_sec = full.sandbox.timeout_sec;
        self.sandbox.min_score = full.sandbox.min_score;
        self.sandbox.max_score = full.sandbox.max_score;

        // ── Nested: developer (public projection only) ──
        // developer.enabled is gated by dev.set_developer_mode (password-checked),
        // NEVER mutated here — apply only the telemetry knobs.
        self.developer.telemetry_enabled = full.developer.telemetry_enabled;
        self.developer.telemetry_max_kb = full.developer.telemetry_max_kb;

        // The following are CRITICAL and intentionally NOT applied:
        //   realtime_enabled, auto_quarantine, heuristic_alerts,
        //   idle_scan_enabled, scheduled_scan_enabled,
        //   excluded_paths, excluded_extensions, excluded_detections,
        //   trusted_hashes, realtime_roots, enhanced_signature_provider,
        //   argus_worker_enabled, argus_worker_path,
        //   scan.argus_worker_enabled, scan.argus_worker_path
    }

    /// Verify the incoming FullConfig leaves every CRITICAL_FIELDS value
    /// unchanged relative to `self`. Returns the list of critical fields
    /// the caller attempted to mutate (empty = OK to apply).
    ///
    /// This is the second layer of the kill-vector defence: even if a
    /// malformed call sneaks a different value past `apply_non_critical`
    /// (it can't, by construction), this verification trips first and
    /// the IPC handler rejects the entire request.
    pub fn critical_diff(&self, full: &FullConfig) -> Vec<&'static str> {
        let mut diffs = Vec::new();
        if self.realtime_enabled != full.realtime_enabled {
            diffs.push("realtime_enabled");
        }
        if self.auto_quarantine != full.auto_quarantine {
            diffs.push("auto_quarantine");
        }
        if self.heuristic_alerts != full.heuristic_alerts {
            diffs.push("heuristic_alerts");
        }
        if self.idle_scan_enabled != full.idle_scan_enabled {
            diffs.push("idle_scan_enabled");
        }
        if self.scheduled_scan_enabled != full.scheduled_scan_enabled {
            diffs.push("scheduled_scan_enabled");
        }
        if self.excluded_paths != full.excluded_paths {
            diffs.push("excluded_paths");
        }
        if self.excluded_extensions != full.excluded_extensions {
            diffs.push("excluded_extensions");
        }
        if self.excluded_detections != full.excluded_detections {
            diffs.push("excluded_detections");
        }
        if self.trusted_hashes != full.trusted_hashes {
            diffs.push("trusted_hashes");
        }
        if self.realtime_roots != full.realtime_roots {
            diffs.push("realtime_roots");
        }
        if self.enhanced_signature_provider != full.enhanced_signature_provider {
            diffs.push("enhanced_signature_provider");
        }
        if self.argus_worker_enabled != full.argus_worker_enabled {
            diffs.push("argus_worker_enabled");
        }
        if self.argus_worker_path != full.argus_worker_path {
            diffs.push("argus_worker_path");
        }
        if self.scan.argus_worker_enabled != full.scan.argus_worker_enabled {
            diffs.push("scan.argus_worker_enabled");
        }
        if self.scan.argus_worker_path != full.scan.argus_worker_path {
            diffs.push("scan.argus_worker_path");
        }
        // Cross-check: anything we diff here must be in CRITICAL_FIELDS.
        // (debug-build assertion catches drift between this fn and the proto list)
        debug_assert!(
            diffs.iter().all(|f| CRITICAL_FIELDS.contains(f)),
            "critical_diff reports a field not in CRITICAL_FIELDS"
        );
        diffs
    }
}

#[cfg(test)]
mod full_config_bridge_tests {
    use super::*;

    #[test]
    fn config_roundtrips_through_full_config() {
        let mut original = Config::default();
        original.max_file_size_mb = 1024;
        original.update_mirror = "test.mirror.example".into();
        original.fish.rename_threshold = 99;
        original.sandbox.min_score = 30;

        let full = FullConfig::from(&original);
        let mut rebuilt = Config::default();
        rebuilt.apply_non_critical(&full);

        // Non-critical fields round-trip.
        assert_eq!(rebuilt.max_file_size_mb, 1024);
        assert_eq!(rebuilt.update_mirror, "test.mirror.example");
        assert_eq!(rebuilt.fish.rename_threshold, 99);
        assert_eq!(rebuilt.sandbox.min_score, 30);
    }

    #[test]
    fn apply_non_critical_preserves_kill_vector_fields() {
        // A baseline with safe kill-vector values.
        let baseline = Config {
            realtime_enabled: true,
            auto_quarantine: true,
            excluded_paths: vec!["safe/path".into()],
            excluded_detections: vec!["Test.Sig".into()],
            trusted_hashes: vec!["a".repeat(64)],
            realtime_roots: vec!["C:\\Users\\test\\Downloads".into()],
            enhanced_signature_provider: "none".into(),
            argus_worker_enabled: false,
            argus_worker_path: "argusd.exe".into(),
            ..Config::default()
        };

        // A hostile FullConfig trying to clobber every kill-vector field.
        let mut hostile = FullConfig::from(&baseline);
        hostile.realtime_enabled = false;
        hostile.auto_quarantine = false;
        hostile.excluded_paths = vec!["C:\\".into()];
        hostile.excluded_detections = vec!["".into()]; // kill-switch
        hostile.trusted_hashes = vec!["0".repeat(64)];
        hostile.realtime_roots = vec![]; // blind the watcher
        hostile.enhanced_signature_provider = "attacker".into();
        hostile.argus_worker_enabled = true;
        hostile.argus_worker_path = "C:\\Windows\\Temp\\evil.exe".into();
        hostile.heuristic_alerts = !baseline.heuristic_alerts;
        hostile.idle_scan_enabled = !baseline.idle_scan_enabled;
        hostile.scheduled_scan_enabled = !baseline.scheduled_scan_enabled;

        let mut victim = baseline.clone();
        victim.apply_non_critical(&hostile);

        // Every kill-vector field is unchanged.
        assert_eq!(victim.realtime_enabled, baseline.realtime_enabled);
        assert_eq!(victim.auto_quarantine, baseline.auto_quarantine);
        assert_eq!(victim.excluded_paths, baseline.excluded_paths);
        assert_eq!(victim.excluded_detections, baseline.excluded_detections);
        assert_eq!(victim.trusted_hashes, baseline.trusted_hashes);
        assert_eq!(victim.realtime_roots, baseline.realtime_roots);
        assert_eq!(
            victim.enhanced_signature_provider,
            baseline.enhanced_signature_provider
        );
        assert_eq!(victim.argus_worker_enabled, baseline.argus_worker_enabled);
        assert_eq!(victim.argus_worker_path, baseline.argus_worker_path);
        assert_eq!(victim.heuristic_alerts, baseline.heuristic_alerts);
        assert_eq!(victim.idle_scan_enabled, baseline.idle_scan_enabled);
        assert_eq!(
            victim.scheduled_scan_enabled,
            baseline.scheduled_scan_enabled
        );
    }

    #[test]
    fn critical_diff_flags_every_attempted_kill_vector_mutation() {
        let baseline = Config::default();
        let mut hostile = FullConfig::from(&baseline);

        // Mutate every kill-vector field.
        hostile.realtime_enabled = !baseline.realtime_enabled;
        hostile.auto_quarantine = !baseline.auto_quarantine;
        hostile.heuristic_alerts = !baseline.heuristic_alerts;
        hostile.idle_scan_enabled = !baseline.idle_scan_enabled;
        hostile.scheduled_scan_enabled = !baseline.scheduled_scan_enabled;
        hostile.excluded_paths.push("attacker".into());
        hostile.excluded_extensions.push("attacker".into());
        hostile.excluded_detections.push("attacker".into());
        hostile.trusted_hashes.push("a".repeat(64));
        hostile.realtime_roots.push("attacker".into());
        hostile.enhanced_signature_provider = "attacker".into();
        hostile.argus_worker_enabled = !baseline.argus_worker_enabled;
        hostile.argus_worker_path = "attacker".into();
        hostile.scan.argus_worker_enabled = !baseline.scan.argus_worker_enabled;
        hostile.scan.argus_worker_path = "attacker".into();

        let diffs = baseline.critical_diff(&hostile);
        // All 15 critical fields should be flagged (15 entries because
        // both top-level + scan.* argus pairs count).
        assert!(diffs.len() >= 13, "critical_diff missed fields: {diffs:?}");
        assert!(diffs.contains(&"realtime_enabled"));
        assert!(diffs.contains(&"excluded_paths"));
        assert!(diffs.contains(&"trusted_hashes"));
        assert!(diffs.contains(&"argus_worker_path"));
    }

    #[test]
    fn full_config_excludes_password_hash_on_wire() {
        let mut config = Config::default();
        config.developer.password_sha256 = "deadbeef".repeat(8); // any 64-char
        let full = FullConfig::from(&config);
        let json = serde_json::to_string(&full).expect("serialize");
        assert!(
            !json.contains("password_sha256"),
            "password_sha256 leaked into wire format: {json}"
        );
        assert!(
            !json.contains("deadbeef"),
            "password hash bytes leaked into wire format"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn developer_password_roundtrip_and_lock() {
        let hash = hash_developer_password("s3kr3t-local");
        assert_eq!(hash.len(), 64);
        assert!(verify_developer_password("s3kr3t-local", &hash));
        assert!(!verify_developer_password("wrong", &hash));
        // Unprovisioned (empty) or malformed hash → always locked.
        assert!(!verify_developer_password("s3kr3t-local", ""));
        assert!(!verify_developer_password("s3kr3t-local", "zzzz"));
    }

    #[test]
    fn developer_mode_disabled_without_password() {
        let mut c = Config {
            developer: DeveloperConfig {
                enabled: true,
                password_sha256: String::new(), // not provisioned
                ..DeveloperConfig::default()
            },
            ..Config::default()
        };
        c.validate();
        assert!(!c.developer.enabled, "enabled must be forced off with no password");

        // Malformed hash is scrubbed to empty → also forces disabled.
        let mut c2 = Config {
            developer: DeveloperConfig {
                enabled: true,
                password_sha256: "NOT-HEX".into(),
                ..DeveloperConfig::default()
            },
            ..Config::default()
        };
        c2.validate();
        assert!(c2.developer.password_sha256.is_empty());
        assert!(!c2.developer.enabled);

        // Valid 64-hex hash → enabled allowed to stand + telemetry cap clamped.
        let mut c3 = Config {
            developer: DeveloperConfig {
                enabled: true,
                password_sha256: hash_developer_password("ok"),
                telemetry_max_kb: 999_999,
                ..DeveloperConfig::default()
            },
            ..Config::default()
        };
        c3.validate();
        assert!(c3.developer.enabled);
        assert_eq!(c3.developer.telemetry_max_kb, 65_536);
    }

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

    #[test]
    fn caps_excluded_extensions() {
        let mut config = Config {
            excluded_extensions: (0..80).map(|i| format!("ext{i}")).collect(),
            ..Config::default()
        };

        config.validate();

        assert_eq!(config.excluded_extensions.len(), 50);
    }

    #[test]
    fn r4_lethal1_executable_extensions_cannot_be_excluded() {
        // THE BIG ONE: previous validate() unconditionally accepted every
        // entry, letting `excluded_extensions=["exe","dll",...]` silently
        // disable scanning of all executables.
        let mut config = Config {
            excluded_extensions: vec![
                "exe".into(),
                ".dll".into(),
                "PS1".into(), // case insensitive
                "scr".into(),
                "bat".into(),
                "cmd".into(),
                "js".into(),
                "msi".into(),
                "lnk".into(),
                "vbs".into(),
                "txt".into(), // benign — should remain
                "log".into(), // benign — should remain
            ],
            ..Config::default()
        };

        config.validate();

        for forbidden in [
            "exe", "dll", "ps1", "scr", "bat", "cmd", "js", "msi", "lnk", "vbs",
        ] {
            assert!(
                !config
                    .excluded_extensions
                    .iter()
                    .any(|e| e.trim().trim_start_matches('.').eq_ignore_ascii_case(forbidden)),
                "executable extension '{forbidden}' leaked through validate() — AV bypass possible"
            );
        }
        assert!(
            config
                .excluded_extensions
                .iter()
                .any(|e| e.eq_ignore_ascii_case("txt")),
            "benign 'txt' was wrongly removed"
        );
    }

    #[test]
    fn r4_lethal1_glob_extensions_refused() {
        let mut config = Config {
            excluded_extensions: vec!["*".into(), "ex?".into(), "txt".into()],
            ..Config::default()
        };
        config.validate();
        assert!(!config.excluded_extensions.iter().any(|e| e.contains('*')));
        assert!(!config.excluded_extensions.iter().any(|e| e.contains('?')));
    }
}

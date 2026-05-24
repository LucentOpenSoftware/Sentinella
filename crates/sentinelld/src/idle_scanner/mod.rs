//! Resource-aware idle background scanner.
//!
//! Proactively scans dormant files that were never seen by the watcher.
//! Asks: "Can I scan without the user noticing?" — not "Is the user away?"
//!
//! Uses CPU load, disk pressure, battery state, and fullscreen detection
//! to decide when to scan. Continues during passive browsing/reading.
//! Pauses during games, compilation, heavy disk I/O, or battery mode.

pub mod resources;

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use rand::Rng;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::engine::ClamEngine;
use crate::ipc::AppState;
use crate::scan::cache::ScanCache;
use resources::{PauseReason, ResourceConfig, check_resources, screen_locked_or_away};

/// Idle scanner speed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanSpeed {
    Slow,   // First 5 min of idle window
    Normal, // Stable idle
    Fast,   // Screen locked / user away
}

/// Observable scanner state for IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdleScannerState {
    Disabled,
    WaitingForCapacity,
    ScanningSlow,
    ScanningNormal,
    ScanningFast,
    PausedCpu,
    PausedDisk,
    PausedFullscreen,
    PausedBattery,
    PausedScanRunning,
    Completed,
}

/// Stats exposed via IPC.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdleScannerStats {
    pub state: IdleScannerState,
    pub files_scanned_session: u64,
    pub current_target: String,
    pub last_pause_reason: String,
    pub last_completed: Option<i64>,
}

/// The idle scanner handle.
pub struct IdleScanner {
    running: Arc<AtomicBool>,
    files_scanned: Arc<AtomicU64>,
    state: Arc<Mutex<IdleScannerState>>,
    current_target: Arc<Mutex<String>>,
    last_pause_reason: Arc<Mutex<String>>,
    last_completed: Arc<Mutex<Option<i64>>>,
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl IdleScanner {
    pub fn start(
        config: Config,
        engine: Arc<ClamEngine>,
        app_state: Arc<AppState>,
        cache: Arc<ScanCache>,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let files_scanned = Arc::new(AtomicU64::new(0));
        let state = Arc::new(Mutex::new(IdleScannerState::WaitingForCapacity));
        let current_target = Arc::new(Mutex::new(String::new()));
        let last_pause_reason = Arc::new(Mutex::new(String::new()));
        let last_completed = Arc::new(Mutex::new(None));

        let r = Arc::clone(&running);
        let fs = Arc::clone(&files_scanned);
        let st = Arc::clone(&state);
        let ct = Arc::clone(&current_target);
        let lp = Arc::clone(&last_pause_reason);
        let lc = Arc::clone(&last_completed);

        let thread = std::thread::Builder::new()
            .name("idle-scanner".into())
            .spawn(move || {
                idle_scanner_loop(config, engine, app_state, cache, r, fs, st, ct, lp, lc);
            })
            .expect("failed to spawn idle scanner thread");

        info!("idle background scanner started");

        Self {
            running,
            files_scanned,
            state,
            current_target,
            last_pause_reason,
            last_completed,
            _thread: Some(thread),
        }
    }

    pub fn stats(&self) -> IdleScannerStats {
        IdleScannerStats {
            state: *self.state.lock().unwrap_or_else(|e| e.into_inner()),
            files_scanned_session: self.files_scanned.load(Ordering::Relaxed),
            current_target: self
                .current_target
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            last_pause_reason: self
                .last_pause_reason
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            last_completed: *self
                .last_completed
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        }
    }

    #[allow(dead_code)] // Used during graceful shutdown (future).
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for IdleScanner {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Priority-ordered scan targets.
fn build_scan_targets() -> Vec<PathBuf> {
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let temp = std::env::var("TEMP").unwrap_or_else(|_| format!("{home}\\AppData\\Local\\Temp"));
    let appdata = std::env::var("APPDATA").unwrap_or_else(|_| format!("{home}\\AppData\\Roaming"));
    let localappdata =
        std::env::var("LOCALAPPDATA").unwrap_or_else(|_| format!("{home}\\AppData\\Local"));

    [
        format!("{home}\\Downloads"),
        format!("{home}\\Desktop"),
        temp,
        appdata,
        localappdata,
        format!("{home}\\Documents"),
    ]
    .into_iter()
    .map(PathBuf::from)
    .filter(|p| p.exists())
    .collect()
}

/// Classify file priority for scan order.
/// Lower = scan first. 0 = highest priority.
fn file_priority(path: &Path) -> u8 {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        // Executables / scripts — highest priority.
        "exe" | "dll" | "scr" | "com" | "pif" => 0,
        "bat" | "cmd" | "ps1" | "vbs" | "js" | "wsh" | "wsf" => 1,
        "msi" | "msix" | "appx" => 2,
        // Archives / containers — may contain threats.
        "zip" | "rar" | "7z" | "tar" | "gz" | "iso" | "cab" => 3,
        // Documents with macro capability.
        "doc" | "docx" | "docm" | "xls" | "xlsx" | "xlsm" | "ppt" | "pptx" | "pptm" | "pdf" => 4,
        // Shortcuts / links.
        "lnk" | "url" => 5,
        // Registry / config that could be malicious.
        "reg" | "inf" => 6,
        // Everything else — lowest priority.
        _ => 10,
    }
}

/// Collect files from a directory, sorted by priority.
fn collect_scannable_files(
    dir: &Path,
    max_size: u64,
    max_count: usize,
    excluded_paths: &[String],
    excluded_extensions: &[String],
) -> Vec<PathBuf> {
    let mut files: Vec<(PathBuf, u8, u64)> = Vec::new();

    if std::fs::read_dir(dir).is_err() {
        return vec![];
    }

    fn walk_recursive(
        dir: &Path,
        files: &mut Vec<(PathBuf, u8, u64)>,
        max_size: u64,
        max_count: usize,
        excluded_paths: &[String],
        excluded_extensions: &[String],
        depth: u32,
    ) {
        if depth > 8 {
            return;
        } // Limit recursion depth.
        if files.len() >= max_count {
            return;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            if files.len() >= max_count {
                break;
            }

            let path = entry.path();

            // Skip build/dev/sentinella dirs.
            if path.is_dir() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();

                // Skip noisy directories.
                if matches!(
                    name.as_str(),
                    "target"
                        | "node_modules"
                        | ".git"
                        | "dist"
                        | "build"
                        | ".next"
                        | ".vite"
                        | ".cargo"
                        | ".rustup"
                        | ".npm"
                        | "__pycache__"
                        | ".fingerprint"
                        | "incremental"
                        | ".gradle"
                        | ".m2"
                        | ".nuget"
                        | ".pnpm-store"
                ) {
                    continue;
                }

                if crate::scan::is_sentinella_path(&path) {
                    continue;
                }
                if crate::scan::is_excluded(&path, excluded_paths, excluded_extensions) {
                    continue;
                }

                walk_recursive(
                    &path,
                    files,
                    max_size,
                    max_count,
                    excluded_paths,
                    excluded_extensions,
                    depth + 1,
                );
                continue;
            }

            if !path.is_file() {
                continue;
            }
            if path.is_symlink() {
                continue;
            }
            if crate::scan::should_skip_file(&path) {
                continue;
            }
            if crate::scan::is_sentinella_path(&path) {
                continue;
            }
            if crate::scan::is_build_or_dev_path(&path) {
                continue;
            }
            if crate::scan::is_excluded(&path, excluded_paths, excluded_extensions) {
                continue;
            }

            // Skip known-safe extensions.
            if let Some(ext) = path.extension() {
                let el = ext.to_string_lossy().to_lowercase();
                if matches!(
                    el.as_str(),
                    "jpg"
                        | "jpeg"
                        | "png"
                        | "gif"
                        | "bmp"
                        | "webp"
                        | "svg"
                        | "ico"
                        | "woff"
                        | "woff2"
                        | "ttf"
                        | "otf"
                        | "eot"
                        | "mp3"
                        | "mp4"
                        | "mkv"
                        | "avi"
                        | "wav"
                        | "flac"
                        | "ogg"
                        | "webm"
                        | "rlib"
                        | "rmeta"
                        | "pdb"
                        | "ilk"
                        | "map"
                        | "log"
                        | "tmp"
                        | "bak"
                        | "lock"
                ) {
                    continue;
                }
            }

            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() == 0 || meta.len() > max_size {
                continue;
            }

            let prio = file_priority(&path);
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            files.push((path, prio, mtime));
        }
    }

    walk_recursive(
        dir,
        &mut files,
        max_size,
        max_count,
        excluded_paths,
        excluded_extensions,
        0,
    );

    // Sort: priority first, then most recently modified first.
    files.sort_by(|a, b| a.1.cmp(&b.1).then(b.2.cmp(&a.2)));

    files.into_iter().map(|(p, _, _)| p).collect()
}

/// Randomized sleep within range.
fn random_sleep(min_ms: u64, max_ms: u64) {
    let ms = if max_ms > min_ms {
        rand::thread_rng().gen_range(min_ms..=max_ms)
    } else {
        min_ms
    };
    std::thread::sleep(Duration::from_millis(ms));
}

/// Main loop.
#[allow(clippy::too_many_arguments)]
fn idle_scanner_loop(
    config: Config,
    engine: Arc<ClamEngine>,
    app_state: Arc<AppState>,
    cache: Arc<ScanCache>,
    running: Arc<AtomicBool>,
    files_scanned: Arc<AtomicU64>,
    state_ref: Arc<Mutex<IdleScannerState>>,
    current_target_ref: Arc<Mutex<String>>,
    last_pause_ref: Arc<Mutex<String>>,
    last_completed_ref: Arc<Mutex<Option<i64>>>,
) {
    // Lower thread priority so OS scheduler prefers user processes.
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::Threading::{
            GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL,
        };
        unsafe {
            let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        }
        info!("idle scanner: thread priority set to BELOW_NORMAL");
    }

    // Initial CPU sample (first call returns 0).
    let _ = resources::cpu_usage_percent();
    std::thread::sleep(Duration::from_secs(2));

    // Wait 30s after daemon start before beginning idle scan.
    info!("idle scanner: waiting 30s before first scan cycle");
    for _ in 0..30 {
        if !running.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    let targets = build_scan_targets();
    info!(targets = targets.len(), "idle scanner: scan targets built");

    loop {
        if !running.load(Ordering::Relaxed) {
            break;
        }

        // ── Hot-reload config from disk each cycle ──────
        let config = crate::config::Config::load(None).unwrap_or(config.clone());

        // If idle scanning was disabled via settings, pause until re-enabled.
        if !config.idle_scan_enabled {
            set_state(&state_ref, IdleScannerState::Disabled);
            info!("idle scanner: disabled via config, sleeping 10s before re-check");
            for _ in 0..10 {
                if !running.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            continue;
        }

        let res_config = ResourceConfig {
            allow_on_battery: config.idle_scan_on_battery,
            cpu_threshold: config.idle_scan_cpu_pause_threshold,
            disk_latency_threshold_ms: config.idle_scan_disk_latency_pause_ms,
            pause_on_fullscreen: config.idle_scan_fullscreen_pause,
        };

        let max_file_size = config.idle_scan_max_file_size_mb * 1024 * 1024;
        let max_files = config.idle_scan_max_files_per_session as usize;

        // ── Wait for system capacity ─────────────────────
        set_state(&state_ref, IdleScannerState::WaitingForCapacity);

        loop {
            if !running.load(Ordering::Relaxed) {
                return;
            }

            // Check memory pressure first — critical pressure pauses idle scanner.
            if app_state.should_pause_idle_for_pressure() {
                let reason = PauseReason::MemoryPressure;
                set_state(&state_ref, IdleScannerState::PausedCpu); // Reuse CPU state for UI.
                *last_pause_ref.lock().unwrap_or_else(|e| e.into_inner()) = reason.label().into();
                std::thread::sleep(Duration::from_secs(reason.sleep_secs()));
                continue;
            }

            let scan_active = app_state.is_scan_active();
            match check_resources(&res_config, scan_active) {
                Some(reason) => {
                    let pause_state = match reason {
                        PauseReason::Battery => IdleScannerState::PausedBattery,
                        PauseReason::Fullscreen => IdleScannerState::PausedFullscreen,
                        PauseReason::HighCpu => IdleScannerState::PausedCpu,
                        PauseReason::HighDisk => IdleScannerState::PausedDisk,
                        PauseReason::ScanRunning => IdleScannerState::PausedScanRunning,
                        PauseReason::MemoryPressure => IdleScannerState::PausedCpu,
                    };
                    set_state(&state_ref, pause_state);
                    *last_pause_ref.lock().unwrap_or_else(|e| e.into_inner()) =
                        reason.label().into();
                    std::thread::sleep(Duration::from_secs(reason.sleep_secs()));
                }
                None => break, // System has capacity → start scanning.
            }
        }

        // ── Scan cycle ───────────────────────────────────
        let cycle_start = Instant::now();
        let mut total_this_cycle: u64 = 0;

        for target_dir in &targets {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            let dir_name = target_dir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            *current_target_ref.lock().unwrap_or_else(|e| e.into_inner()) = dir_name.clone();
            info!(dir = %target_dir.display(), "idle scanner: scanning directory");

            let files = collect_scannable_files(
                target_dir,
                max_file_size,
                max_files,
                &config.excluded_paths,
                &config.excluded_extensions,
            );
            debug!(dir = %dir_name, files = files.len(), "idle scanner: files collected");

            for file_path in &files {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                if total_this_cycle >= max_files as u64 {
                    break;
                }

                // ── Resource check before each file ──────
                // Memory pressure check — break scan cycle if critical.
                if app_state.should_pause_idle_for_pressure() {
                    set_state(&state_ref, IdleScannerState::PausedCpu);
                    *last_pause_ref.lock().unwrap_or_else(|e| e.into_inner()) =
                        "memory_pressure".into();
                    break;
                }
                let scan_active = app_state.is_scan_active();
                if let Some(reason) = check_resources(&res_config, scan_active) {
                    let pause_state = match reason {
                        PauseReason::Battery => IdleScannerState::PausedBattery,
                        PauseReason::Fullscreen => IdleScannerState::PausedFullscreen,
                        PauseReason::HighCpu => IdleScannerState::PausedCpu,
                        PauseReason::HighDisk => IdleScannerState::PausedDisk,
                        PauseReason::ScanRunning => IdleScannerState::PausedScanRunning,
                        PauseReason::MemoryPressure => IdleScannerState::PausedCpu,
                    };
                    set_state(&state_ref, pause_state);
                    *last_pause_ref.lock().unwrap_or_else(|e| e.into_inner()) =
                        reason.label().into();
                    std::thread::sleep(Duration::from_secs(reason.sleep_secs()));

                    // After pause, recheck.
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    continue; // Re-enter loop, will re-check resources.
                }

                // ── Adaptive speed ───────────────────────
                let speed = if screen_locked_or_away() {
                    ScanSpeed::Fast
                } else if cycle_start.elapsed() > Duration::from_secs(300) {
                    ScanSpeed::Normal
                } else {
                    ScanSpeed::Slow
                };

                let scan_state = match speed {
                    ScanSpeed::Slow => IdleScannerState::ScanningSlow,
                    ScanSpeed::Normal => IdleScannerState::ScanningNormal,
                    ScanSpeed::Fast => IdleScannerState::ScanningFast,
                };
                set_state(&state_ref, scan_state);

                // ── Cache check ──────────────────────────
                let file_meta = match std::fs::metadata(file_path) {
                    Ok(meta) => meta,
                    Err(_) => continue,
                };

                if let Some(true) = cache.check_with_metadata(file_path, &file_meta) {
                    continue; // Already scanned clean.
                }

                // ── Verify readable ──────────────────────
                if std::fs::File::open(file_path).is_err() {
                    continue;
                }

                // ── Budget-bounded idle scan ─────────────
                let idle_budget = argus::budget::ScanExecutionBudget::idle();
                let idle_tracker = argus::budget::BudgetTracker::new(
                    idle_budget,
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                );

                let idle_cancel = std::sync::atomic::AtomicBool::new(false);
                let clamav_start = std::time::Instant::now();
                let clam_result = app_state.scan_file_clamav(&engine, file_path, &idle_cancel);
                if idle_tracker.phase_expired(clamav_start, idle_tracker.budget().max_clamav_duration) {
                    idle_tracker.record_timeout(argus::budget::TimeoutReason::ClamAvTimeout);
                }

                // ARGUS analysis (skip if total budget exhausted).
                let argus_verdict = if idle_tracker.is_expired() {
                    idle_tracker.record_timeout(argus::budget::TimeoutReason::TotalTimeout);
                    debug!(file = %file_path.display(), "idle budget exhausted, skipping ARGUS");
                    argus::ArgusVerdict {
                        path: file_path.to_string_lossy().to_string(),
                        file_size: file_meta.len(),
                        sha256: String::new(),
                        mime_type: None,
                        score: 0,
                        verdict: argus::verdict::Verdict::Clean,
                        findings: vec![],
                        analysis_time_us: 0,
                        engine_version: argus::ENGINE_VERSION,
                        timestamp: chrono::Utc::now().timestamp(),
                        explanation: argus::verdict::VerdictExplanation::default(),
                        timing: None,
                    }
                } else {
                    let argus_start = std::time::Instant::now();
                    let v = app_state.argus().analyze_file(file_path);
                    if idle_tracker.phase_expired(argus_start, idle_tracker.budget().max_yara_duration) {
                        idle_tracker.record_timeout(argus::budget::TimeoutReason::YaraTimeout);
                    }
                    v
                };

                let (is_threat, threat_name_opt) = crate::ipc::unify_detection_filtered(
                    clam_result.infected,
                    clam_result.virus_name.as_deref(),
                    &argus_verdict,
                    &app_state.detection_exclusions(),
                );

                if clam_result.error.is_none() {
                    cache.record_with_metadata(file_path, &file_meta, !is_threat);
                }
                total_this_cycle += 1;
                files_scanned.fetch_add(1, Ordering::Relaxed);

                if is_threat {
                    let threat_name = threat_name_opt.unwrap_or_default();
                    warn!(
                        file = %file_path.display(),
                        threat = %threat_name,
                        argus_score = argus_verdict.score,
                        "IDLE SCANNER THREAT DETECTED",
                    );
                    let path_str = file_path.to_string_lossy().to_string();
                    match app_state.quarantine_file(&path_str, &threat_name, "idle_scan") {
                        Ok(q) => info!(id = %q.quarantine_id, "idle scan: auto-quarantined"),
                        Err(e) => warn!(%e, "idle scan: quarantine failed"),
                    }
                }

                // ── Randomized sleep ─────────────────────
                let (min_ms, max_ms) = match speed {
                    ScanSpeed::Slow => (
                        config.idle_scan_slow_delay_min_ms,
                        config.idle_scan_slow_delay_max_ms,
                    ),
                    ScanSpeed::Normal => (
                        config.idle_scan_normal_delay_min_ms,
                        config.idle_scan_normal_delay_max_ms,
                    ),
                    ScanSpeed::Fast => (
                        config.idle_scan_fast_delay_min_ms,
                        config.idle_scan_fast_delay_max_ms,
                    ),
                };
                random_sleep(min_ms, max_ms);
            }
        }

        // ── Cycle complete ───────────────────────────────
        set_state(&state_ref, IdleScannerState::Completed);
        *current_target_ref.lock().unwrap_or_else(|e| e.into_inner()) = String::new();
        *last_completed_ref.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(chrono::Utc::now().timestamp());

        info!(
            files = total_this_cycle,
            elapsed_secs = cycle_start.elapsed().as_secs(),
            "idle scanner: cycle complete",
        );

        app_state.log_activity(
            "info",
            "idle_scan",
            &format!("Background scan complete — {total_this_cycle} files checked"),
            "",
            None,
        );

        // Wait before next cycle — long pause (30-60 min).
        let wait_secs = rand::thread_rng().gen_range(1800..=3600);
        info!(wait_secs, "idle scanner: sleeping until next cycle");
        for _ in 0..wait_secs {
            if !running.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    info!("idle scanner loop exited");
}

fn set_state(state: &Arc<Mutex<IdleScannerState>>, new: IdleScannerState) {
    if let Ok(mut s) = state.lock() {
        *s = new;
    }
}

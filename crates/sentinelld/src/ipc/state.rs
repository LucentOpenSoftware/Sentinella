//! Daemon runtime state — the single source of truth.
//!
//! Supports background Quick Scan with progress tracking and cancellation.
//!
//! ## Lock Safety
//!
//! All `Mutex` and `RwLock` access uses poison-recovering helpers
//! (`lock_inner`, `read_engine`, `write_engine`) so a panic in one
//! request never brings down the entire daemon.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::Instant;
use uuid::Uuid;

use sentinella_ipc_proto::engine::{EngineState, EngineStatus};
#[allow(unused_imports)]
use sentinella_ipc_proto::quarantine::QuarantineEntry;
use sentinella_ipc_proto::update::{UpdateState, UpdateStatus};
use sentinella_ipc_proto::watcher::{WatcherMode, WatcherStatus};

use crate::db::{ActivityRow, Database, DetectionRow, ScanRow};
use crate::engine::ClamEngine;

/// Default max file size to scan (512 MB). Overridden by config.max_file_size_mb.
const DEFAULT_MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Get max file size from config (or default).
fn max_file_size() -> u64 {
    crate::config::Config::load(None)
        .map(|c| c.max_file_size_mb * 1024 * 1024)
        .unwrap_or(DEFAULT_MAX_FILE_SIZE)
}

/// Number of parallel scan threads for background scans.
const SCAN_THREADS: usize = 4;

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn generate_ipc_secret() -> String {
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn load_or_create_ipc_secret() -> Option<String> {
    let path = ipc_secret_path();
    let env_secret = std::env::var("SENTINELLA_IPC_SECRET")
        .ok()
        .filter(|s| s.len() >= 32);

    if let Some(secret) = env_secret {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&path, &secret);
        }
        return Some(secret);
    }

    if let Ok(secret) = std::fs::read_to_string(&path) {
        let trimmed = secret.trim().to_string();
        if trimmed.len() >= 32 {
            return Some(trimmed);
        }
    }

    let secret = generate_ipc_secret();
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            tracing::warn!("cannot create IPC secret directory");
            return None;
        }
    }
    match std::fs::write(&path, &secret) {
        Ok(()) => Some(secret),
        Err(e) => {
            tracing::warn!(%e, "cannot persist IPC secret");
            None
        }
    }
}

fn ipc_secret_path() -> PathBuf {
    // Dev mode: if running from project tree (CWD has crates/sentinelld),
    // use project-local runtime/state/ipc_secret so GUI can find the same file.
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("crates").join("sentinelld").exists() {
            return cwd.join("runtime").join("state").join("ipc_secret");
        }
    }
    // Installed mode: ProgramData.
    sentinella_common::paths::data_dir()
        .join("state")
        .join("ipc_secret")
}

#[derive(Clone, Default)]
enum UpdatePhase {
    #[default]
    Idle,
    Checking,
    Downloading(String), // current database file name
    Applying,
    ReloadingEngine,
    ReloadingArgus,
    Completed,
}

/// Shared daemon state. Wrapped in `Arc` by the IPC server.
pub struct AppState {
    started_at: Instant,
    engine: RwLock<Option<Arc<ClamEngine>>>,
    engine_error: RwLock<Option<String>>,
    signature_count: std::sync::atomic::AtomicU64,
    dll_dir: Option<PathBuf>,
    db_dir: Option<PathBuf>,
    db: Mutex<Option<Database>>,
    watcher: Mutex<Option<crate::watcher::RealtimeWatcher>>,
    idle_scanner: Mutex<Option<crate::idle_scanner::IdleScanner>>,
    scan_cache: Arc<crate::scan::cache::ScanCache>,
    orchestrator: Arc<crate::orchestrator::ScanOrchestrator>,
    argus: Arc<argus::ArgusEngine>,
    argus_worker: crate::argus_worker::ArgusWorkerSettings,
    argus_worker_fallback_count: AtomicU64,
    argus_worker_timeout_count: AtomicU64,
    argus_worker_last_error: Mutex<Option<String>>,
    argus_worker_last_timeout: Mutex<Option<String>>,
    orchestrator_file_scan_enabled: bool,
    orchestrator_folder_scan_enabled: bool,
    orchestrator_quick_scan_enabled: bool,
    last_orchestrated_job: Mutex<Option<OrchestratedJobResult>>,
    orchestrated_completed_file: AtomicU64,
    orchestrated_completed_folder: AtomicU64,
    orchestrated_completed_quick: AtomicU64,
    orchestrated_cancelled_jobs: AtomicU64,
    orchestrated_failed_jobs: AtomicU64,
    ipc_secret: Option<String>,
    inner: Mutex<Inner>,
    // ── IPC health (atomic — no lock) ─────────────────
    ipc_reconnect_count: AtomicU64,
    ipc_last_error_ts: AtomicU64,
    ipc_total_requests: AtomicU64,
    // ── Lock-free scan state for IPC ──────────────────
    scan_live: Mutex<Option<Arc<ScanLiveState>>>,
    // ── Intentional protection disable ───────────────
    /// True when user explicitly paused protection (not crash).
    user_disabled_protection: std::sync::atomic::AtomicBool,
    /// Unix timestamp when protection was disabled (0 = never).
    protection_disabled_at: AtomicU64,
    // ── FISH (File Integrity Shield) ─────────────────
    fish_window: std::sync::Mutex<crate::fish::MutationWindow>,
    fish_config: crate::fish::FishConfig,
    // ── Footprint baselines ──────────────────────────
    footprint_baselines: crate::footprint::FootprintBaselines,
    // ── Memory pressure ──────────────────────────────
    pressure_tracker: crate::footprint::pressure::PressureTracker,
    performance_config: crate::config::PerformanceConfig,
    // ── ClamAV isolation config (cached) ───────────────
    clamav_subprocess_enabled: AtomicBool,
    clamav_worker_timeout_sec: AtomicU64,
    // ── Detection exclusions ──────────────────────────
    excluded_detections: std::sync::Mutex<Vec<String>>,
    // ── Trusted hashes (manual whitelist) ────────────
    trusted_hashes: std::sync::Mutex<Vec<String>>,
    // ── Daemon operating mode ─────────────────────────
    audit_mode: AtomicBool,
    // ── Resilience telemetry ─────────────────────────
    worker_panics_total: AtomicU64,
    worker_timeouts_total: AtomicU64,
    last_recovery_reason: Mutex<Option<String>>,
    /// Watcher heartbeat: unix timestamp of last watcher event.
    watcher_last_heartbeat: AtomicU64,
    /// Orchestrator heartbeat: unix timestamp of last completed job.
    orchestrator_last_heartbeat: AtomicU64,
    // ── FP Calibration ──────────────────────────────
    calibration: Mutex<Option<crate::calibration::CalibrationLog>>,
    // ── Bounded Execution counters ──────────────────
    budget_files_with_timeouts: AtomicU64,
    budget_clamav_timeouts: AtomicU64,
    budget_yara_timeouts: AtomicU64,
    budget_total_timeouts: AtomicU64,
    budget_partial_results: AtomicU64,
    budget_exhausted: AtomicU64,
    budget_realtime_timeouts: AtomicU64,
    budget_idle_timeouts: AtomicU64,
    budget_transient_skips: AtomicU64,
    // ── PLM (Process Lineage Monitor) ────────────────
    plm: Option<crate::plm::PlmMonitor>,
    // ── PowerShell bridge ──────────────────────────
    ps_bridge: Option<crate::amsi::ps_bridge::PsBridge>,
    // ── Trust Graph ────────────────────────────────
    trust_graph: Option<crate::trust_graph::TrustGraph>,
}

struct Inner {
    // ── Active scan job ────────────────────────────────
    active_scan: Option<ScanJob>,

    // ── History ────────────────────────────────────────
    scan_history: Vec<ScanRecord>,
    activity: Vec<ActivityEntry>,

    // ── Challenge token for dangerous commands ─────────
    challenge_token: Option<(String, Instant)>, // (token, created_at)

    // ── Update tracking ────────────────────────────────
    update_running: bool,
    update_phase: UpdatePhase,
    update_current_file: String,
    last_update_timestamp: Option<i64>,
    last_update_error: Option<String>,
}

/// Aggregate scan performance summary.
#[derive(Clone, Default, Serialize)]
pub struct ScanPerformanceSummary {
    pub strategy_full: u64,
    pub strategy_light: u64,
    pub strategy_signature: u64,
    pub strategy_skip: u64,
    pub strategy_too_large: u64,
    pub total_argus_us: u64,
    pub total_yara_us: u64,
    pub total_hash_us: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    /// Slowest files (path, time_us). Capped at 10.
    pub slowest_files: Vec<(String, u64)>,
}

impl ScanPerformanceSummary {
    fn record_file(&mut self, path: &str, timing: &argus::verdict::ScanTiming) {
        // Strategy counts.
        if let Some(strategy) = timing.strategy {
            match strategy {
                argus::verdict::ScanStrategy::FullAnalysis => self.strategy_full += 1,
                argus::verdict::ScanStrategy::LightAnalysis => self.strategy_light += 1,
                argus::verdict::ScanStrategy::SignatureOnly => self.strategy_signature += 1,
                argus::verdict::ScanStrategy::SkipSafe => self.strategy_skip += 1,
                argus::verdict::ScanStrategy::TooLarge => self.strategy_too_large += 1,
            }
        }
        self.total_argus_us += timing.argus_total_us;
        self.total_yara_us += timing.yara_us;
        self.total_hash_us += timing.hash_us;

        // Track slowest files (top 10).
        if timing.argus_total_us > 100_000 {
            // >100ms = notable
            self.slowest_files
                .push((path.to_string(), timing.argus_total_us));
            self.slowest_files.sort_by(|a, b| b.1.cmp(&a.1));
            if self.slowest_files.len() > 10 {
                self.slowest_files.truncate(10);
            }
        }
    }
}

/// Lightweight scan snapshot — readable without locking Inner.
/// Used by scan.status IPC to avoid blocking on worker contention.
pub struct ScanLiveState {
    pub id: String,
    pub kind: String,
    pub started_at: i64,
    pub files_total: AtomicU64,
    pub files_scanned: AtomicU64,
    pub threats_found: AtomicU64,
    pub cancel_flag: Arc<AtomicBool>,
    pub status: std::sync::atomic::AtomicU8, // 0=pending,1=running,2=completed,3=cancelled,4=failed,5=draining
    pub current_path: Mutex<String>,
}

impl ScanLiveState {
    fn status_enum(&self) -> ScanJobStatus {
        match self.status.load(Ordering::Relaxed) {
            1 => ScanJobStatus::Running,
            2 => ScanJobStatus::Completed,
            3 => ScanJobStatus::Cancelled,
            4 => ScanJobStatus::Failed,
            5 => ScanJobStatus::Draining,
            _ => ScanJobStatus::Pending,
        }
    }
    fn set_status(&self, s: ScanJobStatus) {
        self.status.store(
            match s {
                ScanJobStatus::Pending => 0,
                ScanJobStatus::Running => 1,
                ScanJobStatus::Completed => 2,
                ScanJobStatus::Cancelled => 3,
                ScanJobStatus::Failed => 4,
                ScanJobStatus::Draining => 5,
            },
            Ordering::Relaxed,
        );
    }
}

/// A running or completed scan job.
#[derive(Clone)]
struct ScanJob {
    id: Uuid,
    kind: String,
    status: ScanJobStatus,
    started_at: i64,
    finished_at: Option<i64>,
    files_scanned: u64,
    files_total: u64,
    threats_found: u64,
    current_path: String,
    detections: Vec<Detection>,
    errors: Vec<String>,
    cancel_flag: Arc<AtomicBool>,
    perf_summary: ScanPerformanceSummary,
    /// Shared live state for lock-free status reads.
    live: Option<Arc<ScanLiveState>>,
}

#[derive(Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum ScanJobStatus {
    Pending,
    Running,
    Completed,
    Cancelled,
    Failed,
    Draining,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    path: String,
    virus_name: String,
}

impl AppState {
    pub fn new(
        dll_dir: Option<PathBuf>,
        db_dir: Option<PathBuf>,
        database: Option<Database>,
    ) -> Self {
        let now_ts = chrono::Utc::now().timestamp();
        let mut activity = vec![ActivityEntry {
            event_type: "daemon_start".into(),
            message: "Daemon started".into(),
            detail: Some("sentinelld initializing".into()),
            timestamp: now_ts,
        }];

        let (engine, engine_error, sig_count) = match (&dll_dir, &db_dir) {
            (Some(dll), Some(db)) => match ClamEngine::load(dll, db) {
                Ok(eng) => {
                    let sigs = eng.signature_count() as u64;
                    activity.push(ActivityEntry {
                        event_type: "engine_loaded".into(),
                        message: format!("ClamAV engine loaded — {} signatures", sigs),
                        detail: Some("Engine compiled and ready to scan".into()),
                        timestamp: chrono::Utc::now().timestamp(),
                    });
                    (Some(Arc::new(eng)), None, sigs)
                }
                Err(e) => {
                    activity.push(ActivityEntry {
                        event_type: "engine_error".into(),
                        message: format!("Engine failed: {e}"),
                        detail: None,
                        timestamp: chrono::Utc::now().timestamp(),
                    });
                    (None, Some(e), 0)
                }
            },
            _ => {
                activity.push(ActivityEntry {
                    event_type: "engine_skipped".into(),
                    message: "Engine not configured".into(),
                    detail: None,
                    timestamp: chrono::Utc::now().timestamp(),
                });
                (None, Some("Not configured".into()), 0)
            }
        };

        // Persist the startup activity event.
        if let Some(ref db) = database {
            for evt in &activity {
                db.insert_activity(&ActivityRow {
                    event_id: Uuid::new_v4().to_string(),
                    timestamp: evt.timestamp,
                    severity: "info".into(),
                    category: "system".into(),
                    title: evt.message.clone(),
                    message: evt.detail.clone().unwrap_or_default(),
                    related_scan_id: None,
                });
            }
        }

        let daemon_config = crate::config::Config::load(None).unwrap_or_default();
        let argus_worker = crate::argus_worker::ArgusWorkerSettings::from_config(&daemon_config);
        let argus_engine = Arc::new(argus::ArgusEngine::with_defaults());
        activity.push(ActivityEntry {
            event_type: "argus_loaded".into(),
            message: format!(
                "ARGUS heuristics engine v{} initialized — {} layers active",
                argus::ENGINE_VERSION,
                argus_engine.stats().active_layers
            ),
            detail: Some("Layered suspicion engine ready".into()),
            timestamp: chrono::Utc::now().timestamp(),
        });

        // ── Load ARGUS intelligence packs ──────────────────
        // IOC hash database.
        let ioc_paths = [
            std::path::PathBuf::from("runtime/rules/ioc_hashes.txt"),
            std::path::PathBuf::from("runtime/argus/rules/ioc/ioc_hashes.txt"),
            std::path::PathBuf::from("runtime/signatures/ioc_hashes.txt"),
        ];
        for ioc_path in &ioc_paths {
            if ioc_path.exists() {
                match argus_engine.ioc.load_from_file(ioc_path) {
                    Ok(count) => {
                        tracing::info!(count, path = %ioc_path.display(), "IOC hash database loaded");
                        activity.push(ActivityEntry {
                            event_type: "ioc_loaded".into(),
                            message: format!("IOC database loaded — {count} hash(es)"),
                            detail: Some(format!("Source: {}", ioc_path.display())),
                            timestamp: chrono::Utc::now().timestamp(),
                        });
                    }
                    Err(e) => tracing::warn!(%e, "Failed to load IOC database"),
                }
                break;
            }
        }

        // YARA rule engine — compiled on a dedicated thread with 8 MB stack
        // because wasmtime/cranelift JIT uses deep call stacks during compilation.
        let yara_dirs = vec![
            std::path::PathBuf::from("runtime/argus/rules/yara"),
            std::path::PathBuf::from("runtime/rules"),
        ];
        let yara_result = argus_engine.yara.load_rules_on_large_stack(&yara_dirs);

        match yara_result {
            Ok(count) if count > 0 => {
                activity.push(ActivityEntry {
                    event_type: "yara_loaded".into(),
                    message: format!(
                        "ARGUS YARA engine loaded — {count} behavioral rules compiled"
                    ),
                    detail: Some(format!(
                        "Rule sources: {}",
                        yara_dirs
                            .iter()
                            .filter(|d| d.exists())
                            .map(|d| d.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                    timestamp: chrono::Utc::now().timestamp(),
                });
            }
            Ok(_) => {
                tracing::info!("No YARA rules found — YARA layer inactive");
            }
            Err(e) => {
                tracing::warn!(%e, "YARA rule compilation failed");
                activity.push(ActivityEntry {
                    event_type: "yara_error".into(),
                    message: format!("YARA rule loading failed: {e}"),
                    detail: None,
                    timestamp: chrono::Utc::now().timestamp(),
                });
            }
        }

        Self {
            started_at: Instant::now(),
            engine: RwLock::new(engine),
            engine_error: RwLock::new(engine_error),
            signature_count: std::sync::atomic::AtomicU64::new(sig_count),
            dll_dir: dll_dir.clone(),
            db_dir: db_dir.clone(),
            db: Mutex::new(database),
            watcher: Mutex::new(None),
            idle_scanner: Mutex::new(None),
            scan_cache: Arc::new(crate::scan::cache::ScanCache::with_persistence(
                &std::path::PathBuf::from("runtime/state/scan_cache.db"),
            )),
            orchestrator: crate::orchestrator::ScanOrchestrator::start(),
            argus: argus_engine,
            argus_worker,
            argus_worker_fallback_count: AtomicU64::new(0),
            argus_worker_timeout_count: AtomicU64::new(0),
            argus_worker_last_error: Mutex::new(None),
            argus_worker_last_timeout: Mutex::new(None),
            orchestrator_file_scan_enabled: daemon_config.scan.orchestrator_file_scan_enabled,
            orchestrator_folder_scan_enabled: daemon_config.scan.orchestrator_folder_scan_enabled,
            orchestrator_quick_scan_enabled: daemon_config.scan.orchestrator_quick_scan_enabled,
            last_orchestrated_job: Mutex::new(None),
            orchestrated_completed_file: AtomicU64::new(0),
            orchestrated_completed_folder: AtomicU64::new(0),
            orchestrated_completed_quick: AtomicU64::new(0),
            orchestrated_cancelled_jobs: AtomicU64::new(0),
            orchestrated_failed_jobs: AtomicU64::new(0),
            ipc_secret: load_or_create_ipc_secret(),
            ipc_reconnect_count: AtomicU64::new(0),
            ipc_last_error_ts: AtomicU64::new(0),
            ipc_total_requests: AtomicU64::new(0),
            scan_live: Mutex::new(None),
            user_disabled_protection: std::sync::atomic::AtomicBool::new(false),
            protection_disabled_at: AtomicU64::new(0),
            fish_config: crate::fish::FishConfig::default(),
            fish_window: std::sync::Mutex::new(crate::fish::MutationWindow::new(
                &crate::fish::FishConfig::default(),
            )),
            footprint_baselines: crate::footprint::FootprintBaselines::new(),
            pressure_tracker: crate::footprint::pressure::PressureTracker::new(),
            performance_config: crate::config::PerformanceConfig::default(),
            clamav_subprocess_enabled: AtomicBool::new(false),
            clamav_worker_timeout_sec: AtomicU64::new(30),
            excluded_detections: std::sync::Mutex::new(Vec::new()),
            trusted_hashes: std::sync::Mutex::new(Vec::new()),
            audit_mode: AtomicBool::new(false),
            worker_panics_total: AtomicU64::new(0),
            worker_timeouts_total: AtomicU64::new(0),
            last_recovery_reason: Mutex::new(None),
            watcher_last_heartbeat: AtomicU64::new(0),
            orchestrator_last_heartbeat: AtomicU64::new(0),
            calibration: Mutex::new(
                crate::calibration::CalibrationLog::open(
                    &std::path::PathBuf::from("runtime/state/calibration.db"),
                )
                .ok(),
            ),
            budget_files_with_timeouts: AtomicU64::new(0),
            budget_clamav_timeouts: AtomicU64::new(0),
            budget_yara_timeouts: AtomicU64::new(0),
            budget_total_timeouts: AtomicU64::new(0),
            budget_partial_results: AtomicU64::new(0),
            budget_exhausted: AtomicU64::new(0),
            budget_realtime_timeouts: AtomicU64::new(0),
            budget_idle_timeouts: AtomicU64::new(0),
            budget_transient_skips: AtomicU64::new(0),
            plm: Some(crate::plm::PlmMonitor::start(5)),
            ps_bridge: None,
            trust_graph: crate::trust_graph::TrustGraph::open(
                &std::path::PathBuf::from("runtime/state/trust_graph.db"),
            ).ok(),
            inner: Mutex::new(Inner {
                active_scan: None,
                scan_history: Vec::new(),
                activity,
                challenge_token: None,
                update_running: false,
                update_phase: UpdatePhase::Idle,
                update_current_file: String::new(),
                last_update_timestamp: None,
                last_update_error: None,
            }),
        }
    }

    /// Generate a single-use challenge token for dangerous IPC commands.
    /// Token expires after 60 seconds.
    pub fn generate_challenge_token(&self) -> String {
        let token = Uuid::new_v4().to_string();
        let mut inner = self.lock_inner();
        inner.challenge_token = Some((token.clone(), Instant::now()));
        token
    }

    /// Validate GUI-owned IPC secret before issuing dangerous challenge tokens.
    pub fn validate_ipc_auth(&self, auth: &str) -> bool {
        let Some(secret) = self.ipc_secret.as_deref() else {
            tracing::warn!("dangerous IPC rejected: auth secret not configured");
            return false;
        };
        let ok = constant_time_eq(secret.as_bytes(), auth.as_bytes());
        if !ok {
            tracing::warn!("dangerous IPC rejected: invalid auth secret");
        }
        ok
    }

    /// Validate and consume a challenge token. Returns true if valid.
    pub fn validate_challenge_token(&self, token: &str) -> bool {
        let mut inner = self.lock_inner();
        if let Some((ref stored, created)) = inner.challenge_token {
            // Constant-time comparison to prevent timing attacks.
            let ct_eq = stored.len() == token.len()
                && stored
                    .bytes()
                    .zip(token.bytes())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0;
            if ct_eq && created.elapsed().as_secs() < 60 {
                inner.challenge_token = None; // Consumed — single use.
                return true;
            }
        }
        // Log failed attempt.
        drop(inner);
        self.log_activity(
            "warning",
            "security",
            "Invalid challenge token — dangerous command rejected",
            "",
            None,
        );
        false
    }

    pub fn db_ref(&self) -> &Mutex<Option<Database>> {
        &self.db
    }
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
    pub fn argus(&self) -> &argus::ArgusEngine {
        &self.argus
    }
    pub fn plm(&self) -> Option<&crate::plm::PlmMonitor> {
        self.plm.as_ref()
    }

    /// Start the PowerShell Script Block Logging bridge.
    /// Config-gated: only starts if powershell_bridge_enabled = true.
    pub fn start_ps_bridge(self: &Arc<Self>, poll_secs: u64) {
        let engine = Arc::clone(&self.argus);
        let plm_graph = self.plm.as_ref().map(|p| Arc::clone(&p.graph));
        // SAFETY: we only call this once during startup, before any concurrent access.
        // The field is private and only set here.
        let self_ptr = Arc::as_ptr(self) as *mut AppState;
        unsafe {
            (*self_ptr).ps_bridge = Some(
                crate::amsi::ps_bridge::PsBridge::start(poll_secs, engine, plm_graph)
            );
        }
        tracing::info!(poll_secs, "PowerShell Script Block Logging bridge started");
    }

    /// Access the trust graph.
    #[allow(dead_code)]
    pub fn trust_graph(&self) -> Option<&crate::trust_graph::TrustGraph> {
        self.trust_graph.as_ref()
    }

    /// Get PowerShell bridge diagnostics.
    pub fn ps_bridge_diagnostics(&self) -> serde_json::Value {
        if let Some(ref bridge) = self.ps_bridge {
            bridge.diagnostics.to_json()
        } else {
            serde_json::json!({"enabled": false})
        }
    }

    /// Scan a file with ClamAV — routes through subprocess if configured.
    pub fn scan_file_clamav(
        &self,
        engine: &crate::engine::ClamEngine,
        path: &std::path::Path,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> crate::engine::clamav::ScanResult {
        // Use cached performance config — clamav_isolation is read from there.
        // Avoids re-reading TOML from disk on every scan call.
        let use_subprocess = self.clamav_subprocess_enabled.load(Ordering::Relaxed);
        let timeout_sec = self.clamav_worker_timeout_sec.load(Ordering::Relaxed);
        if use_subprocess {
            if self.dll_dir.is_none() || self.db_dir.is_none() {
                tracing::warn!(
                    "clamav_isolation=subprocess but dll_dir/db_dir missing — using in-process"
                );
            }
            // Try subprocess worker.
            if let Some(dll_dir) = &self.dll_dir {
                if let Some(db_dir) = &self.db_dir {
                    let settings = crate::clamav_worker::ClamWorkerSettings {
                        enabled: true,
                        dll_dir: dll_dir.clone(),
                        db_dir: db_dir.clone(),
                        timeout: std::time::Duration::from_secs(timeout_sec.max(10)),
                    };
                    match crate::clamav_worker::scan_file(&settings, path, cancel) {
                        Ok(output) => {
                            return crate::engine::clamav::ScanResult {
                                path: output.path,
                                infected: output.infected,
                                virus_name: output.virus_name,
                                scanned_bytes: output.scanned_bytes,
                                error: output.error,
                            };
                        }
                        Err(e) if e.contains("cancelled") => {
                            return crate::engine::clamav::ScanResult {
                                path: path.to_string_lossy().to_string(),
                                infected: false,
                                virus_name: None,
                                scanned_bytes: 0,
                                error: Some(e),
                            };
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %e,
                                "clamavd subprocess failed — falling back to in-process"
                            );
                            // Fall through to in-process.
                        }
                    }
                }
            }
        }
        // Default: in-process scan.
        engine.scan_file(path)
    }

    pub fn argus_worker_diagnostics(&self) -> serde_json::Value {
        let last_error = self
            .argus_worker_last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let last_timeout = self
            .argus_worker_last_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        serde_json::json!({
            "enabled": self.argus_worker.enabled,
            "path": self.argus_worker.path.clone(),
            "timeout_sec": self.argus_worker.timeout.as_secs(),
            "fallback_count": self.argus_worker_fallback_count.load(Ordering::Relaxed),
            "timeout_count": self.argus_worker_timeout_count.load(Ordering::Relaxed),
            "last_error": last_error,
            "last_timeout": last_timeout,
        })
    }

    pub fn orchestrator_diagnostics(&self) -> serde_json::Value {
        let state = serde_json::to_value(self.orchestrator.diagnostics())
            .unwrap_or_else(|_| serde_json::json!({}));
        let manual_queue = state
            .get("queues")
            .and_then(|queues| queues.as_array())
            .and_then(|queues| {
                queues.iter().find(|queue| {
                    queue.get("kind").and_then(|kind| kind.as_str()) == Some("manual")
                })
            });
        let manual_queue_depth = manual_queue
            .and_then(|queue| queue.get("depth"))
            .and_then(|depth| depth.as_u64())
            .unwrap_or(0);
        let average_manual_scan_duration_ms = manual_queue
            .and_then(|queue| queue.get("average_scan_duration_ms"))
            .and_then(|duration| duration.as_u64())
            .unwrap_or(0);
        let worker_active_path = self
            .scan_live
            .lock()
            .ok()
            .and_then(|live| {
                live.as_ref()
                    .and_then(|state| state.current_path.lock().ok().map(|path| path.clone()))
            })
            .filter(|path| !path.is_empty())
            .or_else(|| {
                let inner = self.lock_inner();
                inner
                    .active_scan
                    .as_ref()
                    .filter(|job| job.status == ScanJobStatus::Running)
                    .map(|job| job.current_path.clone())
            });
        let last_orchestrated_job = self
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        // Health gate — computed outside json! macro.
        let health_gate = {
            let orch_d = self.orchestrator.diagnostics();
            let crashes: u64 = orch_d.workers.iter().map(|w| w.crash_count).sum();
            let timeouts = self.argus_worker_timeout_count.load(Ordering::Relaxed);
            let fallbacks = self.argus_worker_fallback_count.load(Ordering::Relaxed);
            let failed = self.orchestrated_failed_jobs.load(Ordering::Relaxed);
            let completed = self.orchestrated_completed_file.load(Ordering::Relaxed);
            let healthy = crashes == 0 && timeouts == 0 && failed == 0 && fallbacks <= 2;
            let ready_for_next = healthy && completed >= 3;
            serde_json::json!({
                "healthy": healthy,
                "ready_for_next_pilot": ready_for_next,
                "crashes": crashes,
                "timeouts": timeouts,
                "fallbacks": fallbacks,
                "failed": failed,
                "completed_file_scans": completed,
            })
        };

        serde_json::json!({
            "enabled_file_scan": self.orchestrator_file_scan_enabled,
            "enabled_folder_scan": self.orchestrator_folder_scan_enabled,
            "enabled_quick_scan": self.orchestrator_quick_scan_enabled,
            "state": state,
            "last_orchestrated_job": last_orchestrated_job,
            "manual_queue_depth": manual_queue_depth,
            "worker_active_path": worker_active_path,
            "completed_file": self.orchestrated_completed_file.load(Ordering::Relaxed),
            "completed_folder": self.orchestrated_completed_folder.load(Ordering::Relaxed),
            "completed_quick": self.orchestrated_completed_quick.load(Ordering::Relaxed),
            "cancelled_jobs": self.orchestrated_cancelled_jobs.load(Ordering::Relaxed),
            "failed_jobs": self.orchestrated_failed_jobs.load(Ordering::Relaxed),
            "worker_fallbacks": self.argus_worker_fallback_count.load(Ordering::Relaxed),
            "worker_timeouts": self.argus_worker_timeout_count.load(Ordering::Relaxed),
            "average_manual_scan_duration_ms": average_manual_scan_duration_ms,
            "health": health_gate,
        })
    }

    fn record_argus_worker_failure(&self, error: &str) {
        self.argus_worker_fallback_count
            .fetch_add(1, Ordering::Relaxed);
        *self
            .argus_worker_last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(error.to_string());
        if error.contains("timeout") {
            self.argus_worker_timeout_count
                .fetch_add(1, Ordering::Relaxed);
            *self
                .argus_worker_last_timeout
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(error.to_string());
            self.record_worker_timeout(error);
        } else if error.contains("panic") || error.contains("crash") {
            self.record_worker_panic(error);
        }
    }

    fn analyze_argus_file(
        &self,
        path: &Path,
        cancel: &AtomicBool,
    ) -> Result<(argus::ArgusVerdict, Option<String>), String> {
        // Use external worker if explicitly enabled, audit mode, or memory pressure.
        let use_external = self.argus_worker.enabled
            || self.is_audit_mode()
            || (self.performance_config.external_argus_under_pressure
                && self.pressure_tracker.prefer_external_argus());

        if use_external {
            let reason = if self.argus_worker.enabled {
                "config"
            } else if self.is_audit_mode() {
                "audit_mode"
            } else {
                "memory_pressure"
            };
            tracing::debug!(
                path = %path.display(),
                reason,
                "routing ARGUS to external worker"
            );
            match crate::argus_worker::scan_file(&self.argus_worker, path, cancel) {
                Ok(verdict) => return Ok((verdict, None)),
                Err(e) if e.contains("cancelled") => return Err(e),
                Err(e) => {
                    self.record_argus_worker_failure(&e);
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        reason,
                        "ARGUS worker failed, falling back in-process"
                    );
                    let verdict = self.argus.analyze_file(path);
                    return Ok((verdict, Some(e)));
                }
            }
        }
        Ok((self.argus.analyze_file(path), None))
    }

    /// Record an IPC request (called from dispatch).
    pub fn record_request(&self) {
        self.ipc_total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an IPC pipe error/reconnect.
    pub fn record_ipc_error(&self) {
        self.ipc_reconnect_count.fetch_add(1, Ordering::Relaxed);
        self.ipc_last_error_ts
            .store(chrono::Utc::now().timestamp() as u64, Ordering::Relaxed);
    }

    /// Check if a manual scan is currently active (for idle scanner backpressure).
    pub fn is_scan_active(&self) -> bool {
        let inner = self.lock_inner();
        inner
            .active_scan
            .as_ref()
            .map(|j| j.status == ScanJobStatus::Running)
            .unwrap_or(false)
    }

    // ── Lock helpers — recover from poisoned mutexes ───────────
    // A panic inside a locked section poisons the mutex. These helpers
    // recover the inner value so the daemon stays alive.

    fn lock_inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("inner mutex was poisoned — recovering");
            e.into_inner()
        })
    }

    fn lock_db(&self) -> MutexGuard<'_, Option<Database>> {
        self.db.lock().unwrap_or_else(|e| {
            tracing::warn!("db mutex was poisoned — recovering");
            e.into_inner()
        })
    }

    fn lock_watcher(&self) -> MutexGuard<'_, Option<crate::watcher::RealtimeWatcher>> {
        self.watcher.lock().unwrap_or_else(|e| {
            tracing::warn!("watcher mutex was poisoned — recovering");
            e.into_inner()
        })
    }

    fn read_engine(&self) -> RwLockReadGuard<'_, Option<Arc<ClamEngine>>> {
        self.engine.read().unwrap_or_else(|e| {
            tracing::warn!("engine RwLock was poisoned — recovering");
            e.into_inner()
        })
    }

    fn write_engine(&self) -> RwLockWriteGuard<'_, Option<Arc<ClamEngine>>> {
        self.engine.write().unwrap_or_else(|e| {
            tracing::warn!("engine RwLock was poisoned — recovering");
            e.into_inner()
        })
    }

    fn read_engine_error(&self) -> RwLockReadGuard<'_, Option<String>> {
        self.engine_error.read().unwrap_or_else(|e| {
            tracing::warn!("engine_error RwLock was poisoned — recovering");
            e.into_inner()
        })
    }

    fn write_engine_error(&self) -> RwLockWriteGuard<'_, Option<String>> {
        self.engine_error.write().unwrap_or_else(|e| {
            tracing::warn!("engine_error RwLock was poisoned — recovering");
            e.into_inner()
        })
    }

    /// Persist an activity event to both in-memory log and SQLite.
    pub fn log_activity(
        &self,
        severity: &str,
        category: &str,
        title: &str,
        message: &str,
        scan_id: Option<&str>,
    ) {
        let now = chrono::Utc::now().timestamp();
        let evt_id = Uuid::new_v4().to_string();

        // In-memory (capped to prevent unbounded growth).
        {
            let mut inner = self.lock_inner();
            inner.activity.push(ActivityEntry {
                event_type: category.to_string(),
                message: title.to_string(),
                detail: if message.is_empty() {
                    None
                } else {
                    Some(message.to_string())
                },
                timestamp: now,
            });
            // Keep last 500 entries in memory. SQLite has the full history.
            let alen = inner.activity.len();
            if alen > 500 {
                inner.activity.drain(..alen - 500);
            }
        }

        // SQLite.
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                db.insert_activity(&ActivityRow {
                    event_id: evt_id,
                    timestamp: now,
                    severity: severity.into(),
                    category: category.into(),
                    title: title.into(),
                    message: message.into(),
                    related_scan_id: scan_id.map(|s| s.to_string()),
                });
            }
        }
    }

    /// Persist a scan record to SQLite.
    fn persist_scan(&self, scan: &ScanRow) {
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                db.insert_scan(scan);
            }
        }
    }

    /// Persist a detection to SQLite.
    fn persist_detection(&self, det: &DetectionRow) {
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                db.insert_detection(det);
            }
        }
    }

    /// Persist an ARGUS verdict to SQLite as a forensic intelligence record.
    fn persist_argus_verdict(&self, scan_id: &str, verdict: &argus::ArgusVerdict) {
        let findings_json = serde_json::to_string(&verdict.findings).unwrap_or("[]".into());
        let row = crate::db::ArgusVerdictRow {
            scan_id: scan_id.to_string(),
            path: verdict.path.clone(),
            score: verdict.score,
            verdict: verdict.verdict.label().to_string(),
            findings_json,
            sha256: verdict.sha256.clone(),
            mime_type: verdict.mime_type.clone(),
            file_size: verdict.file_size,
            analysis_time_us: verdict.analysis_time_us,
            engine_version: verdict.engine_version.to_string(),
            timestamp: verdict.timestamp,
        };
        let db_guard = self.lock_db();
        if let Some(ref db) = *db_guard {
            db.insert_argus_verdict(&row);
        }
    }

    // ═══════════════════════════════════════════════════════
    //  engine.status
    // ═══════════════════════════════════════════════════════

    pub fn engine_status(&self) -> EngineStatus {
        let inner = self.lock_inner();
        let (db_ver, db_ts) = self.read_cvd_version();
        EngineStatus {
            state: if self.read_engine().is_some() {
                EngineState::Ready
            } else {
                EngineState::Error
            },
            protocol_version: 1,
            db_version: db_ver,
            db_timestamp: db_ts,
            signature_count: self.signature_count.load(Ordering::Relaxed),
            last_update: inner.last_update_timestamp,
            engine_version: sentinella_common::PRODUCT_VERSION.into(),
        }
    }

    /// Read ClamAV database version from CVD file header.
    /// CVD format: first line = `ClamAV-VDB:time:version:sigs:func_level:md5:builder:stime`
    /// `stime` (field 7) is unix timestamp.
    fn read_cvd_version(&self) -> (Option<u32>, Option<i64>) {
        let db_dir = match &self.db_dir {
            Some(d) => d,
            None => return (None, None),
        };

        // Try daily.cvd first (most frequently updated), then main.cvd.
        for name in &["daily.cvd", "daily.cld", "main.cvd", "main.cld"] {
            let path = db_dir.join(name);
            if let Ok(file) = std::fs::File::open(&path) {
                use std::io::Read;
                let mut header = [0u8; 512];
                let mut reader = std::io::BufReader::new(file);
                if reader.read(&mut header).unwrap_or(0) > 20 {
                    let line = String::from_utf8_lossy(&header);
                    if let Some(first_line) = line.lines().next() {
                        let parts: Vec<&str> = first_line.split(':').collect();
                        if parts.len() >= 3 && parts[0].starts_with("ClamAV-VDB") {
                            let version = parts[2].parse::<u32>().ok();
                            // Field 7 (index 7) is unix timestamp if available.
                            let stime = if parts.len() > 7 {
                                parts[7].trim().parse::<i64>().ok()
                            } else {
                                None
                            };
                            return (version, stime);
                        }
                    }
                }
            }
        }

        (None, None)
    }

    // ═══════════════════════════════════════════════════════
    //  scan.start — single file or quick scan
    // ═══════════════════════════════════════════════════════

    pub fn start_scan(
        self: &Arc<Self>,
        scan_type: &str,
        target: Option<&str>,
    ) -> ScanStartResponse {
        let engine_guard = self.read_engine();
        let engine = match &*engine_guard {
            Some(e) => Arc::clone(e),
            None => {
                let err = self
                    .read_engine_error()
                    .clone()
                    .unwrap_or("No engine".into());
                return ScanStartResponse {
                    job_id: Uuid::new_v4().to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some(format!("Engine not available: {err}")),
                };
            }
        };
        drop(engine_guard);

        match scan_type {
            "file" if self.orchestrator_file_scan_enabled => {
                self.start_orchestrated_file_scan(engine, target)
            }
            "file" => self.scan_single_file(&engine, target),
            "quick" if self.orchestrator_quick_scan_enabled => {
                self.start_orchestrated_quick_scan(engine)
            }
            "quick" => self.start_quick_scan(engine),
            "folder" if self.orchestrator_folder_scan_enabled => {
                self.start_orchestrated_folder_scan(engine, target)
            }
            "folder" => self.start_folder_scan(engine, target),
            "full" => self.start_full_scan(engine),
            "startup" => self.start_startup_scan(engine),
            _ => ScanStartResponse {
                job_id: Uuid::new_v4().to_string(),
                status: "error".into(),
                result: None,
                error: Some(format!("Unknown scan type: {scan_type}")),
            },
        }
    }

    fn scan_single_file(&self, engine: &ClamEngine, target: Option<&str>) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        let path_str = match target {
            Some(p) => p,
            None => {
                return ScanStartResponse {
                    job_id: id.to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some("No target path specified".into()),
                };
            }
        };

        let path = Path::new(path_str);
        let mut argus_result: Option<argus::ArgusVerdict> = None;

        let result = if !path.exists() {
            ScanResultResponse {
                path: path_str.to_string(),
                infected: false,
                virus_name: None,
                scanned_bytes: 0,
                error: Some("File not found".into()),
            }
        } else if {
            let config = crate::config::Config::load(None).unwrap_or_default();
            crate::scan::is_excluded(path, &config.excluded_paths, &config.excluded_extensions)
        } {
            ScanResultResponse {
                path: path_str.to_string(),
                infected: false,
                virus_name: None,
                scanned_bytes: 0,
                error: Some("Path excluded by configuration".into()),
            }
        } else {
            // ── Layer 0: ClamAV signature scan ─────────────────
            let no_cancel = AtomicBool::new(false);
            let r = self.scan_file_clamav(&engine, path, &no_cancel);

            // ── Layers 1–7: ARGUS heuristic analysis ───────────
            let (argus_verdict, worker_error) = self
                .analyze_argus_file(path, &no_cancel)
                .unwrap_or_else(|e| (self.argus.analyze_file(path), Some(e)));

            // ── Unified verdict: one file, one detection ──────
            let (infected, virus_name) = unify_detection_filtered(
                r.infected,
                r.virus_name.as_deref(),
                &argus_verdict,
                &self.detection_exclusions(),
            );

            if !argus_verdict.findings.is_empty() {
                tracing::debug!(
                    path = path_str,
                    score = argus_verdict.score,
                    findings = argus_verdict.findings.len(),
                    time_us = argus_verdict.analysis_time_us,
                    "ARGUS analysis: {}",
                    argus_verdict.verdict.label(),
                );
            }
            if let Some(error) = worker_error {
                tracing::warn!(path = path_str, error = %error, "ARGUS worker fallback used");
            }

            argus_result = Some(argus_verdict);

            ScanResultResponse {
                path: r.path,
                infected,
                virus_name,
                scanned_bytes: r.scanned_bytes,
                error: r.error,
            }
        };

        let status = if result.error.is_some() {
            "error"
        } else if result.infected {
            "infected"
        } else {
            "clean"
        };

        let finished = chrono::Utc::now().timestamp();
        let threats = if result.infected { 1u64 } else { 0 };
        let scan_id_str = id.to_string();

        // Persist scan record.
        let scan_row = ScanRow {
            scan_id: scan_id_str.clone(),
            scan_type: "file".into(),
            status: status.to_string(),
            started_at: now,
            finished_at: Some(finished),
            files_scanned: 1,
            threats_found: threats,
            errors_count: if result.error.is_some() { 1 } else { 0 },
            duration_ms: ((finished - now) * 1000) as u64,
        };
        self.persist_scan(&scan_row);

        // Persist ARGUS verdict as forensic record.
        if let Some(ref av) = argus_result {
            self.persist_argus_verdict(&scan_id_str, av);
        }

        // Persist in-memory history (capped).
        let mut inner = self.lock_inner();
        inner.scan_history.push(ScanRecord {
            job_id: scan_id_str.clone(),
            scan_type: "file".into(),
            started_at: now,
            finished_at: finished,
            files_scanned: 1,
            threats_found: threats,
            status: status.to_string(),
        });
        let hlen = inner.scan_history.len();
        if hlen > 200 {
            inner.scan_history.drain(..hlen - 200);
        }
        drop(inner);

        // Persist detection if infected.
        if result.infected {
            self.persist_detection(&DetectionRow {
                detection_id: Uuid::new_v4().to_string(),
                scan_id: scan_id_str.clone(),
                path: path_str.to_string(),
                virus_name: result.virus_name.clone().unwrap_or("Unknown".into()),
                detected_at: finished,
                action_taken: "none".into(),
            });
        }

        // Activity event.
        let severity = if result.infected { "critical" } else { "info" };
        let title = if result.infected {
            format!(
                "Threat: {}",
                result.virus_name.as_deref().unwrap_or("Unknown")
            )
        } else {
            "File scan: clean".into()
        };
        self.log_activity(severity, "scan", &title, path_str, Some(&scan_id_str));

        ScanStartResponse {
            job_id: id.to_string(),
            status: status.to_string(),
            result: Some(result),
            error: None,
        }
    }

    fn start_orchestrated_file_scan(
        self: &Arc<Self>,
        engine: Arc<ClamEngine>,
        target: Option<&str>,
    ) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let path_str = match target {
            Some(p) if !p.trim().is_empty() => p.to_string(),
            _ => {
                return ScanStartResponse {
                    job_id: id.to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some("No target path specified".into()),
                };
            }
        };

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let token = crate::orchestrator::CancellationToken::from_flag(Arc::clone(&cancel_flag));
        let live = Arc::new(ScanLiveState {
            id: id.to_string(),
            kind: "file".into(),
            started_at: now,
            files_total: AtomicU64::new(1),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::clone(&cancel_flag),
            status: std::sync::atomic::AtomicU8::new(0), // pending/queued
            current_path: Mutex::new(path_str.clone()),
        });

        {
            *self.scan_live.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&live));
            let mut inner = self.lock_inner();
            inner.active_scan = Some(ScanJob {
                id,
                kind: "file".into(),
                status: ScanJobStatus::Pending,
                started_at: now,
                finished_at: None,
                files_scanned: 0,
                files_total: 1,
                threats_found: 0,
                current_path: path_str.clone(),
                detections: Vec::new(),
                errors: Vec::new(),
                cancel_flag: Arc::clone(&cancel_flag),
                perf_summary: ScanPerformanceSummary::default(),
                live: Some(Arc::clone(&live)),
            });
        }

        let job = OrchestratedScanJob {
            id: id.to_string(),
            queue_kind: crate::orchestrator::QueueKind::Manual,
            path: path_str.clone(),
            requested_at: now,
        };
        let state = Arc::clone(self);
        let submit_result = self.orchestrator.submit(
            crate::orchestrator::QueueKind::Manual,
            token,
            move |token| {
                state.run_orchestrated_file_scan(job, engine, token, live);
            },
        );

        if let Err(e) = submit_result {
            self.complete_orchestrated_file_failure(
                id.to_string(),
                path_str.clone(),
                now,
                e.clone(),
            );
            return ScanStartResponse {
                job_id: id.to_string(),
                status: "error".into(),
                result: None,
                error: Some(e),
            };
        }

        ScanStartResponse {
            job_id: id.to_string(),
            status: "queued".into(),
            result: None,
            error: None,
        }
    }

    fn run_orchestrated_file_scan(
        self: Arc<Self>,
        job: OrchestratedScanJob,
        engine: Arc<ClamEngine>,
        token: crate::orchestrator::CancellationToken,
        live: Arc<ScanLiveState>,
    ) {
        let started = std::time::Instant::now();
        if token.is_cancelled() {
            self.complete_orchestrated_file_cancelled(&job, &live, started.elapsed());
            return;
        }

        live.set_status(ScanJobStatus::Running);
        {
            let mut inner = self.lock_inner();
            if let Some(ref mut active) = inner.active_scan {
                if active.id.to_string() == job.id {
                    active.status = ScanJobStatus::Running;
                }
            }
        }

        let path = PathBuf::from(&job.path);
        if !path.exists() {
            self.complete_orchestrated_file_error(
                &job,
                &live,
                started.elapsed(),
                "File not found".into(),
            );
            return;
        }
        let config = crate::config::Config::load(None).unwrap_or_default();
        if crate::scan::is_excluded(&path, &config.excluded_paths, &config.excluded_extensions) {
            self.complete_orchestrated_file_error(
                &job,
                &live,
                started.elapsed(),
                "Path excluded by configuration".into(),
            );
            return;
        }

        let cancel_flag = AtomicBool::new(false);
        let result = self.scan_file_clamav(&engine, &path, &cancel_flag);
        if token.is_cancelled() {
            self.complete_orchestrated_file_cancelled(&job, &live, started.elapsed());
            return;
        }

        let cancel_ref = token.flag();
        let (argus_verdict, worker_error) = self
            .analyze_argus_file(&path, &cancel_ref)
            .unwrap_or_else(|e| (self.argus.analyze_file(&path), Some(e)));
        if let Some(error) = worker_error {
            tracing::warn!(path = %job.path, error = %error, "ARGUS worker fallback used");
        }

        if token.is_cancelled() {
            self.complete_orchestrated_file_cancelled(&job, &live, started.elapsed());
            return;
        }

        let (infected, virus_name) = unify_detection_filtered(
            result.infected,
            result.virus_name.as_deref(),
            &argus_verdict,
            &self.detection_exclusions(),
        );
        let scan_result = ScanResultResponse {
            path: result.path,
            infected,
            virus_name,
            scanned_bytes: result.scanned_bytes,
            error: result.error,
        };
        self.complete_orchestrated_file_success(
            &job,
            &live,
            started.elapsed(),
            scan_result,
            argus_verdict,
        );
    }

    fn complete_orchestrated_file_success(
        &self,
        job: &OrchestratedScanJob,
        live: &ScanLiveState,
        elapsed: std::time::Duration,
        result: ScanResultResponse,
        argus_verdict: argus::ArgusVerdict,
    ) {
        let finished = chrono::Utc::now().timestamp();
        let threats = if result.infected { 1 } else { 0 };
        let status = if result.error.is_some() {
            "failed"
        } else if result.infected {
            "completed"
        } else {
            "completed"
        };
        live.files_scanned.store(1, Ordering::Relaxed);
        live.threats_found.store(threats, Ordering::Relaxed);
        live.set_status(ScanJobStatus::Completed);
        self.orchestrated_completed_file
            .fetch_add(1, Ordering::Relaxed);

        self.persist_scan(&ScanRow {
            scan_id: job.id.clone(),
            scan_type: "file".into(),
            status: status.into(),
            started_at: job.requested_at,
            finished_at: Some(finished),
            files_scanned: 1,
            threats_found: threats,
            errors_count: if result.error.is_some() { 1 } else { 0 },
            duration_ms: elapsed.as_millis() as u64,
        });
        self.persist_argus_verdict(&job.id, &argus_verdict);

        if result.infected {
            self.persist_detection(&DetectionRow {
                detection_id: Uuid::new_v4().to_string(),
                scan_id: job.id.clone(),
                path: job.path.clone(),
                virus_name: result.virus_name.clone().unwrap_or("Unknown".into()),
                detected_at: finished,
                action_taken: "none".into(),
            });
        }

        {
            let mut inner = self.lock_inner();
            if let Some(ref mut active) = inner.active_scan {
                if active.id.to_string() == job.id {
                    active.status = ScanJobStatus::Completed;
                    active.finished_at = Some(finished);
                    active.files_scanned = 1;
                    active.threats_found = threats;
                    active.current_path.clear();
                    if result.infected {
                        active.detections = vec![Detection {
                            path: job.path.clone(),
                            virus_name: result.virus_name.clone().unwrap_or("Unknown".into()),
                        }];
                    }
                    if let Some(error) = &result.error {
                        active.errors.push(error.clone());
                    }
                }
            }
            inner.scan_history.push(ScanRecord {
                job_id: job.id.clone(),
                scan_type: "file".into(),
                started_at: job.requested_at,
                finished_at: finished,
                files_scanned: 1,
                threats_found: threats,
                status: status.into(),
            });
            let hlen = inner.scan_history.len();
            if hlen > 200 {
                inner.scan_history.drain(..hlen - 200);
            }
        }

        let verdict = Some(argus_verdict.verdict.label().to_string());
        *self
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(OrchestratedJobResult {
            id: job.id.clone(),
            path: job.path.clone(),
            verdict,
            status: status.into(),
            duration_ms: elapsed.as_millis() as u64,
            error: result.error.clone(),
        });

        let severity = if result.infected { "critical" } else { "info" };
        let title = if result.infected {
            format!(
                "Threat: {}",
                result.virus_name.as_deref().unwrap_or("Unknown")
            )
        } else {
            "File scan: clean".into()
        };
        self.log_activity(severity, "scan", &title, &job.path, Some(&job.id));
    }

    fn complete_orchestrated_file_cancelled(
        &self,
        job: &OrchestratedScanJob,
        live: &ScanLiveState,
        elapsed: std::time::Duration,
    ) {
        let finished = chrono::Utc::now().timestamp();
        live.set_status(ScanJobStatus::Cancelled);
        self.orchestrated_cancelled_jobs
            .fetch_add(1, Ordering::Relaxed);

        {
            let mut inner = self.lock_inner();
            if let Some(ref mut active) = inner.active_scan {
                if active.id.to_string() == job.id {
                    active.status = ScanJobStatus::Cancelled;
                    active.finished_at = Some(finished);
                    active.current_path.clear();
                }
            }
            inner.scan_history.push(ScanRecord {
                job_id: job.id.clone(),
                scan_type: "file".into(),
                started_at: job.requested_at,
                finished_at: finished,
                files_scanned: 0,
                threats_found: 0,
                status: "cancelled".into(),
            });
        }

        *self
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(OrchestratedJobResult {
            id: job.id.clone(),
            path: job.path.clone(),
            verdict: None,
            status: "cancelled".into(),
            duration_ms: elapsed.as_millis() as u64,
            error: None,
        });
        self.log_activity(
            "warning",
            "scan",
            "File scan cancelled",
            &job.path,
            Some(&job.id),
        );
    }

    fn complete_orchestrated_file_error(
        &self,
        job: &OrchestratedScanJob,
        live: &ScanLiveState,
        elapsed: std::time::Duration,
        error: String,
    ) {
        self.complete_orchestrated_file_failure(
            job.id.clone(),
            job.path.clone(),
            job.requested_at,
            error.clone(),
        );
        live.set_status(ScanJobStatus::Failed);
        *self
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(OrchestratedJobResult {
            id: job.id.clone(),
            path: job.path.clone(),
            verdict: None,
            status: "failed".into(),
            duration_ms: elapsed.as_millis() as u64,
            error: Some(error),
        });
    }

    fn complete_orchestrated_file_failure(
        &self,
        id: String,
        path: String,
        requested_at: i64,
        error: String,
    ) {
        let finished = chrono::Utc::now().timestamp();
        self.orchestrated_failed_jobs
            .fetch_add(1, Ordering::Relaxed);
        self.persist_scan(&ScanRow {
            scan_id: id.clone(),
            scan_type: "file".into(),
            status: "failed".into(),
            started_at: requested_at,
            finished_at: Some(finished),
            files_scanned: 0,
            threats_found: 0,
            errors_count: 1,
            duration_ms: ((finished - requested_at).max(0) as u64) * 1000,
        });
        self.log_activity("warning", "scan", "File scan failed", &error, Some(&id));
        let mut inner = self.lock_inner();
        if let Some(ref mut active) = inner.active_scan {
            if active.id.to_string() == id {
                active.status = ScanJobStatus::Failed;
                active.finished_at = Some(finished);
                active.errors.push(error.clone());
                active.current_path.clear();
            }
        }
        inner.scan_history.push(ScanRecord {
            job_id: id.clone(),
            scan_type: "file".into(),
            started_at: requested_at,
            finished_at: finished,
            files_scanned: 0,
            threats_found: 0,
            status: "failed".into(),
        });
        *self
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(OrchestratedJobResult {
            id,
            path,
            verdict: None,
            status: "failed".into(),
            duration_ms: ((finished - requested_at).max(0) as u64) * 1000,
            error: Some(error),
        });
    }

    /// Orchestrated folder scan — runs through worker queue with cancel support.
    fn start_orchestrated_folder_scan(
        self: &Arc<Self>,
        engine: Arc<ClamEngine>,
        target: Option<&str>,
    ) -> ScanStartResponse {
        let folder = match target {
            Some(p) if std::path::Path::new(p).is_dir() => p.to_string(),
            Some(p) => {
                return ScanStartResponse {
                    job_id: Uuid::new_v4().to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some(format!("Not a directory: {p}")),
                };
            }
            None => {
                return ScanStartResponse {
                    job_id: Uuid::new_v4().to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some("No target directory specified".into()),
                };
            }
        };

        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let token = crate::orchestrator::CancellationToken::from_flag(Arc::clone(&cancel_flag));

        let live = Arc::new(ScanLiveState {
            id: id.to_string(),
            kind: "folder".into(),
            started_at: now,
            files_total: AtomicU64::new(0),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::clone(&cancel_flag),
            status: std::sync::atomic::AtomicU8::new(0), // queued
            current_path: Mutex::new(format!("Enumerating {folder}...")),
        });

        {
            *self.scan_live.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&live));
            let mut inner = self.lock_inner();
            inner.active_scan = Some(ScanJob {
                id,
                kind: "folder".into(),
                status: ScanJobStatus::Pending,
                started_at: now,
                finished_at: None,
                files_scanned: 0,
                files_total: 0,
                threats_found: 0,
                current_path: format!("Queued: {folder}"),
                detections: Vec::new(),
                errors: Vec::new(),
                cancel_flag: Arc::clone(&cancel_flag),
                perf_summary: ScanPerformanceSummary::default(),
                live: Some(Arc::clone(&live)),
            });
        }

        self.log_activity(
            "info",
            "scan",
            &format!("Folder scan queued: {folder}"),
            &folder,
            None,
        );

        let state = Arc::clone(self);
        let live_ref = Arc::clone(&live);
        let submit_result = self.orchestrator.submit(
            crate::orchestrator::QueueKind::Manual,
            token.clone(),
            move |_token| {
                // Run through inner worker, passing live state to avoid overwrite.
                let cancel = Arc::clone(&live_ref.cancel_flag);
                let targets = vec![PathBuf::from(&folder)];
                folder_scan_worker_inner(
                    state,
                    id,
                    engine,
                    cancel,
                    targets,
                    "folder",
                    Some(live_ref),
                );
            },
        );

        if let Err(e) = submit_result {
            tracing::error!(%e, "orchestrator folder scan submit failed");
            return ScanStartResponse {
                job_id: id.to_string(),
                status: "error".into(),
                result: None,
                error: Some(e),
            };
        }

        ScanStartResponse {
            job_id: id.to_string(),
            status: "queued".into(),
            result: None,
            error: None,
        }
    }

    /// Orchestrated quick scan — same targets as legacy, routed through queue.
    fn start_orchestrated_quick_scan(
        self: &Arc<Self>,
        engine: Arc<ClamEngine>,
    ) -> ScanStartResponse {
        let home = std::env::var("USERPROFILE").unwrap_or_default();
        let temp =
            std::env::var("TEMP").unwrap_or_else(|_| format!("{home}\\AppData\\Local\\Temp"));
        let targets: Vec<PathBuf> = [
            format!("{home}\\Downloads"),
            format!("{home}\\Desktop"),
            temp,
        ]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();

        if targets.is_empty() {
            return ScanStartResponse {
                job_id: Uuid::new_v4().to_string(),
                status: "error".into(),
                result: None,
                error: Some("No quick scan directories found".into()),
            };
        }

        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let token = crate::orchestrator::CancellationToken::from_flag(Arc::clone(&cancel_flag));

        let live = Arc::new(ScanLiveState {
            id: id.to_string(),
            kind: "quick".into(),
            started_at: now,
            files_total: AtomicU64::new(0),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::clone(&cancel_flag),
            status: std::sync::atomic::AtomicU8::new(0),
            current_path: Mutex::new("Queued: quick scan".into()),
        });

        {
            *self.scan_live.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&live));
            let mut inner = self.lock_inner();
            inner.active_scan = Some(ScanJob {
                id,
                kind: "quick".into(),
                status: ScanJobStatus::Pending,
                started_at: now,
                finished_at: None,
                files_scanned: 0,
                files_total: 0,
                threats_found: 0,
                current_path: "Queued".into(),
                detections: Vec::new(),
                errors: Vec::new(),
                cancel_flag: Arc::clone(&cancel_flag),
                perf_summary: ScanPerformanceSummary::default(),
                live: Some(Arc::clone(&live)),
            });
        }

        self.log_activity("info", "scan", "Quick scan queued (orchestrated)", "", None);

        let state = Arc::clone(self);
        let live_ref = Arc::clone(&live);
        let submit_result = self.orchestrator.submit(
            crate::orchestrator::QueueKind::Manual,
            token,
            move |_token| {
                let cancel = Arc::clone(&live_ref.cancel_flag);
                folder_scan_worker_inner(
                    state,
                    id,
                    engine,
                    cancel,
                    targets,
                    "quick",
                    Some(live_ref),
                );
            },
        );

        if let Err(e) = submit_result {
            tracing::error!(%e, "orchestrator quick scan submit failed");
            return ScanStartResponse {
                job_id: id.to_string(),
                status: "error".into(),
                result: None,
                error: Some(e),
            };
        }

        ScanStartResponse {
            job_id: id.to_string(),
            status: "queued".into(),
            result: None,
            error: None,
        }
    }

    fn start_folder_scan(
        self: &Arc<Self>,
        engine: Arc<ClamEngine>,
        target: Option<&str>,
    ) -> ScanStartResponse {
        let folder = match target {
            Some(p) if std::path::Path::new(p).is_dir() => p.to_string(),
            Some(p) => {
                return ScanStartResponse {
                    job_id: Uuid::new_v4().to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some(format!("Not a directory: {p}")),
                };
            }
            None => {
                return ScanStartResponse {
                    job_id: Uuid::new_v4().to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some("No folder path specified".into()),
                };
            }
        };

        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        {
            let mut inner = self.lock_inner();
            if let Some(ref job) = inner.active_scan {
                if job.status == ScanJobStatus::Running {
                    return ScanStartResponse {
                        job_id: job.id.to_string(),
                        status: "error".into(),
                        result: None,
                        error: Some(
                            "A scan is already running — cancel it first or wait for completion"
                                .into(),
                        ),
                    };
                }
            }
            inner.active_scan = Some(ScanJob {
                id,
                kind: "folder".into(),
                status: ScanJobStatus::Running,
                started_at: now,
                finished_at: None,
                files_scanned: 0,
                files_total: 0,
                threats_found: 0,
                current_path: "Starting...".into(),
                detections: Vec::new(),
                errors: Vec::new(),
                cancel_flag: Arc::clone(&cancel_flag),
                perf_summary: ScanPerformanceSummary::default(),
                live: None,
            });
        }
        self.log_activity(
            "info",
            "scan",
            &format!("Folder scan started: {folder}"),
            &folder,
            None,
        );
        let state = Arc::clone(self);
        let targets = vec![std::path::PathBuf::from(folder)];
        std::thread::spawn(move || {
            folder_scan_worker(state, id, engine, cancel_flag, targets, "folder");
        });
        ScanStartResponse {
            job_id: id.to_string(),
            status: "running".into(),
            result: None,
            error: None,
        }
    }

    fn start_quick_scan(self: &Arc<Self>, engine: Arc<ClamEngine>) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));

        {
            let mut inner = self.lock_inner();
            if let Some(ref job) = inner.active_scan {
                if job.status == ScanJobStatus::Running {
                    return ScanStartResponse {
                        job_id: job.id.to_string(),
                        status: "error".into(),
                        result: None,
                        error: Some(
                            "A scan is already running — cancel it first or wait for completion"
                                .into(),
                        ),
                    };
                }
            }
            inner.active_scan = Some(ScanJob {
                id,
                kind: "quick".into(),
                status: ScanJobStatus::Running,
                started_at: now,
                finished_at: None,
                files_scanned: 0,
                files_total: 0,
                threats_found: 0,
                current_path: "Starting...".into(),
                detections: Vec::new(),
                errors: Vec::new(),
                cancel_flag: Arc::clone(&cancel_flag),
                perf_summary: ScanPerformanceSummary::default(),
                live: None,
            });
            inner.activity.push(ActivityEntry {
                event_type: "scan_start".into(),
                message: "Quick scan started".into(),
                detail: Some("Scanning Downloads, Desktop, Temp".into()),
                timestamp: now,
            });
        }

        // Spawn background scan worker.
        let state = Arc::clone(self);
        std::thread::spawn(move || {
            quick_scan_worker(state, id, engine, cancel_flag);
        });

        ScanStartResponse {
            job_id: id.to_string(),
            status: "running".into(),
            result: None,
            error: None,
        }
    }

    // ═══════════════════════════════════════════════════════
    //  scan.start type="full" — all fixed drives
    // ═══════════════════════════════════════════════════════

    fn start_full_scan(self: &Arc<Self>, engine: Arc<ClamEngine>) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));

        // Check for running scan.
        {
            let mut inner = self.lock_inner();
            if let Some(ref job) = inner.active_scan {
                if job.status == ScanJobStatus::Running {
                    return ScanStartResponse {
                        job_id: job.id.to_string(),
                        status: "error".into(),
                        result: None,
                        error: Some(
                            "A scan is already running — cancel it first or wait for completion"
                                .into(),
                        ),
                    };
                }
            }
            inner.active_scan = Some(ScanJob {
                id,
                kind: "full".into(),
                status: ScanJobStatus::Running,
                started_at: now,
                finished_at: None,
                files_scanned: 0,
                files_total: 0,
                threats_found: 0,
                current_path: "Enumerating drives...".into(),
                detections: Vec::new(),
                errors: Vec::new(),
                cancel_flag: Arc::clone(&cancel_flag),
                perf_summary: ScanPerformanceSummary::default(),
                live: None,
            });
            inner.activity.push(ActivityEntry {
                event_type: "scan_start".into(),
                message: "Full disk scan started".into(),
                detail: Some("Scanning all fixed drives".into()),
                timestamp: now,
            });
        }

        let state = Arc::clone(self);
        std::thread::spawn(move || {
            full_scan_worker(state, id, engine, cancel_flag);
        });

        ScanStartResponse {
            job_id: id.to_string(),
            status: "running".into(),
            result: None,
            error: None,
        }
    }

    // ═══════════════════════════════════════════════════════
    //  scan.start type="startup" — autorun + recent executables
    // ═══════════════════════════════════════════════════════

    fn start_startup_scan(self: &Arc<Self>, engine: Arc<ClamEngine>) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));

        {
            let mut inner = self.lock_inner();
            if let Some(ref job) = inner.active_scan {
                if job.status == ScanJobStatus::Running {
                    return ScanStartResponse {
                        job_id: job.id.to_string(),
                        status: "error".into(),
                        result: None,
                        error: Some(
                            "A scan is already running — cancel it first or wait for completion"
                                .into(),
                        ),
                    };
                }
            }
            inner.active_scan = Some(ScanJob {
                id,
                kind: "startup".into(),
                status: ScanJobStatus::Running,
                started_at: now,
                finished_at: None,
                files_scanned: 0,
                files_total: 0,
                threats_found: 0,
                current_path: "Collecting startup targets...".into(),
                detections: Vec::new(),
                errors: Vec::new(),
                cancel_flag: Arc::clone(&cancel_flag),
                perf_summary: ScanPerformanceSummary::default(),
                live: None,
            });
            inner.activity.push(ActivityEntry {
                event_type: "scan_start".into(),
                message: "Startup scan started".into(),
                detail: Some("Scanning autorun entries + recent executables".into()),
                timestamp: now,
            });
        }

        let state = Arc::clone(self);
        std::thread::spawn(move || {
            startup_scan_worker(state, id, engine, cancel_flag);
        });

        ScanStartResponse {
            job_id: id.to_string(),
            status: "running".into(),
            result: None,
            error: None,
        }
    }

    // ═══════════════════════════════════════════════════════
    //  scan.status
    // ═══════════════════════════════════════════════════════

    pub fn scan_status(&self) -> ScanStatusResponse {
        // ── Lock-free fast path: read from atomic live state ──
        // This avoids contending with scan worker locks during heavy scans.
        if let Ok(live_guard) = self.scan_live.try_lock() {
            if let Some(ref live) = *live_guard {
                let scanned = live.files_scanned.load(Ordering::Relaxed);
                let total = live.files_total.load(Ordering::Relaxed);
                let threats = live.threats_found.load(Ordering::Relaxed);
                let status = live.status_enum();
                let pct = if total > 0 {
                    (scanned as f32 * 100.0 / total as f32).min(100.0)
                } else {
                    0.0
                };
                let path = live
                    .current_path
                    .lock()
                    .map(|p| p.clone())
                    .unwrap_or_default();

                let inner = self.lock_inner();
                let scans_completed = inner.scan_history.len() as u64;
                let detections = inner
                    .active_scan
                    .as_ref()
                    .map(|j| j.detections.clone())
                    .unwrap_or_default();

                return ScanStatusResponse {
                    running: status == ScanJobStatus::Running || status == ScanJobStatus::Draining,
                    job_id: Some(live.id.clone()),
                    state: match status {
                        ScanJobStatus::Pending => "queued",
                        ScanJobStatus::Running => "running",
                        ScanJobStatus::Completed => "completed",
                        ScanJobStatus::Cancelled => "cancelled",
                        ScanJobStatus::Failed => "failed",
                        ScanJobStatus::Draining => "cancelling",
                    },
                    scan_type: Some(live.kind.clone()),
                    files_scanned: scanned,
                    files_total: total,
                    progress_percent: pct,
                    threats_found: threats,
                    current_path: Some(path),
                    scans_completed,
                    detections,
                    started_at: Some(live.started_at),
                    finished_at: None,
                    errors_count: 0,
                };
            }
        }

        // ── Fallback: read from inner (for completed/idle scans) ──
        let inner = self.lock_inner();
        match &inner.active_scan {
            Some(job) => {
                let pct = if job.files_total > 0 {
                    ((job.files_scanned as f32 * 100.0) / job.files_total as f32).min(100.0)
                } else {
                    0.0
                };
                ScanStatusResponse {
                    running: job.status == ScanJobStatus::Running,
                    job_id: Some(job.id.to_string()),
                    state: match job.status {
                        ScanJobStatus::Pending => "queued",
                        ScanJobStatus::Running => "running",
                        ScanJobStatus::Completed => "completed",
                        ScanJobStatus::Cancelled => "cancelled",
                        ScanJobStatus::Failed => "failed",
                        ScanJobStatus::Draining => "cancelling",
                    },
                    scan_type: Some(job.kind.clone()),
                    files_scanned: job.files_scanned,
                    files_total: job.files_total,
                    progress_percent: pct,
                    threats_found: job.threats_found,
                    current_path: Some(job.current_path.clone()),
                    scans_completed: inner.scan_history.len() as u64,
                    detections: job.detections.clone(),
                    started_at: Some(job.started_at),
                    finished_at: job.finished_at,
                    errors_count: job.errors.len() as u64,
                }
            }
            None => ScanStatusResponse {
                running: false,
                job_id: None,
                state: "idle",
                scan_type: None,
                files_scanned: 0,
                files_total: 0,
                progress_percent: 0.0,
                threats_found: 0,
                current_path: None,
                scans_completed: inner.scan_history.len() as u64,
                detections: vec![],
                started_at: None,
                finished_at: None,
                errors_count: 0,
            },
        }
    }

    // ═══════════════════════════════════════════════════════
    //  scan.cancel
    // ═══════════════════════════════════════════════════════

    pub fn cancel_scan(&self) -> bool {
        // Set cancel flag + mark as draining (lock-free for immediate UI response).
        if let Ok(live_guard) = self.scan_live.lock() {
            if let Some(ref live) = *live_guard {
                let previous = live.status_enum();
                live.cancel_flag.store(true, Ordering::Relaxed);
                let next = if previous == ScanJobStatus::Pending {
                    ScanJobStatus::Cancelled
                } else {
                    ScanJobStatus::Draining
                };
                live.set_status(next);
                let mut inner = self.lock_inner();
                if let Some(ref mut job) = inner.active_scan {
                    if job.id.to_string() == live.id {
                        job.cancel_flag.store(true, Ordering::Relaxed);
                        job.status = next;
                    }
                }
                return true;
            }
        }
        // Fallback: check inner.
        let mut inner = self.lock_inner();
        if let Some(ref mut job) = inner.active_scan {
            if job.status == ScanJobStatus::Running || job.status == ScanJobStatus::Pending {
                job.cancel_flag.store(true, Ordering::Relaxed);
                job.status = if job.status == ScanJobStatus::Pending {
                    ScanJobStatus::Cancelled
                } else {
                    ScanJobStatus::Draining
                };
                return true;
            }
        }
        false
    }

    // ═══════════════════════════════════════════════════════
    //  scan.history + remaining endpoints
    // ═══════════════════════════════════════════════════════

    pub fn scan_history(&self) -> Vec<ScanRow> {
        // Prefer SQLite for persistence across restarts.
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                return db.recent_scans(50);
            }
        }
        // Fallback to in-memory.
        let inner = self.lock_inner();
        inner
            .scan_history
            .iter()
            .rev()
            .map(|r| ScanRow {
                scan_id: r.job_id.clone(),
                scan_type: r.scan_type.clone(),
                status: r.status.clone(),
                started_at: r.started_at,
                finished_at: Some(r.finished_at),
                files_scanned: r.files_scanned,
                threats_found: r.threats_found,
                errors_count: 0,
                duration_ms: ((r.finished_at - r.started_at).max(0) as u64) * 1000,
            })
            .collect()
    }

    pub fn quarantine_list(&self) -> Vec<crate::db::QuarantineRow> {
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                return db.list_quarantine();
            }
        }
        vec![]
    }

    pub fn quarantine_file(
        &self,
        path: &str,
        virus_name: &str,
        scan_id: &str,
    ) -> Result<crate::quarantine::QuarantineResult, String> {
        let vault_dir = std::path::PathBuf::from("runtime/quarantine");
        std::fs::create_dir_all(&vault_dir).map_err(|e| format!("Cannot create vault dir: {e}"))?;

        let prepared = crate::quarantine::prepare_quarantine_file(
            std::path::Path::new(path),
            &vault_dir,
            virus_name,
            scan_id,
        )?;
        {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            db.insert_quarantine_item(&prepared.row);
        }
        if let Err(e) = crate::quarantine::finalize_quarantine_file(&prepared) {
            if let Ok(db_guard) = self.db.lock() {
                if let Some(ref db) = *db_guard {
                    db.update_quarantine_status(&prepared.row.quarantine_id, "failed");
                }
            }
            // Clean up orphaned vault file on failure.
            if prepared.vault_path.exists() {
                let _ = std::fs::remove_file(&prepared.vault_path);
            }
            tracing::warn!(id = %prepared.row.quarantine_id, error = %e, "quarantine finalize failed");
            return Err(e);
        }
        let result = prepared.result;

        // Log activity.
        self.log_activity(
            "critical",
            "quarantine",
            &format!("Quarantined: {virus_name}"),
            path,
            Some(scan_id),
        );

        Ok(result)
    }

    pub fn quarantine_restore(&self, id: &str) -> Result<String, String> {
        let item = {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            db.get_quarantine_item(id)
                .ok_or_else(|| format!("Not found: {id}"))?
        };
        let path = crate::quarantine::restore_file_from_row(&item)?;
        {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            db.update_quarantine_status(id, "restored");
        }
        self.log_activity(
            "warning",
            "quarantine",
            "File restored from quarantine",
            &path,
            None,
        );
        Ok(path)
    }

    pub fn quarantine_delete(&self, id: &str) -> Result<(), String> {
        let item = {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            db.get_quarantine_item(id)
                .ok_or_else(|| format!("Not found: {id}"))?
        };
        crate::quarantine::delete_vault_file(&item)?;
        {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            db.update_quarantine_status(id, "deleted");
        }
        self.log_activity(
            "info",
            "quarantine",
            "Quarantine item permanently deleted",
            id,
            None,
        );
        Ok(())
    }

    pub fn watcher_status(&self) -> WatcherStatus {
        let guard = self.lock_watcher();
        match &*guard {
            Some(w) if w.is_running() => WatcherStatus {
                enabled: true,
                mode: WatcherMode::UserMode,
                watched_roots: w
                    .watched_roots()
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect(),
                events_per_sec: 0.0,
                last_event: None,
            },
            _ => WatcherStatus {
                enabled: false,
                mode: WatcherMode::Disabled,
                watched_roots: vec![],
                events_per_sec: 0.0,
                last_event: None,
            },
        }
    }

    /// Reload the ClamAV engine after a signature update.
    /// Creates a new engine, loads new sigs, compiles, then swaps atomically.
    /// If reload fails, the old engine stays active.
    pub fn reload_engine(&self) -> Result<u64, String> {
        let (dll_dir, db_dir) = match (&self.dll_dir, &self.db_dir) {
            (Some(d), Some(db)) => (d, db),
            _ => return Err("DLL or DB directory not configured".into()),
        };

        tracing::info!("reloading ClamAV engine...");
        match ClamEngine::load(dll_dir, db_dir) {
            Ok(new_engine) => {
                let sigs = new_engine.signature_count() as u64;
                self.scan_cache.invalidate_all();
                *self.write_engine() = Some(Arc::new(new_engine));
                *self.write_engine_error() = None;
                self.signature_count.store(sigs, Ordering::Relaxed);
                self.log_activity(
                    "info",
                    "engine",
                    &format!("Engine reloaded — {sigs} signatures"),
                    "",
                    None,
                );
                tracing::info!(sigs, "engine reloaded successfully");
                // Invalidate scan cache — new signatures may detect previously-clean files.
                Ok(sigs)
            }
            Err(e) => {
                tracing::error!(%e, "engine reload failed — keeping old engine");
                self.log_activity("warning", "engine", "Engine reload failed", &e, None);
                Err(e)
            }
        }
    }

    /// Start the real-time watcher. Call after engine is loaded.
    pub fn start_watcher(self: &Arc<Self>) {
        let engine = match &*self.read_engine() {
            Some(e) => Arc::clone(e),
            None => {
                tracing::warn!("cannot start watcher: engine not loaded");
                return;
            }
        };

        let home = std::env::var("USERPROFILE").unwrap_or_default();
        let temp =
            std::env::var("TEMP").unwrap_or_else(|_| format!("{home}\\AppData\\Local\\Temp"));
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let programdata = std::env::var("PROGRAMDATA").unwrap_or_default();

        // Broad watcher scope: user-writable directories where threats arrive.
        let roots: Vec<std::path::PathBuf> = [
            // Primary threat vectors.
            format!("{home}\\Downloads"),
            format!("{home}\\Desktop"),
            temp,
            // User documents — ransomware targets.
            format!("{home}\\Documents"),
            // AppData — malware persistence + browser data.
            format!("{appdata}"),
            format!("{localappdata}\\Temp"),
            // ProgramData — service-level persistence.
            programdata,
            // OneDrive if present.
            format!("{home}\\OneDrive"),
        ]
        .iter()
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists() && !p.as_os_str().is_empty())
        .collect();

        if roots.is_empty() {
            tracing::warn!("no watchable directories found");
            return;
        }

        let root_count = roots.len();
        let root_names: Vec<_> = roots
            .iter()
            .filter_map(|p| {
                p.file_name()
                    .or_else(|| p.components().last().map(|c| c.as_os_str()))
            })
            .map(|n| n.to_string_lossy().to_string())
            .collect();

        match crate::watcher::RealtimeWatcher::start(roots, engine, Arc::clone(self)) {
            Ok(w) => {
                *self.lock_watcher() = Some(w);
                self.log_activity(
                    "info",
                    "watcher",
                    "Real-time protection started",
                    &format!(
                        "Monitoring {} directories: {}",
                        root_count,
                        root_names.join(", ")
                    ),
                    None,
                );
            }
            Err(e) => {
                tracing::error!(%e, "failed to start watcher");
                self.log_activity("warning", "watcher", "Watcher failed to start", &e, None);
            }
        }
    }

    /// Start the resource-aware idle background scanner.
    pub fn start_idle_scanner(self: &Arc<Self>) {
        let config = crate::config::Config::load(None).unwrap_or_default();
        if !config.idle_scan_enabled {
            tracing::info!("idle scanner disabled by config");
            return;
        }

        let engine = match &*self.read_engine() {
            Some(e) => Arc::clone(e),
            None => {
                tracing::warn!("cannot start idle scanner: engine not loaded");
                return;
            }
        };

        let scanner = crate::idle_scanner::IdleScanner::start(
            config,
            engine,
            Arc::clone(self),
            Arc::clone(&self.scan_cache),
        );
        *self.idle_scanner.lock().unwrap_or_else(|e| e.into_inner()) = Some(scanner);
    }

    /// Run a lightweight startup critical areas scan.
    ///
    /// Fires AFTER watcher is running — realtime is never delayed.
    /// Scans: Startup folder, Run/RunOnce keys, recent Downloads/Desktop,
    /// Temp executables. 1 worker, BELOW_NORMAL priority, yields under pressure.
    /// Skips files already in scan cache.
    pub fn start_startup_critical_scan(self: &Arc<Self>) {
        let engine = match &*self.read_engine() {
            Some(e) => Arc::clone(e),
            None => {
                tracing::info!("startup critical scan skipped: engine not loaded");
                return;
            }
        };

        let state = Arc::clone(self);
        let cache = Arc::clone(&self.scan_cache);

        if let Err(e) = std::thread::Builder::new()
            .name("startup-critical".into())
            .spawn(move || {
                startup_critical_scan(state, engine, cache);
            })
        {
            tracing::warn!(error = %e, "failed to spawn startup critical scan thread");
        }
    }

    /// Get idle scanner stats for IPC.
    pub fn idle_scanner_stats(&self) -> crate::idle_scanner::IdleScannerStats {
        let guard = self.idle_scanner.lock().unwrap_or_else(|e| e.into_inner());
        match &*guard {
            Some(scanner) => scanner.stats(),
            None => crate::idle_scanner::IdleScannerStats {
                state: crate::idle_scanner::IdleScannerState::Disabled,
                files_scanned_session: 0,
                current_target: String::new(),
                last_pause_reason: String::new(),
                last_completed: None,
            },
        }
    }

    /// Get last scan performance summary as JSON for diagnostics.
    pub fn last_scan_perf_json(&self) -> serde_json::Value {
        let inner = self.lock_inner();
        inner
            .active_scan
            .as_ref()
            .map(|j| serde_json::to_value(&j.perf_summary).unwrap_or_default())
            .unwrap_or(serde_json::Value::Null)
    }

    pub fn update_status(&self) -> UpdateStatus {
        let inner = self.lock_inner();

        let (state, percent, current_file) = if inner.update_running {
            match &inner.update_phase {
                UpdatePhase::Idle => (UpdateState::Idle, None, String::new()),
                UpdatePhase::Checking => (UpdateState::Checking, Some(5.0), String::new()),
                UpdatePhase::Downloading(file) => {
                    (UpdateState::Downloading, Some(30.0), file.clone())
                }
                UpdatePhase::Applying => (UpdateState::Applying, Some(70.0), String::new()),
                UpdatePhase::ReloadingEngine => (
                    UpdateState::Applying,
                    Some(85.0),
                    "Reloading ClamAV engine...".into(),
                ),
                UpdatePhase::ReloadingArgus => (
                    UpdateState::Applying,
                    Some(95.0),
                    "Reloading ARGUS rules...".into(),
                ),
                UpdatePhase::Completed => (UpdateState::Completed, Some(100.0), String::new()),
            }
        } else {
            match &inner.last_update_error {
                Some(_) => (UpdateState::Error, None, String::new()),
                None => (UpdateState::Idle, None, String::new()),
            }
        };

        UpdateStatus {
            state,
            percent,
            bytes_downloaded: 0,
            bytes_total: None,
            last_error: inner.last_update_error.clone(),
            current_file: if current_file.is_empty() {
                None
            } else {
                Some(current_file)
            },
        }
    }

    /// Start a signature update in the background.
    /// Returns immediately so the IPC handler is NOT blocked.
    pub fn start_update(self: &Arc<Self>) -> serde_json::Value {
        // Prevent concurrent updates.
        {
            let mut inner = self.lock_inner();
            if inner.update_running {
                return serde_json::json!({"ok": false, "error": "Update already in progress"});
            }
            inner.update_running = true;
            inner.last_update_error = None;
        }

        self.log_activity(
            "info",
            "update",
            "Signature update started",
            "Running freshclam...",
            None,
        );

        // Find freshclam + config BEFORE spawning thread (cheap filesystem lookups).
        let freshclam = crate::updater::find_freshclam();
        let config_candidates = [
            std::path::PathBuf::from("runtime/config/freshclam.conf"),
            std::path::PathBuf::from(r"C:\ProgramData\Sentinella\config\freshclam.conf"),
            std::env::current_exe()
                .ok()
                .and_then(|p| {
                    p.parent()
                        .map(|d| d.join("../../../runtime/config/freshclam.conf"))
                })
                .unwrap_or_default(),
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("config/freshclam.conf")))
                .unwrap_or_default(),
        ];
        let config_path = config_candidates
            .iter()
            .find(|p| p.exists())
            .cloned()
            .unwrap_or_else(|| std::path::PathBuf::from("runtime/config/freshclam.conf"));

        let fc_path = match freshclam {
            Some(p) if config_path.exists() => p,
            _ => {
                let msg = if freshclam.is_none() {
                    "freshclam binary not found"
                } else {
                    "freshclam.conf not found"
                };
                let mut inner = self.lock_inner();
                inner.update_running = false;
                inner.last_update_error = Some(msg.to_string());
                self.log_activity("warning", "update", "Update failed", msg, None);
                return serde_json::json!({"ok": false, "error": msg});
            }
        };

        // Spawn the heavy work on a background thread so IPC stays responsive.
        let state = Arc::clone(self);
        let db_dir = std::path::PathBuf::from("runtime/signatures");
        std::thread::spawn(move || {
            // Phase 1: Checking for updates.
            {
                let mut inner = state.lock_inner();
                inner.update_phase = UpdatePhase::Checking;
            }

            // Phase 2: Run freshclam with real-time output parsing.
            let (success, message) = crate::updater::run_freshclam_with_progress(
                &fc_path,
                &config_path,
                &db_dir,
                |line| {
                    // Parse freshclam output to detect download phases.
                    // freshclam outputs lines like:
                    //   "Downloading daily-27800.cdiff [100%]"
                    //   "daily.cvd database is up-to-date"
                    //   "main.cvd is up-to-date"
                    let mut inner = state.lock_inner();
                    if line.contains("Downloading") || line.contains("downloading") {
                        // Extract filename from "Downloading XXX [...]"
                        let file_name = line
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("definitions")
                            .to_string();
                        inner.update_phase = UpdatePhase::Downloading(file_name);
                    } else if line.contains("up-to-date") || line.contains("updated") {
                        inner.update_phase = UpdatePhase::Applying;
                    }
                },
            );

            if success {
                // Phase 3: Reload ClamAV engine.
                {
                    let mut inner = state.lock_inner();
                    inner.last_update_timestamp = Some(chrono::Utc::now().timestamp());
                    inner.update_phase = UpdatePhase::ReloadingEngine;
                }
                let trimmed = message.chars().take(200).collect::<String>();
                state.log_activity(
                    "info",
                    "update",
                    "Signatures updated successfully",
                    &trimmed,
                    None,
                );

                match state.reload_engine() {
                    Ok(_sigs) => { /* reload_engine() already logs activity */ }
                    Err(e) => {
                        state.log_activity(
                            "warning",
                            "update",
                            "Updated but engine reload failed",
                            &e,
                            None,
                        );
                    }
                }

                // Phase 4: Reload ARGUS YARA rules after signature update.
                {
                    let mut inner = state.lock_inner();
                    inner.update_phase = UpdatePhase::ReloadingArgus;
                }
                {
                    let yara_dirs = vec![
                        std::path::PathBuf::from("runtime/argus/rules/yara"),
                        std::path::PathBuf::from("runtime/rules"),
                    ];
                    match state.argus().yara.load_rules_on_large_stack(&yara_dirs) {
                        Ok(count) => {
                            tracing::info!(count, "ARGUS YARA rules reloaded after update");
                        }
                        Err(e) => {
                            tracing::warn!(%e, "YARA reload failed after update — keeping existing rules");
                        }
                    }
                    // Reload IOC hashes.
                    let ioc_paths = [
                        std::path::PathBuf::from("runtime/rules/ioc_hashes.txt"),
                        std::path::PathBuf::from("runtime/argus/rules/ioc/ioc_hashes.txt"),
                    ];
                    for p in &ioc_paths {
                        if p.exists() {
                            if let Ok(c) = state.argus().ioc.load_from_file(p) {
                                tracing::info!(count = c, "IOC hashes reloaded after update");
                                break;
                            }
                        }
                    }
                }

                // Phase 5: Complete.
                {
                    let mut inner = state.lock_inner();
                    inner.update_phase = UpdatePhase::Completed;
                }
            } else {
                let trimmed = message.chars().take(200).collect::<String>();
                let mut inner = state.lock_inner();
                inner.last_update_error = Some(trimmed.clone());
                drop(inner);
                state.log_activity(
                    "warning",
                    "update",
                    "Signature update failed",
                    &trimmed,
                    None,
                );
            }

            // Mark update as done.
            {
                let mut inner = state.lock_inner();
                inner.update_running = false;
                inner.update_phase = UpdatePhase::Idle;
                inner.update_current_file = String::new();
            }
        });

        serde_json::json!({"ok": true, "status": "running"})
    }

    pub fn activity_list(&self) -> Vec<ActivityRow> {
        // Prefer SQLite for persistence across restarts.
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                return db.recent_activity(50);
            }
        }
        // Fallback to in-memory.
        let inner = self.lock_inner();
        inner
            .activity
            .iter()
            .rev()
            .take(50)
            .map(|e| ActivityRow {
                event_id: String::new(),
                timestamp: e.timestamp,
                severity: "info".into(),
                category: e.event_type.clone(),
                title: e.message.clone(),
                message: e.detail.clone().unwrap_or_default(),
                related_scan_id: None,
            })
            .collect()
    }

    pub fn runtime_stats(&self) -> RuntimeStats {
        let inner = self.lock_inner();
        let up = self.started_at.elapsed().as_secs();

        // Use SQLite totals if available (persisted across restarts).
        let (total_scans, total_threats) = {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                (db.total_scans(), db.total_threats())
            } else {
                (
                    inner.scan_history.len() as u64,
                    inner.scan_history.iter().map(|s| s.threats_found).sum(),
                )
            }
        };

        // Compute stale DB status.
        let now_ts = chrono::Utc::now().timestamp();
        let (db_stale, db_stale_hours) = match inner.last_update_timestamp {
            Some(ts) => {
                let hours = ((now_ts - ts).max(0) as u64) / 3600;
                (hours > 24, hours) // Stale if > 24 hours since last update.
            }
            None => (true, 0), // Never updated = stale.
        };

        // Watcher status.
        let watcher_active = self
            .watcher
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|w| w.is_running()))
            .unwrap_or(false);

        // Quarantine count from DB.
        let q_count = {
            let db_guard = self.lock_db();
            db_guard
                .as_ref()
                .map(|db| db.quarantine_count())
                .unwrap_or(0)
        };

        let argus_stats = self.argus.stats();

        RuntimeStats {
            uptime_secs: up,
            uptime_human: format_uptime(up),
            scans_completed: total_scans,
            threats_found_total: total_threats,
            ipc_requests_served: self.ipc_total_requests.load(Ordering::Relaxed),
            quarantine_count: q_count,
            activity_count: inner.activity.len() as u64,
            started_at: chrono::Utc::now().timestamp() - up as i64,
            engine_loaded: self.read_engine().is_some(),
            signature_count: self.signature_count.load(Ordering::Relaxed),
            db_stale,
            db_stale_hours,
            watcher_active,
            last_update_timestamp: inner.last_update_timestamp,
            total_files_scanned: inner.scan_history.iter().map(|s| s.files_scanned).sum(),
            total_detections: {
                let dg = self.lock_db();
                dg.as_ref().map(|d| d.total_detections()).unwrap_or(0)
            },
            argus_version: argus_stats.engine_version,
            argus_files_analyzed: argus_stats.files_analyzed,
            argus_threats_detected: argus_stats.threats_detected,
            argus_active_layers: argus_stats.active_layers,
            argus_avg_analysis_us: argus_stats.avg_analysis_time_us,
            argus_yara_rules: argus_stats.yara_rules_loaded,
            // Unified protection state.
            protection_state: {
                if self.user_disabled_protection.load(Ordering::Relaxed) {
                    "user_disabled".into()
                } else {
                    let engine_ok = self.read_engine().is_some();
                    let argus_ok = argus_stats.active_layers > 0;
                    let yara_ok = argus_stats.yara_rules_loaded > 0;

                    if engine_ok && watcher_active && argus_ok && yara_ok {
                        "fully_protected".into()
                    } else if engine_ok && argus_ok {
                        "degraded".into()
                    } else if engine_ok {
                        "minimal".into()
                    } else {
                        "unprotected".into()
                    }
                }
            },
            protection_detail: {
                let mut issues = Vec::new();
                if self.read_engine().is_none() {
                    issues.push("ClamAV engine unavailable");
                }
                if !watcher_active {
                    issues.push("Real-time watcher inactive");
                }
                if argus_stats.yara_rules_loaded == 0 {
                    issues.push("No YARA rules loaded");
                }
                if issues.is_empty() {
                    None
                } else {
                    Some(issues.join("; "))
                }
            },
            // Scan cache stats.
            cache_hits: {
                let (h, _, _) = self.scan_cache.stats();
                h
            },
            cache_misses: {
                let (_, m, _) = self.scan_cache.stats();
                m
            },
            cache_entries: {
                let (_, _, e) = self.scan_cache.stats();
                e as u64
            },
            // Idle scanner.
            idle_scanner_state: {
                let s = self.idle_scanner_stats();
                format!("{:?}", s.state).to_lowercase()
            },
            idle_scanner_files: self.idle_scanner_stats().files_scanned_session,
            ipc_reconnect_count: self.ipc_reconnect_count.load(Ordering::Relaxed),
            ipc_last_error_ts: self.ipc_last_error_ts.load(Ordering::Relaxed),
            footprint: self.capture_footprint(),
        }
    }

    /// Record a worker panic event.
    pub fn record_worker_panic(&self, reason: &str) {
        self.worker_panics_total.fetch_add(1, Ordering::Relaxed);
        *self
            .last_recovery_reason
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(format!("worker panic: {reason}"));
    }

    /// Record a worker timeout event.
    pub fn record_worker_timeout(&self, reason: &str) {
        self.worker_timeouts_total.fetch_add(1, Ordering::Relaxed);
        *self
            .last_recovery_reason
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(format!("worker timeout: {reason}"));
    }

    /// Update watcher heartbeat.
    pub fn touch_watcher_heartbeat(&self) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.watcher_last_heartbeat.store(ts, Ordering::Relaxed);
    }

    /// Update orchestrator heartbeat.
    pub fn touch_orchestrator_heartbeat(&self) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.orchestrator_last_heartbeat
            .store(ts, Ordering::Relaxed);
    }

    // ── Calibration ──────────────────────────────────────

    /// Record a detection event in the calibration log.
    /// Reserved for Phase 3: wiring into detection paths.
    #[allow(dead_code)]
    pub fn calibration_record_detection(&self, event: crate::calibration::DetectionEvent) {
        if let Ok(guard) = self.calibration.lock() {
            if let Some(ref log) = *guard {
                if let Err(e) = log.record_detection(&event) {
                    tracing::debug!(error = %e, "calibration record_detection failed");
                }
            }
        }
    }

    /// Record a restore event (likely FP) in the calibration log.
    pub fn calibration_record_restore(&self, event: crate::calibration::RestoreEvent) {
        if let Ok(guard) = self.calibration.lock() {
            if let Some(ref log) = *guard {
                if let Err(e) = log.record_restore(&event) {
                    tracing::debug!(error = %e, "calibration record_restore failed");
                }
            }
        }
    }

    /// Export calibration bundle for developer review.
    /// Reserved for Phase 3: CLI/IPC export endpoint.
    #[allow(dead_code)]
    pub fn calibration_export(&self) -> Option<crate::calibration::CalibrationBundle> {
        if let Ok(guard) = self.calibration.lock() {
            if let Some(ref log) = *guard {
                return Some(log.export_calibration_bundle());
            }
        }
        None
    }

    /// Get bounded execution diagnostics.
    /// Reserved: will be exposed via diagnostics.export IPC.
    #[allow(dead_code)]
    pub fn budget_diagnostics(&self) -> serde_json::Value {
        serde_json::json!({
            "files_with_timeouts": self.budget_files_with_timeouts.load(Ordering::Relaxed),
            "clamav_timeouts": self.budget_clamav_timeouts.load(Ordering::Relaxed),
            "yara_timeouts": self.budget_yara_timeouts.load(Ordering::Relaxed),
            "total_timeouts": self.budget_total_timeouts.load(Ordering::Relaxed),
            "partial_results": self.budget_partial_results.load(Ordering::Relaxed),
            "budget_exhausted": self.budget_exhausted.load(Ordering::Relaxed),
            "realtime_timeouts": self.budget_realtime_timeouts.load(Ordering::Relaxed),
            "idle_timeouts": self.budget_idle_timeouts.load(Ordering::Relaxed),
            "transient_skips": self.budget_transient_skips.load(Ordering::Relaxed),
        })
    }

    /// Get runtime intelligence diagnostics (PLM + AMSI).
    #[allow(dead_code)]
    pub fn runtime_intelligence_diagnostics(&self) -> serde_json::Value {
        let plm_diag = if let Some(ref plm) = self.plm {
            plm.diagnostics.to_json(plm.graph.node_count())
        } else {
            serde_json::json!({"enabled": false})
        };
        let ps_diag = self.ps_bridge_diagnostics();
        let trust_diag = self.trust_graph.as_ref()
            .map(|tg| tg.diagnostics())
            .unwrap_or(serde_json::json!({"enabled": false}));
        serde_json::json!({
            "plm": plm_diag,
            "powershell": ps_diag,
            "trust_graph": trust_diag,
            "amsi": {"enabled": false, "note": "AMSI provider not yet registered"},
        })
    }

    /// Get resilience diagnostics.
    pub fn resilience_diagnostics(&self) -> serde_json::Value {
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let watcher_hb = self.watcher_last_heartbeat.load(Ordering::Relaxed);
        let orch_hb = self.orchestrator_last_heartbeat.load(Ordering::Relaxed);

        // Stale heartbeat detection (>120s without event = stale).
        let watcher_stale = watcher_hb > 0 && (now_ts - watcher_hb) > 120;
        let orch_stale = orch_hb > 0 && (now_ts - orch_hb) > 300;

        serde_json::json!({
            "worker_panics": self.worker_panics_total.load(Ordering::Relaxed),
            "worker_timeouts": self.worker_timeouts_total.load(Ordering::Relaxed),
            "argus_fallbacks": self.argus_worker_fallback_count.load(Ordering::Relaxed),
            "argus_timeouts": self.argus_worker_timeout_count.load(Ordering::Relaxed),
            "last_recovery_reason": self.last_recovery_reason.lock()
                .unwrap_or_else(|e| e.into_inner()).clone(),
            "watcher_heartbeat_ts": watcher_hb,
            "watcher_heartbeat_stale": watcher_stale,
            "orchestrator_heartbeat_ts": orch_hb,
            "orchestrator_heartbeat_stale": orch_stale,
        })
    }

    /// Set ClamAV subprocess isolation mode.
    pub fn set_clamav_subprocess(&self, enabled: bool, timeout_sec: u64) {
        self.clamav_subprocess_enabled
            .store(enabled, Ordering::Relaxed);
        self.clamav_worker_timeout_sec
            .store(timeout_sec.max(10), Ordering::Relaxed);
    }

    /// Load FISH config (from daemon config file).
    pub fn load_fish_config(&self, config: crate::fish::FishConfig) {
        // Rebuild mutation window with new thresholds.
        let mut guard = self.fish_window.lock().unwrap_or_else(|e| e.into_inner());
        *guard = crate::fish::MutationWindow::new(&config);
        // Can't easily update fish_config since it's not behind a Mutex.
        // The diagnostics method reads from the window's internal state.
    }

    /// Get FISH diagnostics snapshot.
    pub fn fish_diagnostics(&self) -> crate::fish::FishDiagnostics {
        let guard = self.fish_window.lock().unwrap_or_else(|e| e.into_inner());
        guard.diagnostics(&self.fish_config)
    }

    /// Record a FISH process suspension.
    pub fn fish_record_suspension(&self) {
        let mut guard = self.fish_window.lock().unwrap_or_else(|e| e.into_inner());
        guard.record_suspension();
    }

    /// Record a FISH process termination.
    pub fn fish_record_termination(&self) {
        let mut guard = self.fish_window.lock().unwrap_or_else(|e| e.into_inner());
        guard.record_termination();
    }

    /// Record a FISH mutation event and return the decision.
    pub fn fish_record(&self, event: crate::fish::FileMutationEvent) -> crate::fish::FishDecision {
        let mut guard = self.fish_window.lock().unwrap_or_else(|e| e.into_inner());
        guard.record(event)
    }

    /// Re-enable protection after intentional pause.
    /// User intentionally disables protection (pauses watcher).
    pub fn disable_protection(&self) {
        self.user_disabled_protection.store(true, Ordering::Relaxed);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.protection_disabled_at.store(ts, Ordering::Relaxed);
        // Stop watcher.
        if let Ok(w) = self.watcher.lock() {
            if let Some(ref watcher) = *w {
                watcher.stop();
            }
        }
        tracing::warn!("protection disabled by user");
    }

    /// Re-enable protection after intentional pause.
    pub fn enable_protection(self: &Arc<Self>) {
        self.user_disabled_protection
            .store(false, Ordering::Relaxed);
        self.protection_disabled_at.store(0, Ordering::Relaxed);
        // Restart watcher.
        self.start_watcher();
        tracing::info!("protection re-enabled by user");
    }

    /// Whether protection is intentionally paused by user.
    pub fn is_user_disabled(&self) -> bool {
        self.user_disabled_protection.load(Ordering::Relaxed)
    }

    /// Capture current memory footprint snapshot and update pressure state.
    pub fn capture_footprint(&self) -> crate::footprint::FootprintSnapshot {
        let engine_loaded = self.read_engine().is_some();
        let sig_count = self.signature_count.load(Ordering::Relaxed);
        let argus_stats = self.argus.stats();
        let (_, _, cache_entries) = self.scan_cache.stats();

        let snap = crate::footprint::capture(
            engine_loaded,
            sig_count,
            argus_stats.yara_rules_loaded,
            cache_entries as u64,
            self.orchestrator_active_workers(),
            &self.footprint_baselines,
        );
        // Update pressure tracker on every capture.
        self.pressure_tracker
            .update(snap.working_set_mb, &self.performance_config);
        snap
    }

    /// Update memory pressure state from current footprint.
    pub fn update_pressure(&self) -> crate::footprint::pressure::PressureState {
        let snap = self.capture_footprint();
        self.pressure_tracker
            .update(snap.working_set_mb, &self.performance_config)
    }

    /// Get current memory pressure state (lock-free).
    pub fn pressure_state(&self) -> crate::footprint::pressure::PressureState {
        self.pressure_tracker.current()
    }

    /// Get full memory pressure policy for diagnostics.
    pub fn pressure_policy(&self) -> crate::footprint::pressure::PressurePolicy {
        let snap = self.capture_footprint();
        crate::footprint::pressure::PressurePolicy::evaluate(
            snap.working_set_mb,
            &self.performance_config,
        )
    }

    /// Load detection exclusions from config.
    pub fn load_detection_exclusions(&self, exclusions: Vec<String>) {
        *self
            .excluded_detections
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = exclusions;
    }

    /// Load trusted hashes from config.
    pub fn load_trusted_hashes(&self, hashes: Vec<String>) {
        *self
            .trusted_hashes
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            hashes.into_iter().map(|h| h.to_lowercase()).collect();
    }

    /// Check if a file hash is in the trusted whitelist.
    pub fn is_hash_trusted(&self, sha256: &str) -> bool {
        let guard = self
            .trusted_hashes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.iter().any(|h| h == &sha256.to_lowercase())
    }

    /// Get current detection exclusions.
    pub fn detection_exclusions(&self) -> Vec<String> {
        self.excluded_detections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Set audit mode.
    pub fn set_audit_mode(&self, enabled: bool) {
        self.audit_mode.store(enabled, Ordering::Relaxed);
    }

    /// Check if running in audit mode.
    pub fn is_audit_mode(&self) -> bool {
        self.audit_mode.load(Ordering::Relaxed)
    }

    /// Daemon operating mode label.
    pub fn daemon_mode(&self) -> &'static str {
        if self.is_user_disabled() {
            "user_disabled"
        } else if self.is_audit_mode() {
            "audit"
        } else {
            "normal"
        }
    }

    /// Whether idle scanner should pause due to memory pressure.
    pub fn should_pause_idle_for_pressure(&self) -> bool {
        self.pressure_tracker.should_pause_idle()
    }

    /// Record startup footprint baseline.
    pub fn record_startup_footprint(&self) {
        let snap = self.capture_footprint();
        self.footprint_baselines.record_startup(snap.working_set_mb);
    }

    /// Record post-scan footprint baseline.
    pub fn record_post_scan_footprint(&self) {
        let snap = self.capture_footprint();
        self.footprint_baselines
            .record_post_scan(snap.working_set_mb);
    }

    /// Auto-scan process memory if a running process matches a high-risk file path.
    /// Called after ARGUS produces a HighRisk/Malicious verdict on a file scan.
    pub fn auto_memory_scan_if_running(&self, file_path: &str, argus_score: u32) {
        // Only trigger for high-confidence detections.
        if argus_score < 76 {
            return;
        }

        let file_lower = file_path.to_lowercase();
        let processes = crate::memory_scanner::list_processes();

        for proc in &processes {
            if let Some(ref path) = proc.path {
                if path.to_lowercase() == file_lower {
                    tracing::warn!(
                        pid = proc.pid,
                        process = proc.name.as_str(),
                        argus_score,
                        "auto memory scan: suspicious process is running"
                    );
                    let result = crate::memory_scanner::scan_process(proc.pid, self.argus());
                    let severity = if result.findings.is_empty() {
                        "info"
                    } else {
                        "warning"
                    };
                    self.log_activity(
                        severity,
                        "memory_scan",
                        &format!("Auto memory scan: {} (PID {})", proc.name, proc.pid),
                        &format!(
                            "{} regions, {} findings, {}ms",
                            result.regions_scanned,
                            result.findings.len(),
                            result.scan_time_ms
                        ),
                        None,
                    );
                    // Only scan first matching process.
                    break;
                }
            }
        }
    }

    /// Count active orchestrator workers.
    fn orchestrator_active_workers(&self) -> u32 {
        let diag = self.orchestrator.diagnostics();
        diag.workers.iter().filter(|w| w.active_jobs > 0).count() as u32
    }
}

// ═══════════════════════════════════════════════════════════════
//  Quick scan background worker
// ═══════════════════════════════════════════════════════════════

fn quick_scan_worker(
    state: Arc<AppState>,
    job_id: Uuid,
    engine: Arc<ClamEngine>,
    cancel: Arc<AtomicBool>,
) {
    let home =
        std::env::var("USERPROFILE").unwrap_or_else(|_| std::env::var("HOME").unwrap_or_default());
    let temp = std::env::var("TEMP").unwrap_or_else(|_| format!("{home}\\AppData\\Local\\Temp"));
    let targets: Vec<PathBuf> = [
        format!("{home}\\Downloads"),
        format!("{home}\\Desktop"),
        temp,
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|p| p.exists())
    .collect();
    folder_scan_worker(state, job_id, engine, cancel, targets, "quick");
}

fn full_scan_worker(
    state: Arc<AppState>,
    job_id: Uuid,
    engine: Arc<ClamEngine>,
    cancel: Arc<AtomicBool>,
) {
    use crate::targeting::{TargetConfig, TargetProvider, dedup, full_disk::FullDiskTargets};
    let config = TargetConfig {
        full_scan_fixed_drives: true,
        full_scan_max_depth: 15,
        ..TargetConfig::default()
    };
    let targets = dedup::deduplicate(FullDiskTargets.collect(&config));
    tracing::info!(job = %job_id, drives = targets.len(), "full disk scan starting");
    folder_scan_worker(state, job_id, engine, cancel, targets, "full");
}

fn startup_scan_worker(
    state: Arc<AppState>,
    job_id: Uuid,
    engine: Arc<ClamEngine>,
    cancel: Arc<AtomicBool>,
) {
    use crate::targeting::{TargetConfig, TargetProvider, dedup, startup::StartupTargets};
    let config = TargetConfig {
        startup_scan_enabled: true,
        startup_recent_days: 7,
        ..TargetConfig::default()
    };
    let mut targets = StartupTargets.collect(&config);
    // Startup scan also includes the quick scan dirs for completeness.
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let temp = std::env::var("TEMP").unwrap_or_else(|_| format!("{home}\\AppData\\Local\\Temp"));
    for dir in &[
        format!("{home}\\Downloads"),
        format!("{home}\\Desktop"),
        temp,
    ] {
        let p = PathBuf::from(dir);
        if p.exists() {
            targets.push(p);
        }
    }
    let targets = dedup::deduplicate(targets);
    tracing::info!(job = %job_id, targets = targets.len(), "startup scan starting");
    folder_scan_worker(state, job_id, engine, cancel, targets, "startup");
}

/// Lightweight post-boot scan of critical system areas.
///
/// Runs once after daemon startup. Not a user-visible scan — no progress bar,
/// no scan history entry. Just quiet background verification.
///
/// - 1 thread, BELOW_NORMAL priority
/// - Yields if memory pressure is Warning+
/// - Skips files already in scan cache
/// - Scans: Startup folder, Run keys, recent Downloads/Desktop, Temp executables
fn startup_critical_scan(
    state: Arc<AppState>,
    engine: Arc<ClamEngine>,
    cache: Arc<crate::scan::cache::ScanCache>,
) {
    use tracing::{debug, info, warn};

    // Set thread priority to BELOW_NORMAL — never compete with realtime or user scans.
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL};
        unsafe {
            let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        }
    }

    // Brief delay — let watcher fully initialize first.
    std::thread::sleep(std::time::Duration::from_secs(5));

    info!("startup critical scan: collecting targets...");

    // Collect high-risk targets.
    use crate::targeting::{TargetConfig, TargetProvider, startup::StartupTargets};
    let config = TargetConfig {
        startup_scan_enabled: true,
        startup_recent_days: 7,
        ..TargetConfig::default()
    };
    let mut targets: Vec<PathBuf> = StartupTargets.collect(&config);

    // Also check Temp for recent executables (last 24h only — tighter than full startup scan).
    let temp = std::env::var("TEMP").unwrap_or_default();
    if !temp.is_empty() {
        let temp_dir = PathBuf::from(&temp);
        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(86400);
        if let Ok(entries) = std::fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() { continue; }
                if let Some(ext) = path.extension() {
                    let el = ext.to_string_lossy().to_lowercase();
                    if !matches!(el.as_str(), "exe" | "scr" | "bat" | "cmd" | "ps1" | "vbs" | "msi") {
                        continue;
                    }
                } else { continue; }
                if let Ok(meta) = path.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        if mtime >= cutoff {
                            targets.push(path);
                        }
                    }
                }
            }
        }
    }

    // Dedup.
    targets.sort();
    targets.dedup();

    // Filter out Sentinella's own files and cached-clean files.
    let daemon_config = crate::config::Config::load(None).unwrap_or_default();
    targets.retain(|path| {
        if crate::scan::is_sentinella_path(path) { return false; }
        if crate::scan::is_excluded(path, &daemon_config.excluded_paths, &daemon_config.excluded_extensions) { return false; }
        if let Ok(meta) = path.metadata() {
            if let Some(true) = cache.check_with_metadata(path, &meta) { return false; }
        }
        true
    });

    if targets.is_empty() {
        info!("startup critical scan: all targets cached clean — nothing to do");
        state.log_activity("info", "system", "Startup check: all clear", "Critical areas verified", None);
        return;
    }

    info!(files = targets.len(), "startup critical scan: scanning critical areas");
    state.log_activity(
        "info", "system",
        &format!("Performing startup protection verification... ({} files)", targets.len()),
        "Post-boot critical areas check",
        None,
    );

    let mut scanned = 0u64;
    let mut threats = 0u64;
    let no_cancel = AtomicBool::new(false);

    for path in &targets {
        // Yield under memory pressure.
        let pressure = state.update_pressure();
        if matches!(pressure, crate::footprint::pressure::PressureState::Warning | crate::footprint::pressure::PressureState::Critical) {
            debug!("startup critical scan: pausing for memory pressure");
            std::thread::sleep(std::time::Duration::from_secs(10));
            continue; // Skip this file, will catch it on idle scan later.
        }

        // Check file still exists and is readable.
        if !path.exists() || !path.is_file() { continue; }
        if let Ok(meta) = path.metadata() {
            if meta.len() > 100 * 1024 * 1024 { continue; } // Skip >100MB.
            if meta.len() == 0 { continue; }
        }

        // ClamAV signature scan.
        let result = state.scan_file_clamav(&engine, path, &no_cancel);

        // ARGUS heuristic analysis.
        let argus_verdict = state.argus().analyze_file(path);

        scanned += 1;

        let (is_threat, threat_name_opt) = crate::ipc::unify_detection_filtered(
            result.infected,
            result.virus_name.as_deref(),
            &argus_verdict,
            &state.detection_exclusions(),
        );

        if let Ok(meta) = path.metadata() {
            cache.record_with_metadata(path, &meta, !is_threat);
        }

        if is_threat {
            threats += 1;
            let threat_name = threat_name_opt.unwrap_or_default();
            warn!(
                file = %path.display(),
                threat = %threat_name,
                "STARTUP CRITICAL: threat in autorun/recent files"
            );
            // Auto-quarantine startup threats.
            let path_str = path.to_string_lossy().to_string();
            match state.quarantine_file(&path_str, &threat_name, "startup-critical") {
                Ok(q) => info!(id = %q.quarantine_id, "startup threat quarantined"),
                Err(e) => warn!(%e, "startup quarantine failed"),
            }
        }

        // Brief sleep between files — don't spike CPU on boot.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let summary = if threats > 0 {
        format!("Startup check: {threats} threat(s) found in {scanned} files")
    } else {
        format!("Startup verification complete: {scanned} critical files clean")
    };
    info!("{summary}");
    state.log_activity(
        if threats > 0 { "warning" } else { "info" },
        "system",
        &summary,
        "Post-boot critical areas verification",
        None,
    );
}

fn folder_scan_worker(
    state: Arc<AppState>,
    job_id: Uuid,
    engine: Arc<ClamEngine>,
    cancel: Arc<AtomicBool>,
    targets: Vec<PathBuf>,
    scan_type_name: &str,
) {
    folder_scan_worker_inner(state, job_id, engine, cancel, targets, scan_type_name, None);
}

/// Inner folder scan worker. Accepts optional pre-existing live state
/// for orchestrated scans (avoids overwriting the queued state).
fn folder_scan_worker_inner(
    state: Arc<AppState>,
    job_id: Uuid,
    engine: Arc<ClamEngine>,
    cancel: Arc<AtomicBool>,
    targets: Vec<PathBuf>,
    scan_type_name: &str,
    existing_live: Option<Arc<ScanLiveState>>,
) {
    let scan_type = scan_type_name.to_string();
    let is_quick = matches!(scan_type_name, "quick" | "startup");
    use tracing::{info, warn};

    info!(job = %job_id, dirs = targets.len(), mode = scan_type_name, "scan worker started");

    // Collect files. Quick scan skips build caches/node_modules for speed;
    // full/folder scans collect everything.
    let mut files: Vec<PathBuf> = Vec::new();
    let max_depth = if is_quick { 3 } else { 10 };
    let config = crate::config::Config::load(None).unwrap_or_default();
    for dir in &targets {
        collect_files(
            dir,
            &mut files,
            max_depth,
            &cancel,
            is_quick,
            &config.excluded_paths,
            &config.excluded_extensions,
        );
        if cancel.load(Ordering::Relaxed) {
            break;
        }
    }

    let total_files = files.len() as u64;
    info!(job = %job_id, files = total_files, "file collection complete, scanning");

    // Use existing live state (orchestrated path) or create new (legacy path).
    let live = if let Some(existing) = existing_live {
        // Orchestrated: reuse caller's live state, update files_total.
        existing.files_total.store(total_files, Ordering::Relaxed);
        existing.set_status(ScanJobStatus::Running);
        existing
    } else {
        // Legacy: create fresh live state.
        let live = Arc::new(ScanLiveState {
            id: job_id.to_string(),
            kind: scan_type.clone(),
            started_at: chrono::Utc::now().timestamp(),
            files_total: AtomicU64::new(total_files),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::clone(&cancel),
            status: std::sync::atomic::AtomicU8::new(1), // Running
            current_path: Mutex::new("Starting...".into()),
        });
        *state.scan_live.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&live));
        live
    };

    // Set total in the job for progress tracking.
    {
        let mut inner = state.lock_inner();
        if let Some(ref mut job) = inner.active_scan {
            job.files_total = total_files;
            job.live = Some(Arc::clone(&live));
        }
    }

    // ── Multi-threaded scan pipeline ──────────────────────────
    // ClamAV's compiled engine is thread-safe (read-only after compile).
    // ARGUS engine is also thread-safe (stateless + atomic counters).
    // We use a channel to collect results from worker threads.

    use std::sync::mpsc;

    // Result messages from scan workers.
    enum ScanMsg {
        Progress(String), // current file path
        Threat(Detection, argus::ArgusVerdict),
        ArgusOnly(argus::ArgusVerdict), // findings but not a threat
        Error(String),
        Done,
    }

    let (tx, rx) = mpsc::channel::<ScanMsg>();
    let num_threads = SCAN_THREADS.min(files.len());
    let files = Arc::new(files);
    let next_file = Arc::new(AtomicUsize::new(0));

    // Spawn scan workers.
    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let eng = Arc::clone(&engine);
        let state_ref = Arc::clone(&state);
        let cancel_ref = Arc::clone(&cancel);
        let live_w = Arc::clone(&live);
        let tx_ref = tx.clone();
        let files_ref = Arc::clone(&files);
        let next_ref = Arc::clone(&next_file);
        let scan_type_w = scan_type.clone();

        handles.push(std::thread::spawn(move || {
            loop {
                if cancel_ref.load(Ordering::Relaxed) {
                    break;
                }
                let idx = next_ref.fetch_add(1, Ordering::Relaxed);
                if idx >= files_ref.len() {
                    break;
                }
                let file = &files_ref[idx];

                let _ = tx_ref.send(ScanMsg::Progress(file.to_string_lossy().to_string()));

                // Check file size.
                let file_meta = match std::fs::metadata(file) {
                    Ok(meta) if meta.len() > max_file_size() => {
                        live_w.files_scanned.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Err(e) => {
                        let _ = tx_ref.send(ScanMsg::Error(format!("{}: {e}", file.display())));
                        live_w.files_scanned.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Ok(meta) => meta,
                };

                if let Some(true) = state_ref.scan_cache.check_with_metadata(file, &file_meta) {
                    live_w.files_scanned.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // ── Per-file profile + budget enforcement ──────
                let scan_profile = argus::profile::ScanProfile::for_context(&scan_type_w);
                let tracker = argus::budget::BudgetTracker::new(scan_profile.budget.clone(), Arc::clone(&cancel_ref));

                // ClamAV scan (with budget check).
                let clamav_start = std::time::Instant::now();
                let result = state_ref.scan_file_clamav(&eng, file, &cancel_ref);
                if tracker.phase_expired(clamav_start, tracker.budget().max_clamav_duration) {
                    tracker.record_timeout(argus::budget::TimeoutReason::ClamAvTimeout);
                }

                // Check total budget before ARGUS.
                if tracker.is_expired() {
                    tracker.record_timeout(argus::budget::TimeoutReason::TotalTimeout);
                    // Partial result: ClamAV ran, ARGUS skipped.
                    live_w.files_scanned.fetch_add(1, Ordering::Relaxed);
                    if result.infected {
                        live_w.threats_found.fetch_add(1, Ordering::Relaxed);
                        let vname = result.virus_name.clone().unwrap_or("Unknown".into());
                        let _ = tx_ref.send(ScanMsg::Threat(
                            Detection { path: file.to_string_lossy().to_string(), virus_name: vname },
                            argus::ArgusVerdict {
                                path: file.to_string_lossy().to_string(),
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
                            },
                        ));
                    }
                    // Cache partial result — don't re-scan on next pass.
                    if !result.infected {
                        state_ref.scan_cache.record_with_metadata(file, &file_meta, true);
                    }
                    tracing::debug!(file = %file.display(), timeouts = ?tracker.timeouts(), "budget exhausted, partial result");
                    continue;
                }

                // ARGUS analysis (with budget check).
                let argus_start = std::time::Instant::now();
                let (mut argus_verdict, worker_error) =
                    match state_ref.analyze_argus_file(file, &cancel_ref) {
                        Ok(result) => result,
                        Err(e) => {
                            let _ = tx_ref.send(ScanMsg::Error(format!("{}: {e}", file.display())));
                            break;
                        }
                    };

                // Check YARA/structural phase budgets.
                if let Some(ref mut timing) = argus_verdict.timing {
                    let argus_elapsed = argus_start.elapsed();
                    if argus_elapsed >= tracker.budget().max_yara_duration {
                        tracker.record_timeout(argus::budget::TimeoutReason::YaraTimeout);
                    }
                    // Record timeout evidence in verdict.
                    timing.timeout_reasons = tracker.timeouts();
                    timing.completed_within_budget = !tracker.is_expired() && tracker.timeouts().is_empty();
                }

                // Add timeout suspicion to ARGUS score (timeouts = evidence).
                let timeout_weight = tracker.timeout_suspicion();
                if timeout_weight > 0 {
                    argus_verdict.score = argus_verdict.score.saturating_add(timeout_weight).min(100);
                    argus_verdict.verdict = argus::verdict::Verdict::from_score(argus_verdict.score);

                    // Increment diagnostics counters.
                    state_ref.budget_files_with_timeouts.fetch_add(1, Ordering::Relaxed);
                    for t in &tracker.timeouts() {
                        match t {
                            argus::budget::TimeoutReason::ClamAvTimeout => { state_ref.budget_clamav_timeouts.fetch_add(1, Ordering::Relaxed); }
                            argus::budget::TimeoutReason::YaraTimeout => { state_ref.budget_yara_timeouts.fetch_add(1, Ordering::Relaxed); }
                            argus::budget::TimeoutReason::TotalTimeout => { state_ref.budget_total_timeouts.fetch_add(1, Ordering::Relaxed); }
                            _ => {}
                        }
                    }
                    match tracker.outcome() {
                        argus::budget::BudgetOutcome::Partial | argus::budget::BudgetOutcome::Suspicious => {
                            state_ref.budget_partial_results.fetch_add(1, Ordering::Relaxed);
                        }
                        argus::budget::BudgetOutcome::Exhausted => {
                            state_ref.budget_exhausted.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }

                // ── ADS content scan (ASTRA, profile-aware) ───
                if !tracker.is_expired() {
                    let ads_policy = crate::scan::ads::ads_policy_for_profile(&scan_profile);
                    let streams = crate::scan::ads::enumerate_ads(file);
                    let filtered = crate::scan::ads::filter_streams(streams, ads_policy);
                    for stream in &filtered {
                        if tracker.is_expired() { break; }
                        // Real content scan — feed ADS content to ARGUS.
                        let ads_result = crate::scan::ads::scan_ads_content(stream, state_ref.argus());
                        for finding in ads_result.content_findings {
                            argus_verdict.score = argus_verdict.score.saturating_add(finding.weight).min(100);
                            argus_verdict.findings.push(finding);
                        }
                    }
                    if !filtered.is_empty() {
                        argus_verdict.verdict = argus::verdict::Verdict::from_score(argus_verdict.score);
                    }
                }

                // ── Persistence intelligence ───────────────
                if let Some(ptype) = crate::persistence::check_persistence_context(file) {
                    let finding = crate::persistence::persistence_finding(ptype, file, false);
                    argus_verdict.score = argus_verdict.score.saturating_add(finding.weight).min(100);
                    argus_verdict.findings.push(finding);
                    argus_verdict.verdict = argus::verdict::Verdict::from_score(argus_verdict.score);
                }

                // ── PLM lineage correlation ──────────────
                if let Some(ref plm) = state_ref.plm {
                    if let Some(chain) = plm.query_by_image_path(file) {
                        if let Some(finding) = crate::plm::lineage_finding(&chain) {
                            argus_verdict.score = argus_verdict.score.saturating_add(finding.weight).min(100);
                            argus_verdict.findings.push(finding);
                            argus_verdict.verdict = argus::verdict::Verdict::from_score(argus_verdict.score);
                        }
                    }
                }

                // ── Trust graph: observe + confidence shaping ──
                if let Some(ref tg) = state_ref.trust_graph {
                    let file_key = file.to_string_lossy().to_lowercase();
                    // Observe this file (builds familiarity over time).
                    tg.observe(&file_key, crate::trust_graph::TrustNodeKind::Executable, None);
                    // Query trust level for confidence adjustment.
                    let trust_q = tg.query(&file_key);
                    if trust_q.confidence_discount > 0 && argus_verdict.score > 0 {
                        // Trust discount: reduce score for familiar entities.
                        // NEVER below 0, NEVER suppresses ClamAV positives.
                        if !result.infected {
                            argus_verdict.score = argus_verdict.score.saturating_sub(trust_q.confidence_discount);
                            argus_verdict.verdict = argus::verdict::Verdict::from_score(argus_verdict.score);
                        }
                        if let Some(finding) = crate::trust_graph::trust_finding(&trust_q) {
                            argus_verdict.findings.push(finding);
                        }
                    }
                }

                live_w.files_scanned.fetch_add(1, Ordering::Relaxed);

                if let Some(e) = worker_error {
                    let _ = tx_ref.send(ScanMsg::Error(format!("{}: {e}", file.display())));
                }

                if let Some(ref err) = result.error {
                    let _ = tx_ref.send(ScanMsg::Error(format!("{}: {err}", file.display())));
                }

                let (is_threat, vname_opt) = unify_detection_filtered(
                    result.infected,
                    result.virus_name.as_deref(),
                    &argus_verdict,
                    &state_ref.detection_exclusions(),
                );
                if !is_threat && result.error.is_none() {
                    state_ref
                        .scan_cache
                        .record_with_metadata(file, &file_meta, true);
                }

                if is_threat {
                    live_w.threats_found.fetch_add(1, Ordering::Relaxed);
                    let vname = vname_opt.unwrap_or("Unknown".into());
                    let _ = tx_ref.send(ScanMsg::Threat(
                        Detection {
                            path: file.to_string_lossy().to_string(),
                            virus_name: vname,
                        },
                        argus_verdict,
                    ));
                } else if !argus_verdict.findings.is_empty() {
                    let _ = tx_ref.send(ScanMsg::ArgusOnly(argus_verdict));
                }
            }
            let _ = tx_ref.send(ScanMsg::Done);
        }));
    }
    drop(tx); // Close sender so rx iterator terminates.

    // Collect results from workers.
    let mut detections: Vec<Detection> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut threads_done = 0usize;

    for msg in rx {
        match msg {
            ScanMsg::Progress(path) => {
                // Update live state atomically — no inner lock needed.
                if let Ok(mut p) = live.current_path.lock() {
                    *p = path;
                }
            }
            ScanMsg::Threat(det, verdict) => {
                warn!(file = %det.path, threat = %det.virus_name, "THREAT DETECTED");
                // Record timing.
                if let Some(ref timing) = verdict.timing {
                    let mut inner = state.lock_inner();
                    if let Some(ref mut job) = inner.active_scan {
                        job.perf_summary.record_file(&det.path, timing);
                    }
                }
                state.persist_argus_verdict(&job_id.to_string(), &verdict);
                detections.push(det);
            }
            ScanMsg::ArgusOnly(verdict) => {
                // Record timing.
                if let Some(ref timing) = verdict.timing {
                    let mut inner = state.lock_inner();
                    if let Some(ref mut job) = inner.active_scan {
                        job.perf_summary.record_file(&verdict.path, timing);
                    }
                }
                state.persist_argus_verdict(&job_id.to_string(), &verdict);
            }
            ScanMsg::Error(e) => {
                errors.push(e);
            }
            ScanMsg::Done => {
                threads_done += 1;
                if threads_done >= num_threads {
                    break;
                }
            }
        }
    }

    // Wait for all threads to finish.
    for h in handles {
        let _ = h.join();
    }

    let scanned = live.files_scanned.load(Ordering::Relaxed);
    let threats = live.threats_found.load(Ordering::Relaxed);
    // Mark live state as completed/cancelled.
    live.set_status(if cancel.load(Ordering::Relaxed) {
        ScanJobStatus::Cancelled
    } else {
        ScanJobStatus::Completed
    });

    // Finalize.
    let finished = chrono::Utc::now().timestamp();
    let cancelled = cancel.load(Ordering::Relaxed);
    let scan_id_str = job_id.to_string();
    let status_str = if cancelled {
        "cancelled"
    } else if threats > 0 {
        "threats"
    } else {
        "clean"
    };

    // Log performance summary.
    {
        let inner = state.lock_inner();
        if let Some(ref job) = inner.active_scan {
            let p = &job.perf_summary;
            info!(
                job = %job_id,
                full = p.strategy_full,
                light = p.strategy_light,
                sig_only = p.strategy_signature,
                skipped = p.strategy_skip,
                too_large = p.strategy_too_large,
                argus_ms = p.total_argus_us / 1000,
                yara_ms = p.total_yara_us / 1000,
                hash_ms = p.total_hash_us / 1000,
                slowest_count = p.slowest_files.len(),
                "scan performance summary",
            );
            if !p.slowest_files.is_empty() {
                for (path, us) in p.slowest_files.iter().take(5) {
                    let short = path.rsplit(['/', '\\']).next().unwrap_or(path);
                    info!(file = short, ms = us / 1000, "slow file");
                }
            }
        }
    }

    // Update in-memory scan job state.
    {
        let mut inner = state.lock_inner();
        if let Some(ref mut job) = inner.active_scan {
            job.status = if cancelled {
                ScanJobStatus::Cancelled
            } else {
                ScanJobStatus::Completed
            };
            job.finished_at = Some(finished);
            job.files_scanned = scanned;
            job.threats_found = threats;
            job.detections = detections.clone();
            job.errors = errors;
            job.current_path = String::new();
        }
        let scan_started_at = inner
            .active_scan
            .as_ref()
            .map(|j| j.started_at)
            .unwrap_or(0);
        inner.scan_history.push(ScanRecord {
            job_id: scan_id_str.clone(),
            scan_type: scan_type.clone(),
            started_at: scan_started_at,
            finished_at: finished,
            files_scanned: scanned,
            threats_found: threats,
            status: status_str.to_string(),
        });

        // Persist scan record to SQLite.
        let duration_ms = ((finished - scan_started_at).max(0) as u64) * 1000;
        state.persist_scan(&ScanRow {
            scan_id: scan_id_str.clone(),
            scan_type: scan_type.clone(),
            status: status_str.to_string(),
            started_at: scan_started_at,
            finished_at: Some(finished),
            files_scanned: scanned,
            threats_found: threats,
            errors_count: inner
                .active_scan
                .as_ref()
                .map(|j| j.errors.len() as u64)
                .unwrap_or(0),
            duration_ms,
        });
    }

    // Persist detections to SQLite.
    for det in &detections {
        state.persist_detection(&DetectionRow {
            detection_id: Uuid::new_v4().to_string(),
            scan_id: scan_id_str.clone(),
            path: det.path.clone(),
            virus_name: det.virus_name.clone(),
            detected_at: finished,
            action_taken: "none".into(),
        });
    }

    // Activity event.
    let severity = if threats > 0 {
        "critical"
    } else if cancelled {
        "warning"
    } else {
        "info"
    };
    let title = if cancelled {
        format!("Quick scan cancelled — {scanned} files, {threats} threats")
    } else {
        format!("Quick scan complete — {scanned} files, {threats} threats")
    };
    let detail = if !detections.is_empty() {
        detections
            .iter()
            .map(|d| d.virus_name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        String::new()
    };
    state.log_activity(severity, "scan", &title, &detail, Some(&scan_id_str));

    // Record post-scan footprint baseline + orchestrator heartbeat.
    state.record_post_scan_footprint();
    state.touch_orchestrator_heartbeat();
    let post_snap = state.capture_footprint();
    crate::footprint::log_footprint("post-scan", &post_snap);

    info!(job = %job_id, scanned, threats, cancelled, "quick scan worker finished");
}

/// Recursively collect files from a directory, respecting depth limit.
fn collect_files(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    max_depth: u32,
    cancel: &AtomicBool,
    quick_mode: bool,
    excluded_paths: &[String],
    excluded_extensions: &[String],
) {
    if max_depth == 0 || cancel.load(Ordering::Relaxed) {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();

        // Skip symlinks to avoid loops.
        if path.is_symlink() {
            continue;
        }
        if crate::scan::is_excluded(&path, excluded_paths, excluded_extensions) {
            continue;
        }

        if path.is_dir() {
            if crate::scan::should_skip_dir(&path, quick_mode) {
                continue;
            }
            if crate::scan::is_sentinella_path(&path) {
                continue;
            }
            collect_files(
                &path,
                out,
                max_depth - 1,
                cancel,
                quick_mode,
                excluded_paths,
                excluded_extensions,
            );
        } else if path.is_file() {
            if crate::scan::should_skip_file(&path) {
                continue;
            }
            if crate::scan::is_sentinella_path(&path) {
                continue;
            }
            out.push(path);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Response types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct ScanStartResponse {
    pub job_id: String,
    pub status: String,
    pub result: Option<ScanResultResponse>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResultResponse {
    pub path: String,
    pub infected: bool,
    pub virus_name: Option<String>,
    pub scanned_bytes: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanStatusResponse {
    pub running: bool,
    pub job_id: Option<String>,
    pub state: &'static str,
    pub scan_type: Option<String>,
    pub files_scanned: u64,
    pub files_total: u64,
    pub progress_percent: f32,
    pub threats_found: u64,
    pub current_path: Option<String>,
    pub scans_completed: u64,
    pub detections: Vec<Detection>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub errors_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRecord {
    pub job_id: String,
    pub scan_type: String,
    pub started_at: i64,
    pub finished_at: i64,
    pub files_scanned: u64,
    pub threats_found: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub event_type: String,
    pub message: String,
    pub detail: Option<String>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrchestratedScanJob {
    pub id: String,
    pub queue_kind: crate::orchestrator::QueueKind,
    pub path: String,
    pub requested_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrchestratedJobResult {
    pub id: String,
    pub path: String,
    pub verdict: Option<String>,
    pub status: String,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStats {
    pub uptime_secs: u64,
    pub uptime_human: String,
    pub scans_completed: u64,
    pub threats_found_total: u64,
    pub ipc_requests_served: u64,
    pub quarantine_count: u64,
    pub activity_count: u64,
    pub started_at: i64,
    pub engine_loaded: bool,
    pub signature_count: u64,
    pub db_stale: bool,
    pub db_stale_hours: u64,
    pub watcher_active: bool,
    pub last_update_timestamp: Option<i64>,
    pub total_files_scanned: u64,
    pub total_detections: u64,
    // ARGUS heuristics engine stats.
    pub argus_version: &'static str,
    pub argus_files_analyzed: u64,
    pub argus_threats_detected: u64,
    pub argus_active_layers: u32,
    pub argus_avg_analysis_us: u64,
    pub argus_yara_rules: u64,
    /// Unified protection state derived from all subsystems.
    pub protection_state: String,
    /// Detail about any degraded subsystem.
    pub protection_detail: Option<String>,
    // ── Scan cache stats ────────────────────────────────
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_entries: u64,
    // ── Idle scanner ────────────────────────────────────
    pub idle_scanner_state: String,
    pub idle_scanner_files: u64,
    // ── IPC health ─────────────────────────────────────
    pub ipc_reconnect_count: u64,
    pub ipc_last_error_ts: u64,
    // ── Memory footprint ───────────────────────────────
    pub footprint: crate::footprint::FootprintSnapshot,
}

fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Unified detection logic — merges ClamAV signature + ARGUS heuristic
/// into a single coherent verdict. Never creates duplicate detections.
///
/// Returns `(is_threat, unified_name)`.
/// Unified detection with detection-name exclusion support.
pub fn unify_detection_filtered(
    clamav_infected: bool,
    clamav_name: Option<&str>,
    argus: &argus::ArgusVerdict,
    excluded_detections: &[String],
) -> (bool, Option<String>) {
    // ClamAV signature match → always threat.
    // ARGUS-only → require higher confidence for auto-quarantine.
    // Score 76-84 ARGUS-only = suspicious but NOT auto-quarantined.
    // Score 85+ ARGUS-only = high confidence → auto-quarantine.
    // This prevents "Suspicious.Generic [78/100]" from quarantining
    // legitimate installers that happen to look structurally suspicious.
    let argus_threat = if clamav_infected {
        argus.is_threat() // When ClamAV agrees, normal threshold (76+)
    } else {
        argus.score >= 85 // ARGUS-only needs higher confidence
    };
    let is_threat = clamav_infected || argus_threat;

    if !is_threat {
        return (false, None);
    }

    let name = if clamav_infected {
        // ClamAV is authoritative — use its specific name.
        let base = clamav_name.unwrap_or("Malware.Generic");
        if argus.score > 50 {
            // Both engines agree — note ARGUS confidence.
            format!("{base} [ARGUS: {}/100]", argus.score)
        } else {
            base.to_string()
        }
    } else {
        // ARGUS-only detection — build a descriptive name.
        let top_finding = argus
            .findings
            .first()
            .map(|f| f.layer)
            .unwrap_or(argus::verdict::Layer::PatternDetection);

        let category = match top_finding {
            argus::verdict::Layer::PatternDetection => {
                // Try to be more specific based on finding descriptions.
                let desc = argus
                    .findings
                    .first()
                    .map(|f| f.description.as_str())
                    .unwrap_or("");
                if desc.contains("Discord") || desc.contains("token") {
                    "Stealer.Discord"
                } else if desc.contains("credential") || desc.contains("browser") {
                    "Stealer.Credentials"
                } else if desc.contains("webhook") || desc.contains("exfiltrat") {
                    "Stealer.Exfiltration"
                } else if desc.contains("crypto") || desc.contains("mining") {
                    "Miner.CryptoJack"
                } else if desc.contains("persistence") {
                    "Persistence.Suspicious"
                } else {
                    "Suspicious.Behavior"
                }
            }
            argus::verdict::Layer::PackerDetection => "Packed.Suspicious",
            argus::verdict::Layer::ScriptAnalysis => "Script.Malicious",
            argus::verdict::Layer::FileDeception => "Deception.Disguised",
            argus::verdict::Layer::MimeValidation => "Deception.FakeExtension",
            argus::verdict::Layer::IocCorrelation => "IOC.KnownMalicious",
            argus::verdict::Layer::StructuralAnalysis => "Suspicious.Structure",
            _ => "Suspicious.Generic",
        };

        format!("ARGUS/{category} [{}/100]", argus.score)
    };

    // Check detection-name exclusions.
    if !excluded_detections.is_empty() {
        let name_lower = name.to_lowercase();
        for excl in excluded_detections {
            if name_lower.contains(&excl.to_lowercase()) {
                tracing::info!(
                    detection = name.as_str(),
                    exclusion = excl.as_str(),
                    "detection excluded by user rule"
                );
                return (false, None);
            }
        }
    }

    (true, Some(name))
}

// ── Unit tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use argus::verdict::{ArgusVerdict, Finding, Layer, Severity, Verdict, VerdictExplanation};

    // ── Helpers ──────────────────────────────────────────────────

    /// Build a minimal `ArgusVerdict` with a given score and no findings.
    fn make_verdict(score: u32) -> ArgusVerdict {
        ArgusVerdict {
            path: "C:\\test\\sample.exe".into(),
            file_size: 1024,
            sha256: "aa".repeat(32),
            mime_type: Some("application/x-dosexec".into()),
            score,
            verdict: Verdict::from_score(score),
            findings: Vec::new(),
            analysis_time_us: 100,
            engine_version: argus::ENGINE_VERSION,
            timestamp: 0,
            explanation: VerdictExplanation::default(),
            timing: None,
        }
    }

    /// Build an `ArgusVerdict` with a single finding in the given layer.
    fn make_verdict_with_finding(score: u32, layer: Layer, desc: &str) -> ArgusVerdict {
        let mut v = make_verdict(score);
        v.findings.push(Finding {
            layer,
            severity: Severity::High,
            weight: score,
            description: desc.to_string(),
            technical_detail: None,
        });
        v
    }

    // ── unify_detection_filtered ─────────────────────────────────

    #[test]
    fn clamav_positive_argus_low_score_is_infected() {
        // ClamAV says infected, ARGUS score is low (20).
        // ClamAV is authoritative — result should be infected.
        let argus = make_verdict(20);
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent"), &argus, &[]);
        assert!(infected, "ClamAV positive should always be infected");
        let n = name.unwrap();
        assert!(
            n.contains("Win.Trojan.Agent"),
            "name should contain ClamAV detection: {n}"
        );
        // ARGUS score 20 is <= 50, so no ARGUS annotation expected.
        assert!(
            !n.contains("ARGUS"),
            "low ARGUS score should not be annotated: {n}"
        );
    }

    #[test]
    fn clamav_positive_argus_high_score_includes_argus_annotation() {
        // Both engines agree — ClamAV name should include ARGUS score.
        let argus = make_verdict(90);
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent"), &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("Win.Trojan.Agent"),
            "should contain ClamAV name: {n}"
        );
        assert!(
            n.contains("ARGUS: 90/100"),
            "should annotate ARGUS score when > 50: {n}"
        );
    }

    #[test]
    fn clamav_positive_no_name_defaults_to_malware_generic() {
        // ClamAV infected but virus_name is None → default name.
        let argus = make_verdict(10);
        let (infected, name) = unify_detection_filtered(true, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("Malware.Generic"),
            "missing ClamAV name should default to Malware.Generic: {n}"
        );
    }

    #[test]
    fn clamav_negative_argus_85_is_infected() {
        // ClamAV clean, ARGUS score 85 → ARGUS-only high confidence.
        let argus =
            make_verdict_with_finding(85, Layer::PatternDetection, "Discord token stealer pattern");
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(
            infected,
            "ARGUS score >= 85 without ClamAV should be infected"
        );
        let n = name.unwrap();
        assert!(
            n.starts_with("ARGUS/"),
            "ARGUS-only detection should start with ARGUS/: {n}"
        );
        assert!(n.contains("85/100"), "should contain ARGUS score: {n}");
    }

    #[test]
    fn clamav_negative_argus_score_50_not_infected() {
        // ClamAV clean, ARGUS score 50 — below the 85 threshold for
        // ARGUS-only auto-quarantine.
        let argus = make_verdict(50);
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(
            !infected,
            "ARGUS score 50 without ClamAV should NOT be infected"
        );
        assert!(name.is_none());
    }

    #[test]
    fn clamav_negative_argus_score_84_not_infected() {
        // Edge case: ARGUS score 84 (one below threshold).
        let argus = make_verdict(84);
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(
            !infected,
            "ARGUS score 84 without ClamAV should NOT be infected (threshold is 85)"
        );
        assert!(name.is_none());
    }

    #[test]
    fn clamav_negative_argus_score_0_not_infected() {
        // Both clean — absolutely not infected.
        let argus = make_verdict(0);
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(!infected);
        assert!(name.is_none());
    }

    #[test]
    fn clamav_negative_argus_100_is_infected() {
        // Maximum ARGUS score without ClamAV → definitely infected.
        let argus = make_verdict_with_finding(
            100,
            Layer::IocCorrelation,
            "SHA-256 matches known malware IOC",
        );
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("IOC.KnownMalicious"),
            "IOC layer → IOC.KnownMalicious: {n}"
        );
    }

    // ── Detection exclusion ──────────────────────────────────────

    #[test]
    fn exclusion_suppresses_clamav_detection() {
        // ClamAV infected but detection name matches an exclusion rule.
        let argus = make_verdict(10);
        let exclusions = vec!["Win.Trojan.Agent".to_string()];
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent-12345"), &argus, &exclusions);
        assert!(
            !infected,
            "excluded detection should NOT be reported as infected"
        );
        assert!(name.is_none());
    }

    #[test]
    fn exclusion_is_case_insensitive() {
        // Exclusion rule uses different casing — should still match.
        let argus = make_verdict(10);
        let exclusions = vec!["win.trojan.agent".to_string()];
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent-999"), &argus, &exclusions);
        assert!(
            !infected,
            "case-insensitive exclusion should suppress detection"
        );
        assert!(name.is_none());
    }

    #[test]
    fn exclusion_substring_match() {
        // Exclusion is a substring of the detection name.
        let argus = make_verdict(60);
        let exclusions = vec!["Trojan".to_string()];
        let (infected, _) =
            unify_detection_filtered(true, Some("Win.Trojan.Generic-42"), &argus, &exclusions);
        assert!(!infected, "substring exclusion should match");
    }

    #[test]
    fn exclusion_no_match_still_infected() {
        // Exclusion list exists but does NOT match this detection.
        let argus = make_verdict(60);
        let exclusions = vec!["Ransomware".to_string()];
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent"), &argus, &exclusions);
        assert!(
            infected,
            "non-matching exclusion should leave detection intact"
        );
        assert!(name.is_some());
    }

    #[test]
    fn exclusion_suppresses_argus_only_detection() {
        // ARGUS-only detection excluded by name.
        let argus = make_verdict_with_finding(90, Layer::PatternDetection, "Discord token stealer");
        let exclusions = vec!["Stealer.Discord".to_string()];
        let (infected, name) = unify_detection_filtered(false, None, &argus, &exclusions);
        assert!(
            !infected,
            "ARGUS-only detection should be suppressible by exclusion"
        );
        assert!(name.is_none());
    }

    #[test]
    fn empty_exclusion_list_does_not_suppress() {
        let argus = make_verdict(10);
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent"), &argus, &[]);
        assert!(infected);
        assert!(name.is_some());
    }

    // ── ARGUS-only detection name classification ─────────────────

    #[test]
    fn argus_only_packer_layer_gives_packed_suspicious() {
        let argus = make_verdict_with_finding(90, Layer::PackerDetection, "UPX packer detected");
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("Packed.Suspicious"),
            "PackerDetection layer should yield Packed.Suspicious: {n}"
        );
    }

    #[test]
    fn argus_only_script_layer_gives_script_malicious() {
        let argus =
            make_verdict_with_finding(92, Layer::ScriptAnalysis, "Obfuscated PowerShell dropper");
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("Script.Malicious"),
            "ScriptAnalysis layer should yield Script.Malicious: {n}"
        );
    }

    #[test]
    fn argus_only_deception_layer_gives_deception_disguised() {
        let argus =
            make_verdict_with_finding(95, Layer::FileDeception, "RTLO character in filename");
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("Deception.Disguised"),
            "FileDeception layer should yield Deception.Disguised: {n}"
        );
    }

    #[test]
    fn argus_only_no_findings_defaults_to_suspicious_behavior() {
        // score >= 85 but no findings → falls back to PatternDetection default.
        let argus = make_verdict(85);
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        // With empty findings, top_finding defaults to PatternDetection
        // and desc is "" so we get "Suspicious.Behavior".
        assert!(
            n.contains("Suspicious.Behavior"),
            "no findings should default to Suspicious.Behavior: {n}"
        );
    }

    // ── max_file_size ────────────────────────────────────────────

    #[test]
    fn max_file_size_returns_config_not_hardcoded() {
        // Without a config file present in test environment, max_file_size()
        // should fall back to DEFAULT_MAX_FILE_SIZE (512 MB).
        let size = max_file_size();
        assert_eq!(
            size, DEFAULT_MAX_FILE_SIZE,
            "without config, max_file_size should equal DEFAULT_MAX_FILE_SIZE"
        );
        // Confirm DEFAULT_MAX_FILE_SIZE is 512 MB.
        assert_eq!(
            DEFAULT_MAX_FILE_SIZE,
            512 * 1024 * 1024,
            "DEFAULT_MAX_FILE_SIZE should be 512 MB"
        );
    }

    // ── ScanJobStatus transitions ────────────────────────────────

    /// Build a `ScanLiveState` in its default (Pending) state.
    fn make_live_state() -> ScanLiveState {
        ScanLiveState {
            id: "test-scan-001".into(),
            kind: "quick".into(),
            started_at: 0,
            files_total: AtomicU64::new(0),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            status: std::sync::atomic::AtomicU8::new(0), // 0 = Pending
            current_path: Mutex::new(String::new()),
        }
    }

    #[test]
    fn scan_job_status_pending_to_running() {
        let live = make_live_state();
        assert!(
            live.status_enum() == ScanJobStatus::Pending,
            "initial status should be Pending"
        );
        live.set_status(ScanJobStatus::Running);
        assert!(
            live.status_enum() == ScanJobStatus::Running,
            "should transition to Running"
        );
    }

    #[test]
    fn scan_job_status_running_to_completed() {
        let live = make_live_state();
        live.set_status(ScanJobStatus::Running);
        live.set_status(ScanJobStatus::Completed);
        assert!(
            live.status_enum() == ScanJobStatus::Completed,
            "should transition to Completed"
        );
    }

    #[test]
    fn scan_job_status_running_to_cancelled() {
        let live = make_live_state();
        live.set_status(ScanJobStatus::Running);
        live.set_status(ScanJobStatus::Cancelled);
        assert!(
            live.status_enum() == ScanJobStatus::Cancelled,
            "should transition to Cancelled"
        );
    }

    #[test]
    fn scan_job_status_running_to_draining_to_cancelled() {
        let live = make_live_state();
        live.set_status(ScanJobStatus::Running);
        live.set_status(ScanJobStatus::Draining);
        assert!(
            live.status_enum() == ScanJobStatus::Draining,
            "should transition to Draining"
        );
        live.set_status(ScanJobStatus::Cancelled);
        assert!(
            live.status_enum() == ScanJobStatus::Cancelled,
            "should transition from Draining to Cancelled"
        );
    }

    #[test]
    fn scan_job_status_running_to_failed() {
        let live = make_live_state();
        live.set_status(ScanJobStatus::Running);
        live.set_status(ScanJobStatus::Failed);
        assert!(
            live.status_enum() == ScanJobStatus::Failed,
            "should transition to Failed"
        );
    }

    #[test]
    fn scan_job_status_cancel_flag_is_initially_false() {
        let live = make_live_state();
        assert!(
            !live.cancel_flag.load(Ordering::Relaxed),
            "cancel flag should be false on construction"
        );
    }
}

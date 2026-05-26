//! Daemon supervisor — monitors sentinelld health and restarts on crash.
//!
//! Runs in a background thread. Detects pipe loss, attempts reconnect,
//! spawns daemon if missing. Respects user-disabled state (no respawn).

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Daemon connection state — richer than connected/disconnected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// Initial startup, first connection attempt.
    Connecting,
    /// Pipe healthy, daemon responding.
    Connected,
    /// Pipe lost, attempting reconnect/respawn.
    Recovering,
    /// Recovery timeout exceeded, daemon may need manual intervention.
    Degraded,
    /// Multiple recovery failures, daemon unreachable.
    Disconnected,
    /// User intentionally disabled protection — no auto-respawn.
    UserDisabled,
}

impl ConnectionState {
    fn as_u8(self) -> u8 {
        match self {
            Self::Connecting => 0,
            Self::Connected => 1,
            Self::Recovering => 2,
            Self::Degraded => 3,
            Self::Disconnected => 4,
            Self::UserDisabled => 5,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Connecting,
            1 => Self::Connected,
            2 => Self::Recovering,
            3 => Self::Degraded,
            4 => Self::Disconnected,
            5 => Self::UserDisabled,
            _ => Self::Disconnected,
        }
    }
}

/// Why recovery was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Structured reasons for future diagnostics export.
pub enum RecoveryReason {
    ProcessMissing,
    PipeLost,
    StartupTimeout,
    CrashLoop,
    WorkerPanicStorm,
    MemoryPressure,
    ManualKill,
    UpdateRestart,
    Unknown,
}

/// Recovery telemetry — shared with frontend.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryInfo {
    pub state: ConnectionState,
    pub restart_attempts: u64,
    pub successful_recoveries: u64,
    pub failed_recoveries: u64,
    pub last_restart_reason: Option<String>,
    pub last_restart_at: Option<String>,
    pub daemon_spawned: bool,
    pub crash_loop_detected: bool,
    pub audit_mode: bool,
    pub current_backoff_sec: u64,
    pub stable_since: Option<String>,
}

/// Shared supervisor state — accessible from Tauri commands.
pub struct SupervisorState {
    connection: AtomicU8,
    restart_attempts: AtomicU64,
    successful_recoveries: AtomicU64,
    failed_recoveries: AtomicU64,
    last_restart_reason: Mutex<Option<String>>,
    last_restart_at: Mutex<Option<String>>,
    daemon_spawned: AtomicBool,
    user_disabled: AtomicBool,
    crash_loop_detected: AtomicBool,
    /// Supervisor-driven audit mode (crash loop recovery).
    audit_mode: AtomicBool,
    /// Current backoff in seconds.
    current_backoff_sec: AtomicU64,
    /// Timestamp when daemon became stable (for auto-exit audit mode).
    stable_since: Mutex<Option<Instant>>,
}

impl SupervisorState {
    pub fn new() -> Self {
        Self {
            connection: AtomicU8::new(ConnectionState::Connecting.as_u8()),
            restart_attempts: AtomicU64::new(0),
            successful_recoveries: AtomicU64::new(0),
            failed_recoveries: AtomicU64::new(0),
            last_restart_reason: Mutex::new(None),
            last_restart_at: Mutex::new(None),
            daemon_spawned: AtomicBool::new(false),
            user_disabled: AtomicBool::new(false),
            crash_loop_detected: AtomicBool::new(false),
            audit_mode: AtomicBool::new(false),
            current_backoff_sec: AtomicU64::new(0),
            stable_since: Mutex::new(None),
        }
    }

    pub fn state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.connection.load(Ordering::Relaxed))
    }

    fn set_state(&self, state: ConnectionState) {
        let prev = self.state();
        if prev != state {
            log::info!("supervisor: {} → {}", state_label(prev), state_label(state));
        }
        self.connection.store(state.as_u8(), Ordering::Relaxed);
    }

    pub fn set_user_disabled(&self, disabled: bool) {
        self.user_disabled.store(disabled, Ordering::Relaxed);
        if disabled {
            self.set_state(ConnectionState::UserDisabled);
        }
    }

    pub fn is_user_disabled(&self) -> bool {
        self.user_disabled.load(Ordering::Relaxed)
    }

    pub fn info(&self) -> RecoveryInfo {
        let stable = self.stable_since.lock().unwrap_or_else(|e| e.into_inner())
            .map(|_| chrono::Utc::now().to_rfc3339());
        RecoveryInfo {
            state: self.state(),
            restart_attempts: self.restart_attempts.load(Ordering::Relaxed),
            successful_recoveries: self.successful_recoveries.load(Ordering::Relaxed),
            failed_recoveries: self.failed_recoveries.load(Ordering::Relaxed),
            last_restart_reason: self.last_restart_reason.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            last_restart_at: self.last_restart_at.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            daemon_spawned: self.daemon_spawned.load(Ordering::Relaxed),
            crash_loop_detected: self.crash_loop_detected.load(Ordering::Relaxed),
            audit_mode: self.audit_mode.load(Ordering::Relaxed),
            current_backoff_sec: self.current_backoff_sec.load(Ordering::Relaxed),
            stable_since: stable,
        }
    }

    pub fn is_audit_mode(&self) -> bool {
        self.audit_mode.load(Ordering::Relaxed)
    }

    fn record_attempt(&self, reason: &str) {
        self.restart_attempts.fetch_add(1, Ordering::Relaxed);
        *self.last_restart_reason.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason.to_string());
        let ts = chrono::Utc::now().to_rfc3339();
        *self.last_restart_at.lock().unwrap_or_else(|e| e.into_inner()) = Some(ts);
    }

    fn record_success(&self) {
        self.successful_recoveries.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        self.failed_recoveries.fetch_add(1, Ordering::Relaxed);
    }
}

fn state_label(s: ConnectionState) -> &'static str {
    match s {
        ConnectionState::Connecting => "connecting",
        ConnectionState::Connected => "connected",
        ConnectionState::Recovering => "recovering",
        ConnectionState::Degraded => "degraded",
        ConnectionState::Disconnected => "disconnected",
        ConnectionState::UserDisabled => "user_disabled",
    }
}

/// Check if daemon pipe is reachable (sync, fast).
fn check_daemon() -> bool {
    blocking_daemon_call_simple("health").is_some()
}

/// Check if daemon reports user_disabled state.
fn check_user_disabled() -> bool {
    blocking_daemon_call_simple("health")
        .and_then(|v| v.get("user_disabled")?.as_bool())
        .unwrap_or(false)
}

fn blocking_daemon_call_simple(method: &str) -> Option<serde_json::Value> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .ok()?;

    rt.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(6),
            crate::daemon_client::call_simple(method),
        )
        .await
        .ok()?
        .ok()
    })
}

struct DaemonLayout {
    exe: PathBuf,
    daemon_dir: PathBuf,
    runtime_root: PathBuf,
}

fn program_data_root() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    PathBuf::from(base).join("Sentinella")
}

fn is_installed_context(gui_dir: &Path) -> bool {
    let lower = gui_dir.to_string_lossy().to_ascii_lowercase();
    lower.contains(r"\program files\") || lower.contains(r"\program files (x86)\")
}

fn daemon_candidates(gui_dir: &Path) -> [PathBuf; 4] {
    [
        gui_dir.join("resources").join("daemon").join("sentinelld.exe"),
        gui_dir.join("daemon").join("sentinelld.exe"),
        gui_dir.join("sentinelld.exe"),
        gui_dir.join("resources").join("sentinelld.exe"),
    ]
}

fn find_daemon_layout() -> Option<DaemonLayout> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in daemon_candidates(dir) {
                if candidate.exists() {
                    let daemon_dir = candidate.parent()?.to_path_buf();
                    let portable_root = daemon_dir.join("runtime");
                    let runtime_root = if is_installed_context(dir) {
                        program_data_root()
                    } else if portable_root.exists() {
                        portable_root
                    } else {
                        program_data_root()
                    };
                    return Some(DaemonLayout {
                        exe: candidate,
                        daemon_dir,
                        runtime_root,
                    });
                }
            }

            for ancestor in dir.ancestors().skip(1) {
                let dev = ancestor.join("target").join("release").join("sentinelld.exe");
                if dev.exists() {
                    return Some(DaemonLayout {
                        daemon_dir: dev.parent()?.to_path_buf(),
                        exe: dev,
                        runtime_root: ancestor.join("runtime"),
                    });
                }
                let dev_debug = ancestor.join("target").join("debug").join("sentinelld.exe");
                if dev_debug.exists() {
                    return Some(DaemonLayout {
                        daemon_dir: dev_debug.parent()?.to_path_buf(),
                        exe: dev_debug,
                        runtime_root: ancestor.join("runtime"),
                    });
                }
            }
        }
    }
    None
}

#[allow(dead_code)]
/// Find the daemon executable.
fn find_daemon_exe() -> Option<std::path::PathBuf> {
    // Try relative to our own exe first (installed layout).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("sentinelld.exe");
            if candidate.exists() {
                return Some(candidate);
            }
            // Dev layout: gui/src-tauri/target/debug or release → project root.
            for ancestor in dir.ancestors().skip(1) {
                let dev = ancestor.join("target").join("release").join("sentinelld.exe");
                if dev.exists() {
                    return Some(dev);
                }
                let dev_debug = ancestor.join("target").join("debug").join("sentinelld.exe");
                if dev_debug.exists() {
                    return Some(dev_debug);
                }
            }
        }
    }
    // Not found in any known location.
    None
}

/// Attempt to spawn daemon process. If `audit` is true, adds `--audit-mode`.
fn spawn_daemon(state: &SupervisorState) -> bool {
    spawn_daemon_mode(state, state.is_audit_mode())
}

fn spawn_daemon_mode(state: &SupervisorState, audit: bool) -> bool {
    let layout = match find_daemon_layout() {
        Some(layout) => layout,
        None => {
            log::warn!("supervisor: sentinelld.exe not found — cannot spawn");
            return false;
        }
    };

    let dll_dir = layout.daemon_dir.clone();
    let db_dir = layout.runtime_root.join("signatures");
    let state_db = layout.runtime_root.join("state").join("sentinella.db");
    let work_dir = layout.daemon_dir.clone();

    log::info!(
        "supervisor: spawning daemon - {} (cwd: {}, runtime: {}) audit={audit}",
        layout.exe.display(),
        work_dir.display(),
        layout.runtime_root.display()
    );
    state.record_attempt(if audit { "crash_loop_audit" } else { "pipe_lost" });

    // Spawn detached — daemon runs independently of GUI.
    #[cfg(target_os = "windows")]
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new(&layout.exe);
    cmd.current_dir(&work_dir)
        .env(crate::ipc_auth::ENV_NAME, crate::ipc_auth::secret())
        .arg("--foreground")
        .arg("--log-level")
        .arg("info")
        .arg("--dll-dir")
        .arg(&dll_dir)
        .arg("--runtime-root")
        .arg(&layout.runtime_root)
        .arg("--state-db")
        .arg(&state_db)
        .arg("--db-dir")
        .arg(&db_dir);
    if audit {
        cmd.arg("--audit-mode");
    }
    #[cfg(target_os = "windows")]
    cmd.creation_flags(0x00000008); // DETACHED_PROCESS
    match cmd.spawn()
    {
        Ok(_child) => {
            state.daemon_spawned.store(true, Ordering::Relaxed);
            log::info!("supervisor: daemon spawned successfully");
            true
        }
        Err(e) => {
            log::error!("supervisor: failed to spawn daemon: {e}");
            false
        }
    }
}

/// Escalating backoff — never caps permanently, but slows down.
const BACKOFF_SECS: &[u64] = &[0, 1, 3, 5, 10, 20, 30, 60];

/// Max rapid crashes before declaring crash loop → enter audit mode.
const CRASH_LOOP_THRESHOLD: u64 = 5;
const CRASH_LOOP_WINDOW: Duration = Duration::from_secs(120);

/// Minutes stable in audit mode before auto-exiting to normal.
const AUDIT_STABLE_MINUTES: u64 = 10;

/// Start the supervisor background thread.
pub fn start(state: Arc<SupervisorState>) {
    if let Err(e) = std::thread::Builder::new()
        .name("supervisor".into())
        .spawn(move || supervisor_loop(state))
    {
        log::error!("supervisor: failed to spawn thread: {e}");
    }
}

fn supervisor_loop(state: Arc<SupervisorState>) {
    log::info!("supervisor: starting — waiting for daemon");
    std::thread::sleep(Duration::from_secs(2));

    let mut consecutive_failures = 0u64;
    let mut crash_timestamps: Vec<Instant> = Vec::new();

    loop {
        // User disabled → do nothing.
        if state.is_user_disabled() {
            state.set_state(ConnectionState::UserDisabled);
            *state.stable_since.lock().unwrap_or_else(|e| e.into_inner()) = None;
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }

        let alive = check_daemon();

        if alive {
            // Check if daemon reports user_disabled.
            if check_user_disabled() {
                state.set_user_disabled(true);
                continue;
            }

            let was_recovering = state.state() != ConnectionState::Connected;
            if was_recovering {
                state.record_success();
                state.set_state(ConnectionState::Connected);
                consecutive_failures = 0;
            }

            // Track stability for audit mode auto-exit.
            if state.is_audit_mode() {
                let mut stable = state.stable_since.lock().unwrap_or_else(|e| e.into_inner());
                if stable.is_none() {
                    *stable = Some(Instant::now());
                    log::info!("supervisor: audit mode — stability timer started");
                } else if let Some(since) = *stable {
                    let stable_mins = since.elapsed().as_secs() / 60;
                    if stable_mins >= AUDIT_STABLE_MINUTES {
                        log::info!("supervisor: stable for {stable_mins}min — exiting audit mode");
                        state.audit_mode.store(false, Ordering::Relaxed);
                        *stable = None;
                        // Will restart daemon in normal mode on next cycle
                        // (current daemon keeps running, it's already stable).
                    }
                }
            }

            std::thread::sleep(Duration::from_secs(5));
            continue;
        }

        // ── Daemon not reachable ─────────────────────────
        if state.state() == ConnectionState::Connected {
            log::warn!("supervisor: daemon pipe lost — entering recovery");
            *state.stable_since.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }

        consecutive_failures += 1;

        // Crash loop detection → escalate to audit mode.
        let now = Instant::now();
        crash_timestamps.push(now);
        crash_timestamps.retain(|t| now.duration_since(*t) < CRASH_LOOP_WINDOW);
        if crash_timestamps.len() as u64 >= CRASH_LOOP_THRESHOLD && !state.is_audit_mode() {
            state.crash_loop_detected.store(true, Ordering::Relaxed);
            state.audit_mode.store(true, Ordering::Relaxed);
            log::error!(
                "supervisor: crash loop ({} crashes in {}s) — escalating to AUDIT MODE",
                crash_timestamps.len(), CRASH_LOOP_WINDOW.as_secs()
            );
            crash_timestamps.clear();
        }

        // Escalating backoff — never gives up, caps at 60s.
        let idx = (consecutive_failures - 1).min(BACKOFF_SECS.len() as u64 - 1) as usize;
        let backoff_sec = BACKOFF_SECS[idx];
        state.current_backoff_sec.store(backoff_sec, Ordering::Relaxed);

        // Connection state reflects severity.
        if consecutive_failures <= 2 {
            state.set_state(ConnectionState::Recovering);
        } else if consecutive_failures <= 5 {
            state.set_state(ConnectionState::Degraded);
        } else {
            state.set_state(ConnectionState::Disconnected);
        }

        if backoff_sec > 0 {
            std::thread::sleep(Duration::from_secs(backoff_sec));
        }

        // Check if daemon came back on its own.
        if check_daemon() {
            state.set_state(ConnectionState::Connected);
            state.record_success();
            consecutive_failures = 0;
            continue;
        }

        // Daemon still gone — spawn it (audit mode if escalated).
        if spawn_daemon(&state) {
            let mut spawned_ok = false;
            for _wait in 0..20 {
                std::thread::sleep(Duration::from_secs(1));
                if check_daemon() {
                    spawned_ok = true;
                    break;
                }
            }
            if spawned_ok {
                state.set_state(ConnectionState::Connected);
                state.record_success();
                consecutive_failures = 0;
                log::info!("supervisor: daemon recovered (audit={})", state.is_audit_mode());
            } else {
                state.record_failure();
                log::warn!("supervisor: spawn ok but pipe unavailable after 20s");
            }
        } else {
            state.record_failure();
        }

        std::thread::sleep(Duration::from_secs(2));
    }
}

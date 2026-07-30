//! ETW real-time process creation intake for PLM.
//!
//! Listens for kernel process events via Windows ETW.
//! Requires admin/elevated privileges. Falls back to snapshot mode
//! if ETW is unavailable.
//!
//! Architecture (post F-1 fix — this is what the code actually does):
//!   StartTraceW on a PRIVATELY-NAMED SYSTEM LOGGER session:
//!     LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE
//!     Wnode.Guid = SESSION_GUID (fixed private GUID — randomly generated once,
//!                  then frozen as a const; NEVER SystemTraceControlGuid —
//!                  private name + SystemTraceControlGuid makes StartTraceW
//!                  fail with ERROR_INVALID_PARAMETER per MS Learn)
//!     EnableFlags = PROCESS | IMAGE_LOAD | FILE_IO_INIT — valid here because
//!                  EnableFlags "is only valid for system loggers"
//!                  (EVENT_TRACE_PROPERTIES, MS Learn) and system-logger mode
//!                  makes this session one. Before this fix the session ran
//!                  REAL_TIME-only, the flags were inert, and the kernel
//!                  delivered zero events while diagnostics claimed "running".
//!   → OpenTraceW → ProcessTrace (blocking, own thread)
//!   → EVENT_RECORD callback → parse process start → feed LineageGraph
//!
//! Health is a stage machine (EtwStage), not a bare bool: etw_running is
//! derived CONSERVATIVELY — true only once the consumer is open
//! (ConsumerOpened and beyond). StartTraceW success alone is NOT reported
//! as running. Persistent StartTraceW failure (>= MAX_CONSECUTIVE_FAILURES
//! of any code, or ERROR_INVALID_PARAMETER once) or a zero-event consumer
//! (~2 min) flips the daemon to snapshot-primary via etw_gave_up / the
//! zero-event alarm in PlmMonitor's watchdog.
//!
//! There is intentionally NO EnableTraceEx2: kernel MOF process/image-load/
//! file-io events are enabled via EVENT_TRACE_PROPERTIES.EnableFlags under
//! system-logger mode. Switching to manifest providers
//! (Microsoft-Windows-Kernel-*) via EnableTraceEx2 is future work — it would
//! change event layouts and break every MOF parser offset in this file.

#![cfg(target_os = "windows")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use super::cmdline::{CommandLineState, SharedCommandLineQuerier};
use super::{LineageGraph, ProcessNode};
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

// ── Session configuration (F-1 fix) ─────────────────────────────

/// ETW logger mode bits. Sourced from the windows-crate SDK bindings so
/// the values cannot drift from evntrace.h — a hand-typed literal here
/// once read 0x00000200, which is actually EVENT_TRACE_DELAY_OPEN_FILE_MODE,
/// and would have silently kept the session a non-system logger (F-1
/// unfixed) while the bit-assertion test passed against its own wrong
/// constant. The SDK cross-check test below guards this class.
pub const EVENT_TRACE_REAL_TIME_MODE_BITS: u32 =
    windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_REAL_TIME_MODE;
pub const EVENT_TRACE_SYSTEM_LOGGER_MODE_BITS: u32 =
    windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_SYSTEM_LOGGER_MODE;

/// `LogFileMode` for the SentinellaPLM session: real-time delivery AND
/// system-logger mode. System-logger mode is what makes the kernel
/// `EnableFlags` below valid (MS Learn, EVENT_TRACE_PROPERTIES:
/// "EnableFlags is only valid for system loggers").
pub const SESSION_LOG_FILE_MODE: u32 =
    EVENT_TRACE_REAL_TIME_MODE_BITS | EVENT_TRACE_SYSTEM_LOGGER_MODE_BITS;

/// Kernel `EnableFlags`: EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_IMAGE_LOAD
/// | EVENT_TRACE_FLAG_FILE_IO_INIT. Only meaningful for system loggers.
/// Derived from the SDK bindings (see `session_constants_match_sdk`).
pub const SESSION_ENABLE_FLAGS: u32 = windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_FLAG_PROCESS.0
    | windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_FLAG_IMAGE_LOAD.0
    | windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_FLAG_FILE_IO_INIT.0;

/// Fixed PRIVATE session GUID for SentinellaPLM. Randomly generated once
/// (UUIDv4) and then frozen here as a const — the value itself carries no
/// meaning; it only needs to be unique and stable across restarts so a
/// stale session from a previous run is found by name and stopped.
///
/// R-LETHAL-class trap avoided: this must NEVER be SystemTraceControlGuid
/// ({9e814aad-3204-11d2-9a82-006008a86939}). Per the StartTraceW docs,
/// `Wnode.Guid == SystemTraceControlGuid` combined with an `InstanceName`
/// other than KERNEL_LOGGER_NAME fails with ERROR_INVALID_PARAMETER. The
/// "Configuring and Starting a System Trace Provider Session" doc requires
/// privately-named system loggers to assign a NEW GUID to Wnode.Guid.
pub const SESSION_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0x9c4b1e7a,
    0x3f2d,
    0x4a8c,
    [0xb5, 0xe1, 0x6d, 0x2f, 0x0a, 0x93, 0xc7, 0xd4],
);

/// The exact session configuration handed to StartTraceW. Pure data so the
/// bit-level contract with the kernel is unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfig {
    pub log_file_mode: u32,
    pub enable_flags: u32,
    pub session_guid: windows::core::GUID,
}

/// Build the session config. Single source of truth for `run_etw_session`.
pub fn session_config() -> SessionConfig {
    SessionConfig {
        log_file_mode: SESSION_LOG_FILE_MODE,
        enable_flags: SESSION_ENABLE_FLAGS,
        session_guid: SESSION_GUID,
    }
}

// ── Stage machine (F-1 fix: replaces the bare etw_running bool) ──

/// Lifecycle stage of the ETW intake. The kernel `EnableFlags` apply at
/// StartTrace time for a system logger, so "provider enablement" is modeled
/// as `FlagsActive` immediately after the session comes alive.
///
/// `etw_running` is derived CONSERVATIVELY from this stage: true only at
/// `ConsumerOpened` and beyond (session up AND consumer attached). This is
/// the fix for the F-1 lie where StartTraceW success alone set
/// `running=true` while the kernel delivered nothing.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EtwStage {
    /// Thread spawned, nothing attempted yet.
    Requested = 0,
    /// About to call (or retrying) StartTraceW.
    Starting = 1,
    /// StartTraceW succeeded; the kernel session exists.
    SessionAlive = 2,
    /// Kernel EnableFlags applied at StartTrace (system-logger mode).
    FlagsActive = 3,
    /// OpenTraceW succeeded; a consumer is attached to the stream.
    ConsumerOpened = 4,
    /// At least one event was delivered to the callback.
    Processing = 5,
    /// At least one event parsed into a valid lineage record.
    EventsConfirmed = 6,
    /// Consumer open but unhealthy (see degraded_reason codes).
    Degraded = 7,
    /// Orderly stop (ProcessTrace returned, handles closed).
    Stopped = 8,
    /// StartTraceW/OpenTraceW failed; `failed_win32` carries the code.
    Failed = 9,
}

impl EtwStage {
    fn from_u64(v: u64) -> Self {
        match v {
            1 => Self::Starting,
            2 => Self::SessionAlive,
            3 => Self::FlagsActive,
            4 => Self::ConsumerOpened,
            5 => Self::Processing,
            6 => Self::EventsConfirmed,
            7 => Self::Degraded,
            8 => Self::Stopped,
            9 => Self::Failed,
            _ => Self::Requested,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Starting => "starting",
            Self::SessionAlive => "session_alive",
            Self::FlagsActive => "flags_active",
            Self::ConsumerOpened => "consumer_opened",
            Self::Processing => "processing",
            Self::EventsConfirmed => "events_confirmed",
            Self::Degraded => "degraded",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

/// Conservative health derivation: the intake only counts as "running" once
/// a consumer is actually attached. SessionAlive/FlagsActive are deliberately
/// NOT running — StartTraceW success proves nothing about event delivery.
pub fn conservative_etw_running(stage: EtwStage) -> bool {
    matches!(
        stage,
        EtwStage::ConsumerOpened
            | EtwStage::Processing
            | EtwStage::EventsConfirmed
            | EtwStage::Degraded
    )
}

/// Stage-transition validator. Keeps the machine honest: any transition not
/// listed here is ignored (logged at debug) instead of corrupting health.
pub fn valid_stage_transition(from: EtwStage, to: EtwStage) -> bool {
    use EtwStage::*;
    if from == to {
        return true; // idempotent re-store (e.g. Failed code update)
    }
    match from {
        Requested => to == Starting,
        Starting => matches!(to, SessionAlive | Failed | Stopped),
        SessionAlive => matches!(to, FlagsActive | Failed | Stopped),
        FlagsActive => matches!(to, ConsumerOpened | Failed | Stopped),
        ConsumerOpened => matches!(to, Processing | Degraded | Stopped | Failed),
        Processing => matches!(to, EventsConfirmed | Degraded | Stopped | Failed),
        EventsConfirmed => matches!(to, Degraded | Stopped | Failed),
        Degraded => matches!(to, Processing | EventsConfirmed | Stopped | Failed),
        // Retry loop re-enters Starting after a stopped/failed attempt.
        Stopped | Failed => to == Starting,
    }
}

// ── Error classification (give-up semantics) ────────────────────

pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_NO_SYSTEM_RESOURCES: u32 = 1450;

/// What a failed StartTraceW/OpenTraceW win32 code means for the retry loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartErrorDisposition {
    /// ERROR_ALREADY_EXISTS (183): a stale session owns the name — the
    /// caller stops it and retries. NOT counted toward give-up.
    StaleSession,
    /// ERROR_INVALID_PARAMETER (87): our session config is invalid; retrying
    /// can never succeed. Give up immediately (fatal).
    Fatal,
    /// Everything else — including ERROR_ACCESS_DENIED (5, not elevated) and
    /// ERROR_NO_SYSTEM_RESOURCES (1450, all 8 system-logger slots taken) —
    /// is environmental/transient: counted toward the consecutive-failure
    /// give-up budget. 1450 counts exactly like access-denied per the F-1
    /// fix design: slot exhaustion must restore snapshot-primary, not spin.
    Counted,
}

pub fn classify_start_error(code: u32) -> StartErrorDisposition {
    match code {
        ERROR_ALREADY_EXISTS => StartErrorDisposition::StaleSession,
        ERROR_INVALID_PARAMETER => StartErrorDisposition::Fatal,
        _ => StartErrorDisposition::Counted,
    }
}

/// Consecutive session-start failures (of ANY counted code) after which ETW
/// intake gives up and `etw_gave_up` is set so the PLM watchdog restores the
/// snapshot fallback to primary frequency. Before the F-1 fix only error 5
/// counted, so a new persistent failure mode would retry forever at 30 s
/// backoff with the snapshot stuck at supplemental cadence.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// degraded_reason code: consumer open, zero events after the grace period.
pub const DEGRADED_ZERO_EVENTS: u64 = 1;

// ── Diagnostics ─────────────────────────────────────────────────

/// ETW process intake diagnostics.
pub struct EtwIntakeDiagnostics {
    pub events_seen: AtomicU64,
    pub events_dropped: AtomicU64,
    pub reconnects: AtomicU64,
    /// CONSERVATIVE health flag, derived from `stage` via
    /// `conservative_etw_running` — true only at ConsumerOpened and beyond.
    /// Kept as a field (not a method) so existing readers
    /// (ipc/state.rs surface, plm/mod.rs watchdog + weedhack mirror) keep
    /// their protocol shape; all writes go through `set_stage`.
    pub etw_running: AtomicBool,
    pub last_event_ts: AtomicU64,
    /// Set to true when ETW gives up retrying (>= MAX_CONSECUTIVE_FAILURES
    /// consecutive failures of any code, or a fatal config error).
    /// PlmMonitor can check this to switch to full snapshot mode.
    pub etw_gave_up: AtomicBool,
    /// Current lifecycle stage (`EtwStage as u64`). Single writer: the ETW
    /// thread (plus the watchdog for the Degraded transition).
    pub stage: AtomicU64,
    /// Last win32 code that drove the stage to Failed (0 = none).
    pub failed_win32: AtomicU64,
    /// Why the stage is Degraded (0 = not degraded; DEGRADED_* codes).
    pub degraded_reason: AtomicU64,
    /// One-shot latch: the zero-event watchdog already warned.
    pub zero_event_alarm: AtomicBool,
}

impl EtwIntakeDiagnostics {
    pub fn new() -> Self {
        Self {
            events_seen: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            etw_running: AtomicBool::new(false),
            last_event_ts: AtomicU64::new(0),
            etw_gave_up: AtomicBool::new(false),
            stage: AtomicU64::new(EtwStage::Requested as u64),
            failed_win32: AtomicU64::new(0),
            degraded_reason: AtomicU64::new(0),
            zero_event_alarm: AtomicBool::new(false),
        }
    }

    pub fn current_stage(&self) -> EtwStage {
        EtwStage::from_u64(self.stage.load(Ordering::Relaxed))
    }

    pub fn stage_name(&self) -> &'static str {
        self.current_stage().name()
    }

    /// Advance the stage machine. Invalid transitions are ignored (debug
    /// log) rather than corrupting the health surface. `etw_running` is
    /// re-derived on every accepted transition.
    fn set_stage(&self, to: EtwStage) {
        let from = self.current_stage();
        if !valid_stage_transition(from, to) {
            tracing::debug!(
                from = from.name(),
                to = to.name(),
                "PLM ETW: ignoring invalid stage transition"
            );
            return;
        }
        self.stage.store(to as u64, Ordering::Relaxed);
        self.etw_running
            .store(conservative_etw_running(to), Ordering::Relaxed);
    }

    /// Record a session failure: stage → Failed with the win32 code.
    fn note_failed(&self, code: u32) {
        self.failed_win32.store(code as u64, Ordering::Relaxed);
        self.set_stage(EtwStage::Failed);
    }

    /// Watchdog hook: consumer open but zero delivered events past the grace
    /// period — the F-1 silent-zero failure mode. Keeps etw_running true
    /// (the consumer IS attached; the stream is starved) but flips the stage
    /// so the health surface stops claiming full health.
    pub fn note_zero_event_degraded(&self) {
        self.degraded_reason
            .store(DEGRADED_ZERO_EVENTS, Ordering::Relaxed);
        self.set_stage(EtwStage::Degraded);
    }
}

/// Try to start ETW process monitoring.
/// Returns a thread handle if successful, or an error string.
/// The thread runs until `running` is set to false.
pub fn start_etw_intake(
    graph: Arc<LineageGraph>,
    diagnostics: Arc<EtwIntakeDiagnostics>,
    running: Arc<AtomicBool>,
    cmdline_querier: Arc<SharedCommandLineQuerier>,
) -> Result<std::thread::JoinHandle<()>, String> {
    // Test if we can create a trace session (requires admin).
    // Do a quick probe before spawning the thread.
    let thread = std::thread::Builder::new()
        .name("plm-etw".into())
        .spawn(move || {
            etw_process_loop(graph, diagnostics, running, cmdline_querier);
        })
        .map_err(|e| format!("failed to spawn ETW thread: {e}"))?;

    Ok(thread)
}

/// Structured session failure so the retry loop classifies the actual
/// win32 code instead of substring-matching a formatted error string (the
/// old "failed: 5 " match also tripped on codes 50-59/500-599).
#[derive(Debug)]
enum SessionError {
    /// Properties buffer layout failed (internal, not a win32 code).
    Layout(String),
    /// StartTraceW returned ERROR_ALREADY_EXISTS; the stale session was
    /// stopped by-name. Retry immediately, not a failure.
    StaleSessionCleaned,
    /// StartTraceW failed with this win32 code.
    StartTrace { code: u32 },
    /// OpenTraceW failed with this win32 code (session already stopped).
    OpenTrace { code: u32 },
}

impl SessionError {
    fn win32_code(&self) -> u32 {
        match self {
            Self::Layout(_) | Self::StaleSessionCleaned => 0,
            Self::StartTrace { code } | Self::OpenTrace { code } => *code,
        }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Layout(e) => write!(f, "ETW props layout failed: {e}"),
            Self::StaleSessionCleaned => write!(f, "stale session cleaned, will retry"),
            Self::StartTrace { code } => write!(f, "StartTraceW failed: win32 {code}"),
            Self::OpenTrace { code } => write!(f, "OpenTraceW failed: win32 {code}"),
        }
    }
}

impl From<String> for SessionError {
    fn from(e: String) -> Self {
        Self::Layout(e)
    }
}

/// Sleep in 500 ms slices so shutdown (`running = false`) is observed
/// promptly — PlmMonitor::Drop joins this thread and must not block for a
/// full 30 s backoff while the SCM waits on service stop.
fn interruptible_sleep(running: &AtomicBool, secs: u64) {
    let mut slices = secs.saturating_mul(2);
    while slices > 0 && running.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(500));
        slices -= 1;
    }
}

/// Main ETW processing loop. Retries on failure with backoff.
/// Gives up after `MAX_CONSECUTIVE_FAILURES` consecutive failures of ANY
/// counted code (access-denied, 1450 slot exhaustion, …) or immediately on
/// a fatal config error (87), setting `etw_gave_up` so the snapshot
/// fallback is restored to primary frequency.
fn etw_process_loop(
    graph: Arc<LineageGraph>,
    diag: Arc<EtwIntakeDiagnostics>,
    running: Arc<AtomicBool>,
    cmdline_querier: Arc<SharedCommandLineQuerier>,
) {
    tracing::info!("PLM ETW intake starting");

    let session_name = "SentinellaPLM";
    let mut backoff_secs = 1u64;
    let mut consecutive_failures = 0u32;

    diag.set_stage(EtwStage::Starting);

    while running.load(Ordering::Relaxed) {
        if diag.current_stage() != EtwStage::Starting {
            diag.set_stage(EtwStage::Starting);
        }
        match run_etw_session(session_name, &graph, &diag, &running, &cmdline_querier) {
            Ok(()) => {
                tracing::info!("PLM ETW session ended cleanly");
                diag.set_stage(EtwStage::Stopped);
                break;
            }
            Err(SessionError::StaleSessionCleaned) => {
                // Crash-between-StartTrace-and-OpenTrace (or any orphaned
                // session from a previous run) lands here: the stale session
                // was already stopped by name inside run_etw_session. Not a
                // failure — do not count it toward give-up.
                diag.reconnects.fetch_add(1, Ordering::Relaxed);
                consecutive_failures = 0;
                tracing::info!("PLM ETW: stale session cleaned, will retry");
                interruptible_sleep(&running, 1);
                continue;
            }
            Err(e) => {
                diag.reconnects.fetch_add(1, Ordering::Relaxed);

                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let code = e.win32_code();
                let disposition = classify_start_error(code);
                // A failure after the consumer was open means the config is
                // fundamentally fine (this is a mid-life stream loss) — reset
                // the consecutive-start budget; the failure itself still counts.
                let reached_consumer = diag.etw_running.load(Ordering::Relaxed);
                diag.note_failed(code);
                consecutive_failures = if reached_consumer {
                    1
                } else {
                    consecutive_failures.saturating_add(1)
                };

                let fatal = disposition == StartErrorDisposition::Fatal
                    || consecutive_failures >= MAX_CONSECUTIVE_FAILURES;

                if fatal {
                    tracing::warn!(
                        stage = diag.stage_name(),
                        win32 = code,
                        disposition = ?disposition,
                        attempts = consecutive_failures,
                        fatal = true,
                        "PLM ETW giving up, snapshot fallback becomes primary"
                    );
                    diag.etw_gave_up.store(true, Ordering::Relaxed);
                    break;
                }

                tracing::warn!(
                    stage = diag.stage_name(),
                    win32 = code,
                    disposition = ?disposition,
                    attempts = consecutive_failures,
                    backoff_secs,
                    fatal = false,
                    error = %e,
                    "PLM ETW session failed, will retry"
                );

                // Backoff: 1s, 2s, 4s, 8s, max 30s (shutdown-interruptible).
                interruptible_sleep(&running, backoff_secs);
                backoff_secs = (backoff_secs * 2).min(30);
            }
        }
    }

    // Orderly exit with no recorded end stage (e.g. shutdown during backoff):
    // leave Failed in place (it carries the diagnostic code), otherwise mark
    // Stopped so health never claims an active session post-exit.
    match diag.current_stage() {
        EtwStage::Failed | EtwStage::Stopped => {}
        _ => diag.set_stage(EtwStage::Stopped),
    }

    tracing::info!("PLM ETW intake stopped");
}

/// Run a single ETW trace session. Returns when stopped or on error.
fn run_etw_session(
    session_name: &str,
    graph: &Arc<LineageGraph>,
    diag: &Arc<EtwIntakeDiagnostics>,
    running: &Arc<AtomicBool>,
    cmdline_querier: &Arc<SharedCommandLineQuerier>,
) -> Result<(), SessionError> {
    use windows::Win32::System::Diagnostics::Etw::*;
    use windows::core::PCWSTR;

    let session_name_wide: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Aligned EVENT_TRACE_PROPERTIES storage (shared helper). The previous
    // `vec![0u8; props_size]` cast to *mut EVENT_TRACE_PROPERTIES was
    // misaligned-reference UB: the struct has 8-byte-aligned members but
    // Vec<u8> guarantees only 1-byte alignment. The storage sets
    // Wnode.BufferSize + LoggerNameOffset and writes the terminated
    // UTF-16 logger name; we only set session-semantic fields here.
    let mut props_storage =
        sentinella_common::etw_props::EventTracePropsStorage::with_extra(session_name, None, 256)
            .map_err(|e| SessionError::Layout(format!("{e}")))?;
    let cfg = session_config();
    let props = props_storage.props_mut();
    props.Wnode.ClientContext = 1;
    props.Wnode.Flags = 0x00020000; // WNODE_FLAG_TRACED_GUID
    // F-1 fix: privately-named SYSTEM LOGGER. Wnode.Guid is the frozen
    // private SESSION_GUID (never SystemTraceControlGuid — private name +
    // that GUID = ERROR_INVALID_PARAMETER per StartTraceW docs), and
    // LogFileMode carries EVENT_TRACE_SYSTEM_LOGGER_MODE so the kernel
    // EnableFlags below are valid ("EnableFlags is only valid for system
    // loggers" — EVENT_TRACE_PROPERTIES, MS Learn). Without the mode bit
    // the flags were inert and the session delivered zero events.
    props.Wnode.Guid = cfg.session_guid;
    props.LogFileMode = cfg.log_file_mode;
    // Process events (0x00000001 = EVENT_TRACE_FLAG_PROCESS) + image-load
    // events (0x00000004 = EVENT_TRACE_FLAG_IMAGE_LOAD) + file-IO initiator
    // events (0x04000000 = EVENT_TRACE_FLAG_FILE_IO_INIT). The shared
    // session dispatcher in `etw_event_callback` routes by provider+opcode
    // so the existing PLM process-create path is bit-for-bit unchanged.
    // ImageLoad → `etw_image_load`; FileIo Create → `etw_file_io`.
    props.EnableFlags = EVENT_TRACE_FLAG(cfg.enable_flags);

    let mut session_handle = CONTROLTRACE_HANDLE::default();
    let start_result = unsafe {
        StartTraceW(
            &mut session_handle,
            PCWSTR(session_name_wide.as_ptr()),
            props,
        )
    };

    if start_result.0 != 0 {
        if start_result.0 == ERROR_ALREADY_EXISTS {
            // Stale session (previous unclean exit, or a crash between
            // StartTrace and OpenTrace left a session with no consumer) —
            // stop it by name and let the loop retry.
            let mut stop_storage = stop_props_storage()?;
            unsafe {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR(session_name_wide.as_ptr()),
                    stop_storage.props_mut(),
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(SessionError::StaleSessionCleaned);
        }
        return Err(SessionError::StartTrace {
            code: start_result.0,
        });
    }

    // StartTraceW succeeded. NOTE: this alone is NOT "running" — the
    // conservative etw_running flag only flips at ConsumerOpened.
    diag.set_stage(EtwStage::SessionAlive);
    tracing::info!(
        "PLM ETW system-logger session started (kernel EnableFlags active at StartTrace)"
    );
    // For a system logger the kernel EnableFlags apply at StartTrace time —
    // there is no separate provider-enablement call to model.
    diag.set_stage(EtwStage::FlagsActive);

    // Set up consumer.
    let graph_ptr = Arc::as_ptr(graph) as usize;
    let diag_ptr = Arc::as_ptr(diag) as usize;

    // Store context for callback.
    CALLBACK_GRAPH.store(graph_ptr as u64, Ordering::SeqCst);
    CALLBACK_DIAG.store(diag_ptr as u64, Ordering::SeqCst);
    CALLBACK_CMDLINE.store(Arc::as_ptr(cmdline_querier) as u64, Ordering::SeqCst);

    let mut logfile = EVENT_TRACE_LOGFILEW::default();
    let mut logfile_name = session_name_wide.clone();
    logfile.LoggerName = windows::core::PWSTR(logfile_name.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode = 0x00000100 | 0x10000000; // REAL_TIME + EVENT_RECORD
    logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        let code = unsafe { windows::Win32::Foundation::GetLastError() }.0;
        // R3-10: clear the callback context statics installed above —
        // the success path zeroes them after ProcessTrace returns; this
        // early-return branch must do the same so no dangling raw
        // pointers outlive the session loop.
        CALLBACK_GRAPH.store(0, Ordering::SeqCst);
        CALLBACK_DIAG.store(0, Ordering::SeqCst);
        CALLBACK_CMDLINE.store(0, Ordering::SeqCst);
        // Stop the session we just started before bailing —
        // otherwise it leaks as an orphaned kernel session until the next
        // run's stale-session cleanup reclaims it.
        let mut stop_storage = stop_props_storage()?;
        unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(session_name_wide.as_ptr()),
                stop_storage.props_mut(),
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        return Err(SessionError::OpenTrace { code });
    }

    // The consumer is attached — THIS is the first point where the intake
    // may report running (conservative derivation via set_stage).
    diag.set_stage(EtwStage::ConsumerOpened);

    // ProcessTrace blocks until session stops.
    // ARCH-3 fix: use a separate flag for the stop thread so that if
    // ProcessTrace returns early (error/OS killed session), the stop
    // thread exits its polling loop and join() doesn't deadlock.
    // The `running` flag is shared with the main PLM loop and must NOT
    // be set to false here — that would kill the entire PLM monitor.
    let trace_done = Arc::new(AtomicBool::new(false));
    let trace_done_clone = Arc::clone(&trace_done);

    let handles = [trace_handle];
    let running_clone = Arc::clone(running);
    let session_name_stop = session_name_wide.clone();
    let stop_thread = std::thread::spawn(move || {
        // Wait for either: shutdown requested OR ProcessTrace returned.
        while running_clone.load(Ordering::Relaxed) && !trace_done_clone.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        // Stop session to unblock ProcessTrace (idempotent if already stopped).
        let Ok(mut stop_storage) = stop_props_storage() else {
            return;
        };
        unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(session_name_stop.as_ptr()),
                stop_storage.props_mut(),
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    });

    let _ = unsafe { ProcessTrace(&handles, None, None) };

    // R3-10: clear callback context BEFORE releasing handle so any late
    // event delivery sees null pointers and bails out, preventing UAF
    // when the caller drops its Arc<LineageGraph> / Arc<EtwIntakeDiagnostics>.
    CALLBACK_GRAPH.store(0, Ordering::SeqCst);
    CALLBACK_DIAG.store(0, Ordering::SeqCst);
    CALLBACK_CMDLINE.store(0, Ordering::SeqCst);

    // R3-10: release consumer handle (was leaked).
    let _ = unsafe { CloseTrace(trace_handle) };

    // Signal stop thread that ProcessTrace has returned.
    trace_done.store(true, Ordering::Relaxed);
    let _ = stop_thread.join();
    // etw_running is re-derived by the caller's set_stage(Stopped) — no
    // direct store here (all health writes go through the stage machine).

    Ok(())
}

/// Build an aligned stop/cleanup properties buffer for `ControlTraceW`.
///
/// Stop-by-name buffers carry no logger name content (the name is passed
/// via the PCWSTR argument), so this uses an empty logger name + 512 bytes
/// of trailing slack — matching the old hand-rolled `size + 512` buffers,
/// minus the misaligned `vec![0u8; _]` cast UB. `Wnode.BufferSize` and
/// `LoggerNameOffset` are set by the storage constructor.
fn stop_props_storage(
) -> Result<sentinella_common::etw_props::EventTracePropsStorage, String> {
    sentinella_common::etw_props::EventTracePropsStorage::with_extra("", None, 512)
        .map_err(|e| format!("ETW stop props layout failed: {e}"))
}

// ── Callback globals (same pattern as sandboxd) ──────────────

static CALLBACK_GRAPH: AtomicU64 = AtomicU64::new(0);
static CALLBACK_DIAG: AtomicU64 = AtomicU64::new(0);
/// Raw pointer to the Arc<SharedCommandLineQuerier> owned by the session
/// loop — same lifetime discipline as CALLBACK_GRAPH/DIAG: stored before
/// the consumer opens, zeroed before the owning Arcs drop (both teardown
/// paths). Zero = no querier wired → nodes record NotCollected, never a
/// fabricated command line.
static CALLBACK_CMDLINE: AtomicU64 = AtomicU64::new(0);

/// Process GUID for ETW kernel process events.
const PROCESS_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0x3d6fa8d0,
    0xfe05,
    0x11d0,
    [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
);

/// ETW event callback — receives every kernel event.
unsafe extern "system" fn etw_event_callback(record: *mut EVENT_RECORD) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe {
            if record.is_null() {
                return;
            }
            let event = &*record;

            let provider = event.EventHeader.ProviderId;
            let opcode = event.EventHeader.EventDescriptor.Opcode;

            // Wave 4: dispatcher — ImageLoad events route to the dedicated
            // handler. Return early so we don't fall through into the
            // process-start path (which would mis-parse Image data).
            if provider == super::etw_image_load::IMAGE_LOAD_GUID
                && opcode == super::etw_image_load::OPCODE_IMAGE_LOAD
            {
                super::etw_image_load::handle_image_load_event(event);
                return;
            }

            // Wave 6: dispatcher — FileIo Create events route to the wallet
            // harvest handler. Callback-side aggressive substring filter
            // drops 99%+ of file opens before they reach the bounded
            // channel; non-wallet paths never leave the kernel dispatch
            // thread.
            if provider == super::etw_file_io::FILE_IO_GUID
                && opcode == super::etw_file_io::OPCODE_FILE_CREATE
            {
                super::etw_file_io::handle_file_io_event(event);
                return;
            }

            // Only process start events (opcode 1).
            if provider != PROCESS_GUID || opcode != 1 {
                return;
            }

            let graph_ptr = CALLBACK_GRAPH.load(Ordering::SeqCst);
            let diag_ptr = CALLBACK_DIAG.load(Ordering::SeqCst);
            if graph_ptr == 0 || diag_ptr == 0 {
                return;
            }

            let diag = &*(diag_ptr as *const EtwIntakeDiagnostics);
            diag.events_seen.fetch_add(1, Ordering::Relaxed);
            // First delivered event: ConsumerOpened → Processing (also
            // rescues a Degraded zero-event stage if the stream recovers).
            if matches!(
                diag.current_stage(),
                EtwStage::ConsumerOpened | EtwStage::Degraded
            ) {
                diag.set_stage(EtwStage::Processing);
            }
            diag.last_event_ts.store(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                Ordering::Relaxed,
            );

            // Parse process start event data. Guard null/zero-length
            // UserData — from_raw_parts requires a non-null pointer even
            // for length 0 (else UB).
            if event.UserData.is_null() || event.UserDataLength == 0 {
                return;
            }
            let data = std::slice::from_raw_parts(
                event.UserData as *const u8,
                event.UserDataLength as usize,
            );

            // PID from the event header (authoritative).
            let pid = event.EventHeader.ProcessId;

            // Audit fix: the kernel Process_TypeGroup1 layout is
            //   UniqueProcessKey (pointer-sized: 4 on x86, 8 on x64)
            //   ProcessId  (u32)
            //   ParentId   (u32)   ← what we want
            // The previous code read ParentId from offset 4, which on an
            // x64 OS is the HIGH DWORD of the 8-byte UniqueProcessKey →
            // garbage parent PIDs → broken lineage chains. ParentId sits at
            // `ptr_size + 4`. Sentinella ships x64 and the kernel event
            // layout follows the OS bitness, so size_of::<usize>() is the
            // correct pointer width here.
            let ptr_size = std::mem::size_of::<usize>();
            let ppid_off = ptr_size + 4;
            if data.len() < ppid_off + 4 {
                return;
            }
            let ppid = u32::from_le_bytes([
                data[ppid_off],
                data[ppid_off + 1],
                data[ppid_off + 2],
                data[ppid_off + 3],
            ]);

            // Image name resolution for process START events.
            // ETW event data (authoritative, free) → ToolHelp fallback (expensive).
            let image_name = extract_image_from_event(data)
                .or_else(|| get_process_image(pid))
                .unwrap_or_else(|| format!("pid:{pid}"));
            let exe_name = image_name
                .rsplit('\\')
                .next()
                .unwrap_or(&image_name)
                .to_string();

            // Event-time command-line capture. The kernel
            // Process_TypeGroup1 event layout does NOT carry the command
            // line (its MOF fields end at ImageFileName), so we query the
            // live process NOW via NtQueryInformationProcess — a lazy
            // query at scan time would lose the exit race against
            // short-lived persistence children. Protected/exited
            // processes yield first-class states (AccessDenied /
            // ProcessExited), counted in PLM diagnostics; a zeroed
            // static (querier not wired / tearing down) records honest
            // NotCollected. NEVER a fabricated empty string.
            let cmd_ptr = CALLBACK_CMDLINE.load(Ordering::SeqCst);
            let command_line = if cmd_ptr != 0 {
                let querier = &*(cmd_ptr as *const SharedCommandLineQuerier);
                querier.query(pid)
            } else {
                CommandLineState::NotCollected
            };

            let graph = &*(graph_ptr as *const LineageGraph);
            graph.record_process(ProcessNode {
                pid,
                parent_pid: ppid,
                image_path: image_name,
                image_name: exe_name,
                command_line,
                is_signed: None,
                integrity_level: None,
                created_at: Instant::now(),
                timestamp: chrono::Utc::now().timestamp(),
            });
            // First event that parsed into a valid lineage record confirms
            // end-to-end delivery: Processing → EventsConfirmed.
            if diag.current_stage() == EtwStage::Processing {
                diag.set_stage(EtwStage::EventsConfirmed);
            }
        }
    }));

    if result.is_err() {
        // Callback panicked — increment dropped counter.
        // ARCH-4 fix: was using CALLBACK_GRAPH (LineageGraph*) as EtwIntakeDiagnostics*.
        let diag_ptr = CALLBACK_DIAG.load(Ordering::SeqCst);
        if diag_ptr != 0 {
            unsafe {
                let diag = &*(diag_ptr as *const EtwIntakeDiagnostics);
                diag.events_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Try to extract image path from ETW process start event data.
///
/// Wave 4 visibility bump: the ImageLoad ETW callback reuses this exact
/// wide-string scanner to extract the loaded-module path. The same shape
/// — drive-letter-prefixed WCHAR path embedded in opaque event data —
/// applies to both event types, so the parser is shared.
pub(crate) fn extract_image_from_event_pub(data: &[u8]) -> Option<String> {
    extract_image_from_event(data)
}

/// Generalized path extractor for ImageLoad / FileIo event bodies.
///
/// CRITICAL DIFFERENCE from `extract_image_from_event`: the process-start
/// extractor only recognizes DOS `X:\...` paths and is backstopped by a
/// ToolHelp `get_process_image(pid)` fallback. Kernel **ImageLoad** and
/// **FileIo_Create** events instead carry the path as an **NT device
/// path** — `\Device\HarddiskVolumeN\...`, `\SystemRoot\...`, or
/// `\??\C:\...` — and the two new pumps have NO fallback. A drive-letter-
/// only scanner therefore returns `None` for essentially every real event,
/// silently disabling the WeedHack browser-injection and wallet-harvest
/// detectors in production (unit tests pass only because they synthesize
/// `C:\` bodies). This extractor accepts both NT and DOS forms.
///
/// Downstream matchers (`path_looks_walletish`, `is_user_writable_path`,
/// `module_is_dll`) are all case-insensitive substring/suffix checks that
/// already match inside an NT path (e.g. `\Device\HarddiskVolume2\Users\
/// t\AppData\Local\Google\Chrome\User Data\...` contains `\user data\`),
/// so fixing extraction is sufficient — no downstream change needed.
///
/// Strategy: WCHAR-aligned scan for the first plausible embedded path —
/// a printable wide-string starting with either a DOS drive anchor
/// (`[A-Za-z]:`) or a leading backslash (NT path), containing a path
/// separator and of reasonable length. Bounds-checked; never panics.
pub(crate) fn extract_path_from_event(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let max = data.len().saturating_sub(4);
    let mut offset = 0usize;
    while offset <= max {
        let lo = data[offset];
        let hi = data[offset + 1];
        // Only WCHAR-aligned ASCII anchors (high byte zero).
        if hi == 0 {
            let dos = lo.is_ascii_alphabetic()
                && offset + 4 <= data.len()
                && data[offset + 2] == 0x3A // ':'
                && data[offset + 3] == 0;
            let nt = lo == b'\\';
            if dos || nt {
                if let Some(s) = read_wide_path(data, offset) {
                    return Some(s);
                }
            }
        }
        offset += 2;
    }
    None
}

/// Read a printable UTF-16LE path starting at `start`, stopping at a NUL
/// pair or a control character. Returns the string only if it looks like
/// a path (contains a backslash, length > 3). Bounds-checked.
fn read_wide_path(data: &[u8], start: usize) -> Option<String> {
    let mut end = start;
    while end + 1 < data.len() {
        let lo = data[end];
        let hi = data[end + 1];
        if lo == 0 && hi == 0 {
            break; // NUL terminator
        }
        // Stop if we run out of the printable-ASCII wide-string region
        // (a control char or a non-zero high byte that isn't a normal BMP
        // path character) — prevents running into adjacent binary fields.
        if hi == 0 && lo < 0x20 {
            break;
        }
        end += 2;
    }
    if end <= start + 4 {
        return None;
    }
    let wide: Vec<u16> = data[start..end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&wide);
    if s.contains('\\') && s.len() > 3 {
        Some(s)
    } else {
        None
    }
}

/// Try to extract image path from ETW process start event data.
///
/// Process start event layout (kernel provider, opcode 1), x64:
///   Offset 0:   UniqueProcessKey (pointer-sized: 8 on x64, 4 on x86)
///   Offset 8:   ProcessId (u32)  — but we use the header PID
///   Offset 12:  ParentId (u32)
///   Offset 16:  SessionId (u32), ExitStatus (i32), DirectoryTableBase, …
///   Variable:   ImageFileName as null-terminated wide string after fixed fields
///
/// The image path is typically at offset 52+ (x64) after SessionId, ExitStatus, etc.
/// We scan for a plausible wide-string path starting with drive letter.
fn extract_image_from_event(data: &[u8]) -> Option<String> {
    // Minimum: need at least 60 bytes for fixed fields + some path data.
    if data.len() < 60 {
        return None;
    }

    // Scan for a wide-string path pattern: drive letter (A-Z) followed by ':'
    // as UTF-16LE: [0x41-0x5A, 0x00, 0x3A, 0x00]. Audit fix: previously
    // `ch >= b'C'` dropped legitimate A:/B: paths.
    for offset in (40..data.len().saturating_sub(8)).step_by(2) {
        if offset + 4 > data.len() {
            break;
        }
        let ch = data[offset];
        let ch_hi = data[offset + 1];
        let colon = data[offset + 2];
        let colon_hi = data[offset + 3];

        if ch_hi == 0 && colon == 0x3A && colon_hi == 0 && ch.is_ascii_uppercase() {
            // Found potential path start. Read until null terminator or end.
            let path_start = offset;
            let mut path_end = path_start;
            while path_end + 1 < data.len() {
                let lo = data[path_end];
                let hi = data[path_end + 1];
                if lo == 0 && hi == 0 {
                    break;
                }
                path_end += 2;
            }
            if path_end > path_start + 4 {
                let wide: Vec<u16> = data[path_start..path_end]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&wide);
                // Validate: must contain backslash and look like a path.
                if s.contains('\\') && s.len() > 3 {
                    return Some(s);
                }
            }
        }
    }

    None
}

/// Look up process image path by PID via ToolHelp32 snapshot.
fn get_process_image(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::*;

    // RAII guard: see plm::snapshot_processes for the rationale (manual
    // CloseHandle on every path leaks the kernel handle on any panic).
    struct SnapshotGuard(HANDLE);
    impl Drop for SnapshotGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let _guard = SnapshotGuard(snapshot);
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_err() {
            return None;
        }

        loop {
            if entry.th32ProcessID == pid {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                return Some(String::from_utf16_lossy(&entry.szExeFile[..len]));
            }
            if Process32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }
        None
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Session config: exact bit-level contract with the kernel ──

    #[test]
    fn session_config_exact_bits() {
        let cfg = session_config();
        // REAL_TIME (0x100) | SYSTEM_LOGGER (0x02000000) = 0x02000100.
        // Anything else and the kernel EnableFlags are inert again (the
        // F-1 bug). Note 0x200 is EVENT_TRACE_DELAY_OPEN_FILE_MODE — a
        // previous revision of this test asserted THAT as "system logger".
        assert_eq!(cfg.log_file_mode, 0x02000100);
        assert_ne!(cfg.log_file_mode & EVENT_TRACE_SYSTEM_LOGGER_MODE_BITS, 0);
        assert_ne!(cfg.log_file_mode & EVENT_TRACE_REAL_TIME_MODE_BITS, 0);
        // PROCESS | IMAGE_LOAD | FILE_IO_INIT.
        assert_eq!(cfg.enable_flags, 0x00000001 | 0x00000004 | 0x04000000);
        assert_eq!(cfg.session_guid, SESSION_GUID);
    }

    #[test]
    fn session_constants_match_sdk() {
        // The drift guard for the class that produced the 0x200 bug: every
        // ETW constant this module relies on must equal the SDK binding.
        use windows::Win32::System::Diagnostics::Etw::*;
        assert_eq!(EVENT_TRACE_REAL_TIME_MODE_BITS, EVENT_TRACE_REAL_TIME_MODE);
        assert_eq!(
            EVENT_TRACE_SYSTEM_LOGGER_MODE_BITS,
            EVENT_TRACE_SYSTEM_LOGGER_MODE
        );
        assert_eq!(EVENT_TRACE_SYSTEM_LOGGER_MODE, 0x02000000);
        assert_eq!(SESSION_ENABLE_FLAGS, 0x00000001 | 0x00000004 | 0x04000000);
        assert_eq!(EVENT_TRACE_FLAG_PROCESS.0, 0x00000001);
        assert_eq!(EVENT_TRACE_FLAG_IMAGE_LOAD.0, 0x00000004);
        assert_eq!(EVENT_TRACE_FLAG_FILE_IO_INIT.0, 0x04000000);
    }

    #[test]
    fn session_guid_is_not_system_trace_control_guid() {
        // The R-LETHAL trap: private session name + SystemTraceControlGuid
        // makes StartTraceW fail with ERROR_INVALID_PARAMETER (MS Learn).
        assert_ne!(
            SESSION_GUID,
            windows::Win32::System::Diagnostics::Etw::SystemTraceControlGuid
        );
        // And it must not be the zero GUID either (zero asks the system to
        // generate one — fine per docs, but we deliberately froze a private
        // one; a regression to zero should be a loud test failure).
        assert_ne!(SESSION_GUID, windows::core::GUID::zeroed());
    }

    // ── Error classifier: give-up decisions ─────────────────────

    #[test]
    fn classify_error_codes() {
        // 183: stale session — stop + retry, never counted.
        assert_eq!(
            classify_start_error(ERROR_ALREADY_EXISTS),
            StartErrorDisposition::StaleSession
        );
        // 87: invalid config — fatal immediately, retrying is pointless.
        assert_eq!(
            classify_start_error(ERROR_INVALID_PARAMETER),
            StartErrorDisposition::Fatal
        );
        // 5 (access denied) and 1450 (all 8 system-logger slots taken)
        // both count toward the consecutive-failure give-up budget.
        assert_eq!(
            classify_start_error(ERROR_ACCESS_DENIED),
            StartErrorDisposition::Counted
        );
        assert_eq!(
            classify_start_error(ERROR_NO_SYSTEM_RESOURCES),
            StartErrorDisposition::Counted
        );
        // Anything else (e.g. 53 ERROR_BAD_NETPATH) is counted, never
        // silently fatal and never silently free.
        assert_eq!(classify_start_error(53), StartErrorDisposition::Counted);
        assert_eq!(classify_start_error(0), StartErrorDisposition::Counted);
        assert_eq!(classify_start_error(u32::MAX), StartErrorDisposition::Counted);
    }

    // ── Stage-transition validator ──────────────────────────────

    #[test]
    fn stage_transitions_happy_path() {
        use EtwStage::*;
        let path = [
            (Requested, Starting),
            (Starting, SessionAlive),
            (SessionAlive, FlagsActive),
            (FlagsActive, ConsumerOpened),
            (ConsumerOpened, Processing),
            (Processing, EventsConfirmed),
            (EventsConfirmed, Stopped),
        ];
        for (from, to) in path {
            assert!(valid_stage_transition(from, to), "{from:?} -> {to:?}");
        }
    }

    #[test]
    fn stage_transitions_reject_skips_and_resurrections() {
        use EtwStage::*;
        // Cannot claim consumer-opened straight from Starting (the old lie).
        assert!(!valid_stage_transition(Starting, ConsumerOpened));
        assert!(!valid_stage_transition(Starting, Processing));
        assert!(!valid_stage_transition(Requested, EventsConfirmed));
        // A stopped/failed session cannot jump back to a live stage without
        // re-entering Starting.
        assert!(!valid_stage_transition(Stopped, ConsumerOpened));
        assert!(!valid_stage_transition(Failed, Processing));
        // But the retry loop MAY re-enter Starting from a terminal stage.
        assert!(valid_stage_transition(Stopped, Starting));
        assert!(valid_stage_transition(Failed, Starting));
        // Degraded can recover when events resume, or die.
        assert!(valid_stage_transition(Degraded, Processing));
        assert!(valid_stage_transition(Degraded, EventsConfirmed));
        assert!(valid_stage_transition(Degraded, Stopped));
        assert!(!valid_stage_transition(Degraded, Starting));
    }

    // ── Conservative health derivation ──────────────────────────

    #[test]
    fn etw_running_only_from_consumer_opened_up() {
        use EtwStage::*;
        for stage in [Requested, Starting, SessionAlive, FlagsActive] {
            assert!(
                !conservative_etw_running(stage),
                "{stage:?} must NOT report running — StartTraceW success proves nothing"
            );
        }
        for stage in [ConsumerOpened, Processing, EventsConfirmed, Degraded] {
            assert!(conservative_etw_running(stage), "{stage:?} must report running");
        }
        for stage in [Stopped, Failed] {
            assert!(!conservative_etw_running(stage));
        }
    }

    #[test]
    fn diagnostics_derive_running_from_stage() {
        let d = EtwIntakeDiagnostics::new();
        assert_eq!(d.current_stage(), EtwStage::Requested);
        assert!(!d.etw_running.load(Ordering::Relaxed));
        assert_eq!(d.stage_name(), "requested");

        d.set_stage(EtwStage::Starting);
        d.set_stage(EtwStage::SessionAlive);
        d.set_stage(EtwStage::FlagsActive);
        // Session alive + flags active is still NOT running.
        assert!(!d.etw_running.load(Ordering::Relaxed));

        d.set_stage(EtwStage::ConsumerOpened);
        assert!(d.etw_running.load(Ordering::Relaxed));

        // Invalid transition ignored: ConsumerOpened cannot jump to Starting.
        d.set_stage(EtwStage::Starting);
        assert_eq!(d.current_stage(), EtwStage::ConsumerOpened);

        d.set_stage(EtwStage::Stopped);
        assert!(!d.etw_running.load(Ordering::Relaxed));
    }

    #[test]
    fn note_failed_records_code_and_clears_running() {
        let d = EtwIntakeDiagnostics::new();
        d.set_stage(EtwStage::Starting);
        d.note_failed(ERROR_NO_SYSTEM_RESOURCES);
        assert_eq!(d.current_stage(), EtwStage::Failed);
        assert_eq!(d.failed_win32.load(Ordering::Relaxed), 1450);
        assert!(!d.etw_running.load(Ordering::Relaxed));
    }

    #[test]
    fn zero_event_degraded_keeps_running_but_marks_reason() {
        let d = EtwIntakeDiagnostics::new();
        d.set_stage(EtwStage::Starting);
        d.set_stage(EtwStage::SessionAlive);
        d.set_stage(EtwStage::FlagsActive);
        d.set_stage(EtwStage::ConsumerOpened);
        d.note_zero_event_degraded();
        assert_eq!(d.current_stage(), EtwStage::Degraded);
        assert_eq!(d.degraded_reason.load(Ordering::Relaxed), DEGRADED_ZERO_EVENTS);
        // Consumer IS attached — running stays true, health is "degraded".
        assert!(d.etw_running.load(Ordering::Relaxed));
    }

    // ── Live integration (opt-in, elevated Windows only) ────────

    /// Prerequisites: Windows 8+, ELEVATED test runner (admin + the trace
    /// session privilege), no leftover `SentinellaPLM` session is required
    /// (stale cleanup is exercised if one exists).
    /// Run explicitly:
    ///   cargo test -p sentinelld etw_live_system_logger_delivers_events -- --ignored --nocapture
    ///
    /// Expected on a healthy elevated box:
    ///   - stage reaches ConsumerOpened within ~5 s,
    ///   - events_seen >= 1 within ~30 s of spawning `cmd /c exit`,
    ///   - stage reaches EventsConfirmed (event parsed, not just delivered).
    /// Expected failure signatures:
    ///   - stage Failed + failed_win32 == 5    → test runner not elevated;
    ///   - stage Failed + failed_win32 == 1450 → all 8 system-logger slots
    ///     taken (check `logman query -ets`, stop stray sessions);
    ///   - stage Failed + failed_win32 == 87   → session config regression
    ///     (e.g. someone set SystemTraceControlGuid);
    ///   - stage stuck at ConsumerOpened with events_seen == 0 → the kernel
    ///     flags are inert again (LogFileMode lost SYSTEM_LOGGER_MODE).
    /// The test always stops the session on exit (running=false → the stop
    /// thread issues ControlTraceW(STOP) and the loop joins).
    #[test]
    #[ignore = "requires an elevated Windows box; run with --ignored"]
    fn etw_live_system_logger_delivers_events() {
        let graph = Arc::new(LineageGraph::new());
        let diag = Arc::new(EtwIntakeDiagnostics::new());
        let running = Arc::new(AtomicBool::new(true));
        let cmdline_diag = Arc::new(crate::plm::cmdline::CommandLineDiagnostics::new());
        let cmdline = Arc::new(SharedCommandLineQuerier::production(Arc::clone(
            &cmdline_diag,
        )));

        let handle = start_etw_intake(
            Arc::clone(&graph),
            Arc::clone(&diag),
            Arc::clone(&running),
            Arc::clone(&cmdline),
        )
        .expect("ETW thread spawn failed");

        // Wait for the consumer to attach (or a failure to surface).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            let stage = diag.current_stage();
            if conservative_etw_running(stage) || stage == EtwStage::Failed {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        assert!(
            diag.etw_running.load(Ordering::Relaxed),
            "consumer never opened; stage={} failed_win32={}",
            diag.stage_name(),
            diag.failed_win32.load(Ordering::Relaxed),
        );

        // Generate a process-start event.
        std::process::Command::new("cmd.exe")
            .args(["/c", "exit", "0"])
            .status()
            .expect("failed to spawn child process");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if diag.events_seen.load(Ordering::Relaxed) > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }

        // Orderly shutdown: flag → stop thread → ControlTraceW(STOP) → join.
        running.store(false, Ordering::Relaxed);
        let _ = handle.join();

        assert!(
            diag.events_seen.load(Ordering::Relaxed) > 0,
            "zero events delivered; stage={} failed_win32={} degraded_reason={}",
            diag.stage_name(),
            diag.failed_win32.load(Ordering::Relaxed),
            diag.degraded_reason.load(Ordering::Relaxed),
        );
        assert_eq!(diag.current_stage(), EtwStage::Stopped);

        // Command-line collection was wired into this session: every
        // delivered process-start must have produced exactly one query
        // outcome. `cmd /c exit` is short-lived, so ProcessExited is an
        // acceptable outcome — what we assert is that the pipeline RAN
        // and accounted every event, not which state won the race.
        let total = cmdline_diag.total();
        assert!(
            total > 0,
            "ETW events delivered but command-line querier never ran; \
             cmdline telemetry: {}",
            cmdline_diag.to_json()
        );
    }
}

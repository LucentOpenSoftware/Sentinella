//! ETW real-time process creation intake for PLM.
//!
//! Listens for kernel process events via Windows ETW.
//! Requires admin/elevated privileges. Falls back to snapshot mode
//! if ETW is unavailable.
//!
//! Architecture:
//!   StartTraceW → EnableTraceEx2 → ProcessTrace (blocking, own thread)
//!   EVENT_RECORD callback → parse process start → feed LineageGraph

#![cfg(target_os = "windows")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use super::{LineageGraph, ProcessNode};
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

/// ETW process intake diagnostics.
pub struct EtwIntakeDiagnostics {
    pub events_seen: AtomicU64,
    pub events_dropped: AtomicU64,
    pub reconnects: AtomicU64,
    pub etw_running: AtomicBool,
    pub last_event_ts: AtomicU64,
    /// Set to true when ETW gives up retrying (e.g. access denied, not admin).
    /// PlmMonitor can check this to switch to full snapshot mode.
    pub etw_gave_up: AtomicBool,
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
        }
    }
}

/// PLM mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlmMode {
    /// Real-time ETW process events.
    Etw,
    /// Periodic process snapshot polling.
    Snapshot,
    /// ETW primary + snapshot periodic cleanup.
    Hybrid,
}

/// Try to start ETW process monitoring.
/// Returns a thread handle if successful, or an error string.
/// The thread runs until `running` is set to false.
pub fn start_etw_intake(
    graph: Arc<LineageGraph>,
    diagnostics: Arc<EtwIntakeDiagnostics>,
    running: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, String> {
    // Test if we can create a trace session (requires admin).
    // Do a quick probe before spawning the thread.
    let thread = std::thread::Builder::new()
        .name("plm-etw".into())
        .spawn(move || {
            etw_process_loop(graph, diagnostics, running);
        })
        .map_err(|e| format!("failed to spawn ETW thread: {e}"))?;

    Ok(thread)
}

/// Maximum retry attempts for access-denied (error 5) before giving up.
/// After this many failures, ETW intake stops retrying and signals
/// the PLM monitor to rely on snapshot mode exclusively.
const MAX_ACCESS_DENIED_RETRIES: u32 = 5;

/// Main ETW processing loop. Retries on failure with backoff.
/// Gives up after `MAX_ACCESS_DENIED_RETRIES` access-denied failures.
fn etw_process_loop(
    graph: Arc<LineageGraph>,
    diag: Arc<EtwIntakeDiagnostics>,
    running: Arc<AtomicBool>,
) {
    tracing::info!("PLM ETW intake starting");

    let session_name = "SentinellaPLM";
    let mut backoff_secs = 1u64;
    let mut access_denied_count = 0u32;

    while running.load(Ordering::Relaxed) {
        match run_etw_session(session_name, &graph, &diag, &running) {
            Ok(()) => {
                tracing::info!("PLM ETW session ended cleanly");
                break;
            }
            Err(e) => {
                diag.etw_running.store(false, Ordering::Relaxed);
                diag.reconnects.fetch_add(1, Ordering::Relaxed);

                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let is_access_denied = e.contains("failed: 5");
                if is_access_denied {
                    access_denied_count += 1;
                }

                if is_access_denied && access_denied_count >= MAX_ACCESS_DENIED_RETRIES {
                    tracing::info!(
                        attempts = access_denied_count,
                        "PLM ETW: access denied (not admin), switching to snapshot-only mode"
                    );
                    diag.etw_gave_up.store(true, Ordering::Relaxed);
                    break;
                }

                tracing::warn!(
                    error = %e,
                    backoff_secs,
                    attempt = access_denied_count,
                    "PLM ETW session failed, will retry"
                );

                // Backoff: 1s, 2s, 4s, 8s, max 30s.
                std::thread::sleep(std::time::Duration::from_secs(backoff_secs));
                backoff_secs = (backoff_secs * 2).min(30);
            }
        }
    }

    tracing::info!("PLM ETW intake stopped");
}

/// Run a single ETW trace session. Returns when stopped or on error.
fn run_etw_session(
    session_name: &str,
    graph: &Arc<LineageGraph>,
    diag: &Arc<EtwIntakeDiagnostics>,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    use windows::Win32::System::Diagnostics::Etw::*;
    use windows::core::PCWSTR;

    let session_name_wide: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let name_bytes: Vec<u8> = unsafe {
        std::slice::from_raw_parts(
            session_name_wide.as_ptr() as *const u8,
            session_name_wide.len() * 2,
        )
        .to_vec()
    };

    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes.len() + 256;
    let mut props_buf = vec![0u8; props_size];
    let props = unsafe { &mut *(props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
    props.Wnode.BufferSize = props_size as u32;
    props.Wnode.ClientContext = 1;
    props.Wnode.Flags = 0x00020000; // WNODE_FLAG_TRACED_GUID
    props.LogFileMode = 0x00000100; // EVENT_TRACE_REAL_TIME_MODE
    props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    // Process events only (flag 0x00000001 = EVENT_TRACE_FLAG_PROCESS).
    props.EnableFlags = EVENT_TRACE_FLAG(0x00000001);

    let name_offset = props.LoggerNameOffset as usize;
    if name_offset + name_bytes.len() <= props_buf.len() {
        props_buf[name_offset..name_offset + name_bytes.len()].copy_from_slice(&name_bytes);
    }

    let mut session_handle = CONTROLTRACE_HANDLE::default();
    let start_result = unsafe {
        StartTraceW(
            &mut session_handle,
            PCWSTR(session_name_wide.as_ptr()),
            props,
        )
    };

    if start_result.0 != 0 {
        if start_result.0 == 183 {
            // Stale session — stop and retry.
            let mut stop_buf = vec![0u8; props_size];
            let stop_props =
                unsafe { &mut *(stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
            stop_props.Wnode.BufferSize = props_size as u32;
            stop_props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            unsafe {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR(session_name_wide.as_ptr()),
                    stop_props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err("stale session cleaned, will retry".into());
        }
        return Err(format!(
            "StartTraceW failed: {} (need admin?)",
            start_result.0
        ));
    }

    tracing::info!("PLM ETW kernel trace session started");
    diag.etw_running.store(true, Ordering::Relaxed);

    // Set up consumer.
    let graph_ptr = Arc::as_ptr(graph) as usize;
    let diag_ptr = Arc::as_ptr(diag) as usize;

    // Store context for callback.
    CALLBACK_GRAPH.store(graph_ptr as u64, Ordering::SeqCst);
    CALLBACK_DIAG.store(diag_ptr as u64, Ordering::SeqCst);

    let mut logfile = EVENT_TRACE_LOGFILEW::default();
    let mut logfile_name = session_name_wide.clone();
    logfile.LoggerName = windows::core::PWSTR(logfile_name.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode = 0x00000100 | 0x10000000; // REAL_TIME + EVENT_RECORD
    logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        return Err("OpenTraceW failed".into());
    }

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
        let stop_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 512;
        let mut stop_buf = vec![0u8; stop_size];
        let stop_props = unsafe { &mut *(stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        stop_props.Wnode.BufferSize = stop_size as u32;
        stop_props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(session_name_stop.as_ptr()),
                stop_props,
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

    // R3-10: release consumer handle (was leaked).
    let _ = unsafe { CloseTrace(trace_handle) };

    // Signal stop thread that ProcessTrace has returned.
    trace_done.store(true, Ordering::Relaxed);
    let _ = stop_thread.join();
    diag.etw_running.store(false, Ordering::Relaxed);

    Ok(())
}

// ── Callback globals (same pattern as sandboxd) ──────────────

static CALLBACK_GRAPH: AtomicU64 = AtomicU64::new(0);
static CALLBACK_DIAG: AtomicU64 = AtomicU64::new(0);

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
            diag.last_event_ts.store(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                Ordering::Relaxed,
            );

            // Parse process start event data.
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

            let graph = &*(graph_ptr as *const LineageGraph);
            graph.record_process(ProcessNode {
                pid,
                parent_pid: ppid,
                image_path: image_name,
                image_name: exe_name,
                command_line: None,
                is_signed: None,
                integrity_level: None,
                created_at: Instant::now(),
                timestamp: chrono::Utc::now().timestamp(),
            });
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

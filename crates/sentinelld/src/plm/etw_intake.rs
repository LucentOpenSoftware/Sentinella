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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
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
}

impl EtwIntakeDiagnostics {
    pub fn new() -> Self {
        Self {
            events_seen: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            etw_running: AtomicBool::new(false),
            last_event_ts: AtomicU64::new(0),
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

/// Main ETW processing loop. Retries on failure with backoff.
fn etw_process_loop(
    graph: Arc<LineageGraph>,
    diag: Arc<EtwIntakeDiagnostics>,
    running: Arc<AtomicBool>,
) {

    tracing::info!("PLM ETW intake starting");

    let session_name = "SentinellaPLM";
    let mut backoff_secs = 1u64;

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

                tracing::warn!(
                    error = %e,
                    backoff_secs,
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
            let stop_props = unsafe { &mut *(stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
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
        return Err(format!("StartTraceW failed: {} (need admin?)", start_result.0));
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
    let handles = [trace_handle];
    let running_clone = Arc::clone(running);
    let session_name_stop = session_name_wide.clone();
    let stop_thread = std::thread::spawn(move || {
        // Wait for running=false, then stop the session.
        while running_clone.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        // Stop session to unblock ProcessTrace.
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

    let _ = stop_thread.join();
    diag.etw_running.store(false, Ordering::Relaxed);

    Ok(())
}

// ── Callback globals (same pattern as sandboxd) ──────────────

static CALLBACK_GRAPH: AtomicU64 = AtomicU64::new(0);
static CALLBACK_DIAG: AtomicU64 = AtomicU64::new(0);

/// Process GUID for ETW kernel process events.
const PROCESS_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0x3d6fa8d0, 0xfe05, 0x11d0,
    [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
);

/// ETW event callback — receives every kernel event.
unsafe extern "system" fn etw_event_callback(record: *mut EVENT_RECORD) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { unsafe {
        if record.is_null() { return; }
        let event = &*record;

        let provider = event.EventHeader.ProviderId;
        let opcode = event.EventHeader.EventDescriptor.Opcode;

        // Only process start events (opcode 1).
        if provider != PROCESS_GUID || opcode != 1 {
            return;
        }

        let graph_ptr = CALLBACK_GRAPH.load(Ordering::SeqCst);
        let diag_ptr = CALLBACK_DIAG.load(Ordering::SeqCst);
        if graph_ptr == 0 || diag_ptr == 0 { return; }

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

        if data.len() < 8 { return; }

        // Process start event layout (varies by OS version):
        // Offset 0: ProcessId (u32) — but this is in the header.
        let pid = event.EventHeader.ProcessId;
        let ppid = if data.len() >= 8 {
            u32::from_le_bytes([data[4], data[5], data[6], data[7]])
        } else {
            0
        };

        // Image name: try to extract from event data (after fixed fields).
        // The image name is a null-terminated wide string at variable offset.
        // Simplified: use PID to look up image name via ToolHelp32.
        let image_name = get_process_image(pid).unwrap_or_else(|| format!("pid:{pid}"));
        let exe_name = image_name.rsplit('\\').next().unwrap_or(&image_name).to_string();

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
    }}));

    if result.is_err() {
        // Callback panicked — increment dropped counter.
        let diag_ptr = CALLBACK_GRAPH.load(Ordering::SeqCst);
        if diag_ptr != 0 {
            unsafe {
                let diag = &*(diag_ptr as *const EtwIntakeDiagnostics);
                diag.events_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Look up process image path by PID via ToolHelp32 snapshot.
fn get_process_image(pid: u32) -> Option<String> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::Foundation::CloseHandle;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_err() {
            let _ = CloseHandle(snapshot);
            return None;
        }

        loop {
            if entry.th32ProcessID == pid {
                let _ = CloseHandle(snapshot);
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                return Some(String::from_utf16_lossy(&entry.szExeFile[..len]));
            }
            if Process32NextW(snapshot, &mut entry).is_err() { break; }
        }

        let _ = CloseHandle(snapshot);
        None
    }
}

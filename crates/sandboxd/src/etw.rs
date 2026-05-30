//! ETW behavioral monitor — real Windows kernel event tracing.
//!
//! Two backends:
//! - **EtwKernelSession**: Real ETW kernel trace with EVENT_RECORD callback.
//!   Captures process start/stop, image loads, network connects in real-time.
//! - **PollingFallback**: Process snapshot polling + netstat. Always available.
//!
//! `monitor_process()` tries ETW first, falls back to polling if unavailable.
//! The contract (EtwFinding with confidence/source) is identical regardless of backend.

#![cfg(target_os = "windows")]

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Etw::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::core::PCWSTR;

/// Behavioral finding from ETW monitoring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EtwFinding {
    pub kind: String,
    pub severity: String,
    pub detail: String,
    pub confidence: String,
    pub source: String,
}

/// Collected ETW behavioral telemetry.
#[derive(Debug, Clone)]
pub struct EtwReport {
    pub findings: Vec<EtwFinding>,
    pub processes_spawned: Vec<String>,
    pub dlls_loaded: Vec<String>,
    pub registry_writes: Vec<String>,
    pub network_connections: Vec<String>,
    #[allow(dead_code)]
    pub files_written: Vec<String>,
    pub errors: Vec<String>,
    pub backend_used: String,
}

impl EtwReport {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            processes_spawned: Vec::new(),
            dlls_loaded: Vec::new(),
            registry_writes: Vec::new(),
            network_connections: Vec::new(),
            files_written: Vec::new(),
            errors: Vec::new(),
            backend_used: "none".into(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════

/// Monitor until timeout or caller requests early stop.
pub fn monitor_process_until(
    pid: u32,
    timeout: Duration,
    sandbox_dir: &Path,
    stop: &AtomicBool,
) -> EtwReport {
    match etw_kernel_monitor(pid, timeout, sandbox_dir, stop) {
        Ok(report) => report,
        Err(e) => {
            let mut report = EtwReport::new();
            report
                .errors
                .push(format!("ETW kernel session unavailable: {e}"));
            report.backend_used = "polling_fallback".into();
            polling_monitor(pid, timeout, sandbox_dir, &mut report, stop);
            report
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Backend 1: Real ETW Kernel Session with EVENT_RECORD callback
// ═══════════════════════════════════════════════════════════════

/// Global callback context — ETW callbacks are bare `extern "system"` fns.
static ETW_CTX: Mutex<Option<EtwContext>> = Mutex::new(None);
static ETW_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
const MAX_ETW_STRING_CHARS: usize = 512;

struct EtwContext {
    target_pid: u32,
    report: Arc<Mutex<EtwReport>>,
    monitored_pids: Arc<Mutex<HashSet<u32>>>,
}

struct EtwContextGuard;

impl Drop for EtwContextGuard {
    fn drop(&mut self) {
        let mut ctx = ETW_CTX.lock().unwrap_or_else(|e| e.into_inner());
        *ctx = None;
    }
}

/// Drop guard — ensures StopTraceW is called even on panic.
struct SessionGuard {
    handle: CONTROLTRACE_HANDLE,
    props_size: usize,
    active: bool,
}

impl SessionGuard {
    fn stop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let mut buf = vec![0u8; self.props_size];
        let props = unsafe { &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        props.Wnode.BufferSize = self.props_size as u32;
        props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        unsafe {
            let _ = ControlTraceW(self.handle, PCWSTR::null(), props, EVENT_TRACE_CONTROL_STOP);
        }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

fn etw_kernel_monitor(
    pid: u32,
    timeout: Duration,
    _sandbox_dir: &Path,
    stop: &AtomicBool,
) -> Result<EtwReport, String> {
    let report = Arc::new(Mutex::new(EtwReport::new()));
    {
        let mut r = report.lock().unwrap_or_else(|e| e.into_inner());
        r.backend_used = "etw_kernel_session".into();
    }
    let monitored_pids = Arc::new(Mutex::new(HashSet::from([pid])));

    // ── Set up callback context ──────────────────────────
    ETW_EVENT_COUNT.store(0, Ordering::Relaxed);
    {
        let mut ctx = ETW_CTX.lock().unwrap_or_else(|e| e.into_inner());
        if ctx.is_some() {
            eprintln!("WARNING: ETW_CTX was not cleaned up from a previous call — overwriting");
            *ctx = None;
        }
        *ctx = Some(EtwContext {
            target_pid: pid,
            report: Arc::clone(&report),
            monitored_pids: Arc::clone(&monitored_pids),
        });
    }
    let _ctx_guard = EtwContextGuard;

    // ── Start kernel trace session ───────────────────────
    // Fixed session name — ensures stale sessions from killed sandboxd processes
    // are always reclaimed via the error-183 retry path.
    let session_name = "SentinellaSandbox".to_string();
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
    props.EnableFlags = EVENT_TRACE_FLAG(
        0x00000001 | 0x00000004 | 0x00020000 | 0x00010000, // PROCESS + IMAGE + REGISTRY + NETWORK
    );

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

            // Rebuild props for retry.
            let mut retry_buf = vec![0u8; props_size];
            let retry_props =
                unsafe { &mut *(retry_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
            retry_props.Wnode.BufferSize = props_size as u32;
            retry_props.Wnode.ClientContext = 1;
            retry_props.Wnode.Flags = 0x00020000;
            retry_props.LogFileMode = 0x00000100;
            retry_props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            retry_props.EnableFlags =
                EVENT_TRACE_FLAG(0x00000001 | 0x00000004 | 0x00020000 | 0x00010000);
            let off = retry_props.LoggerNameOffset as usize;
            if off + name_bytes.len() <= retry_buf.len() {
                retry_buf[off..off + name_bytes.len()].copy_from_slice(&name_bytes);
            }
            let retry = unsafe {
                StartTraceW(
                    &mut session_handle,
                    PCWSTR(session_name_wide.as_ptr()),
                    retry_props,
                )
            };
            if retry.0 != 0 {
                return Err(format!("StartTraceW retry failed: {}", retry.0));
            }
        } else {
            return Err(format!(
                "StartTraceW failed: {} (need admin?)",
                start_result.0
            ));
        }
    }

    let mut _guard = SessionGuard {
        handle: session_handle,
        props_size,
        active: true,
    };

    // ── Open trace for real-time consumption ─────────────
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    logfile.LoggerName = windows::core::PWSTR(session_name_wide.as_ptr() as *mut u16);
    logfile.Anonymous1.ProcessTraceMode = 0x00000100 | 0x10000000; // REAL_TIME + EVENT_RECORD
    logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        return Err("OpenTraceW failed".into());
    }

    // ── ProcessTrace in background thread ─────────────────
    let consumer_thread = std::thread::spawn(move || {
        let handles = [trace_handle];
        unsafe {
            let _ = ProcessTrace(&handles, None, None);
        }
    });

    let start = Instant::now();
    while start.elapsed() < timeout && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(50));
    }

    // Stop session → unblocks ProcessTrace.
    _guard.stop();

    // Close trace handle.
    unsafe {
        let _ = CloseTrace(trace_handle);
    }
    let _ = consumer_thread.join();

    let result = report.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(result)
}

// ═══════════════════════════════════════════════════════════════
//  EVENT_RECORD callback — receives real kernel events
// ═══════════════════════════════════════════════════════════════

/// Well-known kernel provider GUIDs.
const PROCESS_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
const TCPIP_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2);
const IMAGE_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518);
const REGISTRY_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0xae53722e_c863_11d2_8659_00c04fa321a1);

/// Safely extract a null-terminated wide string from ETW event UserData.
///
/// Reads up to `max_len` wide chars (u16) starting at `offset` bytes into a
/// `data` buffer of `data_len` bytes. Returns `None` if the pointer is null,
/// the offset is out of range, or the string is empty.
///
/// SAFETY: `data_len` MUST be the true length of the `data` buffer. The bound
/// is enforced HERE — `offset` past the end or a `max_len` larger than the
/// remaining bytes is clamped — so a mis-sized caller cannot make this read
/// past the (attacker-controlled, ETW-provided) buffer. An out-of-bounds read
/// here is an access violation, which the callback's `catch_unwind` does NOT
/// catch; the previous version trusted the caller's `max_len` entirely.
unsafe fn extract_wide_string(
    data: *const u8,
    data_len: usize,
    offset: usize,
    max_len: usize,
) -> Option<String> {
    if data.is_null() || offset >= data_len {
        return None;
    }
    // Wide chars that actually fit in the buffer from `offset`.
    let avail_chars = (data_len - offset) / 2;
    let max_len = max_len.min(avail_chars);
    if max_len == 0 {
        return None;
    }
    let base = unsafe { data.add(offset) as *const u16 };
    let mut len = 0usize;
    while len < max_len {
        let ch = unsafe { *base.add(len) };
        if ch == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(base, len) };
    Some(String::from_utf16_lossy(slice))
}

/// Check whether an image path is a suspicious DLL load location.
fn is_suspicious_dll_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("\\temp\\") || lower.contains("\\appdata\\") || lower.contains("\\downloads\\")
}

/// Check whether a registry key path targets a persistence location.
fn is_persistence_key(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("\\run\\")
        || lower.contains("\\runonce\\")
        || lower.contains("\\services\\")
        || lower.contains("\\currentversion\\run")
}

/// Classify TCP destination port severity.
fn classify_port_severity(port: u16) -> &'static str {
    if port == 4444 {
        "critical"
    } else if port >= 1 && port <= 1024 {
        "high"
    } else if port > 49152 {
        "medium"
    } else {
        "high" // default for mid-range ports
    }
}

fn process_start_is_relevant(
    monitored_pids: &HashSet<u32>,
    event_pid: u32,
    parent_pid: u32,
    child_pid: u32,
) -> bool {
    monitored_pids.contains(&event_pid)
        || monitored_pids.contains(&parent_pid)
        || monitored_pids.contains(&child_pid)
}

unsafe extern "system" fn etw_event_callback(event: *mut EVENT_RECORD) {
    // Wrap in catch_unwind — panic across extern "system" boundary is UB.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        etw_event_callback_inner(event);
    }));
}

unsafe fn etw_event_callback_inner(event: *mut EVENT_RECORD) {
    if event.is_null() {
        return;
    }
    let event = unsafe { &*event };
    ETW_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);

    let ctx_guard = match ETW_CTX.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let ctx = match ctx_guard.as_ref() {
        Some(c) => c,
        None => return,
    };

    let provider = event.EventHeader.ProviderId;
    let event_pid = event.EventHeader.ProcessId;
    let opcode = event.EventHeader.EventDescriptor.Opcode;

    let is_process_start = provider == PROCESS_GUID && opcode == 1;
    if !is_process_start {
        let is_relevant = {
            let pids = ctx.monitored_pids.lock().unwrap_or_else(|e| e.into_inner());
            pids.contains(&event_pid)
        };
        if !is_relevant {
            return;
        }
    }

    // ── Process events ────────────────────────────────────
    if provider == PROCESS_GUID && opcode == 1 {
        // Process start — extract child PID and optional command line.
        // Validate: the first u32 in all known versions (v0-v5) is the new process PID.
        // We also validate the extracted PID looks real (non-zero, not our own PID).
        if event.UserDataLength >= 4 && !event.UserData.is_null() {
            let child_pid = unsafe { *(event.UserData as *const u32) };
            let parent_pid = if event.UserDataLength >= 8 {
                unsafe { *((event.UserData as *const u8).add(4) as *const u32) }
            } else {
                0
            };
            let is_relevant_spawn = {
                let pids = ctx.monitored_pids.lock().unwrap_or_else(|e| e.into_inner());
                process_start_is_relevant(&pids, event_pid, parent_pid, child_pid)
            };
            // Sanity check: PID should be > 4 (system PIDs) and < 100000 (reasonable range).
            if is_relevant_spawn
                && child_pid != ctx.target_pid
                && child_pid > 4
                && child_pid < 100_000
            {
                let mut pids = ctx.monitored_pids.lock().unwrap_or_else(|e| e.into_inner());
                if pids.insert(child_pid) {
                    drop(pids);
                    let name =
                        get_process_name(child_pid).unwrap_or_else(|| format!("PID-{child_pid}"));

                    // Try to extract command line from kernel process start event v3+.
                    // Layout: PID(u32) + ParentPID(u32) = 8 bytes, then variable
                    // fields. The command line is a wide string after the fixed header
                    // fields. We attempt to read it starting at a conservative offset.
                    let cmdline = if event.UserDataLength > 60 {
                        // Skip past the fixed-size fields (PID, ParentPID, SessionId,
                        // ExitStatus, DirectoryTableBase, UserSID, ImageFileName, then
                        // CommandLine). The command line offset varies by event version;
                        // we scan from offset 60 which works for v3/v4 process start
                        // events. Max 512 wide chars.
                        unsafe {
                            extract_wide_string(
                                event.UserData as *const u8,
                                event.UserDataLength as usize,
                                60,
                                MAX_ETW_STRING_CHARS,
                            )
                        }
                    } else {
                        None
                    };

                    let severity = if is_suspicious_process(&name) {
                        "high"
                    } else {
                        "medium"
                    };
                    let detail = match &cmdline {
                        Some(cl) if !cl.is_empty() => {
                            format!("Spawned {} (PID {child_pid}) cmdline: {cl}", name)
                        }
                        _ => format!("Spawned {} (PID {child_pid})", name),
                    };

                    let mut r = ctx.report.lock().unwrap_or_else(|e| e.into_inner());
                    r.processes_spawned.push(name.clone());
                    r.findings.push(EtwFinding {
                        kind: "process_spawn".into(),
                        severity: severity.into(),
                        detail,
                        confidence: "observed".into(),
                        source: "etw_kernel_process".into(),
                    });
                }
            }
        }
    }

    // ── Network events (enhanced with port severity) ────
    if provider == TCPIP_GUID && (opcode == 12 || opcode == 15) {
        if event.UserDataLength >= 14 && !event.UserData.is_null() {
            let data = event.UserData as *const u8;
            let ip = unsafe {
                format!(
                    "{}.{}.{}.{}",
                    *data.add(8),
                    *data.add(9),
                    *data.add(10),
                    *data.add(11)
                )
            };
            let port = unsafe { u16::from_be_bytes([*data.add(12), *data.add(13)]) };
            if ip != "127.0.0.1" && ip != "0.0.0.0" {
                let severity = classify_port_severity(port);
                let mut r = ctx.report.lock().unwrap_or_else(|e| e.into_inner());
                let detail = format!("TCP connect to {ip}:{port}");
                if !r.network_connections.contains(&detail) {
                    r.network_connections.push(detail.clone());
                    r.findings.push(EtwFinding {
                        kind: "network_connection".into(),
                        severity: severity.into(),
                        detail,
                        confidence: "observed".into(),
                        source: "etw_kernel_tcpip".into(),
                    });
                }
            }
        }
    }

    // ── Image load events ────────────────────────────────
    if provider == IMAGE_GUID && opcode == 10 {
        // Image load event: the image path is stored as a wide string in
        // UserData after the fixed-size header fields. We read from offset 0
        // because the kernel image load event's variable data begins with the
        // filename as a wide string (after an 8-byte base address + size prefix
        // on some versions, but the path is the dominant payload).
        if event.UserDataLength > 0 && !event.UserData.is_null() {
            if let Some(image_path) = unsafe {
                extract_wide_string(
                    event.UserData as *const u8,
                    event.UserDataLength as usize,
                    0,
                    MAX_ETW_STRING_CHARS,
                )
            } {
                if is_suspicious_dll_path(&image_path) {
                    let mut r = ctx.report.lock().unwrap_or_else(|e| e.into_inner());
                    // Dedup: skip if we already recorded this exact DLL path.
                    if !r.dlls_loaded.contains(&image_path) {
                        r.dlls_loaded.push(image_path.clone());
                        r.findings.push(EtwFinding {
                            kind: "suspicious_dll_load".into(),
                            severity: "medium".into(),
                            detail: format!("DLL loaded from suspicious path: {image_path}"),
                            confidence: "observed".into(),
                            source: "etw_kernel_image".into(),
                        });
                    }
                }
            }
        }
    }

    // ── Registry persistence events ──────────────────────
    if provider == REGISTRY_GUID && (opcode == 22 || opcode == 23) {
        // Opcode 22 = SetValue, 23 = CreateKey.
        // The key path is a wide string in UserData.
        if event.UserDataLength > 0 && !event.UserData.is_null() {
            if let Some(key_path) = unsafe {
                extract_wide_string(
                    event.UserData as *const u8,
                    event.UserDataLength as usize,
                    0,
                    MAX_ETW_STRING_CHARS,
                )
            } {
                if is_persistence_key(&key_path) {
                    let op = if opcode == 22 {
                        "SetValue"
                    } else {
                        "CreateKey"
                    };
                    let detail = format!("Registry {op} on persistence key: {key_path}");
                    let mut r = ctx.report.lock().unwrap_or_else(|e| e.into_inner());
                    // Dedup: skip if this exact registry detail was already recorded.
                    if !r.registry_writes.contains(&detail) {
                        r.registry_writes.push(detail.clone());
                        r.findings.push(EtwFinding {
                            kind: "registry_persistence".into(),
                            severity: "high".into(),
                            detail,
                            confidence: "observed".into(),
                            source: "etw_kernel_registry".into(),
                        });
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Backend 2: Polling Fallback
// ═══════════════════════════════════════════════════════════════

fn polling_monitor(
    pid: u32,
    timeout: Duration,
    _sandbox_dir: &Path,
    report: &mut EtwReport,
    stop: &AtomicBool,
) {
    let start = Instant::now();
    let mut seen: HashSet<u32> = HashSet::from([pid]);

    while start.elapsed() < timeout && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        for (child_pid, child_name) in enumerate_children(pid) {
            if seen.insert(child_pid) {
                let severity = if is_suspicious_process(&child_name) {
                    "high"
                } else {
                    "medium"
                };
                report.processes_spawned.push(child_name.clone());
                report.findings.push(EtwFinding {
                    kind: "process_spawn".into(),
                    severity: severity.into(),
                    detail: format!("Spawned {} (PID {})", child_name, child_pid),
                    confidence: "observed".into(),
                    source: "behavioral_monitor_polling".into(),
                });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Shared helpers
// ═══════════════════════════════════════════════════════════════

pub(crate) fn is_suspicious_process(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        "powershell.exe"
            | "cmd.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "regsvr32.exe"
            | "rundll32.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
            | "msiexec.exe"
            | "net.exe"
            | "net1.exe"
            | "schtasks.exe"
            | "reg.exe"
            | "wmic.exe"
            | "vssadmin.exe"
            | "bcdedit.exe"
            | "attrib.exe"
            | "icacls.exe"
            | "takeown.exe"
    )
}

fn enumerate_children(parent_pid: u32) -> Vec<(u32, String)> {
    let mut results = Vec::new();
    let snap = unsafe {
        match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return results,
        }
    };
    let mut pe: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    unsafe {
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                if pe.th32ParentProcessID == parent_pid && pe.th32ProcessID != parent_pid {
                    let name = String::from_utf16_lossy(
                        &pe.szExeFile[..pe
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(pe.szExeFile.len())],
                    );
                    results.push((pe.th32ProcessID, name));
                }
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    results
}

fn get_process_name(pid: u32) -> Option<String> {
    use windows::Win32::System::Threading::*;
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };
    let mut buf = [0u16; 260];
    let mut len = buf.len() as u32;
    let result = unsafe {
        if QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok()
        {
            let path = String::from_utf16_lossy(&buf[..len as usize]);
            std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
        } else {
            None
        }
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_wide_string_is_bounds_safe() {
        // "Hi\0" as UTF-16LE = 6 bytes.
        let buf: Vec<u8> = vec![0x48, 0, 0x69, 0, 0, 0];
        unsafe {
            // Normal decode.
            assert_eq!(
                extract_wide_string(buf.as_ptr(), buf.len(), 0, 16).as_deref(),
                Some("Hi")
            );
            // Huge max_len is clamped to the buffer — no OOB read.
            assert_eq!(
                extract_wide_string(buf.as_ptr(), buf.len(), 0, 999_999).as_deref(),
                Some("Hi")
            );
            // Offset past the end → None (the OLD code would read past the
            // buffer here = access violation, uncatchable by catch_unwind).
            assert_eq!(extract_wide_string(buf.as_ptr(), buf.len(), 99, 16), None);
            // Offset exactly at end → None.
            assert_eq!(extract_wide_string(buf.as_ptr(), buf.len(), buf.len(), 16), None);
            // Null pointer → None.
            assert_eq!(extract_wide_string(std::ptr::null(), 10, 0, 4), None);
        }
    }

    #[test]
    fn suspicious_processes() {
        assert!(is_suspicious_process("powershell.exe"));
        assert!(is_suspicious_process("cmd.exe"));
        assert!(is_suspicious_process("POWERSHELL.EXE"));
        assert!(!is_suspicious_process("notepad.exe"));
        assert!(!is_suspicious_process("explorer.exe"));
    }

    #[test]
    fn etw_report_empty() {
        let r = EtwReport::new();
        assert!(r.findings.is_empty());
        assert_eq!(r.backend_used, "none");
    }

    #[test]
    fn finding_serializes() {
        let f = EtwFinding {
            kind: "test".into(),
            severity: "high".into(),
            detail: "d".into(),
            confidence: "observed".into(),
            source: "etw_kernel_process".into(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("etw_kernel_process"));
    }

    #[test]
    fn dedup_logic() {
        let existing = vec![EtwFinding {
            kind: "process_spawn".into(),
            severity: "high".into(),
            detail: "Spawned cmd.exe".into(),
            confidence: "observed".into(),
            source: "etw_kernel_process".into(),
        }];
        let dup = EtwFinding {
            kind: "process_spawn".into(),
            severity: "high".into(),
            detail: "Spawned cmd.exe".into(),
            confidence: "observed".into(),
            source: "etw_kernel_process".into(),
        };
        assert!(
            existing
                .iter()
                .any(|f| f.kind == dup.kind && f.detail == dup.detail)
        );

        let not_dup = EtwFinding {
            kind: "network_connection".into(),
            severity: "high".into(),
            detail: "TCP connect".into(),
            confidence: "observed".into(),
            source: "etw_kernel_tcpip".into(),
        };
        assert!(
            !existing
                .iter()
                .any(|f| f.kind == not_dup.kind && f.detail == not_dup.detail)
        );
    }

    fn score_for(sev: &str) -> i32 {
        match sev {
            "critical" => 25,
            "high" => 15,
            "medium" => 10,
            "low" => 5,
            _ => 0,
        }
    }

    #[test]
    fn score_values() {
        assert_eq!(score_for("critical"), 25);
        assert_eq!(score_for("high"), 15);
        assert_eq!(score_for("medium"), 10);
        assert_eq!(score_for("low"), 5);
        assert_eq!(score_for("info"), 0);
    }

    #[test]
    fn backend_tracking() {
        let mut r = EtwReport::new();
        assert_eq!(r.backend_used, "none");
        r.backend_used = "etw_kernel_session".into();
        assert_eq!(r.backend_used, "etw_kernel_session");
    }

    #[test]
    fn context_guard_clears_global_context() {
        {
            let mut ctx = ETW_CTX.lock().unwrap_or_else(|e| e.into_inner());
            *ctx = Some(EtwContext {
                target_pid: 1234,
                report: Arc::new(Mutex::new(EtwReport::new())),
                monitored_pids: Arc::new(Mutex::new(HashSet::from([1234]))),
            });
        }
        {
            let _guard = EtwContextGuard;
        }
        let ctx = ETW_CTX.lock().unwrap_or_else(|e| e.into_inner());
        assert!(ctx.is_none());
    }

    #[test]
    fn suspicious_dll_paths() {
        assert!(is_suspicious_dll_path(
            "C:\\Users\\user\\AppData\\Local\\Temp\\evil.dll"
        ));
        assert!(is_suspicious_dll_path(
            "C:\\Users\\user\\Downloads\\payload.dll"
        ));
        assert!(is_suspicious_dll_path(
            "C:\\Users\\user\\AppData\\Roaming\\malware.dll"
        ));
        assert!(!is_suspicious_dll_path(
            "C:\\Windows\\System32\\kernel32.dll"
        ));
        assert!(!is_suspicious_dll_path("C:\\Program Files\\App\\legit.dll"));
    }

    #[test]
    fn persistence_keys() {
        assert!(is_persistence_key(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"
        ));
        assert!(is_persistence_key(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\payload"
        ));
        assert!(is_persistence_key(
            "HKLM\\System\\CurrentControlSet\\Services\\malware"
        ));
        assert!(is_persistence_key(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ));
        assert!(!is_persistence_key(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
        ));
        assert!(!is_persistence_key("HKCU\\Software\\SomeApp\\Settings"));
    }

    #[test]
    fn port_severity_classification() {
        assert_eq!(classify_port_severity(4444), "critical");
        assert_eq!(classify_port_severity(80), "high");
        assert_eq!(classify_port_severity(443), "high");
        assert_eq!(classify_port_severity(1), "high");
        assert_eq!(classify_port_severity(1024), "high");
        assert_eq!(classify_port_severity(49153), "medium");
        assert_eq!(classify_port_severity(65535), "medium");
        assert_eq!(classify_port_severity(8080), "high"); // mid-range defaults to high
    }

    #[test]
    fn process_start_relevant_when_parent_monitored() {
        let pids = HashSet::from([1000]);
        assert!(process_start_is_relevant(&pids, 2000, 1000, 2000));
    }

    #[test]
    fn process_start_relevant_when_event_pid_monitored() {
        let pids = HashSet::from([1000]);
        assert!(process_start_is_relevant(&pids, 1000, 4, 2000));
    }

    #[test]
    fn process_start_ignores_unrelated_pid() {
        let pids = HashSet::from([1000]);
        assert!(!process_start_is_relevant(&pids, 3000, 2000, 4000));
    }

    #[test]
    fn extract_wide_string_basic() {
        // Build a null-terminated wide string "hello" in a buffer.
        let wide: Vec<u16> = "hello".encode_utf16().chain(std::iter::once(0)).collect();
        let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_ne_bytes()).collect();
        let result = unsafe { extract_wide_string(bytes.as_ptr(), bytes.len(), 0, 256) };
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn extract_wide_string_with_offset() {
        // 4 bytes of padding, then "test\0" as wide string.
        let mut bytes: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD]; // 4-byte prefix
        let wide: Vec<u16> = "test".encode_utf16().chain(std::iter::once(0)).collect();
        bytes.extend(wide.iter().flat_map(|w| w.to_ne_bytes()));
        let result = unsafe { extract_wide_string(bytes.as_ptr(), bytes.len(), 4, 256) };
        assert_eq!(result, Some("test".to_string()));
    }

    #[test]
    fn extract_wide_string_null_ptr() {
        let result = unsafe { extract_wide_string(std::ptr::null(), 256, 0, 256) };
        assert_eq!(result, None);
    }

    #[test]
    fn extract_wide_string_empty() {
        // Just a null terminator.
        let wide: Vec<u16> = vec![0];
        let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_ne_bytes()).collect();
        let result = unsafe { extract_wide_string(bytes.as_ptr(), bytes.len(), 0, 256) };
        assert_eq!(result, None);
    }

    #[test]
    fn extract_wide_string_max_len_respected() {
        // "abcdefgh\0" — but max_len = 3, so only "abc" is returned.
        let wide: Vec<u16> = "abcdefgh"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_ne_bytes()).collect();
        let result = unsafe { extract_wide_string(bytes.as_ptr(), bytes.len(), 0, 3) };
        assert_eq!(result, Some("abc".to_string()));
    }

    #[test]
    fn image_load_finding_fields() {
        let f = EtwFinding {
            kind: "suspicious_dll_load".into(),
            severity: "medium".into(),
            detail:
                "DLL loaded from suspicious path: C:\\Users\\user\\AppData\\Local\\Temp\\evil.dll"
                    .into(),
            confidence: "observed".into(),
            source: "etw_kernel_image".into(),
        };
        assert_eq!(f.source, "etw_kernel_image");
        assert_eq!(f.severity, "medium");
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("suspicious_dll_load"));
    }

    #[test]
    fn registry_finding_fields() {
        let f = EtwFinding {
            kind: "registry_persistence".into(),
            severity: "high".into(),
            detail: "Registry SetValue on persistence key: HKLM\\...\\Run\\evil".into(),
            confidence: "observed".into(),
            source: "etw_kernel_registry".into(),
        };
        assert_eq!(f.source, "etw_kernel_registry");
        assert_eq!(f.severity, "high");
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("registry_persistence"));
    }

    #[test]
    fn dedup_across_event_types() {
        let mut r = EtwReport::new();
        // Simulate adding an image load finding.
        let dll = "C:\\Users\\u\\AppData\\evil.dll".to_string();
        r.dlls_loaded.push(dll.clone());
        // Check dedup: same path should be detected.
        assert!(r.dlls_loaded.contains(&dll));
        // Registry dedup.
        let reg = "Registry SetValue on persistence key: HKLM\\...\\Run\\x".to_string();
        r.registry_writes.push(reg.clone());
        assert!(r.registry_writes.contains(&reg));
    }

    // ═══════════════════════════════════════════════════════════
    //  Scenario tests — validate classification logic without
    //  requiring actual ETW sessions or admin rights.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn scenario_benign_no_findings() {
        // A process named "notepad.exe" is not suspicious.
        assert!(!is_suspicious_process("notepad.exe"));
        // A DLL loaded from System32 is not suspicious.
        assert!(!is_suspicious_dll_path(r"C:\Windows\System32\kernel32.dll"));
        // A registry key not in Run/Services is not persistence.
        assert!(!is_persistence_key(r"HKCU\Software\SomeApp\Settings"));
    }

    #[test]
    fn scenario_cmd_spawn_is_suspicious() {
        assert!(is_suspicious_process("cmd.exe"));
        assert!(is_suspicious_process("CMD.EXE"));
    }

    #[test]
    fn scenario_dll_from_temp_suspicious() {
        assert!(is_suspicious_dll_path(
            r"C:\Users\test\AppData\Local\Temp\malware.dll"
        ));
        assert!(is_suspicious_dll_path(
            r"C:\Users\test\Downloads\payload.dll"
        ));
        assert!(!is_suspicious_dll_path(r"C:\Windows\System32\ntdll.dll"));
    }

    #[test]
    fn scenario_run_key_is_persistence() {
        assert!(is_persistence_key(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware"
        ));
        assert!(is_persistence_key(
            r"HKLM\System\CurrentControlSet\Services\BadService"
        ));
        assert!(!is_persistence_key(r"HKCU\Software\SomeApp\Preferences"));
    }

    #[test]
    fn scenario_tcp_port_classification() {
        assert_eq!(classify_port_severity(4444), "critical"); // Metasploit
        assert_eq!(classify_port_severity(80), "high"); // Standard port
        assert_eq!(classify_port_severity(443), "high"); // HTTPS
        assert_eq!(classify_port_severity(8080), "high"); // Common proxy
        assert_eq!(classify_port_severity(55000), "medium"); // Ephemeral
    }

    #[test]
    fn scenario_timeout_is_medium_severity() {
        // Timeout finding should be medium severity (from main.rs logic).
        let score = match "medium" {
            "critical" => 25,
            "high" => 15,
            "medium" => 10,
            "low" => 5,
            _ => 0,
        };
        assert_eq!(score, 10);
    }

    #[test]
    fn scenario_score_cap_at_50() {
        // 10 high findings = 150 raw -> capped to 50.
        let findings: Vec<&str> = vec!["high"; 10];
        let raw: i32 = findings
            .iter()
            .map(|s| match *s {
                "high" => 15,
                _ => 0,
            })
            .sum();
        assert_eq!(raw, 150);
        let capped = raw.min(50);
        assert_eq!(capped, 50);
    }

    #[test]
    fn scenario_dedup_prevents_double_count() {
        let mut findings = vec![EtwFinding {
            kind: "process_spawn".into(),
            severity: "high".into(),
            detail: "Spawned cmd.exe (PID 1234)".into(),
            confidence: "observed".into(),
            source: "etw_kernel_process".into(),
        }];
        // Same finding again — should be detected as duplicate.
        let dup = EtwFinding {
            kind: "process_spawn".into(),
            severity: "high".into(),
            detail: "Spawned cmd.exe (PID 1234)".into(),
            confidence: "observed".into(),
            source: "etw_kernel_process".into(),
        };
        let is_dup = findings
            .iter()
            .any(|f| f.kind == dup.kind && f.detail == dup.detail);
        assert!(is_dup, "Duplicate finding should be detected");
        // Don't add it.
        if !is_dup {
            findings.push(dup);
        }
        assert_eq!(findings.len(), 1, "Should still have only 1 finding");
    }

    #[test]
    fn scenario_backend_used_tracking() {
        let mut r = EtwReport::new();
        assert_eq!(r.backend_used, "none");
        r.backend_used = "etw_kernel_session".into();
        assert_eq!(r.backend_used, "etw_kernel_session");
        r.backend_used = "polling_fallback".into();
        assert_eq!(r.backend_used, "polling_fallback");
    }

    #[test]
    fn polling_monitor_stops_early() {
        let mut r = EtwReport::new();
        r.backend_used = "polling_fallback".into();
        let stop = AtomicBool::new(true);
        let start = Instant::now();

        polling_monitor(
            999_999,
            Duration::from_secs(10),
            Path::new("."),
            &mut r,
            &stop,
        );

        assert!(start.elapsed() < Duration::from_secs(1));
    }
}

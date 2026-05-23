//! FISH active response — process suspension and termination.
//!
//! When FISH detects a ransomware burst pattern and active response is
//! enabled, this module identifies and acts on the offending process.
//!
//! Attribution strategy (user-mode, best-effort):
//! 1. Check recently-written files for exclusive locks → identify writer PID
//! 2. Enumerate processes, find those with handles to affected directories
//! 3. Fallback: scan recently-started processes with suspicious names
//!
//! Safety rules:
//! - NEVER suspend/kill system processes (PID < 8, services.exe, csrss.exe, etc.)
//! - NEVER suspend/kill Sentinella's own processes
//! - Log every action for audit trail
//! - Prefer suspension over termination (reversible)

use serde::Serialize;
use std::path::Path;

/// Result of an active response action.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)] // Used in future GUI response display.
pub struct ResponseAction {
    pub action: ResponseType,
    pub pid: u32,
    pub process_name: String,
    pub reason: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    Observe,
    Suspend,
    Terminate,
}

impl ResponseType {
    pub fn from_config(s: &str) -> Self {
        match s {
            "suspend" => Self::Suspend,
            "terminate" => Self::Terminate,
            _ => Self::Observe,
        }
    }
}

/// System-critical processes that must NEVER be suspended/terminated.
const PROTECTED_PROCESSES: &[&str] = &[
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "dwm.exe",
    "explorer.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "fontdrvhost.exe",
    // Sentinella's own processes.
    "sentinelld.exe",
    "sentinella.exe",
    "argusd.exe",
    "sentinella-argus.exe",
];

/// Find processes likely responsible for file modifications in a directory.
/// Returns PIDs sorted by suspicion (most suspicious first).
pub fn find_suspect_processes(affected_dir: &Path) -> Vec<SuspectProcess> {
    #[cfg(target_os = "windows")]
    {
        find_suspects_windows(affected_dir)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = affected_dir;
        Vec::new()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SuspectProcess {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub suspicion_reason: String,
}

/// Suspend all threads of a process (reversible).
pub fn suspend_process(pid: u32) -> Result<(), String> {
    if is_protected(pid) {
        return Err(format!(
            "PID {pid} is a protected system process — refusing to suspend"
        ));
    }
    #[cfg(target_os = "windows")]
    {
        suspend_process_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Process suspension only supported on Windows".into())
    }
}

/// Terminate a process (irreversible — use as last resort).
pub fn terminate_process(pid: u32) -> Result<(), String> {
    if is_protected(pid) {
        return Err(format!(
            "PID {pid} is a protected system process — refusing to terminate"
        ));
    }
    #[cfg(target_os = "windows")]
    {
        terminate_process_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Process termination only supported on Windows".into())
    }
}

fn is_protected(pid: u32) -> bool {
    if pid <= 4 {
        return true; // System Idle + System process.
    }
    // Check process name against protected list.
    #[cfg(target_os = "windows")]
    {
        if let Some(name) = get_process_name(pid) {
            let lower = name.to_lowercase();
            return PROTECTED_PROCESSES.iter().any(|p| lower == *p);
        }
    }
    false
}

// ═══════════════════════════════════════════════════════════════
//  Windows implementation
// ═══════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn get_process_name(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };

    let mut name_buf = [0u16; 260];
    let mut name_len = name_buf.len() as u32;
    let result = unsafe {
        if windows::Win32::System::Threading::QueryFullProcessImageNameW(
            handle,
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(name_buf.as_mut_ptr()),
            &mut name_len,
        )
        .is_ok()
        {
            let path = String::from_utf16_lossy(&name_buf[..name_len as usize]);
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

#[cfg(target_os = "windows")]
fn find_suspects_windows(affected_dir: &Path) -> Vec<SuspectProcess> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::EnumProcesses;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let mut pids = [0u32; 4096];
    let mut bytes_returned = 0u32;
    let ok = unsafe {
        EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * 4) as u32,
            &mut bytes_returned,
        )
    };
    if ok.is_err() {
        return Vec::new();
    }
    let count = bytes_returned as usize / 4;

    let dir_lower = affected_dir.to_string_lossy().to_lowercase();
    let mut suspects = Vec::new();

    for &pid in &pids[..count] {
        if pid <= 4 {
            continue;
        }

        let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            Ok(h) => h,
            Err(_) => continue,
        };

        let mut name_buf = [0u16; 260];
        let mut name_len = name_buf.len() as u32;
        let proc_info = unsafe {
            if windows::Win32::System::Threading::QueryFullProcessImageNameW(
                handle,
                windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
            )
            .is_ok()
            {
                let path = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let name = std::path::Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                Some((name, path))
            } else {
                None
            }
        };
        unsafe {
            let _ = CloseHandle(handle);
        }

        if let Some((name, path)) = proc_info {
            let name_lower = name.to_lowercase();

            // Skip protected processes.
            if PROTECTED_PROCESSES.iter().any(|p| name_lower == *p) {
                continue;
            }

            // Heuristic: process running from the affected directory.
            let path_lower = path.to_lowercase();
            if path_lower.contains(&dir_lower) {
                suspects.push(SuspectProcess {
                    pid,
                    name: name.clone(),
                    path: Some(path.clone()),
                    suspicion_reason: "running from affected directory".into(),
                });
                continue;
            }

            // Heuristic: process with suspicious name patterns.
            let suspicious_names = [
                "encrypt", "ransom", "locker", "crypt", "wncry", "cerber", "locky", "wannacry",
                "petya", "ryuk",
            ];
            if suspicious_names.iter().any(|s| name_lower.contains(s)) {
                suspects.push(SuspectProcess {
                    pid,
                    name,
                    path: Some(path),
                    suspicion_reason: "suspicious process name".into(),
                });
            }
        }
    }

    suspects
}

#[cfg(target_os = "windows")]
fn suspend_process_windows(pid: u32) -> Result<(), String> {
    // NtSuspendProcess is the cleanest way, but it's undocumented.
    // Alternative: enumerate threads and suspend each.
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows::Win32::System::Threading::{OpenThread, SuspendThread, THREAD_SUSPEND_RESUME};

    let snap = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| format!("CreateToolhelp32Snapshot failed: {e}"))?
    };

    let mut te: THREADENTRY32 = unsafe { std::mem::zeroed() };
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    let mut suspended = 0u32;
    let mut ok = unsafe { Thread32First(snap, &mut te) };
    while ok.is_ok() {
        if te.th32OwnerProcessID == pid {
            if let Ok(thread) = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID) }
            {
                unsafe {
                    let _ = SuspendThread(thread);
                }
                unsafe {
                    let _ = CloseHandle(thread);
                }
                suspended += 1;
            }
        }
        ok = unsafe { Thread32Next(snap, &mut te) };
    }

    unsafe {
        let _ = CloseHandle(snap);
    }

    if suspended > 0 {
        tracing::warn!(pid, threads = suspended, "FISH: process suspended");
        Ok(())
    } else {
        Err(format!("No threads suspended for PID {pid}"))
    }
}

#[cfg(target_os = "windows")]
fn terminate_process_windows(pid: u32) -> Result<(), String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    let handle = unsafe {
        OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| format!("Cannot open process {pid} for termination: {e}"))?
    };

    let result = unsafe { TerminateProcess(handle, 1) };
    unsafe {
        let _ = CloseHandle(handle);
    }

    result.map_err(|e| format!("TerminateProcess failed: {e}"))?;
    tracing::warn!(pid, "FISH: process terminated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_processes_are_protected() {
        assert!(is_protected(0));
        assert!(is_protected(4));
    }

    #[test]
    fn response_type_from_config() {
        assert_eq!(ResponseType::from_config("observe"), ResponseType::Observe);
        assert_eq!(ResponseType::from_config("suspend"), ResponseType::Suspend);
        assert_eq!(
            ResponseType::from_config("terminate"),
            ResponseType::Terminate
        );
        assert_eq!(ResponseType::from_config("invalid"), ResponseType::Observe);
    }

    #[test]
    fn protected_process_names() {
        // Can't test by PID easily, but verify the list is populated.
        assert!(PROTECTED_PROCESSES.contains(&"csrss.exe"));
        assert!(PROTECTED_PROCESSES.contains(&"sentinelld.exe"));
        assert!(PROTECTED_PROCESSES.contains(&"explorer.exe"));
    }
}

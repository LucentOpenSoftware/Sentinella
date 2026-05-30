//! Advanced Memory Scanner — runtime process memory inspection.
//!
//! Scans process memory for unpacked malware, injected code, and
//! shellcode payloads. Triggered after ARGUS flags a suspicious file
//! or on manual request.
//!
//! Strategy: enumerate executable memory regions of a target process,
//! read their contents, scan with YARA + pattern detection.
//!
//! Limitations (user-mode):
//! - Cannot scan kernel memory
//! - Cannot scan processes with higher privilege
//! - Some processes guard their memory (anti-debug)
//! - Memory regions may change between enumeration and read
//!
//! Budget discipline:
//! - max_region_size_mb: largest single region to read
//! - max_total_scan_mb: total bytes across all regions per process
//! - max_regions_per_process: region count cap
//! - timeout_secs: wall-clock timeout per process
//! - cancel_flag: shared cancellation signal

use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Budget configuration for memory scanning.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct MemoryScanBudget {
    pub max_region_size_mb: u64,
    pub max_total_scan_mb: u64,
    pub max_regions_per_process: u32,
    pub timeout_secs: u64,
}

impl Default for MemoryScanBudget {
    fn default() -> Self {
        Self {
            max_region_size_mb: 64,
            max_total_scan_mb: 256,
            max_regions_per_process: 512,
            timeout_secs: 30,
        }
    }
}

/// Why a region or process was skipped.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum MemoryTimeoutReason {
    RegionTooLarge,
    BudgetExceeded,
    AccessDenied,
    ReadFailed,
    YaraTimeout,
    WallClockTimeout,
    RegionLimitReached,
    Cancelled,
}

/// Result of scanning one process's memory.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryScanResult {
    pub pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub regions_scanned: u32,
    pub regions_skipped: u32,
    pub bytes_scanned: u64,
    pub findings: Vec<MemoryFinding>,
    pub errors: Vec<String>,
    pub skip_reasons: Vec<MemoryTimeoutReason>,
    pub access_denied_count: u32,
    pub scan_time_ms: u64,
    pub modules: Vec<ModuleInfo>,
}

/// Loaded module information for a process.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: u64,
    pub size: u64,
}

/// A finding in process memory.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryFinding {
    pub region_address: u64,
    pub region_size: u64,
    pub description: String,
    pub severity: MemorySeverity,
    /// YARA rule name if matched.
    pub yara_rule: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySeverity {
    Info,
    Suspicious,
    Malicious,
}

/// Scan a specific process by PID with budget and cancellation.
pub fn scan_process(
    pid: u32,
    argus: &argus::ArgusEngine,
    budget: &MemoryScanBudget,
    cancel: &Arc<AtomicBool>,
) -> MemoryScanResult {
    let start = std::time::Instant::now();
    let mut result = MemoryScanResult {
        pid,
        process_name: String::new(),
        process_path: None,
        regions_scanned: 0,
        regions_skipped: 0,
        bytes_scanned: 0,
        findings: Vec::new(),
        errors: Vec::new(),
        skip_reasons: Vec::new(),
        access_denied_count: 0,
        scan_time_ms: 0,
        modules: Vec::new(),
    };

    if pid == std::process::id() {
        result.scan_time_ms = start.elapsed().as_millis() as u64;
        return result;
    }

    #[cfg(target_os = "windows")]
    {
        scan_process_windows(pid, argus, budget, cancel, &start, &mut result);
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (argus, budget, cancel);
        result
            .errors
            .push("Memory scanning only supported on Windows".into());
    }

    result.scan_time_ms = start.elapsed().as_millis() as u64;
    result
}

/// Convenience: scan with default budget, no cancellation.
#[allow(dead_code)]
pub fn scan_process_simple(pid: u32, argus: &argus::ArgusEngine) -> MemoryScanResult {
    scan_process(
        pid,
        argus,
        &MemoryScanBudget::default(),
        &Arc::new(AtomicBool::new(false)),
    )
}

/// List running processes with basic info.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub memory_mb: u64,
}

pub fn list_processes() -> Vec<ProcessInfo> {
    #[cfg(target_os = "windows")]
    {
        list_processes_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Vec::new()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Windows implementation
// ═══════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn scan_process_windows(
    pid: u32,
    argus: &argus::ArgusEngine,
    budget: &MemoryScanBudget,
    cancel: &Arc<AtomicBool>,
    start: &std::time::Instant,
    result: &mut MemoryScanResult,
) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, VirtualQueryEx,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    // Get process name/path first.
    if let Some(info) = get_process_info_windows(pid) {
        result.process_name = info.name;
        result.process_path = info.path;
    }

    result.modules = enumerate_modules_windows(pid);

    let handle = unsafe {
        match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => {
                result.access_denied_count += 1;
                result.skip_reasons.push(MemoryTimeoutReason::AccessDenied);
                return;
            }
        }
    };
    // RAII handle close: the scan loop allocates `vec![0u8; region_size]` per
    // committed-exec region (up to max_region_size). A panic on OOM here would
    // skip the manual CloseHandle at the end → process handle leak in the
    // long-running daemon. The guard fires on every drop, including unwind.
    struct OpenHandleGuard(windows::Win32::Foundation::HANDLE);
    impl Drop for OpenHandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
    let _handle_guard = OpenHandleGuard(handle);

    // Enumerate memory regions.
    let mut address: usize = 0;
    let mut regions_seen: u32 = 0;
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    let max_scan_bytes = budget.max_total_scan_mb.saturating_mul(1024 * 1024);
    let max_region_size = budget
        .max_region_size_mb
        .saturating_mul(1024 * 1024)
        .min(usize::MAX as u64) as usize;

    loop {
        if cancel.load(Ordering::Relaxed) {
            result.skip_reasons.push(MemoryTimeoutReason::Cancelled);
            break;
        }
        if start.elapsed().as_secs() >= budget.timeout_secs {
            result
                .skip_reasons
                .push(MemoryTimeoutReason::WallClockTimeout);
            break;
        }
        if regions_seen >= budget.max_regions_per_process {
            result
                .skip_reasons
                .push(MemoryTimeoutReason::RegionLimitReached);
            break;
        }

        let ret = unsafe {
            VirtualQueryEx(
                handle,
                Some(address as *const std::ffi::c_void),
                &mut mbi,
                mbi_size,
            )
        };
        if ret == 0 {
            break; // No more regions.
        }
        regions_seen = regions_seen.saturating_add(1);

        // Only scan committed, executable regions — where unpacked code lives.
        let is_executable = mbi.Protect == PAGE_EXECUTE
            || mbi.Protect == PAGE_EXECUTE_READ
            || mbi.Protect == PAGE_EXECUTE_READWRITE
            || mbi.Protect == PAGE_EXECUTE_WRITECOPY;
        let is_rwx = mbi.Protect == PAGE_EXECUTE_READWRITE;
        let is_image_backed = mbi.Type == MEM_IMAGE;

        if mbi.State == MEM_COMMIT && is_executable && mbi.RegionSize > 0 {
            if is_rwx && mbi.RegionSize > 4096 {
                result.findings.push(MemoryFinding {
                    region_address: mbi.BaseAddress as u64,
                    region_size: mbi.RegionSize as u64,
                    description: format!(
                        "RWX memory region ({} KB) — read+write+execute is a strong indicator of injected or self-modifying code",
                        mbi.RegionSize / 1024
                    ),
                    severity: MemorySeverity::Suspicious,
                    yara_rule: None,
                });
            }

            if !is_image_backed && mbi.RegionSize > 4096 {
                result.findings.push(MemoryFinding {
                    region_address: mbi.BaseAddress as u64,
                    region_size: mbi.RegionSize as u64,
                    description: format!(
                        "Unbacked executable memory ({} KB) — not backed by any image file",
                        mbi.RegionSize / 1024
                    ),
                    severity: MemorySeverity::Info,
                    yara_rule: None,
                });
            }

            let region_size = mbi.RegionSize.min(max_region_size);
            if mbi.RegionSize > max_region_size {
                result.regions_skipped += 1;
                result
                    .skip_reasons
                    .push(MemoryTimeoutReason::RegionTooLarge);
            }

            if result.bytes_scanned.saturating_add(region_size as u64) > max_scan_bytes {
                result.regions_skipped += 1;
                result
                    .skip_reasons
                    .push(MemoryTimeoutReason::BudgetExceeded);
                result
                    .errors
                    .push("Max scan bytes reached — stopping".into());
                break;
            }

            // Read region.
            let mut buffer = vec![0u8; region_size];
            let mut bytes_read = 0usize;
            let ok = unsafe {
                ReadProcessMemory(
                    handle,
                    mbi.BaseAddress,
                    buffer.as_mut_ptr() as *mut std::ffi::c_void,
                    region_size,
                    Some(&mut bytes_read),
                )
            };

            if ok.is_ok() && bytes_read > 0 {
                buffer.truncate(bytes_read);
                result.regions_scanned += 1;
                result.bytes_scanned += bytes_read as u64;

                // ARGUS analysis on memory buffer (includes YARA + pattern detection).
                let region_name = format!("pid{}:0x{:x}", pid, mbi.BaseAddress as u64);
                let verdict = argus.analyze_buffer(&region_name, &buffer);
                for f in &verdict.findings {
                    result.findings.push(MemoryFinding {
                        region_address: mbi.BaseAddress as u64,
                        region_size: bytes_read as u64,
                        description: f.description.clone(),
                        severity: if f.weight >= 15 {
                            MemorySeverity::Malicious
                        } else if f.weight >= 5 {
                            MemorySeverity::Suspicious
                        } else {
                            MemorySeverity::Info
                        },
                        yara_rule: f.technical_detail.clone(),
                    });
                }

                // Pattern checks on memory buffer.
                check_memory_patterns(
                    &buffer,
                    mbi.BaseAddress as u64,
                    bytes_read as u64,
                    &mut result.findings,
                );
            } else {
                result.regions_skipped += 1;
                result.skip_reasons.push(MemoryTimeoutReason::ReadFailed);
            }
        }

        let base_address = mbi.BaseAddress as usize;
        if mbi.RegionSize == 0
            || mbi.RegionSize > usize::MAX.saturating_sub(base_address)
            || base_address.saturating_add(mbi.RegionSize) <= address
        {
            result
                .skip_reasons
                .push(MemoryTimeoutReason::RegionLimitReached);
            break;
        }

        // Advance to next region. checked_add catches wrap-around at the
        // 64-bit address space tail; old `if address == 0` only caught exact
        // wrap to zero, not partial wrap.
        match (mbi.BaseAddress as usize).checked_add(mbi.RegionSize) {
            Some(next) => address = next,
            None => break, // wrap → end of address space
        }
        if address == 0 {
            break;
        }
    }

    // _handle_guard closes the OpenProcess handle on drop (incl. panic unwind).
}

#[cfg(target_os = "windows")]
fn enumerate_modules_windows(pid: u32) -> Vec<ModuleInfo> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

    let mut modules = Vec::new();
    let snap = unsafe {
        match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
            Ok(h) => h,
            Err(_) => return modules,
        }
    };

    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    let mut ok = unsafe { Module32FirstW(snap, &mut entry).is_ok() };
    while ok {
        let name = String::from_utf16_lossy(
            &entry.szModule[..entry
                .szModule
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szModule.len())],
        );
        let path = String::from_utf16_lossy(
            &entry.szExePath[..entry
                .szExePath
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExePath.len())],
        );
        modules.push(ModuleInfo {
            name,
            path,
            base_address: entry.modBaseAddr as u64,
            size: entry.modBaseSize as u64,
        });
        if modules.len() >= 2048 {
            break;
        }
        ok = unsafe { Module32NextW(snap, &mut entry).is_ok() };
    }

    unsafe {
        let _ = CloseHandle(snap);
    }
    modules
}

/// Check memory buffer for suspicious patterns (shellcode, PE headers, etc.).
fn check_memory_patterns(
    data: &[u8],
    base_addr: u64,
    size: u64,
    findings: &mut Vec<MemoryFinding>,
) {
    // PE header in non-image memory (injected PE).
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        // Check for valid PE signature at offset in e_lfanew.
        if data.len() >= 64 {
            let lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
            // Defensive: `lfanew` is attacker-controlled (raw memory bytes). On
            // 32-bit usize, `lfanew + 4` can wrap (lfanew=u32::MAX) → tiny
            // result → in-bounds slice into the wrong place → panic / OOB read.
            // checked_add eliminates the class.
            if let Some(end) = lfanew.checked_add(4) {
                if end <= data.len() && data[lfanew..end] == [0x50, 0x45, 0x00, 0x00] {
                    findings.push(MemoryFinding {
                        region_address: base_addr,
                        region_size: size,
                        description: "PE header found in executable memory — possible injected or unpacked module".into(),
                        severity: MemorySeverity::Suspicious,
                        yara_rule: None,
                    });
                }
            }
        }
    }

    // ── Shellcode indicators ──────────────────────────────

    // NOP sled (32+ consecutive NOPs).
    if data.len() >= 32 {
        let mut nop_count = 0u32;
        for &b in data.iter().take(8192) {
            if b == 0x90 {
                nop_count += 1;
                if nop_count >= 32 {
                    findings.push(MemoryFinding {
                        region_address: base_addr,
                        region_size: size,
                        description: "Large NOP sled detected — common shellcode landing pad"
                            .into(),
                        severity: MemorySeverity::Suspicious,
                        yara_rule: None,
                    });
                    break;
                }
            } else {
                nop_count = 0;
            }
        }
    }

    // ── Reflective DLL loading indicators ────────────────
    // "ReflectiveLoader" string in executable memory.
    let contains = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);
    if contains(b"ReflectiveLoader") || contains(b"reflective_loader") {
        findings.push(MemoryFinding {
            region_address: base_addr,
            region_size: size,
            description: "Reflective DLL loader string found in memory — technique used to load DLLs without LoadLibrary".into(),
            severity: MemorySeverity::Malicious,
            yara_rule: None,
        });
    }

    // ── Common API resolution strings in shellcode ───────
    // Shellcode often resolves APIs by hash or string — these indicate manual API resolution.
    let api_strings = [
        b"kernel32.dll" as &[u8],
        b"ntdll.dll",
        b"VirtualAlloc",
        b"LoadLibraryA",
        b"GetProcAddress",
    ];
    let mut api_hits = 0u32;
    for needle in &api_strings {
        if contains(needle) {
            api_hits += 1;
        }
    }
    if api_hits >= 3 {
        findings.push(MemoryFinding {
            region_address: base_addr,
            region_size: size,
            description: format!(
                "Manual API resolution pattern ({api_hits}/5 common APIs as strings) — indicates position-independent shellcode or reflective loader"
            ),
            severity: MemorySeverity::Suspicious,
            yara_rule: None,
        });
    }

    // ── High entropy check (packed/encrypted payload) ────
    if data.len() >= 1024 {
        let entropy = calculate_entropy(&data[..data.len().min(65536)]);
        if entropy > 7.5 {
            findings.push(MemoryFinding {
                region_address: base_addr,
                region_size: size,
                description: format!(
                    "High entropy ({entropy:.2}) in executable memory — possible encrypted or compressed payload"
                ),
                severity: MemorySeverity::Suspicious,
                yara_rule: None,
            });
        }
    }

    // ── Process hollowing signature ──────────────────────
    // NtUnmapViewOfSection + NtWriteVirtualMemory strings.
    if contains(b"NtUnmapViewOfSection") || contains(b"ZwUnmapViewOfSection") {
        findings.push(MemoryFinding {
            region_address: base_addr,
            region_size: size,
            description: "Process hollowing API string (NtUnmapViewOfSection) in memory — used to replace process image".into(),
            severity: MemorySeverity::Malicious,
            yara_rule: None,
        });
    }
}

/// Shannon entropy of a byte buffer (0.0 = uniform, 8.0 = random).
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(target_os = "windows")]
fn get_process_info_windows(pid: u32) -> Option<ProcessInfo> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };

    // Get process image name.
    let mut name_buf = [0u16; 260];
    let mut name_len = name_buf.len() as u32;
    let name = unsafe {
        if windows::Win32::System::Threading::QueryFullProcessImageNameW(
            handle,
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(name_buf.as_mut_ptr()),
            &mut name_len,
        )
        .is_ok()
        {
            let path = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let file_name = std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            Some((file_name, path))
        } else {
            None
        }
    };

    // Get memory info.
    let memory_mb = unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(handle, &mut counters, counters.cb).is_ok() {
            counters.WorkingSetSize as u64 / (1024 * 1024)
        } else {
            0
        }
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    let (proc_name, proc_path) = name.unwrap_or_default();
    Some(ProcessInfo {
        pid,
        name: proc_name,
        path: Some(proc_path),
        memory_mb,
    })
}

#[cfg(target_os = "windows")]
fn list_processes_windows() -> Vec<ProcessInfo> {
    use windows::Win32::System::ProcessStatus::EnumProcesses;

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
    let mut result = Vec::with_capacity(count);

    for &pid in &pids[..count] {
        if pid == 0 {
            continue;
        } // System Idle Process.
        if let Some(info) = get_process_info_windows(pid) {
            if !info.name.is_empty() {
                result.push(info);
            }
        }
    }

    result.sort_by(|a, b| b.memory_mb.cmp(&a.memory_mb));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_header_detection() {
        let mut findings = Vec::new();
        // Valid MZ + PE signature at offset 0x80.
        let mut data = vec![0u8; 256];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        // e_lfanew at offset 60 = 0x80.
        data[60] = 0x80;
        data[61] = 0x00;
        data[62] = 0x00;
        data[63] = 0x00;
        // PE signature at 0x80.
        data[0x80] = 0x50; // P
        data[0x81] = 0x45; // E
        data[0x82] = 0x00;
        data[0x83] = 0x00;

        check_memory_patterns(&data, 0x10000, 256, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("PE header"));
    }

    #[test]
    fn nop_sled_detection() {
        let mut findings = Vec::new();
        let mut data = vec![0u8; 100];
        // 40 consecutive NOPs.
        for b in data.iter_mut().take(40) {
            *b = 0x90;
        }

        check_memory_patterns(&data, 0x20000, 100, &mut findings);
        assert!(findings.iter().any(|f| f.description.contains("NOP sled")));
    }

    #[test]
    fn clean_memory_no_findings() {
        let mut findings = Vec::new();
        let data = vec![0xCC; 256]; // INT3 breakpoints — not suspicious.
        check_memory_patterns(&data, 0x30000, 256, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn list_processes_returns_something() {
        let procs = list_processes();
        // Should find at least our own process.
        assert!(!procs.is_empty(), "Should find running processes");
    }

    #[test]
    fn reflective_loader_detection() {
        let mut findings = Vec::new();
        let mut data = vec![0u8; 256];
        data[10..26].copy_from_slice(b"ReflectiveLoader");
        check_memory_patterns(&data, 0x40000, 256, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("Reflective DLL"))
        );
    }

    #[test]
    fn api_resolution_detection() {
        let mut findings = Vec::new();
        let mut data = vec![0u8; 1024];
        // Place 3+ API strings.
        data[10..22].copy_from_slice(b"kernel32.dll");
        data[100..112].copy_from_slice(b"VirtualAlloc");
        data[200..214].copy_from_slice(b"GetProcAddress");
        check_memory_patterns(&data, 0x50000, 1024, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("API resolution"))
        );
    }

    #[test]
    fn process_hollowing_detection() {
        let mut findings = Vec::new();
        let mut data = vec![0u8; 256];
        data[10..30].copy_from_slice(b"NtUnmapViewOfSection");
        check_memory_patterns(&data, 0x60000, 256, &mut findings);
        assert!(findings.iter().any(|f| f.description.contains("hollowing")));
    }

    #[test]
    fn entropy_calculation() {
        // All zeros = entropy 0.
        let zeros = vec![0u8; 1024];
        assert!(calculate_entropy(&zeros) < 0.01);

        // Random-ish data = high entropy.
        let random: Vec<u8> = (0..1024).map(|i| (i * 37 + 13) as u8).collect();
        assert!(calculate_entropy(&random) > 6.0);
    }

    #[test]
    fn high_entropy_detection() {
        let mut findings = Vec::new();
        // Create high-entropy buffer (simulated encrypted data).
        let data: Vec<u8> = (0..4096).map(|i| ((i * 251 + 97) % 256) as u8).collect();
        check_memory_patterns(&data, 0x70000, 4096, &mut findings);
        // Should detect high entropy.
        assert!(findings.iter().any(|f| f.description.contains("entropy")));
    }

    #[test]
    fn self_process_skipped() {
        let budget = MemoryScanBudget::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let result = scan_process(
            std::process::id(),
            &argus::ArgusEngine::with_defaults(),
            &budget,
            &cancel,
        );
        assert_eq!(result.regions_scanned, 0);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn cancelled_scan_stops() {
        let budget = MemoryScanBudget::default();
        let cancel = Arc::new(AtomicBool::new(true)); // pre-cancelled
        let result = scan_process(4, &argus::ArgusEngine::with_defaults(), &budget, &cancel);
        // Should have stopped immediately — either access denied or cancelled.
        let has_cancel_or_denied = result.skip_reasons.iter().any(|r| {
            matches!(
                r,
                MemoryTimeoutReason::Cancelled | MemoryTimeoutReason::AccessDenied
            )
        });
        assert!(has_cancel_or_denied || result.regions_scanned == 0);
    }

    #[test]
    fn budget_defaults_are_sane() {
        let b = MemoryScanBudget::default();
        assert_eq!(b.max_region_size_mb, 64);
        assert_eq!(b.max_total_scan_mb, 256);
        assert_eq!(b.max_regions_per_process, 512);
        assert_eq!(b.timeout_secs, 30);
    }

    #[test]
    fn module_info_fields() {
        let m = ModuleInfo {
            name: "test.dll".into(),
            path: "C:\\test.dll".into(),
            base_address: 0x7FF00000,
            size: 4096,
        };
        assert_eq!(m.name, "test.dll");
        assert_eq!(m.size, 4096);
    }
}

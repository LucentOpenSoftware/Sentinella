//! Windows resource signals — CPU, battery, fullscreen, disk pressure.
//!
//! These tell the idle scanner: "Does the system have spare capacity right now?"
//! Not: "Is the user present?"

use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

/// Cached CPU idle/kernel/user ticks for delta computation.
static PREV_IDLE: AtomicU64 = AtomicU64::new(0);
static PREV_KERNEL: AtomicU64 = AtomicU64::new(0);
static PREV_USER: AtomicU64 = AtomicU64::new(0);

/// Get current CPU usage percent (0–100).
/// Uses GetSystemTimes() delta between calls.
/// First call returns 0 (no delta yet).
pub fn cpu_usage_percent() -> u32 {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::FILETIME;
        use windows::Win32::System::Threading::GetSystemTimes;

        let mut idle = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();

        let ok = unsafe {
            GetSystemTimes(
                Some(&mut idle as *mut _),
                Some(&mut kernel as *mut _),
                Some(&mut user as *mut _),
            )
        };
        if ok.is_err() {
            return 0;
        }

        let ft_to_u64 =
            |ft: FILETIME| -> u64 { (ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64 };

        let idle_now = ft_to_u64(idle);
        let kernel_now = ft_to_u64(kernel);
        let user_now = ft_to_u64(user);

        let prev_i = PREV_IDLE.swap(idle_now, Ordering::Relaxed);
        let prev_k = PREV_KERNEL.swap(kernel_now, Ordering::Relaxed);
        let prev_u = PREV_USER.swap(user_now, Ordering::Relaxed);

        // First call — no delta.
        if prev_i == 0 && prev_k == 0 && prev_u == 0 {
            return 0;
        }

        let idle_delta = idle_now.saturating_sub(prev_i);
        let kernel_delta = kernel_now.saturating_sub(prev_k);
        let user_delta = user_now.saturating_sub(prev_u);

        let total = kernel_delta + user_delta; // kernel includes idle
        if total == 0 {
            return 0;
        }

        // CPU busy = total - idle. Kernel time includes idle time.
        let busy = total.saturating_sub(idle_delta);
        ((busy * 100) / total) as u32
    }

    #[cfg(not(target_os = "windows"))]
    {
        0
    }
}

/// Check if system is on battery (laptop unplugged).
pub fn on_battery() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::Power::GetSystemPowerStatus;
        use windows::Win32::System::Power::SYSTEM_POWER_STATUS;

        let mut status = SYSTEM_POWER_STATUS::default();
        let ok = unsafe { GetSystemPowerStatus(&mut status) };
        if ok.is_err() {
            return false;
        }

        // ACLineStatus: 0 = offline (battery), 1 = online (plugged in), 255 = unknown
        status.ACLineStatus == 0
    }

    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Check if a true-fullscreen / game / presentation app is active.
///
/// v0.1.8 tightening: the v0.1.7 implementation trusted `QUNS_BUSY (2)`
/// from `SHQueryUserNotificationState`, but that code fires for far more
/// than just games — any app that calls `ITaskbarList3::SetProgressState`,
/// any DirectComposition/DWM hardware-accelerated window when maximized,
/// and notoriously WebView2 (Tauri's GUI runtime) when its main window is
/// merely maximized. Result: the user's idle scanner sat in
/// "Pausado · fullscreen" forever while they had Sentinella itself open
/// maximized, even though no real game was running.
///
/// Layered detector now:
///   1. SHQueryUserNotificationState — ONLY trust the unambiguous game
///      codes: QUNS_RUNNING_D3D_FULL_SCREEN (3), QUNS_PRESENTATION_MODE
///      (4), QUNS_APP (7 — Windows 8+ Modern fullscreen). Drop
///      QUNS_BUSY (2) entirely; it's too broad.
///   2. Foreground-window heuristic — if SHQuery says clear, double-check
///      by asking Windows for the foreground window: a true fullscreen
///      game covers the entire monitor AND has no caption/border. A
///      maximized normal app HAS a caption. Skip the entire check if the
///      foreground window belongs to OUR own process (Sentinella GUI or
///      sentinelld), since those obviously aren't games.
///   3. Conservative on errors — every Win32 call falls back to "not
///      fullscreen" rather than "yes pause" to avoid sticky pauses on
///      systems where the APIs misbehave.
pub fn fullscreen_or_busy() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Layer 1: shell notification state — trust ONLY the game codes.
        if shell_says_definitely_game() {
            return true;
        }
        // Layer 2: foreground window check — covers cases where SHQuery
        // doesn't pick up legacy D3D fullscreen but the window is one.
        foreground_is_true_fullscreen()
    }

    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
fn shell_says_definitely_game() -> bool {
    use windows::Win32::UI::Shell::SHQueryUserNotificationState;
    match unsafe { SHQueryUserNotificationState() } {
        // QUNS_RUNNING_D3D_FULL_SCREEN (3) = D3D fullscreen game
        // QUNS_PRESENTATION_MODE (4) = explicit "I'm presenting" mode
        // QUNS_APP (7) = Windows 8+ Modern app fullscreen
        // NOTE: deliberately NOT matching QUNS_BUSY (2) — too many
        // false-positives from regular maximized apps (see fn doc).
        Ok(s) => matches!(s.0, 3 | 4 | 7),
        Err(_) => false,
    }
}

#[cfg(target_os = "windows")]
fn foreground_is_true_fullscreen() -> bool {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowLongW, GetWindowRect, GetWindowThreadProcessId,
        GWL_STYLE, WS_BORDER, WS_CAPTION, WS_DLGFRAME,
    };

    unsafe {
        let hwnd: HWND = GetForegroundWindow();
        if hwnd.0.is_null() {
            return false;
        }

        // Whose process owns this window?
        let mut pid: u32 = 0;
        let _ = GetWindowThreadProcessId(hwnd, Some(&mut pid as *mut u32));
        if pid != 0 {
            // Skip our own GUI / daemon — they're never games.
            if process_id_is_ours(pid) {
                return false;
            }
        }

        // Get window style. A true fullscreen game has NO caption / border
        // (it's a borderless rect covering the whole monitor). A merely
        // maximized normal app has WS_CAPTION + WS_BORDER + WS_DLGFRAME
        // — that's the case we wrongly flagged in v0.1.7.
        let style = GetWindowLongW(hwnd, GWL_STYLE) as u32;
        let has_caption = (style & WS_CAPTION.0) != 0;
        let has_border = (style & WS_BORDER.0) != 0;
        let has_dlgframe = (style & WS_DLGFRAME.0) != 0;
        if has_caption || has_border || has_dlgframe {
            return false; // normal windowed/maximized app
        }

        // Borderless — check if it covers the entire monitor.
        let mut wr = windows::Win32::Foundation::RECT::default();
        if GetWindowRect(hwnd, &mut wr as *mut _).is_err() {
            return false;
        }
        let monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        let mut mi: MONITORINFO = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if !GetMonitorInfoW(monitor, &mut mi as *mut _).as_bool() {
            return false;
        }
        wr.left == mi.rcMonitor.left
            && wr.top == mi.rcMonitor.top
            && wr.right == mi.rcMonitor.right
            && wr.bottom == mi.rcMonitor.bottom
    }
}

#[cfg(target_os = "windows")]
fn process_id_is_ours(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
    use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle: HANDLE = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let mut buf = [0u16; 1024];
        // windows 0.58: pass HANDLE (not Option) for the process and the
        // null HMODULE for "main executable".
        let len = GetModuleFileNameExW(handle, HMODULE::default(), &mut buf);
        let _ = CloseHandle(handle);
        if len == 0 {
            return false;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]).to_lowercase();
        // Match either the GUI or the daemon — both are "ours".
        path.ends_with("sentinella.exe")
            || path.ends_with("sentinelld.exe")
            || path.ends_with("sentinella-cli.exe")
            || path.ends_with("argusd.exe")
    }
}

/// Check if screen is locked / user away (favorable for faster scanning).
pub fn screen_locked_or_away() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::UI::Shell::SHQueryUserNotificationState;

        match unsafe { SHQueryUserNotificationState() } {
            Ok(s) => s.0 == 1, // QUNS_NOT_PRESENT = screensaver/locked
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Simple disk pressure check: time a metadata stat on a system file.
/// Returns latency in milliseconds. If >threshold, disk is busy.
pub fn disk_read_latency_ms() -> u64 {
    let start = std::time::Instant::now();
    let probe = std::path::Path::new("C:\\Windows\\System32\\ntdll.dll");
    let _ = std::fs::metadata(probe);
    start.elapsed().as_millis() as u64
}

/// Combined resource check: returns a `PauseReason` or `None` if system has capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseReason {
    Battery,
    Fullscreen,
    HighCpu,
    HighDisk,
    ScanRunning,
    MemoryPressure,
}

impl PauseReason {
    pub fn label(self) -> &'static str {
        match self {
            PauseReason::Battery => "on_battery",
            PauseReason::Fullscreen => "fullscreen",
            PauseReason::HighCpu => "high_cpu",
            PauseReason::HighDisk => "high_disk",
            PauseReason::ScanRunning => "scan_running",
            PauseReason::MemoryPressure => "memory_pressure",
        }
    }

    pub fn sleep_secs(self) -> u64 {
        match self {
            PauseReason::Battery => 60,
            PauseReason::Fullscreen => 30,
            PauseReason::ScanRunning => 10,
            PauseReason::HighCpu => 10,
            PauseReason::HighDisk => 5,
            PauseReason::MemoryPressure => 30,
        }
    }
}

pub struct ResourceConfig {
    pub allow_on_battery: bool,
    pub cpu_threshold: u32,
    pub disk_latency_threshold_ms: u64,
    pub pause_on_fullscreen: bool,
}

/// Check system resources. Returns None if idle enough, Some(reason) if should pause.
///
/// `gui_fullscreen_hint`: v0.1.9 Phase 4 addition. The GUI runs in the
/// user session and can call `GetForegroundWindow` correctly; the daemon
/// runs in session 0 (it's a Windows service) and cannot. The GUI pushes
/// its verdict via `system.fullscreen_report` and the caller consults
/// `AppState::fresh_gui_fullscreen(...)` before invoking us. Passing
/// `Some(true|false)` here trusts the GUI verdict; passing `None` (no
/// fresh GUI report, or no GUI connected) falls back to the session-0
/// SHQuery-only detector — better than nothing but blind to most games.
pub fn check_resources(
    config: &ResourceConfig,
    scan_running: bool,
    gui_fullscreen_hint: Option<bool>,
) -> Option<PauseReason> {
    if !config.allow_on_battery && on_battery() {
        return Some(PauseReason::Battery);
    }
    if config.pause_on_fullscreen {
        let fs = gui_fullscreen_hint.unwrap_or_else(fullscreen_or_busy);
        if fs {
            return Some(PauseReason::Fullscreen);
        }
    }
    if scan_running {
        return Some(PauseReason::ScanRunning);
    }
    let cpu = cpu_usage_percent();
    if cpu > config.cpu_threshold {
        debug!(
            cpu,
            threshold = config.cpu_threshold,
            "idle scanner: CPU too high"
        );
        return Some(PauseReason::HighCpu);
    }
    let disk_ms = disk_read_latency_ms();
    if disk_ms > config.disk_latency_threshold_ms {
        debug!(
            disk_ms,
            threshold = config.disk_latency_threshold_ms,
            "idle scanner: disk pressure"
        );
        return Some(PauseReason::HighDisk);
    }
    None
}

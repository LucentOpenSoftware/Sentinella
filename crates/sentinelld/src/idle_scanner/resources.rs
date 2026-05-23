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

/// Check if a fullscreen/busy/game/presentation app is active.
/// Uses SHQueryUserNotificationState — returns true if user should not be disturbed.
pub fn fullscreen_or_busy() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::UI::Shell::SHQueryUserNotificationState;

        let state = unsafe { SHQueryUserNotificationState() };
        match state {
            Ok(s) => {
                // QUNS_BUSY(2) = fullscreen app
                // QUNS_RUNNING_D3D_FULL_SCREEN(3) = game
                // QUNS_PRESENTATION_MODE(4) = presentation
                matches!(s.0, 2 | 3 | 4)
            }
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        false
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
pub fn check_resources(config: &ResourceConfig, scan_running: bool) -> Option<PauseReason> {
    if !config.allow_on_battery && on_battery() {
        return Some(PauseReason::Battery);
    }
    if config.pause_on_fullscreen && fullscreen_or_busy() {
        return Some(PauseReason::Fullscreen);
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

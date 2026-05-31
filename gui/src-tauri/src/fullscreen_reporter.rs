//! Pushes user-session foreground-window fullscreen verdict to the
//! daemon every 5 seconds. v0.1.9 Phase 4 fix for audit MED-8.
//!
//! Why this module exists:
//!
//! The daemon runs as a Windows service (session 0). `GetForegroundWindow`
//! returns NULL from session 0 because that session has no interactive
//! desktop. The v0.1.8 foreground-window-style fullscreen detector in
//! `sentinelld/src/idle_scanner/resources.rs` therefore degenerated to
//! "always returns false" in production, and the idle scanner's
//! pause-on-fullscreen feature was effectively off — idle scans could
//! resume on top of running games.
//!
//! Fix: the GUI process (sentinella.exe) runs in the user session and
//! CAN call `GetForegroundWindow` correctly. This module polls the
//! foreground every 5s, classifies it via the same layered detector
//! used daemon-side (SHQuery + foreground-window geometry + style +
//! own-process skip), and pushes the verdict to the daemon over IPC
//! (`system.fullscreen_report`). The daemon caches the verdict with a
//! 15s freshness window; the idle scanner consults the cache before
//! falling back to its own session-0 SHQuery-only path.
//!
//! Failure modes (all fail-safe — scans continue, no privilege boundary
//! crossed):
//!   * IPC push fails -> daemon's cache goes stale after 15s, idle
//!     scanner falls back to its own session-0 detector. No worse than
//!     v0.1.8.
//!   * GUI not running -> daemon never gets a fresh verdict, falls back
//!     to session-0 detector. No worse than v0.1.8.
//!   * Win32 quirk returns null hwnd -> we report `false` and the cache
//!     gets a fresh "not fullscreen" — fail-open, matching the daemon's
//!     existing posture.

use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const INITIAL_GRACE: Duration = Duration::from_secs(2);

/// Spawn the background poll-and-push loop. Called once from
/// `lib.rs::setup` after the daemon-client is initialised.
pub fn spawn() {
    tokio::spawn(async {
        // Give the daemon-client a moment to discover the named pipe
        // and read the IPC secret. If the pipe isn't ready yet, the
        // first push just fails silently and the next 5s iteration
        // tries again.
        tokio::time::sleep(INITIAL_GRACE).await;

        let mut prev_reported: Option<bool> = None;
        loop {
            let active = is_truly_fullscreen();
            match crate::daemon_client::call_auth(
                "system.fullscreen_report",
                serde_json::json!({ "active": active }),
            )
            .await
            {
                Ok(_) => {
                    if Some(active) != prev_reported {
                        log::debug!(
                            "fullscreen_reporter: verdict {} -> {}",
                            prev_reported
                                .map(|p| if p { "ON" } else { "OFF" })
                                .unwrap_or("?"),
                            if active { "ON" } else { "OFF" }
                        );
                        prev_reported = Some(active);
                    }
                }
                Err(e) => {
                    // Don't spam logs — only on transition or first failure.
                    if prev_reported.is_some() {
                        log::debug!("fullscreen_reporter: push failed: {e}");
                    }
                    prev_reported = None;
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
}

// ─── Detector (copy of sentinelld's layered detector) ────────────
//
// Kept in-sync MANUALLY with `sentinelld/src/idle_scanner/resources.rs`.
// We don't depend on the sentinelld crate from the GUI (would invert the
// architecture — GUI shouldn't compile-time-depend on the daemon binary),
// and there's no shared sentinella-common module for Win32 helpers yet.
// If you change one detector, change BOTH. A future refactor could move
// the function to sentinella-common.

#[cfg(target_os = "windows")]
fn is_truly_fullscreen() -> bool {
    if shell_says_definitely_game() {
        return true;
    }
    foreground_is_true_fullscreen()
}

#[cfg(not(target_os = "windows"))]
fn is_truly_fullscreen() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn shell_says_definitely_game() -> bool {
    use windows::Win32::UI::Shell::SHQueryUserNotificationState;
    match unsafe { SHQueryUserNotificationState() } {
        // QUNS_RUNNING_D3D_FULL_SCREEN (3), QUNS_PRESENTATION_MODE (4),
        // QUNS_APP (7). Deliberately NOT matching QUNS_BUSY (2) — too
        // many false positives from regular maximized apps (Tauri / WebView2
        // / DWM-accelerated windows).
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
            // Shouldn't happen from the user session, but fail-open.
            return false;
        }

        // Skip our own process — Sentinella maximized is not a game.
        let mut pid: u32 = 0;
        let _ = GetWindowThreadProcessId(hwnd, Some(&mut pid as *mut u32));
        if pid != 0 && process_id_is_ours(pid) {
            return false;
        }

        // Borderless game heuristic: no caption / border / dialog frame.
        let style = GetWindowLongW(hwnd, GWL_STYLE) as u32;
        let has_caption = (style & WS_CAPTION.0) != 0;
        let has_border = (style & WS_BORDER.0) != 0;
        let has_dlgframe = (style & WS_DLGFRAME.0) != 0;
        if has_caption || has_border || has_dlgframe {
            return false;
        }

        // Borderless — check if it covers the whole monitor.
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
        let len = GetModuleFileNameExW(handle, HMODULE::default(), &mut buf);
        let _ = CloseHandle(handle);
        if len == 0 {
            return false;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]).to_lowercase();
        path.ends_with("sentinella.exe")
            || path.ends_with("sentinelld.exe")
            || path.ends_with("sentinella-cli.exe")
            || path.ends_with("argusd.exe")
    }
}

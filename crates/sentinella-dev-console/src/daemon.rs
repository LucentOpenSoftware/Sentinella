//! Helpers for inspecting and toggling the installed SentinellaDaemon
//! Windows service from the dev-console.

use std::path::PathBuf;
use std::process::Command;

use crate::ipc;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone)]
pub struct DaemonSnapshot {
    pub service_present: bool,
    pub service_running: bool,
    /// Whether the IPC secret file is present on disk — informational for
    /// future "snapshot mode" diagnostics. Read by external consumers.
    #[allow(dead_code)]
    pub ipc_secret_present: bool,
    pub version: Option<String>,
    pub uptime_secs: Option<u64>,
    pub config_path: PathBuf,
    pub argusd_path: Option<PathBuf>,
}

impl DaemonSnapshot {
    pub fn collect() -> Self {
        let service_running = matches!(query_state_code(), Some(2 | 4 | 5));
        let service_present = service_running || sc_service_exists();
        let ipc_secret_present = ipc::load_secret().is_some();

        let (version, uptime_secs) = match ipc::call_simple("health") {
            Ok(v) => (
                v.get("version").and_then(|x| x.as_str()).map(String::from),
                v.get("uptime_secs").and_then(|x| x.as_u64()),
            ),
            Err(_) => (None, None),
        };

        let pd_root = ipc::programdata_root();
        let config_path = pd_root.join("config").join("sentinelld.toml");
        let argusd_path = locate_argusd();

        Self {
            service_present,
            service_running,
            ipc_secret_present,
            version,
            uptime_secs,
            config_path,
            argusd_path,
        }
    }
}

/// Locate an `argusd.exe` to benchmark. Search order is dev-first:
///
///   1. Next to this dev-console exe (the developer's personal toolbox
///      layout — copy `sentinella-dev-console.exe` + `argusd.exe` to one
///      folder, ship it).
///   2. Cargo workspace builds: walk `current_exe().ancestors()` looking
///      for a sibling `target/release/argusd.exe` or `target/debug/
///      argusd.exe`. This covers `cargo run -p sentinella-dev-console`
///      from a workspace checkout.
///   3. The installed Sentinella copy under
///      `<Program Files>\Sentinella\daemon\argusd.exe`.
///
/// Dev-first matters because the whole point of this tool is to bench
/// the version of ARGUS we *just built*, not whichever version is
/// installed. (v0.1.5 argusd does not even have the `benchmark`
/// subcommand — falling through to the installer copy was producing a
/// confusing "unrecognized subcommand" error.)
pub fn locate_argusd() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok();

    // (1) Next to this exe.
    if let Some(parent) = exe.as_ref().and_then(|e| e.parent()) {
        let side = parent.join("argusd.exe");
        if side.exists() {
            return Some(side);
        }
    }

    // (2) Workspace target/{release,debug}/argusd.exe — walk ancestors
    //     so it works when this exe sits at `target/release/`,
    //     `target/debug/`, or deeper (e.g. `target/release/deps/`).
    if let Some(ref e) = exe {
        for ancestor in e.ancestors() {
            for sub in ["release/argusd.exe", "debug/argusd.exe"] {
                let p = ancestor.join(sub);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }

    // (3) Installed Sentinella.
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    let base = PathBuf::from(pf).join("Sentinella");
    for sub in [
        "daemon/argusd.exe",
        "resources/daemon/argusd.exe",
        "argusd.exe",
    ] {
        let p = base.join(sub);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Parse `sc query SentinellaDaemon` and extract the STATE numeric code.
/// Robust against localized field labels (the numeric is constant).
/// Returns None when the service is not installed or sc.exe fails.
///
/// Locale note: on Spanish Windows the output is
///
/// ```text
/// TIPO   : 10  WIN32_OWN_PROCESS
/// ESTADO : 1   STOPPED
/// ```
///
/// The naive "first line where digit is followed by whitespace + a letter"
/// rule would return TIPO=10 instead of ESTADO=1. SERVICE_TYPE codes are
/// always >= 10 (WIN32_OWN_PROCESS=0x10, WIN32_SHARE_PROCESS=0x20, …) while
/// STATE codes are 1..=7. Constraining the candidate to that range picks
/// the right line on every locale we've seen.
fn query_state_code() -> Option<u32> {
    let out = quiet_command("sc")
        .args(["query", "SentinellaDaemon"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let Some(idx) = line.find(':') else { continue };
        let rest = line[idx + 1..].trim_start();
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() || digits.len() >= rest.len() {
            continue;
        }
        let tail = &rest[digits.len()..];
        if !tail.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        if !tail
            .trim_start()
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
        {
            continue;
        }
        if let Ok(n) = digits.parse::<u32>() {
            if (1..=7).contains(&n) {
                return Some(n);
            }
        }
    }
    None
}

fn sc_service_exists() -> bool {
    let out = quiet_command("sc")
        .args(["query", "SentinellaDaemon"])
        .output()
        .ok();
    // sc returns 1060 (ERROR_SERVICE_DOES_NOT_EXIST) when missing; any
    // other "OK" or "running" exit means it's installed.
    matches!(out, Some(o) if o.status.code() != Some(1060))
}

pub fn restart_service() -> Result<String, String> {
    stop_service()?;
    start_service()?;
    Ok("service restarted".into())
}

pub fn stop_service() -> Result<(), String> {
    let out = quiet_command("sc")
        .args(["stop", "SentinellaDaemon"])
        .output()
        .map_err(|e| format!("sc stop: {e}"))?;
    // Tolerate "already stopped" (1062) — caller wants the end state, not the path.
    if !out.status.success() && out.status.code() != Some(1062) {
        return Err(format!(
            "sc stop failed: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        ));
    }
    // Poll until truly STOPPED (1) or timeout.
    for _ in 0..30 {
        if matches!(query_state_code(), Some(1) | None) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err("daemon did not stop within 15s".into())
}

pub fn start_service() -> Result<(), String> {
    let out = quiet_command("sc")
        .args(["start", "SentinellaDaemon"])
        .output()
        .map_err(|e| format!("sc start: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "sc start failed: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        ));
    }
    // Poll until RUNNING (4) or timeout.
    for _ in 0..30 {
        if matches!(query_state_code(), Some(4)) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err("daemon did not reach RUNNING within 15s".into())
}

/// Build a Command with the CREATE_NO_WINDOW flag set on Windows so we
/// don't flash console windows during sc / argusd invocations. (Same
/// hygiene as the daemon's own win_process::QuietCommand.)
pub fn quiet_command<S: AsRef<std::ffi::OsStr>>(program: S) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// True when the current process is running with an elevated token. We
/// gate config edits + service restart on this so we don't silently fail.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool { true }

/// Relaunch the current executable through `ShellExecuteW` with the
/// `runas` verb so Windows shows the UAC prompt and the new process
/// receives an elevated token. On success the current process exits
/// cleanly; the caller never returns here. On failure (UAC denied,
/// missing exe path) returns an error string for the UI to surface.
#[cfg(windows)]
pub fn relaunch_as_admin() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_NORMAL;

    let exe = std::env::current_exe()
        .map_err(|e| format!("current_exe: {e}"))?;
    let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let verb_w: Vec<u16> = "runas\0".encode_utf16().collect();

    // ShellExecuteW returns a HINSTANCE; values <= 32 are error codes.
    let hinst = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb_w.as_ptr(),
            exe_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_NORMAL,
        )
    };
    if (hinst as isize) <= 32 {
        let code = hinst as isize;
        return Err(match code {
            // SE_ERR_ACCESSDENIED → user clicked No on UAC.
            5 => "UAC prompt was denied".to_string(),
            _ => format!("ShellExecuteW failed (code {code})"),
        });
    }
    // Elevated copy spawned successfully — quit this one so we don't
    // race with the new instance on config writes.
    std::process::exit(0);
}

#[cfg(not(windows))]
pub fn relaunch_as_admin() -> Result<(), String> {
    Err("relaunch_as_admin is Windows-only".into())
}

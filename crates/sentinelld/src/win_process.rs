//! Single-source-of-truth for spawning child processes without flashing a
//! console window on Windows.
//!
//! v0.1.6 had several `Command::spawn` sites missing the
//! `CREATE_NO_WINDOW` creation flag, each causing a brief CMD/console
//! window to pop up when the daemon (running as SYSTEM) invoked
//! `freshclam.exe`, `icacls.exe`, `wevtutil.exe`, `reg.exe`, or a sibling
//! worker binary. The user-visible result was a flock of ghost windows
//! during every signature reload.
//!
//! Phase 1 of the v0.1.7 engine-hot-swap work centralises this so future
//! `Command::new` sites cannot drift. Pattern:
//!
//! ```ignore
//! use crate::win_process::QuietCommand;
//!
//! let child = Command::new(&worker)
//!     .args(["--foo", "--bar"])
//!     .stdout(Stdio::piped())
//!     .stderr(Stdio::piped())
//!     .quiet_windows()   // <-- applies CREATE_NO_WINDOW on Windows
//!     .spawn()?;
//! ```
//!
//! The trait is a no-op on non-Windows so call sites stay
//! platform-portable without `#[cfg(target_os = "windows")]` blocks.

/// `CREATE_NO_WINDOW` from Win32 process creation flags. Child runs with
/// no console allocated; pipes still work for stdout/stderr.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `DETACHED_PROCESS` from Win32 process creation flags. Child detaches
/// from any inherited console and does not allocate a new one. Reserved
/// for spawn-and-forget daemons (the supervisor's daemon spawn already
/// uses this); not needed for the wait-on-completion children covered by
/// `quiet_windows`.
#[allow(dead_code)]
pub const DETACHED_PROCESS: u32 = 0x0000_0008;

/// Builder-pattern extension that stamps the right Windows flags on a
/// `Command` to suppress ghost console windows. Returns the same `&mut
/// Command` so it chains naturally with the rest of the builder.
///
/// `&mut Command` (rather than the owned `Command`) is what the standard
/// builder methods return, so this slots in anywhere `.args(...)` does.
pub trait QuietCommand {
    fn quiet_windows(&mut self) -> &mut Self;
}

impl QuietCommand for std::process::Command {
    #[cfg(target_os = "windows")]
    fn quiet_windows(&mut self) -> &mut Self {
        use std::os::windows::process::CommandExt;
        self.creation_flags(CREATE_NO_WINDOW)
    }

    #[cfg(not(target_os = "windows"))]
    fn quiet_windows(&mut self) -> &mut Self {
        self
    }
}

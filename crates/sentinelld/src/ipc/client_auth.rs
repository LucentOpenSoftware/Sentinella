//! Per-connection client authentication for the IPC named pipe.
//!
//! Background: the `ipc_secret` file is granted `BUILTIN\Users (R)` so the
//! unelevated GUI of any logged-in user can read it. That makes the shared
//! secret a weak boundary between local users — anyone logged in could read it
//! and drive the SYSTEM daemon. This module adds a SECOND, independent gate:
//! on each pipe connection the daemon resolves the *connecting process's*
//! identity (SID, session, elevation) from the OS and authorizes only the
//! interactive console user (or an elevated/SYSTEM caller). The secret is
//! thereby demoted to an anti-CSRF nonce rather than the sole authority.
//!
//! Design for safety (this sits on the critical IPC accept path):
//!   * The *policy* (`decide`) is a pure function — fully unit-tested.
//!   * The *resolution* (`resolve_client`) is thin unsafe FFI that returns
//!     `None` on ANY error, and the caller treats `None` as **fail-open**
//!     (allow + warn). A transient API quirk must never brick the GUI↔daemon
//!     channel (WORKING_STATE "DO NOT BREAK" invariant). We only ever
//!     fail-CLOSED on a *positive* deny from a successfully-resolved identity.

/// Identity of a connecting pipe client, resolved from its process token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    /// String SID of the token user (e.g. `S-1-5-21-...`).
    pub sid: String,
    /// Windows session ID the client process runs in (0 = services session).
    pub session_id: u32,
    /// Token is elevated (admin).
    pub is_elevated: bool,
    /// Token user is NT AUTHORITY\SYSTEM (`S-1-5-18`).
    pub is_system: bool,
    /// SID is a well-known untrusted principal (Anonymous / Null).
    pub well_known_untrusted: bool,
}

/// Authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(&'static str),
}

/// Pure authorization policy. `active_console` is the physical console
/// session id (`None` if it can't be determined → callers fail-open).
///
/// Rules (first match wins):
///   1. Anonymous / Null SID            → Deny (never a legit GUI).
///   2. SYSTEM or elevated admin        → Allow (daemon helpers / admins,
///      including admins on RDP sessions).
///   3. Same session as the console     → Allow (the interactive user's GUI).
///   4. Different session, unprivileged  → Deny (another local/RDP user).
///   5. Console session unknown          → Allow (fail-open).
pub fn decide(id: &ClientIdentity, active_console: Option<u32>) -> Decision {
    if id.well_known_untrusted {
        return Decision::Deny("anonymous/null SID");
    }
    if id.is_system || id.is_elevated {
        return Decision::Allow;
    }
    match active_console {
        Some(console) if id.session_id == console => Decision::Allow,
        Some(_) => Decision::Deny("unprivileged caller in a non-console session"),
        None => Decision::Allow, // cannot determine console session → fail-open
    }
}

/// Stricter policy for **privileged-mutation methods** (everything on the
/// `is_challengeable_method` allowlist — protection.set_critical,
/// protection.disable/enable, settings.set, settings.set_full, sources.*,
/// engine.reload, argus.reload, quarantine.*).
///
/// v0.1.9 audit finding: the v0.1.8 connection-level [`decide`] allows
/// any unelevated interactive console user (rule 3 above) because the
/// `ipc_secret` file is intentionally `BUILTIN\Users:(R)` so the
/// unelevated GUI can do reads + status polling. That's fine for reads,
/// but for kill-vector mutations the GUI is supposed to bounce the user
/// through UAC first — and v0.1.7→v0.1.8 forgot to enforce that on the
/// daemon side. Any unelevated process running as the console user
/// (CLI, LOLBin, Office macro) could request a challenge token for
/// `protection.set_critical` and disable realtime / blank
/// `realtime_roots` without ever triggering UAC.
///
/// This function is the daemon-side gate that closes that hole.
/// Returns Allow only if the caller is elevated or SYSTEM.
///
/// Fail-open behaviour on `None`: if pipe-identity resolution failed at
/// connect time (`resolve_client` returned `None` and the WORKING_STATE
/// invariant kept the connection alive), we still allow — punishing a
/// legitimate elevated GUI for an OS API quirk would brick the only way
/// the user has to manage the daemon. The Deny path is for
/// *positively-resolved* unelevated callers only.
pub fn require_elevation(id: Option<&ClientIdentity>) -> Decision {
    match id {
        Some(i) if i.well_known_untrusted => Decision::Deny("anonymous/null SID"),
        Some(i) if i.is_system || i.is_elevated => Decision::Allow,
        Some(_) => Decision::Deny("kill-vector method requires elevated caller"),
        None => Decision::Allow, // pipe identity unresolved → fail-open
    }
}

// ─── New v0.1.9 entry point: authorize + return identity ───────────
//
// The original `authorize_pipe_client` returns `bool` and drops the
// resolved `ClientIdentity` — which is exactly the problem the audit
// flagged. This new entry point lets the caller plumb the identity
// through to the dispatcher so handler-level elevation checks
// (`require_elevation`) can run for every challengeable method.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeAuth {
    /// Connection allowed. `identity` is `Some` when resolution
    /// succeeded, `None` when it failed (fail-open path).
    Allow { identity: Option<ClientIdentity> },
    /// Positively-resolved unauthorized caller — connection must be
    /// closed without serving any requests.
    Deny,
}

/// Resolve + decide for a connected named-pipe handle, returning the
/// resolved [`ClientIdentity`] on Allow so the dispatcher can run
/// per-method elevation gates.
#[cfg(target_os = "windows")]
pub fn authorize_and_resolve_pipe_client(
    pipe: std::os::windows::io::RawHandle,
) -> PipeAuth {
    match resolve_client(pipe) {
        Some(id) => match decide(&id, active_console_session()) {
            Decision::Allow => PipeAuth::Allow {
                identity: Some(id),
            },
            Decision::Deny(reason) => {
                tracing::warn!(
                    sid = id.sid.as_str(),
                    session = id.session_id,
                    reason,
                    "IPC: rejected pipe client (per-connection SID check)"
                );
                PipeAuth::Deny
            }
        },
        None => {
            tracing::warn!(
                "IPC: could not resolve pipe client identity — allowing (fail-open), elevation gates will also fail-open for this connection"
            );
            PipeAuth::Allow { identity: None }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn authorize_and_resolve_pipe_client(
    _pipe: std::os::unix::io::RawFd,
) -> PipeAuth {
    PipeAuth::Allow { identity: None }
}

/// Resolve + decide for a connected named-pipe handle. Returns `true` to allow
/// the connection. On any resolution failure, fail-OPEN (allow + warn) so an
/// API quirk never bricks a legitimate GUI; only a positively-resolved Deny
/// rejects the connection.
#[cfg(target_os = "windows")]
pub fn authorize_pipe_client(pipe: std::os::windows::io::RawHandle) -> bool {
    match resolve_client(pipe) {
        Some(id) => match decide(&id, active_console_session()) {
            Decision::Allow => true,
            Decision::Deny(reason) => {
                tracing::warn!(
                    sid = id.sid.as_str(),
                    session = id.session_id,
                    reason,
                    "IPC: rejected pipe client (per-connection SID check)"
                );
                false
            }
        },
        None => {
            tracing::warn!(
                "IPC: could not resolve pipe client identity — allowing (fail-open)"
            );
            true
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn authorize_pipe_client(_pipe: std::os::unix::io::RawFd) -> bool {
    true
}

/// Active physical console session id, or `None` if unavailable
/// (`0xFFFFFFFF` means "no session attached").
#[cfg(target_os = "windows")]
fn active_console_session() -> Option<u32> {
    let s = unsafe { windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId() };
    if s == u32::MAX { None } else { Some(s) }
}

/// Resolve the connecting client's identity from the pipe handle. Returns
/// `None` on any failure (caller fails open).
#[cfg(target_os = "windows")]
fn resolve_client(pipe: std::os::windows::io::RawHandle) -> Option<ClientIdentity> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation,
        TokenSessionId, TokenUser,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let pipe_handle = HANDLE(pipe as *mut std::ffi::c_void);

        // 1. Connecting process id.
        let mut client_pid: u32 = 0;
        windows::Win32::System::Pipes::GetNamedPipeClientProcessId(pipe_handle, &mut client_pid)
            .ok()?;
        if client_pid == 0 {
            return None;
        }

        // 2. Open the process (limited) + its token.
        let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_pid).ok()?;
        // RAII-ish: ensure handles close on every return path.
        let mut token = HANDLE::default();
        let token_ok = OpenProcessToken(proc, TOKEN_QUERY, &mut token).is_ok();
        if !token_ok {
            let _ = CloseHandle(proc);
            return None;
        }

        let result = (|| {
            // 3. Token user SID.
            let mut len: u32 = 0;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
            if len == 0 {
                return None;
            }
            let mut buf = vec![0u8; len as usize];
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
                len,
                &mut len,
            )
            .ok()?;
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let sid_ptr = token_user.User.Sid;
            if sid_ptr.is_invalid() {
                return None;
            }

            // SID → string.
            let mut sid_pwstr = windows::core::PWSTR::null();
            ConvertSidToStringSidW(sid_ptr, &mut sid_pwstr).ok()?;
            let sid = sid_pwstr.to_string().unwrap_or_default();
            let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
                sid_pwstr.0 as *mut std::ffi::c_void,
            ));
            if sid.is_empty() {
                return None;
            }

            // 4. Session id.
            let mut session_id: u32 = 0;
            let mut sret: u32 = 0;
            let _ = GetTokenInformation(
                token,
                TokenSessionId,
                Some(&mut session_id as *mut u32 as *mut std::ffi::c_void),
                std::mem::size_of::<u32>() as u32,
                &mut sret,
            );

            // 5. Elevation.
            let mut elev = TOKEN_ELEVATION::default();
            let mut eret: u32 = 0;
            let is_elevated = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elev as *mut _ as *mut std::ffi::c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut eret,
            )
            .is_ok()
                && elev.TokenIsElevated != 0;

            let is_system = sid == "S-1-5-18";
            let well_known_untrusted = sid == "S-1-5-7" || sid == "S-1-0-0";

            Some(ClientIdentity {
                sid,
                session_id,
                is_elevated,
                is_system,
                well_known_untrusted,
            })
        })();

        let _ = CloseHandle(token);
        let _ = CloseHandle(proc);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(sid: &str, session: u32, elevated: bool) -> ClientIdentity {
        ClientIdentity {
            sid: sid.into(),
            session_id: session,
            is_elevated: elevated,
            is_system: sid == "S-1-5-18",
            well_known_untrusted: sid == "S-1-5-7" || sid == "S-1-0-0",
        }
    }

    #[test]
    fn anonymous_sid_denied() {
        assert_eq!(
            decide(&id("S-1-5-7", 1, false), Some(1)),
            Decision::Deny("anonymous/null SID")
        );
        assert_eq!(
            decide(&id("S-1-0-0", 1, false), Some(1)),
            Decision::Deny("anonymous/null SID")
        );
    }

    #[test]
    fn system_and_elevated_always_allowed() {
        // SYSTEM (e.g. daemon helper) regardless of session.
        assert_eq!(decide(&id("S-1-5-18", 0, false), Some(1)), Decision::Allow);
        // Elevated admin on a non-console session (RDP admin) still allowed.
        assert_eq!(
            decide(&id("S-1-5-21-1-2-3-1001", 2, true), Some(1)),
            Decision::Allow
        );
    }

    #[test]
    fn interactive_console_user_allowed() {
        assert_eq!(
            decide(&id("S-1-5-21-1-2-3-1001", 1, false), Some(1)),
            Decision::Allow
        );
    }

    #[test]
    fn unprivileged_non_console_session_denied() {
        // A different local/RDP user (session 2), not elevated, while the
        // console user is session 1 → rejected. This is the cross-user gate.
        assert_eq!(
            decide(&id("S-1-5-21-9-9-9-1055", 2, false), Some(1)),
            Decision::Deny("unprivileged caller in a non-console session")
        );
        // Unprivileged services-session (0) caller also rejected.
        assert_eq!(
            decide(&id("S-1-5-21-9-9-9-1055", 0, false), Some(1)),
            Decision::Deny("unprivileged caller in a non-console session")
        );
    }

    #[test]
    fn unknown_console_session_fails_open() {
        // Headless / RDP-only box where WTSGetActiveConsoleSessionId == -1.
        assert_eq!(
            decide(&id("S-1-5-21-1-2-3-1001", 3, false), None),
            Decision::Allow
        );
    }

    // ── v0.1.9: require_elevation gate for privileged mutations ──

    #[test]
    fn require_elevation_denies_unelevated_console_user() {
        // The exact case the audit flagged: a non-elevated process running
        // as the interactive console user has read the ipc_secret, opened
        // the pipe, and requested a protection.set_critical challenge
        // token. v0.1.7→v0.1.8 allowed this. v0.1.9 must reject it.
        let console_user = id("S-1-5-21-1-2-3-1001", 1, false);
        match require_elevation(Some(&console_user)) {
            Decision::Deny(_) => {} // expected
            Decision::Allow => panic!(
                "unelevated console user must be denied for kill-vector \
                 mutations; this is the v0.1.8 UAC-bypass regression"
            ),
        }
    }

    #[test]
    fn require_elevation_allows_elevated_admin_and_system() {
        let elevated_admin = id("S-1-5-21-1-2-3-1001", 1, true);
        let system = id("S-1-5-18", 0, false);
        assert_eq!(require_elevation(Some(&elevated_admin)), Decision::Allow);
        assert_eq!(require_elevation(Some(&system)), Decision::Allow);
    }

    #[test]
    fn require_elevation_denies_anonymous_even_if_marked_elevated() {
        // Anonymous SID is rejected ahead of the elevation check —
        // defence in depth against any future test/mock that constructs
        // an anonymous identity with is_elevated=true (impossible in
        // practice but the check should still hold).
        let anon = ClientIdentity {
            sid: "S-1-5-7".into(),
            session_id: 1,
            is_elevated: true,
            is_system: false,
            well_known_untrusted: true,
        };
        assert_eq!(
            require_elevation(Some(&anon)),
            Decision::Deny("anonymous/null SID")
        );
    }

    #[test]
    fn require_elevation_fails_open_on_unresolved_identity() {
        // OS API quirk swallowed the peer identity at connect time.
        // We can't punish a legitimate elevated GUI for that — the
        // alternative is bricking the GUI↔daemon channel on hardware
        // where some token call misbehaves. Fail-open here matches the
        // WORKING_STATE invariant the rest of the module already follows.
        assert_eq!(require_elevation(None), Decision::Allow);
    }
}

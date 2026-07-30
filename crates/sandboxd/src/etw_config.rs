//! Pure, cross-platform session-config builder for sandboxd's private ETW
//! system-logger session — the F-1/C-1 fix, factored out of the FFI code so
//! the bit-level invariants are unit-testable on any platform.
//!
//! WHY this module exists (C-1): `EVENT_TRACE_PROPERTIES.EnableFlags` is
//! documented by Microsoft as valid *only for system loggers* —
//! "EnableFlags is only valid for system loggers, i.e. trace sessions that
//! are started using the EVENT_TRACE_SYSTEM_LOGGER_MODE logger mode flag,
//! the KERNEL_LOGGER_NAME session name, the SystemTraceControlGuid session
//! GUID, or the GlobalLoggerGuid session GUID" (EVENT_TRACE_PROPERTIES,
//! MS Learn). sandboxd's session previously set REAL_TIME mode only and
//! never assigned `Wnode.Guid`, so `StartTraceW` succeeded while the kernel
//! ignored the EnableFlags and delivered zero events on every detonation —
//! with `backend_used` still reporting `"etw_kernel_session"`.
//!
//! The doc-correct architecture ("Configuring and Starting a System Trace
//! Provider Session", MS Learn): private session name + `LogFileMode` |=
//! `EVENT_TRACE_SYSTEM_LOGGER_MODE` + `Wnode.Guid` = a NEW private GUID.
//! `Wnode.Guid` must NOT be `SystemTraceControlGuid` unless the session is
//! named "NT Kernel Logger" — StartTraceW fails with
//! `ERROR_INVALID_PARAMETER` otherwise. Do NOT "simplify" this by copying
//! the kernel-logger GUID here; that re-breaks the session.
//!
//! DEDUP FLAG (orchestrator): sentinelld's PLM intake
//! (`crates/sentinelld/src/plm/etw_intake.rs`, owned by a parallel agent
//! this round) and etw_probe build the same shape of config. Once both
//! sides land, the shared builder belongs in
//! `sentinella_common::etw_props` next to `EventTracePropsStorage` so the
//! three call sites cannot drift again. Until then this module is
//! sandboxd-local by design — editing sentinelld is out of scope.

/// `EVENT_TRACE_REAL_TIME_MODE` — events are consumed via OpenTraceW
/// callbacks instead of written to an .etl file.
pub const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x0000_0100;

/// `EVENT_TRACE_SYSTEM_LOGGER_MODE` — promotes the session to a system
/// logger so the kernel honors `EnableFlags`. THE flag whose absence
/// caused C-1 (session starts, zero events, no error anywhere).
pub const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x0200_0000;

/// `WNODE_FLAG_TRACED_GUID` — events are delivered as trace GUIDs
/// (required for the classic kernel MOF providers the callback parses).
pub const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;

/// QPC timestamps (Wnode.ClientContext = 1).
pub const CLIENT_CONTEXT_QPC: u32 = 1;

// ── Kernel EnableFlags ───────────────────────────────────────────
// Each flag MUST correspond to a provider the EVENT_RECORD callback in
// `etw.rs` actually parses (contract-tested in this crate — see
// `etw::tests::every_parsed_provider_has_an_enable_flag`); setting a flag
// nobody parses wastes kernel buffer bandwidth, and parsing a provider
// whose flag is missing silently disables that detector.
pub const EVENT_TRACE_FLAG_PROCESS: u32 = 0x0000_0001; // PROCESS_GUID, opcode 1
pub const EVENT_TRACE_FLAG_IMAGE_LOAD: u32 = 0x0000_0004; // IMAGE_GUID, opcode 10
pub const EVENT_TRACE_FLAG_NETWORK_TCPIP: u32 = 0x0001_0000; // TCPIP_GUID, opcodes 12/15
pub const EVENT_TRACE_FLAG_REGISTRY: u32 = 0x0002_0000; // REGISTRY_GUID, opcodes 22/23

/// Fixed private session GUID for the sandboxd system-logger session, in
/// `GUID::from_u128` byte order: `{8d2e6f41-3c5a-4b97-a2e8-5f1c9d4b6a03}`.
///
/// Generated once for this component; fixed (not per-run random) so
/// stale-session reclamation via the error-183 path and diagnostics stay
/// deterministic across detonations. MUST remain distinct from
/// sentinelld's PLM session GUID (see the contract test below): two live
/// sessions sharing a GUID collide, and there are only 8 system-logger
/// slots on Win8+ (2 reserved), so collisions are expensive.
pub const SESSION_GUID_U128: u128 = 0x8d2e6f41_3c5a_4b97_a2e8_5f1c9d4b6a03;

/// Private session name. Fixed so a stale session orphaned by a killed
/// sandboxd is always reclaimed by the ERROR_ALREADY_EXISTS (183)
/// stop-and-retry path in `etw.rs`.
pub const SESSION_NAME: &str = "SentinellaSandbox";

/// Everything `StartTraceW` needs beyond buffer layout (which
/// `EventTracePropsStorage` owns). Pure data — no windows-crate types — so
/// the invariants are testable off-Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemLoggerConfig {
    pub session_name: &'static str,
    /// `Wnode.Guid`, in `windows::core::GUID::from_u128` byte order.
    pub session_guid: u128,
    /// `LogFileMode` — REAL_TIME | SYSTEM_LOGGER_MODE, nothing else.
    pub log_file_mode: u32,
    /// `Wnode.Flags`.
    pub wnode_flags: u32,
    /// `Wnode.ClientContext`.
    pub client_context: u32,
    /// `EnableFlags` — kernel MOF provider bitmask (system loggers only).
    pub enable_flags: u32,
}

/// The one correct sandboxd session config. `etw.rs` applies this verbatim
/// on both the initial `StartTraceW` and the stale-session retry path.
pub fn sandbox_session_config() -> SystemLoggerConfig {
    SystemLoggerConfig {
        session_name: SESSION_NAME,
        session_guid: SESSION_GUID_U128,
        log_file_mode: EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE,
        wnode_flags: WNODE_FLAG_TRACED_GUID,
        client_context: CLIENT_CONTEXT_QPC,
        enable_flags: EVENT_TRACE_FLAG_PROCESS
            | EVENT_TRACE_FLAG_IMAGE_LOAD
            | EVENT_TRACE_FLAG_NETWORK_TCPIP
            | EVENT_TRACE_FLAG_REGISTRY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SystemTraceControlGuid` `{9e814aad-3204-11d2-9a82-006008a86939}` —
    /// reserved for sessions named "NT Kernel Logger". Using it with a
    /// private name makes StartTraceW fail with ERROR_INVALID_PARAMETER
    /// (StartTraceW, MS Learn). Forbidden here.
    const SYSTEM_TRACE_CONTROL_GUID_U128: u128 =
        0x9e814aad_3204_11d2_9a82_006008a86939;

    /// `GlobalLoggerGuid` `{def3fe10-3205-11d2-9a82-006008a86939}` —
    /// reserved for the boot-time Global Logger session. Forbidden.
    const GLOBAL_LOGGER_GUID_U128: u128 = 0xdef3fe10_3205_11d2_9a82_006008a86939;

    /// sentinelld PLM intake session GUID as LANDED this round in
    /// `crates/sentinelld/src/plm/etw_intake.rs` (`SESSION_GUID`,
    /// `{9c4b1e7a-3f2d-4a8c-b5e1-6d2f0a93c7d4}`).
    ///
    /// CROSS-CRATE CONTRACT: sandboxd's session GUID must never equal the
    /// daemon's — two same-GUID system loggers cannot coexist and each
    /// consumes one of 8 kernel slots. If sentinelld's constant changes,
    /// update this one to match (or better: move both GUIDs into
    /// sentinella_common — see DEDUP FLAG above).
    const SENTINELLD_PLM_SESSION_GUID_LANDED: u128 =
        0x9c4b1e7a_3f2d_4a8c_b5e1_6d2f0a93c7d4;

    #[test]
    fn log_file_mode_is_exactly_realtime_plus_system_logger() {
        let cfg = sandbox_session_config();
        assert_eq!(cfg.log_file_mode, 0x0000_0100 | 0x0200_0000);
        assert_ne!(cfg.log_file_mode & EVENT_TRACE_SYSTEM_LOGGER_MODE, 0,
            "C-1 regression guard: without SYSTEM_LOGGER_MODE the kernel \
             ignores EnableFlags and the session delivers zero events");
        assert_ne!(cfg.log_file_mode & EVENT_TRACE_REAL_TIME_MODE, 0);
    }

    #[test]
    fn enable_flags_cover_exactly_the_parsed_providers() {
        let cfg = sandbox_session_config();
        assert_eq!(
            cfg.enable_flags,
            0x0000_0001 | 0x0000_0004 | 0x0001_0000 | 0x0002_0000,
            "flags must match the etw.rs callback's parsed providers \
             (process/image-load/tcpip/registry) — drift here silently \
             disables a detector"
        );
    }

    #[test]
    fn session_guid_is_private_and_well_formed() {
        let cfg = sandbox_session_config();
        assert_ne!(cfg.session_guid, 0, "GUID_NULL means auto-generated");
        assert_ne!(
            cfg.session_guid, SYSTEM_TRACE_CONTROL_GUID_U128,
            "SystemTraceControlGuid with a private session name = \
             ERROR_INVALID_PARAMETER from StartTraceW"
        );
        assert_ne!(
            cfg.session_guid, GLOBAL_LOGGER_GUID_U128,
            "GlobalLoggerGuid is reserved for the boot-time Global Logger"
        );
    }

    #[test]
    fn session_guid_differs_from_sentinelld_landed_guid() {
        assert_ne!(
            SESSION_GUID_U128, SENTINELLD_PLM_SESSION_GUID_LANDED,
            "cross-component contract: sandboxd and sentinelld must not \
             share a system-logger session GUID"
        );
    }

    #[test]
    fn builder_is_consistent_with_constants() {
        let cfg = sandbox_session_config();
        assert_eq!(cfg.session_name, SESSION_NAME);
        assert_eq!(cfg.session_guid, SESSION_GUID_U128);
        assert_eq!(cfg.wnode_flags, WNODE_FLAG_TRACED_GUID);
        assert_eq!(cfg.client_context, CLIENT_CONTEXT_QPC);
    }
}

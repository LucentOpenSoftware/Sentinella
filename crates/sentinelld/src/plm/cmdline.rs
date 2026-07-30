//! Process command-line collection for PLM `ProcessNode`s.
//!
//! ## Why this module exists
//!
//! Before v0.1.12 every production `ProcessNode` was recorded with
//! `command_line: None` (ToolHelp32 doesn't carry it, and the kernel
//! `Process_TypeGroup1` ETW event layout does NOT include a command line —
//! its MOF fields stop at `ImageFileName`; a `CommandLine` field only
//! exists on the *manifest-based* `Microsoft-Windows-Kernel-Process`
//! provider and on security event 4688 with the command-line audit GPO,
//! neither of which the SentinellaPLM system-logger session consumes).
//! The four command-line-pivot WeedHack runtime signals
//! (`JavaSecurityUpdaterTask`, `UpdaterVbsLaunch`,
//! `DefenderDisableUnderJava`, `RunKeyFromJava`) therefore evaluated an
//! empty string on every production chain — dead even with a healthy ETW
//! stream.
//!
//! ## Source decision
//!
//! `NtQueryInformationProcess(ProcessCommandLineInformation)` (class 60):
//!
//! - **Kernel-mediated** — the kernel copies the command line out of the
//!   target's process parameters into OUR buffer. No `ReadProcessMemory`,
//!   no PEB walking, and therefore **no WOW64 problem** (a 64-bit service
//!   reading a 32-bit process PEB needs a second pointer layout — that
//!   entire failure class is avoided).
//! - **Bounded** — we pass a fixed-cap buffer (see
//!   `MAX_COMMAND_LINE_UTF16_UNITS`) and never allocate from the length
//!   the kernel reports beyond that cap.
//! - **Documented** — the function and class are documented on MS Learn
//!   (originally "undocumented" but stable since NT 3.x and documented
//!   since 2021).
//!
//! Rejected alternatives: direct PEB reading (WOW64 layout split, raw
//! cross-process pointer chasing — strictly more unsafe surface for zero
//! gain), WMI `Win32_Process` / `Get-CimInstance` (spawns a WmiPrvSe
//! round-trip per process start, seconds of latency under load — the
//! exact event-time-vs-late-query race this workstream exists to close;
//! the codebase's `ps_bridge` is a PowerShell *script-block* log reader,
//! not a process-query helper, so there was nothing to reuse).
//!
//! ## Threat model
//!
//! The command line is **attacker-controlled**: the creating process
//! supplies it verbatim, and the runtime process can rewrite its own PEB
//! copy afterwards. It is therefore NEVER identity (image path + signer
//! stay authoritative) and every read is treated as hostile input:
//!
//! - hard length cap (anything larger is `Malformed`, never a bigger
//!   allocation);
//! - the returned `UNICODE_STRING` header is validated field-by-field
//!   (even length, pointer inside our buffer, extent inside our buffer)
//!   before a single code unit is read;
//! - embedded NULs truncate (defense against smuggling a benign prefix in
//!   front of a hostile suffix);
//! - UTF-16 is decoded lossily only after all structural checks pass.
//!
//! Failure is NORMAL, not exceptional: PPL-protected processes, `System`,
//! `Registry`, `Memory Compression` and secure processes deny `OpenProcess`
//! even to a SYSTEM service, and short-lived processes exit between the
//! ETW event and our query. Those outcomes are first-class states
//! (`AccessDenied` / `ProcessExited`), counted in PLM diagnostics, and —
//! critically — are all treated by the detectors as "no data". No state
//! is ever collapsed into a fabricated empty-or-benign command line.
//!
//! ## Timing
//!
//! Collection happens at process-discovery time (ETW process-create
//! callback, snapshot-poll first sighting) — NOT lazily at scan time —
//! because WeedHack's persistence children (`schtasks.exe`, `reg.exe`,
//! `wscript.exe`) are short-lived: a query issued seconds later loses the
//! race against process exit and returns `ProcessExited`.

#![allow(dead_code)]

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum command-line length we accept, in UTF-16 code units.
///
/// `CreateProcessW` caps a Windows command line at 32,767 UTF-16 units
/// (≈64 KiB), so 32,768 units (64 KiB of UTF-16) can hold ANY legal
/// Windows command line — a claimed length beyond this cap is not a long
/// command line, it's a corrupt/hostile header, and is reported as
/// `Malformed` rather than triggering a larger allocation. The resulting
/// allocation ceiling is ~64 KiB per process-discovery event, bounded
/// regardless of input.
pub const MAX_COMMAND_LINE_UTF16_UNITS: usize = 32 * 1024;

/// Outcome of attempting to collect a process's command line.
///
/// Replaces the old `Option<String>` whose `None` silently collapsed
/// "not asked", "asked but refused", "process gone", "genuinely empty",
/// and "kernel response didn't validate" into one indistinguishable
/// value — which is how the WeedHack command-line signals ended up dead
/// with no telemetry explaining why. Every variant maps to exactly one
/// diagnostics counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandLineState {
    /// Collection was never attempted (no querier wired, non-Windows
    /// build, or the process was seen before this collector existed).
    NotCollected,
    /// An OS call failed with an unexpected status/Win32 code (the
    /// payload: NTSTATUS or Win32 error as u32). Unexpected codes land
    /// here rather than being guessed at.
    Failed(u32),
    /// `OpenProcess`/`NtQueryInformationProcess` was refused. NORMAL for
    /// PPL-protected and secure system processes — not an error.
    AccessDenied,
    /// The process exited between discovery and query (PID invalid, or
    /// `STATUS_PROCESS_IS_TERMINATING`). NORMAL for short-lived children.
    ProcessExited,
    /// Query succeeded; the process genuinely has no command line
    /// (zero-length). Distinct from "no data" — detectors may rely on it.
    Empty,
    /// The kernel response failed structural validation (odd byte length,
    /// pointer outside our buffer, extent beyond our buffer, claimed
    /// length beyond the cap). Never decoded, never trusted.
    Malformed,
    /// A validated, capped, decoded command line.
    Present(String),
}

impl CommandLineState {
    /// The command line IF AND ONLY IF it was actually collected.
    /// Every other state is "no data" and returns `None` — detectors must
    /// not treat missing data as an empty (benign) command line, and must
    /// never see a fabricated substitute.
    pub fn as_present(&self) -> Option<&str> {
        match self {
            CommandLineState::Present(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Stable machine-readable label for diagnostics/tests.
    pub fn label(&self) -> &'static str {
        match self {
            CommandLineState::NotCollected => "not_collected",
            CommandLineState::Failed(_) => "failed",
            CommandLineState::AccessDenied => "access_denied",
            CommandLineState::ProcessExited => "process_exited",
            CommandLineState::Empty => "empty",
            CommandLineState::Malformed => "malformed",
            CommandLineState::Present(_) => "present",
        }
    }
}

/// Truncated SHA-256 fingerprint (first 8 bytes, 16 lowercase hex chars)
/// of a command line. Correlation-grade: two findings that saw the same
/// command line share the fingerprint, but the raw text is unrecoverable.
fn redacted_fingerprint(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// PRIVACY: a raw command line NEVER serializes.
///
/// `CommandLineState` reaches JSON in exactly one structural way — as a
/// field of `ProcessNode`, serialized into `Finding::technical_detail`
/// (see `plm::lineage_finding`) — and findings are persisted to the
/// SQLite forensic DB and returned over IPC methods whose auth secret is
/// world-readable (BUILTIN\Users). Command lines routinely carry
/// credentials, tokens, and private paths, so the raw text must never
/// leave the daemon. Implementing `Serialize` MANUALLY (instead of
/// deriving) makes the redaction a property of the type: any present or
/// future serialization path — findings, diagnostics JSON, logs that
/// `{:?}`-free serialize a chain — gets the redacted form automatically.
///
/// Wire format:
///   - `Present(s)`  → `{"state":"present","len_utf16":N,"sha256_16":"…"}`
///     (length + truncated SHA-256 fingerprint for correlation; the GUI
///     displays this in place of the old raw string);
///   - `Failed(code)` → `{"state":"failed","code":N}` (the diagnostic code
///     is not sensitive and is kept);
///   - every other variant → its bare `label()` string.
impl Serialize for CommandLineState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            CommandLineState::Present(s) => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("state", "present")?;
                map.serialize_entry("len_utf16", &s.encode_utf16().count())?;
                map.serialize_entry("sha256_16", &redacted_fingerprint(s))?;
                map.end()
            }
            CommandLineState::Failed(code) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("state", "failed")?;
                map.serialize_entry("code", code)?;
                map.end()
            }
            other => serializer.serialize_str(other.label()),
        }
    }
}

/// Per-state telemetry for command-line collection. Owned by
/// `PlmDiagnostics` (surfaced under `command_line` in the PLM status
/// JSON) and shared with the querier, which increments exactly one
/// counter per `query()` call.
pub struct CommandLineDiagnostics {
    pub present: AtomicU64,
    pub access_denied: AtomicU64,
    pub process_exited: AtomicU64,
    pub failed: AtomicU64,
    pub empty: AtomicU64,
    pub malformed: AtomicU64,
    pub not_collected: AtomicU64,
}

impl CommandLineDiagnostics {
    pub fn new() -> Self {
        Self {
            present: AtomicU64::new(0),
            access_denied: AtomicU64::new(0),
            process_exited: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            empty: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            not_collected: AtomicU64::new(0),
        }
    }

    pub fn note(&self, state: &CommandLineState) {
        let counter = match state {
            CommandLineState::Present(_) => &self.present,
            CommandLineState::AccessDenied => &self.access_denied,
            CommandLineState::ProcessExited => &self.process_exited,
            CommandLineState::Failed(_) => &self.failed,
            CommandLineState::Empty => &self.empty,
            CommandLineState::Malformed => &self.malformed,
            CommandLineState::NotCollected => &self.not_collected,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total(&self) -> u64 {
        self.present.load(Ordering::Relaxed)
            + self.access_denied.load(Ordering::Relaxed)
            + self.process_exited.load(Ordering::Relaxed)
            + self.failed.load(Ordering::Relaxed)
            + self.empty.load(Ordering::Relaxed)
            + self.malformed.load(Ordering::Relaxed)
            + self.not_collected.load(Ordering::Relaxed)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "present": self.present.load(Ordering::Relaxed),
            "access_denied": self.access_denied.load(Ordering::Relaxed),
            "process_exited": self.process_exited.load(Ordering::Relaxed),
            "failed": self.failed.load(Ordering::Relaxed),
            "empty": self.empty.load(Ordering::Relaxed),
            "malformed": self.malformed.load(Ordering::Relaxed),
            "not_collected": self.not_collected.load(Ordering::Relaxed),
        })
    }
}

/// Narrow OS-boundary trait — the only seam the Windows API hides
/// behind. Matches the codebase's existing fake pattern
/// (`ModuleSignerVerifier` / `LineageResolver`): production installs the
/// NtQueryInformationProcess backend, tests install a scripted fake, and
/// all validation/telemetry logic runs against the trait so it's
/// exercisable without touching a live process.
pub trait CommandLineBackend: Send + Sync {
    fn query(&self, pid: u32) -> CommandLineState;
}

/// Production querier shared by both discovery paths (ETW callback via a
/// raw-pointer static, snapshot loop by reference). Wraps the backend and
/// records one telemetry observation per query so the PLM status surface
/// shows WHY command lines are missing when they are.
pub struct SharedCommandLineQuerier {
    backend: Box<dyn CommandLineBackend>,
    diagnostics: Arc<CommandLineDiagnostics>,
}

impl SharedCommandLineQuerier {
    /// Production constructor: NtQueryInformationProcess backend on
    /// Windows, a `NotCollected` null backend elsewhere.
    pub fn production(diagnostics: Arc<CommandLineDiagnostics>) -> Self {
        Self {
            backend: default_backend(),
            diagnostics,
        }
    }

    /// Test constructor: any scripted backend, real telemetry.
    #[cfg(test)]
    pub fn with_backend(
        backend: Box<dyn CommandLineBackend>,
        diagnostics: Arc<CommandLineDiagnostics>,
    ) -> Self {
        Self {
            backend,
            diagnostics,
        }
    }

    pub fn query(&self, pid: u32) -> CommandLineState {
        let state = self.backend.query(pid);
        self.diagnostics.note(&state);
        state
    }
}

/// Non-Windows / unwired backend: honest `NotCollected` — the detectors
/// see "no data", never an empty string.
struct NullBackend;

impl CommandLineBackend for NullBackend {
    fn query(&self, _pid: u32) -> CommandLineState {
        CommandLineState::NotCollected
    }
}

#[cfg(target_os = "windows")]
fn default_backend() -> Box<dyn CommandLineBackend> {
    Box::new(WindowsBackend)
}

#[cfg(not(target_os = "windows"))]
fn default_backend() -> Box<dyn CommandLineBackend> {
    Box::new(NullBackend)
}

// ─────────────────────────────────────────────────────────────────────
//  Pure parsing/validation — cross-platform so tests run anywhere
// ─────────────────────────────────────────────────────────────────────

/// Decode an already-validated slice of UTF-16 code units into a
/// `Present`/`Empty` state.
///
/// - Truncates at the first NUL unit: an embedded NUL is a classic
///   smuggling vector (benign-looking prefix, hostile tail past the
///   terminator a naive C-string reader would stop at — we stop too, but
///   deliberately, so the visible value is what a human would see).
/// - Caps at `MAX_COMMAND_LINE_UTF16_UNITS` (structural cap is enforced
///   earlier; this is belt-and-braces for direct callers).
/// - Lossy-decodes: a lone surrogate is replaced, never panics, never
///   fails — the structural guarantees came from validation upstream.
pub(crate) fn decode_command_line_units(units: &[u16]) -> CommandLineState {
    let nul_end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    let end = nul_end.min(MAX_COMMAND_LINE_UTF16_UNITS);
    if end == 0 {
        return CommandLineState::Empty;
    }
    let s = String::from_utf16_lossy(&units[..end]);
    if s.is_empty() {
        CommandLineState::Empty
    } else {
        CommandLineState::Present(s)
    }
}

/// Parse the `UNICODE_STRING` header + payload the kernel wrote into our
/// buffer for `ProcessCommandLineInformation`.
///
/// Pure and cross-platform: tests synthesize kernel responses as byte
/// buffers and drive every accept/reject branch without a live process.
///
/// Layout (both bitnesses): `Length u16 @0`, `MaximumLength u16 @2`,
/// padding to pointer alignment, `Buffer ptr @ size_of::<usize>()`,
/// struct size `2 * size_of::<usize>()`. Parsed field-by-field from raw
/// bytes — no struct punning, no alignment assumptions.
///
/// Rejections (`Malformed`, never decoded):
///   - header truncated;
///   - odd byte length (UTF-16 code units are 2 bytes);
///   - payload pointer or payload extent outside our buffer. The
///     allocation cap is enforced structurally — our buffer is fixed at
///     ~64 KiB, so any claimed extent that would exceed it fails here
///     rather than triggering a larger allocation.
///
/// A zero claimed length is a genuinely empty command line (`Empty`),
/// which IS a legitimate kernel result for some system processes.
pub(crate) fn parse_unicode_string_payload(buf: &[u8]) -> CommandLineState {
    let ptr_size = std::mem::size_of::<usize>();
    let us_size = 2 * ptr_size;
    if buf.len() < us_size {
        return CommandLineState::Malformed;
    }

    let length = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if length == 0 {
        return CommandLineState::Empty;
    }
    if length % 2 != 0 {
        return CommandLineState::Malformed;
    }

    let mut ptr_bytes = [0u8; 8];
    ptr_bytes[..ptr_size].copy_from_slice(&buf[ptr_size..2 * ptr_size]);
    let payload_ptr = usize::from_le_bytes(ptr_bytes);

    // The kernel must point back INTO our buffer (it copies the string
    // after the header). Validate the extent with checked arithmetic;
    // only then is slicing safe.
    let Some(offset) = payload_ptr.checked_sub(buf.as_ptr() as usize) else {
        return CommandLineState::Malformed;
    };
    let Some(end) = offset.checked_add(length) else {
        return CommandLineState::Malformed;
    };
    if end > buf.len() {
        return CommandLineState::Malformed;
    }

    let units: Vec<u16> = buf[offset..end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    decode_command_line_units(&units)
}

// ─────────────────────────────────────────────────────────────────────
//  Windows backend — NtQueryInformationProcess(ProcessCommandLineInformation)
// ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
struct WindowsBackend;

#[cfg(target_os = "windows")]
impl CommandLineBackend for WindowsBackend {
    fn query(&self, pid: u32) -> CommandLineState {
        query_command_line_nt(pid)
    }
}

#[cfg(target_os = "windows")]
fn query_command_line_nt(pid: u32) -> CommandLineState {
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL,
        STATUS_INFO_LENGTH_MISMATCH, STATUS_PROCESS_IS_TERMINATING,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const ERROR_ACCESS_DENIED_WIN32: u32 = 5;
    const ERROR_INVALID_PARAMETER_WIN32: u32 = 87;

    // Open with full query access first (documented requirement for
    // ProcessCommandLineInformation); on refusal retry with limited
    // access, which suffices on Win10 1607+ for PEB-derived classes and
    // is granted to SYSTEM for more processes. ERROR_INVALID_PARAMETER
    // from OpenProcess means the PID is already gone (exit race — NORMAL
    // for short-lived persistence children); ERROR_ACCESS_DENIED is the
    // PPL / secure-process case and is equally normal for a SYSTEM AV.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => {
            let code = unsafe { GetLastError() }.0;
            match code {
                ERROR_INVALID_PARAMETER_WIN32 => return CommandLineState::ProcessExited,
                ERROR_ACCESS_DENIED_WIN32 => {
                    match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
                        Ok(h) => h,
                        Err(_) => {
                            let code2 = unsafe { GetLastError() }.0;
                            return if code2 == ERROR_INVALID_PARAMETER_WIN32 {
                                CommandLineState::ProcessExited
                            } else {
                                CommandLineState::AccessDenied
                            };
                        }
                    }
                }
                other => return CommandLineState::Failed(other),
            }
        }
    };

    // RAII guard — same pattern as the snapshot guard in plm::mod: a
    // panic between open and close must not leak a kernel handle.
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    let _guard = HandleGuard(handle);

    let us_size = 2 * std::mem::size_of::<usize>();
    // Hard allocation ceiling: header + max legal command line + NUL.
    // Sized once; the kernel can never make us grow past it.
    let cap = us_size + MAX_COMMAND_LINE_UTF16_UNITS * 2 + 2;
    let mut buf: Vec<u8> = vec![0u8; us_size + 512];

    // Two-call pattern: first call returns BUFFER_TOO_SMALL /
    // INFO_LENGTH_MISMATCH with the required size in ReturnLength; grow
    // (within the cap) and retry. Bounded to 3 attempts — a kernel that
    // keeps moving the target is answered with Malformed, not a loop.
    for _ in 0..3 {
        let mut return_len: u32 = 0;
        // SAFETY: `buf` is a live, exclusively-owned Vec<u8> whose pointer
        // and exact length we pass; the kernel writes at most `buf.len()`
        // bytes. `return_len` is a live out-param. `handle` is a valid
        // process handle owned by `_guard` for the call's duration. No
        // pointers into `buf` outlive this statement — the UNICODE_STRING
        // header is re-parsed from raw bytes (never dereferenced) by
        // `parse_unicode_string_payload`, which validates every offset
        // against `buf.len()` before slicing.
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                ProcessCommandLineInformation,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                buf.len() as u32,
                &mut return_len,
            )
        };

        if status.is_ok() {
            return parse_unicode_string_payload(&buf);
        }
        if status == STATUS_PROCESS_IS_TERMINATING {
            return CommandLineState::ProcessExited;
        }
        if status == STATUS_ACCESS_DENIED {
            return CommandLineState::AccessDenied;
        }
        if status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH {
            let need = return_len as usize;
            if need > buf.len() && need <= cap {
                buf.resize(need, 0);
                continue;
            }
            // Required size exceeds the legal-command-line cap (or the
            // kernel contradicts itself): refuse to grow, call it what
            // it is.
            return CommandLineState::Malformed;
        }
        return CommandLineState::Failed(status.0 as u32);
    }
    CommandLineState::Malformed
}

// ─────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Scripted backend — the fake-half of the trait seam.
    struct FakeBackend {
        per_pid: HashMap<u32, CommandLineState>,
        default: CommandLineState,
    }

    impl CommandLineBackend for FakeBackend {
        fn query(&self, pid: u32) -> CommandLineState {
            self.per_pid
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| self.default.clone())
        }
    }

    /// Build a buffer exactly like the kernel would fill it:
    /// UNICODE_STRING header + UTF-16 payload (optionally NUL-terminated).
    fn kernel_response(units: &[u16], terminate: bool) -> Vec<u8> {
        let ptr_size = std::mem::size_of::<usize>();
        let us_size = 2 * ptr_size;
        let mut payload: Vec<u16> = units.to_vec();
        if terminate {
            payload.push(0);
        }
        let mut buf = vec![0u8; us_size + payload.len() * 2];
        let length = (units.len() * 2) as u16;
        let maximum = (payload.len() * 2) as u16;
        buf[0..2].copy_from_slice(&length.to_le_bytes());
        buf[2..4].copy_from_slice(&maximum.to_le_bytes());
        let payload_ptr = buf.as_ptr() as usize + us_size;
        buf[ptr_size..2 * ptr_size].copy_from_slice(&payload_ptr.to_le_bytes()[..ptr_size]);
        for (i, u) in payload.iter().enumerate() {
            buf[us_size + i * 2..us_size + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        buf
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn parses_terminated_command_line() {
        let buf = kernel_response(&wide("javaw.exe -jar Component.jar"), true);
        let state = parse_unicode_string_payload(&buf);
        assert_eq!(
            state,
            CommandLineState::Present("javaw.exe -jar Component.jar".into())
        );
    }

    #[test]
    fn parses_unterminated_command_line() {
        // The kernel does NOT guarantee a NUL terminator — Length rules.
        let buf = kernel_response(&wide("cmd.exe /c whoami"), false);
        let state = parse_unicode_string_payload(&buf);
        assert_eq!(
            state,
            CommandLineState::Present("cmd.exe /c whoami".into())
        );
    }

    #[test]
    fn zero_length_is_empty_not_malformed() {
        let buf = kernel_response(&[], false);
        assert_eq!(parse_unicode_string_payload(&buf), CommandLineState::Empty);
    }

    #[test]
    fn embedded_nul_truncates() {
        let buf = kernel_response(&wide("benign.exe\0evil -DisableRealtimeMonitoring"), true);
        let state = parse_unicode_string_payload(&buf);
        assert_eq!(state, CommandLineState::Present("benign.exe".into()));
    }

    #[test]
    fn odd_byte_length_is_malformed() {
        let mut buf = kernel_response(&wide("ab"), true);
        buf[0] = 3; // Length = 3 bytes — impossible for UTF-16.
        assert_eq!(parse_unicode_string_payload(&buf), CommandLineState::Malformed);
    }

    #[test]
    fn length_beyond_buffer_is_malformed_not_allocation() {
        // u16 Length maxes at 65535 bytes; our buffer holds far less than
        // that after the header, so a maxed-out claim must fail the
        // extent check — and must never cause a larger allocation.
        let mut buf = kernel_response(&wide("ab"), true);
        buf[0..2].copy_from_slice(&(u16::MAX - 1).to_le_bytes()); // keep it even
        assert_eq!(parse_unicode_string_payload(&buf), CommandLineState::Malformed);
    }

    #[test]
    fn pointer_outside_buffer_is_malformed() {
        let mut buf = kernel_response(&wide("x"), true);
        let ptr_size = std::mem::size_of::<usize>();
        let hostile = 0x4141_4141usize;
        buf[ptr_size..2 * ptr_size].copy_from_slice(&hostile.to_le_bytes()[..ptr_size]);
        assert_eq!(parse_unicode_string_payload(&buf), CommandLineState::Malformed);
    }

    #[test]
    fn extent_beyond_buffer_is_malformed() {
        let mut buf = kernel_response(&wide("ab"), true);
        buf[0..2].copy_from_slice(&4096u16.to_le_bytes()); // claims 2K units, buffer has 3
        assert_eq!(parse_unicode_string_payload(&buf), CommandLineState::Malformed);
    }

    #[test]
    fn truncated_header_is_malformed() {
        let buf = vec![0u8; 4];
        assert_eq!(parse_unicode_string_payload(&buf), CommandLineState::Malformed);
    }

    #[test]
    fn lone_surrogate_decodes_lossy_without_panic() {
        let buf = kernel_response(&[0x0061, 0xD800, 0x0062], true); // a <lone-high> b
        match parse_unicode_string_payload(&buf) {
            CommandLineState::Present(s) => assert_eq!(s.chars().count(), 3),
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn querier_counts_every_state_exactly_once() {
        let diag = Arc::new(CommandLineDiagnostics::new());
        let mut per_pid = HashMap::new();
        per_pid.insert(1, CommandLineState::Present("a.exe".into()));
        per_pid.insert(2, CommandLineState::AccessDenied);
        per_pid.insert(3, CommandLineState::ProcessExited);
        per_pid.insert(4, CommandLineState::Failed(0xC000_0005));
        per_pid.insert(5, CommandLineState::Empty);
        per_pid.insert(6, CommandLineState::Malformed);
        let querier = SharedCommandLineQuerier::with_backend(
            Box::new(FakeBackend {
                per_pid,
                default: CommandLineState::NotCollected,
            }),
            Arc::clone(&diag),
        );

        assert_eq!(
            querier.query(1),
            CommandLineState::Present("a.exe".into())
        );
        assert_eq!(querier.query(2), CommandLineState::AccessDenied);
        assert_eq!(querier.query(3), CommandLineState::ProcessExited);
        assert_eq!(querier.query(4), CommandLineState::Failed(0xC000_0005));
        assert_eq!(querier.query(5), CommandLineState::Empty);
        assert_eq!(querier.query(6), CommandLineState::Malformed);
        assert_eq!(querier.query(99), CommandLineState::NotCollected);

        assert_eq!(diag.present.load(Ordering::Relaxed), 1);
        assert_eq!(diag.access_denied.load(Ordering::Relaxed), 1);
        assert_eq!(diag.process_exited.load(Ordering::Relaxed), 1);
        assert_eq!(diag.failed.load(Ordering::Relaxed), 1);
        assert_eq!(diag.empty.load(Ordering::Relaxed), 1);
        assert_eq!(diag.malformed.load(Ordering::Relaxed), 1);
        assert_eq!(diag.not_collected.load(Ordering::Relaxed), 1);
        assert_eq!(diag.total(), 7);
    }

    #[test]
    fn null_backend_reports_not_collected() {
        let backend = NullBackend;
        assert_eq!(backend.query(1234), CommandLineState::NotCollected);
    }

    // ── serialization privacy (MEDIUM fix) ──────────────────────
    //
    // CommandLineState is serialized into Finding::technical_detail via
    // ProcessNode → persisted to the forensic DB and returned over IPC.
    // The raw command line must NEVER appear in any serialized form.

    #[test]
    fn present_serializes_redacted_never_raw() {
        let secret = "net use \\\\srv\\c$ /user:admin Sup3rSecretToken=abc123";
        let state = CommandLineState::Present(secret.to_string());
        let json = serde_json::to_string(&state).unwrap();
        assert!(
            !json.contains("Sup3rSecretToken"),
            "raw secret leaked into serialized state: {json}"
        );
        assert!(!json.contains(secret), "raw cmdline leaked: {json}");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["state"], "present");
        assert_eq!(
            v["len_utf16"].as_u64().unwrap() as usize,
            secret.encode_utf16().count()
        );
        let fp = v["sha256_16"].as_str().unwrap();
        assert_eq!(fp.len(), 16, "truncated SHA-256 must be 8 bytes hex");
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        // Correlation property: same input → same fingerprint, different
        // input → different fingerprint.
        let again = serde_json::to_string(&CommandLineState::Present(secret.to_string())).unwrap();
        assert!(again.contains(fp));
        let other = serde_json::to_string(&CommandLineState::Present("other.exe".into())).unwrap();
        assert!(!other.contains(fp));
    }

    #[test]
    fn non_present_states_serialize_without_content() {
        // Unit variants: bare label. Failed: label + (non-sensitive) code.
        assert_eq!(
            serde_json::to_string(&CommandLineState::NotCollected).unwrap(),
            "\"not_collected\""
        );
        assert_eq!(
            serde_json::to_string(&CommandLineState::AccessDenied).unwrap(),
            "\"access_denied\""
        );
        assert_eq!(
            serde_json::to_string(&CommandLineState::ProcessExited).unwrap(),
            "\"process_exited\""
        );
        assert_eq!(
            serde_json::to_string(&CommandLineState::Empty).unwrap(),
            "\"empty\""
        );
        assert_eq!(
            serde_json::to_string(&CommandLineState::Malformed).unwrap(),
            "\"malformed\""
        );
        let failed = serde_json::to_string(&CommandLineState::Failed(5)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&failed).unwrap();
        assert_eq!(v["state"], "failed");
        assert_eq!(v["code"], 5);
    }

    #[test]
    fn as_present_is_some_only_for_present() {
        assert_eq!(
            CommandLineState::Present("x".into()).as_present(),
            Some("x")
        );
        for s in [
            CommandLineState::NotCollected,
            CommandLineState::Failed(5),
            CommandLineState::AccessDenied,
            CommandLineState::ProcessExited,
            CommandLineState::Empty,
            CommandLineState::Malformed,
        ] {
            assert_eq!(s.as_present(), None, "{} must be 'no data'", s.label());
        }
    }

    #[test]
    fn diagnostics_json_lists_all_states() {
        let diag = CommandLineDiagnostics::new();
        diag.note(&CommandLineState::Present("x".into()));
        diag.note(&CommandLineState::AccessDenied);
        let j = diag.to_json();
        for key in [
            "present",
            "access_denied",
            "process_exited",
            "failed",
            "empty",
            "malformed",
            "not_collected",
        ] {
            assert!(j.get(key).is_some(), "missing key {key}");
        }
        assert_eq!(j["present"], 1);
        assert_eq!(j["access_denied"], 1);
    }

    // ── adversarial sweeps (workstreams X+Y) ────────────────────
    //
    // The UNICODE_STRING parser consumes attacker-controlled bytes (a
    // process supplies its own command line). These tests pin totality
    // against seeded deterministic sweeps and replay the committed
    // cargo-fuzz seed corpus through the SAME rebase convention the
    // `cmdline_decode` fuzz target uses (no cargo-fuzz required).
    //
    // Rebase convention: the parser requires the payload pointer to be an
    // absolute address inside the buffer, which a byte string cannot
    // carry. Harnesses therefore interpret the pointer field as a
    // RELATIVE offset and rebase it: ptr = buf.as_ptr() + (rel % len).
    // This keeps every validation branch reachable from bytes alone.

    /// xorshift64* — deterministic, no rand crate, no thread_rng.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            let mut v = Vec::with_capacity(n);
            while v.len() < n {
                v.extend_from_slice(&self.next().to_le_bytes());
            }
            v.truncate(n);
            v
        }
    }

    /// Rebase the pointer field of a raw buffer per the convention above.
    fn rebase_pointer(buf: &mut [u8]) {
        let ptr_size = std::mem::size_of::<usize>();
        if buf.len() < 2 * ptr_size {
            return; // parser will call it Malformed on its own
        }
        let mut rel_bytes = [0u8; 8];
        rel_bytes[..ptr_size].copy_from_slice(&buf[ptr_size..2 * ptr_size]);
        let rel = usize::from_le_bytes(rel_bytes) % buf.len();
        let abs = buf.as_ptr() as usize + rel;
        buf[ptr_size..2 * ptr_size].copy_from_slice(&abs.to_le_bytes()[..ptr_size]);
    }

    /// The post-conditions every parse outcome must satisfy.
    fn assert_state_invariants(state: &CommandLineState) {
        if let CommandLineState::Present(s) = state {
            assert!(
                s.encode_utf16().count() <= MAX_COMMAND_LINE_UTF16_UNITS,
                "present value exceeds the structural cap"
            );
            assert!(!s.is_empty(), "empty string must be Empty, not Present");
            assert!(!s.contains('\0'), "embedded NUL must have truncated");
        }
    }

    /// Seeded sweep: arbitrary byte buffers (rebased) through the
    /// UNICODE_STRING parser — never panics, outcome always a valid state.
    #[test]
    fn seeded_sweep_parse_never_panics() {
        let mut rng = XorShift(0xCD10_0BAD_F00D_1234);
        for i in 0..2048 {
            let len = (rng.next() % 512) as usize;
            let mut buf = rng.bytes(len);
            // Every fourth buffer gets a plausible-looking header so the
            // deep validation branches (extent checks, decode) are hit.
            if i % 4 == 0 && buf.len() >= 2 * std::mem::size_of::<usize>() + 8 {
                let claimed = (rng.next() % 700) as u16;
                buf[0..2].copy_from_slice(&claimed.to_le_bytes());
            }
            rebase_pointer(&mut buf);
            let state = parse_unicode_string_payload(&buf);
            assert_state_invariants(&state);
        }
    }

    /// Seeded sweep: arbitrary UTF-16 unit sequences through the decoder —
    /// lone surrogates, NUL runs, cap-length inputs; never panics.
    #[test]
    fn seeded_sweep_decode_units_never_panics() {
        let mut rng = XorShift(0xDEC0_DE11_5EED_A55E);
        for _ in 0..2048 {
            let n = (rng.next() % 600) as usize;
            let mut units = Vec::with_capacity(n);
            for _ in 0..n {
                // Bias toward interesting code units: NULs and surrogates.
                units.push(match rng.next() % 4 {
                    0 => 0,
                    1 => 0xD800 + (rng.next() % 0x800) as u16, // surrogate range
                    _ => rng.next() as u16,
                });
            }
            let state = decode_command_line_units(&units);
            assert_state_invariants(&state);
            // Deterministic truncation contract: the visible value never
            // extends past the first NUL unit.
            if let (CommandLineState::Present(s), Some(nul)) =
                (&state, units.iter().position(|&u| u == 0))
            {
                let prefix: String = String::from_utf16_lossy(&units[..nul]);
                assert_eq!(*s, prefix);
            }
        }
    }

    /// Replay the committed cargo-fuzz seed corpus for `cmdline_decode`
    /// through the same rebase convention + entry point. Seeds come from
    /// fuzz/tools/gen_framework_corpus.py (deterministic). Exact outcome
    /// expectations are x64-layout-specific (16-byte header); the no-panic
    /// + invariants replay runs on every platform.
    #[test]
    fn seed_corpus_replays_cleanly() {
        let seeds: [&[u8]; 5] = [
            include_bytes!("../../../../fuzz/corpus/cmdline_decode/seed00-valid-terminated.bin"),
            include_bytes!("../../../../fuzz/corpus/cmdline_decode/seed01-embedded-nul.bin"),
            include_bytes!("../../../../fuzz/corpus/cmdline_decode/seed02-odd-length.bin"),
            include_bytes!("../../../../fuzz/corpus/cmdline_decode/seed03-extent-past-buffer.bin"),
            include_bytes!("../../../../fuzz/corpus/cmdline_decode/seed04-random.bin"),
        ];
        let mut states = Vec::new();
        for raw in seeds {
            let mut buf = raw.to_vec();
            rebase_pointer(&mut buf);
            let state = parse_unicode_string_payload(&buf);
            assert_state_invariants(&state);
            states.push(state);
        }

        if std::mem::size_of::<usize>() == 8 {
            assert_eq!(
                states[0],
                CommandLineState::Present("javaw.exe -jar Component.jar".into())
            );
            assert_eq!(states[1], CommandLineState::Present("benign.exe".into()));
            assert_eq!(states[2], CommandLineState::Malformed, "odd byte length");
            assert_eq!(states[3], CommandLineState::Malformed, "extent past buffer");
        }
    }
}

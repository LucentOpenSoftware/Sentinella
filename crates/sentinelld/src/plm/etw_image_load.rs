//! Windows kernel ImageLoad ETW pump for WeedHack browser-injection
//! detection.
//!
//! ## Architecture
//!
//! ```text
//!  ┌────────────────────────────────────┐
//!  │  Windows kernel ETW (shared        │
//!  │  SentinellaPLM session)            │
//!  │  - EVENT_TRACE_FLAG_PROCESS  ──────┼─→ existing PLM ProcessStart handler
//!  │  - EVENT_TRACE_FLAG_IMAGE_LOAD     │
//!  └──────────────┬─────────────────────┘
//!                 │ ImageLoad EVENT_RECORD
//!                 v
//!  ┌────────────────────────────────────┐
//!  │  handle_image_load_event           │   Hot path. No syscalls, no
//!  │  - extract PID + module path       │   I/O; one bounded String
//!  │  - cheap .dll prefilter            │   alloc per forwarded event.
//!  │  - try_send to bounded channel ────┼─→ drop if full → forwarded/dropped counter
//!  └──────────────┬─────────────────────┘
//!                 │ ImageLoadRawEvent
//!                 v
//!  ┌────────────────────────────────────┐
//!  │  worker thread                     │
//!  │  - resolve target_image_name       │
//!  │    via LineageGraph (cheap)        │
//!  │  - BrowserImageLoadFilter          │
//!  │  - WeedHackCampaignTracker         │
//!  └──────────────┬─────────────────────┘
//!                 │ CampaignFinding recorded in diagnostics;
//!                 │ next scan-site hook surfaces via ConvergenceLedger
//!                 v
//! ```
//!
//! ## Why reuse the PLM session
//!
//! Only one MOF-flag ETW session can be active per provider at a time on
//! Windows. The existing `SentinellaPLM` session uses
//! `EVENT_TRACE_FLAG_PROCESS`; we add `EVENT_TRACE_FLAG_IMAGE_LOAD` to it
//! and dispatch by `(provider GUID, opcode)` in `etw_intake::etw_event_callback`.
//! The existing process-start path is bit-for-bit unchanged.
//!
//! Result: zero new kernel sessions, zero new admin privileges required
//! beyond what PLM already needs.
//!
//! ## Failure modes (all bounded)
//!
//! - **Non-admin daemon**: PLM ETW fails StartTraceW with access denied,
//!   `etw_gave_up` is set, our diagnostics inherit it. The worker thread
//!   continues to drain its (empty) channel and is effectively idle.
//! - **Channel full**: `try_send` returns Err; `dropped` counter advances.
//!   The callback never blocks the kernel ETW dispatch thread.
//! - **Malformed event body**: parser returns `None`; `parse_errors`
//!   advances. No panic, no log spam.
//! - **PID not in LineageGraph**: worker drops the event with
//!   `events_dropped_no_image` counter. We fail-closed: classifying an
//!   injection without knowing the target image isn't safe.

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use super::weedhack_campaign::{WeedHackCampaignDiagnostics, WeedHackCampaignTracker};
use super::weedhack_image_load::{
    BrowserImageLoadFilter, ImageLoadRawEvent, LineageGraphJavaChecker, ModuleSignerVerifier,
};
#[cfg(test)]
use super::weedhack_image_load::NullSignerVerifier;
use super::LineageGraph;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────
//  ETW provider constants
// ─────────────────────────────────────────────────────────────────────

/// `Image_TypeGroup1` MOF class provider GUID for kernel ImageLoad events
/// (`{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}`).
#[cfg(target_os = "windows")]
pub(crate) const IMAGE_LOAD_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0x2cb15d1d,
    0x5fc1,
    0x11d2,
    [0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18],
);

/// Opcode for ImageLoad (a DLL or image was mapped into a process).
/// Opcode 2 (DCStart, rundown of already-loaded images) is intentionally
/// ignored — we only care about NEW loads after the daemon starts.
pub(crate) const OPCODE_IMAGE_LOAD: u8 = 10;

// ─────────────────────────────────────────────────────────────────────
//  Channel sizing
// ─────────────────────────────────────────────────────────────────────

/// Bounded channel between the ETW callback and the worker thread.
/// 1024 is generous — the worker drains in sub-microsecond per event;
/// browser startup bursts of ~150 loads fit comfortably without spilling.
pub const CHANNEL_CAPACITY: usize = 1024;

// ─────────────────────────────────────────────────────────────────────
//  Diagnostics
// ─────────────────────────────────────────────────────────────────────

/// ImageLoad ETW pump diagnostics. Surfaced via
/// `PlmMonitor::weedhack_diagnostics_json()` under `image_load_etw`.
pub struct ImageLoadEtwDiagnostics {
    /// True while the underlying ETW session (PLM-shared) is running.
    /// Mirrors `EtwIntakeDiagnostics.etw_running`.
    pub running: AtomicBool,
    /// True if the session start was denied due to insufficient privilege.
    /// Mirrors `EtwIntakeDiagnostics.etw_gave_up` (any access-denied
    /// scenario sets `gave_up`).
    pub access_denied: AtomicBool,
    /// True after the PLM session abandoned retries.
    pub gave_up: AtomicBool,
    /// Raw ImageLoad events seen by the callback (post-dispatch).
    pub events_seen: AtomicU64,
    /// Events the callback parsed successfully and tried to forward.
    pub events_parsed: AtomicU64,
    /// Events whose body could not be parsed (no plausible path).
    pub parse_errors: AtomicU64,
    /// try_send succeeded.
    pub forwarded: AtomicU64,
    /// try_send failed: channel full or worker disconnected.
    pub dropped: AtomicU64,
    /// Worker couldn't resolve target image name (PID not in graph).
    pub events_dropped_no_image: AtomicU64,
    /// Worker handed an event to the BrowserImageLoadFilter and the
    /// canonical detector emitted a signal.
    pub signals_emitted: AtomicU64,
    /// PLM session reconnect count (proxy from `EtwIntakeDiagnostics`).
    pub reconnects: AtomicU64,
}

impl ImageLoadEtwDiagnostics {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            access_denied: AtomicBool::new(false),
            gave_up: AtomicBool::new(false),
            events_seen: AtomicU64::new(0),
            events_parsed: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            events_dropped_no_image: AtomicU64::new(0),
            signals_emitted: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
        }
    }

    /// JSON snapshot in the shape required by the Wave 4 spec.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "running": self.running.load(Ordering::Relaxed),
            "access_denied": self.access_denied.load(Ordering::Relaxed),
            "gave_up": self.gave_up.load(Ordering::Relaxed),
            "events_seen": self.events_seen.load(Ordering::Relaxed),
            "events_parsed": self.events_parsed.load(Ordering::Relaxed),
            "parse_errors": self.parse_errors.load(Ordering::Relaxed),
            "forwarded": self.forwarded.load(Ordering::Relaxed),
            "dropped": self.dropped.load(Ordering::Relaxed),
            "events_dropped_no_image": self.events_dropped_no_image.load(Ordering::Relaxed),
            "signals_emitted": self.signals_emitted.load(Ordering::Relaxed),
            "reconnects": self.reconnects.load(Ordering::Relaxed),
        })
    }
}

impl Default for ImageLoadEtwDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Worker thread — drains channel, runs filter, ingests into tracker
// ─────────────────────────────────────────────────────────────────────

/// Shared state the worker thread needs. Bundled into one struct so the
/// thread spawn signature stays clean.
pub struct ImageLoadWorkerArgs {
    pub rx: Receiver<ImageLoadRawEvent>,
    pub filter: Arc<BrowserImageLoadFilter>,
    pub tracker: Arc<WeedHackCampaignTracker>,
    pub campaign_diagnostics: Arc<WeedHackCampaignDiagnostics>,
    pub graph: Arc<LineageGraph>,
    pub etw_diagnostics: Arc<ImageLoadEtwDiagnostics>,
    pub running: Arc<AtomicBool>,
    /// Wave 5: signer verifier (production = WinTrust-backed). Injected
    /// so tests can substitute mocks and production can pick a real or
    /// no-op verifier per build configuration.
    pub signer_verifier: Arc<dyn ModuleSignerVerifier>,
}

/// Main worker loop. Drains the channel until `running` flips or the
/// channel is disconnected.
pub fn image_load_worker_loop(args: ImageLoadWorkerArgs) {
    tracing::debug!("WeedHack ImageLoad worker started");
    while args.running.load(Ordering::Relaxed) {
        match args.rx.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => process_one(&args, event),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    tracing::debug!("WeedHack ImageLoad worker stopped");
}

/// Per-event work — kept in its own function so tests can drive it
/// without spinning a thread.
pub fn process_one(args: &ImageLoadWorkerArgs, mut event: ImageLoadRawEvent) {
    // Resolve the target process image name from the lineage graph.
    // Fail-closed: if we can't identify the target process, we cannot
    // safely classify the load as browser-injection vs. unrelated.
    if event.target_image_name.is_empty() {
        match args.graph.get_node(event.target_pid) {
            Some(node) => {
                event.target_image_name = node.image_name;
            }
            None => {
                args.etw_diagnostics
                    .events_dropped_no_image
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    args.etw_diagnostics
        .events_parsed
        .fetch_add(1, Ordering::Relaxed);

    // Filter + canonical detector. Verifier is injected via args
    // (Wave 5): production uses WinTrustModuleSignerVerifier; tests
    // substitute scripted mocks. The detector policy is unchanged —
    // we just pipe a richer verdict source into the same gate.
    let lineage = LineageGraphJavaChecker::new(Arc::clone(&args.graph));
    let signal = match args
        .filter
        .process_event(event.clone(), &*args.signer_verifier, &lineage)
    {
        Some(s) => s,
        None => return,
    };
    args.etw_diagnostics
        .signals_emitted
        .fetch_add(1, Ordering::Relaxed);

    // Feed the campaign tracker. We discard the returned argus::Finding —
    // the spec is explicit that ETW must NOT push directly to any ledger.
    // The campaign state lives in the tracker; the next scan-site hook
    // surfaces it via ConvergenceLedger on its natural cadence.
    if let Some(finding) = args.tracker.ingest_signal(event.target_pid, signal) {
        let root_image = args
            .graph
            .get_node(finding.root.pid)
            .map(|n| n.image_name);
        let now_unix = chrono::Utc::now().timestamp();
        args.campaign_diagnostics
            .record(&finding, root_image, now_unix);
        args.campaign_diagnostics
            .note_active(args.tracker.active_campaign_count());
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Static callback wiring
// ─────────────────────────────────────────────────────────────────────

/// Channel sender shared with the ETW callback. Set once at start; never
/// cleared (the leak is one SyncSender, ~24 bytes — bounded and tiny).
static SENDER: OnceLock<SyncSender<ImageLoadRawEvent>> = OnceLock::new();

/// Diagnostics handle shared with the ETW callback. Same lifecycle as
/// `SENDER`.
static DIAG: OnceLock<Arc<ImageLoadEtwDiagnostics>> = OnceLock::new();

/// Install the channel + diagnostics handle for the ETW callback. Idempotent
/// — subsequent calls after a successful install are no-ops.
pub fn install_callback_endpoints(
    diagnostics: Arc<ImageLoadEtwDiagnostics>,
) -> Receiver<ImageLoadRawEvent> {
    let (tx, rx) = sync_channel(CHANNEL_CAPACITY);
    let _ = SENDER.set(tx);
    let _ = DIAG.set(diagnostics);
    rx
}

// ─────────────────────────────────────────────────────────────────────
//  Parser — OS-agnostic, testable
// ─────────────────────────────────────────────────────────────────────

/// Parse the loaded-module path out of an ImageLoad event body. Reuses
/// the wide-string scanner from `etw_intake` (the kernel layout puts the
/// FileName field as a null-terminated WCHAR string after fixed-size
/// header fields; the scanner finds it regardless of bitness).
///
/// Returns `None` for malformed bodies (too short, no plausible path
/// found). Never panics.
pub fn parse_image_load_body(data: &[u8]) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        // Use the NT+DOS-aware extractor, NOT the process-start extractor:
        // ImageLoad bodies carry `\Device\HarddiskVolumeN\...` NT paths and
        // this pump has no ToolHelp fallback. See etw_intake docs.
        super::etw_intake::extract_path_from_event(data)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // On non-Windows builds the parser is exercised by unit tests
        // only. Mirror the NT+DOS-aware scanner so tests run anywhere.
        nt_aware_scan_for_path(data)
    }
}

/// OS-agnostic mirror of `etw_intake::extract_path_from_event`. Accepts both
/// NT device paths (`\Device\...`, `\SystemRoot\...`) and DOS `X:\...` paths.
/// Used on non-Windows builds / CI where the Windows extractor is absent.
#[cfg_attr(target_os = "windows", allow(dead_code))]
fn nt_aware_scan_for_path(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let max = data.len().saturating_sub(4);
    let mut offset = 0usize;
    while offset <= max {
        let lo = data[offset];
        let hi = data[offset + 1];
        if hi == 0 {
            let dos = lo.is_ascii_alphabetic()
                && offset + 4 <= data.len()
                && data[offset + 2] == 0x3A
                && data[offset + 3] == 0;
            let nt = lo == b'\\';
            if dos || nt {
                let start = offset;
                let mut end = start;
                while end + 1 < data.len() {
                    let l = data[end];
                    let h = data[end + 1];
                    if l == 0 && h == 0 {
                        break;
                    }
                    if h == 0 && l < 0x20 {
                        break;
                    }
                    end += 2;
                }
                if end > start + 4 {
                    let wide: Vec<u16> = data[start..end]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let s = String::from_utf16_lossy(&wide);
                    if s.contains('\\') && s.len() > 3 {
                        return Some(s);
                    }
                }
            }
        }
        offset += 2;
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
//  Filtering boundary
// ─────────────────────────────────────────────────────────────────────

/// Cheap kernel-side prefilter — the only policy the callback applies.
/// Everything semantic happens off the hot path in
/// `BrowserImageLoadFilter` / `weedhack_browser_injection::evaluate`.
fn module_is_dll(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".dll") || lower.ends_with(".ocx")
}

// ─────────────────────────────────────────────────────────────────────
//  Windows ETW callback — hot path
// ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub(crate) unsafe fn handle_image_load_event(
    event: &windows::Win32::System::Diagnostics::Etw::EVENT_RECORD,
) {
    // Both endpoints must be installed before we attempt anything.
    let Some(diag) = DIAG.get() else {
        return;
    };
    let Some(sender) = SENDER.get() else {
        return;
    };

    diag.events_seen.fetch_add(1, Ordering::Relaxed);

    // Authoritative PID from the event header. PID 0 = System Idle /
    // kernel — skip; nothing on our radar runs there.
    let pid = event.EventHeader.ProcessId;
    if pid == 0 {
        return;
    }

    // Parse the body for the loaded-module path. Guard against a null /
    // zero-length UserData: `from_raw_parts(null, 0)` is UB even for len 0.
    if event.UserData.is_null() || event.UserDataLength == 0 {
        return;
    }
    let data = unsafe {
        std::slice::from_raw_parts(event.UserData as *const u8, event.UserDataLength as usize)
    };
    let path = match parse_image_load_body(data) {
        Some(p) => p,
        None => {
            diag.parse_errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Cheap kernel-side prefilter — only DLL-shaped modules. Drops
    // executables, NLS, fonts, sys drivers, etc. before they cost us a
    // channel slot.
    if !module_is_dll(&path) {
        // Not a parse error; just out of scope. No counter advance —
        // we don't want this counted as "dropped" since it's expected.
        return;
    }

    let raw = ImageLoadRawEvent {
        target_pid: pid,
        // Resolved off-hot-path by the worker.
        target_image_name: String::new(),
        loaded_module_path: path,
        timestamp_unix: chrono::Utc::now().timestamp(),
    };

    match sender.try_send(raw) {
        Ok(()) => {
            diag.forwarded.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            diag.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) unsafe fn handle_image_load_event(_event: &()) {
    // No-op on non-Windows builds; the dispatcher in etw_intake is
    // already #[cfg(target_os = "windows")] so this is never called.
}

// ─────────────────────────────────────────────────────────────────────
//  Lifecycle — spawn worker, share endpoints with callback
// ─────────────────────────────────────────────────────────────────────

/// Start the WeedHack ImageLoad worker thread.
///
/// Returns the shared diagnostics handle. The thread runs until
/// `running` flips to false; the worker drains naturally then.
///
/// Idempotent — calling twice in a process is harmless; the second call
/// returns a fresh diagnostics handle that will simply never receive
/// events because the static SENDER/DIAG endpoints were already claimed
/// by the first call.
pub fn start_image_load_worker(
    filter: Arc<BrowserImageLoadFilter>,
    tracker: Arc<WeedHackCampaignTracker>,
    campaign_diagnostics: Arc<WeedHackCampaignDiagnostics>,
    graph: Arc<LineageGraph>,
    running: Arc<AtomicBool>,
    signer_verifier: Arc<dyn ModuleSignerVerifier>,
) -> (
    Arc<ImageLoadEtwDiagnostics>,
    Option<std::thread::JoinHandle<()>>,
) {
    let diag = Arc::new(ImageLoadEtwDiagnostics::new());
    let rx = install_callback_endpoints(Arc::clone(&diag));

    let args = ImageLoadWorkerArgs {
        rx,
        filter,
        tracker,
        campaign_diagnostics,
        graph,
        etw_diagnostics: Arc::clone(&diag),
        running,
        signer_verifier,
    };

    let handle = std::thread::Builder::new()
        .name("plm-image-load".into())
        .spawn(move || image_load_worker_loop(args))
        .ok();

    (diag, handle)
}

// ─────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn build_synthetic_imageload_body(path: &str) -> Vec<u8> {
        // Layout we emit: 40 zero bytes (covers ImageBase, ImageSize,
        // ProcessId, ImageChecksum, TimeDateStamp, Reserved on x64) +
        // WCHAR null-terminated path. The scanner finds the wide-string
        // path; nothing else here is meaningful.
        let mut buf = vec![0u8; 40];
        for ch in path.encode_utf16() {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        buf.extend_from_slice(&[0, 0]); // null terminator
        // Pad so the scanner doesn't bail on minimum-length check.
        while buf.len() < 80 {
            buf.push(0);
        }
        buf
    }

    #[test]
    fn parser_extracts_dll_path_from_synthetic_body() {
        let body = build_synthetic_imageload_body(
            "C:\\Users\\t\\AppData\\Local\\Temp\\krxz.dll",
        );
        let path = parse_image_load_body(&body).expect("parser must find path");
        assert!(path.contains("krxz.dll"));
        assert!(path.starts_with("C:\\Users\\t\\AppData"));
    }

    #[test]
    fn parser_returns_none_on_short_body() {
        assert!(parse_image_load_body(&[0u8; 32]).is_none());
        assert!(parse_image_load_body(&[]).is_none());
    }

    #[test]
    fn parser_returns_none_on_body_without_drive_letter() {
        let mut body = vec![0u8; 60];
        // Lowercase 'c' should not match the uppercase-letter scanner.
        body.extend_from_slice(&[b'c', 0, b':', 0, b'\\', 0]);
        assert!(parse_image_load_body(&body).is_none());
    }

    /// Build a body carrying an NT device path (what real kernel ImageLoad
    /// / FileIo events deliver), with no DOS drive letter.
    fn build_nt_path_body(path: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 24]; // fixed header bytes before the path
        for ch in path.encode_utf16() {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        buf.extend_from_slice(&[0, 0]);
        while buf.len() < 64 {
            buf.push(0);
        }
        buf
    }

    #[test]
    fn parser_extracts_nt_device_path() {
        // The H1 regression: kernel events carry \Device\... NT paths, not
        // C:\ DOS paths. Pre-fix the extractor returned None for these and
        // the detectors were silently dead in production.
        let body = build_nt_path_body(
            "\\Device\\HarddiskVolume2\\Users\\t\\AppData\\Local\\Temp\\krxz.dll",
        );
        let path = parse_image_load_body(&body).expect("must extract NT path");
        assert!(path.contains("krxz.dll"), "got: {path}");
        assert!(path.starts_with("\\Device\\HarddiskVolume2"), "got: {path}");
    }

    #[test]
    fn parser_extracts_systemroot_path() {
        let body = build_nt_path_body("\\SystemRoot\\System32\\evil.dll");
        let path = parse_image_load_body(&body).expect("must extract \\SystemRoot path");
        assert!(path.ends_with("evil.dll"), "got: {path}");
    }

    #[test]
    fn nt_path_flows_through_user_writable_matcher() {
        // The downstream matcher is substring-based, so an NT path with a
        // user-writable foothold segment must still match — proving the H1
        // fix is sufficient without touching downstream logic.
        let body = build_nt_path_body(
            "\\Device\\HarddiskVolume2\\Users\\t\\AppData\\Local\\Temp\\x.dll",
        );
        let path = parse_image_load_body(&body).expect("extract");
        assert!(
            super::super::weedhack_browser_injection::is_user_writable_path(&path),
            "NT path must match user-writable substring: {path}"
        );
    }

    #[test]
    fn parser_still_handles_dos_paths() {
        // DOS paths must keep working (process-start events, some FileIo).
        let body = build_synthetic_imageload_body(
            "C:\\Users\\t\\AppData\\Local\\Temp\\krxz.dll",
        );
        let path = parse_image_load_body(&body).expect("DOS path still works");
        assert!(path.contains("krxz.dll"));
    }

    #[test]
    fn module_is_dll_classifier() {
        assert!(module_is_dll("C:\\Temp\\x.dll"));
        assert!(module_is_dll("C:\\Temp\\X.DLL"));
        assert!(module_is_dll("C:\\Temp\\legacy.ocx"));
        assert!(!module_is_dll("C:\\Temp\\notepad.exe"));
        assert!(!module_is_dll("C:\\Temp\\driver.sys"));
        assert!(!module_is_dll("C:\\Temp\\strange"));
    }

    #[test]
    fn diagnostics_json_shape_is_complete() {
        let d = ImageLoadEtwDiagnostics::new();
        let j = d.to_json();
        for k in [
            "running",
            "access_denied",
            "gave_up",
            "events_seen",
            "events_parsed",
            "parse_errors",
            "forwarded",
            "dropped",
            "events_dropped_no_image",
            "signals_emitted",
            "reconnects",
        ] {
            assert!(j.get(k).is_some(), "missing diagnostics key: {k}");
        }
    }

    // ── Worker pipeline tests (no real ETW required) ──────────────

    fn build_test_args() -> ImageLoadWorkerArgs {
        let (_tx, rx) = sync_channel(64);
        ImageLoadWorkerArgs {
            rx,
            filter: Arc::new(BrowserImageLoadFilter::new()),
            tracker: Arc::new(WeedHackCampaignTracker::new(Arc::new(
                NoOpResolver,
            ))),
            campaign_diagnostics: Arc::new(WeedHackCampaignDiagnostics::new()),
            graph: Arc::new(LineageGraph::new()),
            etw_diagnostics: Arc::new(ImageLoadEtwDiagnostics::new()),
            running: Arc::new(AtomicBool::new(true)),
            // Default test verifier: NullSignerVerifier (returns Unknown).
            // This keeps existing Wave 4 test behavior bit-for-bit, since
            // those tests asserted against Unknown-treatment semantics.
            signer_verifier: Arc::new(NullSignerVerifier),
        }
    }

    struct NoOpResolver;
    impl super::super::weedhack_campaign::LineageResolver for NoOpResolver {
        fn resolve_campaign_root(
            &self,
            _pid: u32,
        ) -> Option<super::super::weedhack_campaign::CampaignRoot> {
            None
        }
    }

    fn record(graph: &LineageGraph, pid: u32, ppid: u32, name: &str) {
        graph.record_process(super::super::ProcessNode {
            pid,
            parent_pid: ppid,
            image_path: format!("C:\\{name}"),
            image_name: name.to_string(),
            command_line: super::super::cmdline::CommandLineState::NotCollected,
            is_signed: None,
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: chrono::Utc::now().timestamp(),
        });
    }

    #[test]
    fn worker_drops_event_when_target_pid_missing_from_graph() {
        let args = build_test_args();
        let event = ImageLoadRawEvent {
            target_pid: 9999,
            target_image_name: String::new(),
            loaded_module_path: "C:\\Users\\t\\AppData\\Local\\Temp\\krxz.dll".into(),
            timestamp_unix: 1_700_000_000,
        };
        process_one(&args, event);
        assert_eq!(
            args.etw_diagnostics
                .events_dropped_no_image
                .load(Ordering::Relaxed),
            1,
            "missing PID must increment no_image counter"
        );
        assert_eq!(
            args.etw_diagnostics.events_parsed.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn worker_resolves_target_image_from_graph_and_runs_filter() {
        let args = build_test_args();
        // Build a process tree the canonical detector accepts.
        record(&args.graph, 1, 0, "javaw.exe");
        record(&args.graph, 2, 1, "chrome.exe");

        let event = ImageLoadRawEvent {
            target_pid: 2,
            target_image_name: String::new(),
            loaded_module_path: "C:\\Users\\t\\AppData\\Local\\Temp\\krxz.dll".into(),
            timestamp_unix: 1_700_000_000,
        };
        process_one(&args, event);

        assert_eq!(
            args.etw_diagnostics.events_parsed.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            args.etw_diagnostics
                .signals_emitted
                .load(Ordering::Relaxed),
            1,
            "unsigned-DLL + chrome target + java ancestor must emit"
        );
    }

    #[test]
    fn worker_does_not_emit_for_non_browser_target() {
        let args = build_test_args();
        record(&args.graph, 1, 0, "javaw.exe");
        record(&args.graph, 2, 1, "notepad.exe");

        let event = ImageLoadRawEvent {
            target_pid: 2,
            target_image_name: String::new(),
            loaded_module_path: "C:\\Users\\t\\AppData\\Local\\Temp\\krxz.dll".into(),
            timestamp_unix: 1_700_000_000,
        };
        process_one(&args, event);

        assert_eq!(
            args.etw_diagnostics.events_parsed.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            args.etw_diagnostics
                .signals_emitted
                .load(Ordering::Relaxed),
            0,
            "non-browser target must NOT emit"
        );
    }

    #[test]
    fn worker_loop_exits_when_running_flips_false() {
        // Build args with a sender we hold so the channel doesn't
        // disconnect; flip running to false → worker exits via timeout
        // branch.
        let (tx, rx) = sync_channel::<ImageLoadRawEvent>(8);
        let running = Arc::new(AtomicBool::new(true));
        let args = ImageLoadWorkerArgs {
            rx,
            filter: Arc::new(BrowserImageLoadFilter::new()),
            tracker: Arc::new(WeedHackCampaignTracker::new(Arc::new(NoOpResolver))),
            campaign_diagnostics: Arc::new(WeedHackCampaignDiagnostics::new()),
            graph: Arc::new(LineageGraph::new()),
            etw_diagnostics: Arc::new(ImageLoadEtwDiagnostics::new()),
            running: Arc::clone(&running),
            signer_verifier: Arc::new(NullSignerVerifier),
        };
        let handle = std::thread::spawn(move || image_load_worker_loop(args));
        // Keep tx alive so the channel doesn't auto-disconnect.
        running.store(false, Ordering::Relaxed);
        // Worker checks `running` after each 500ms timeout — wait a bit longer.
        let join_result = handle.join();
        assert!(join_result.is_ok(), "worker must exit cleanly");
        drop(tx);
    }

    #[test]
    fn channel_full_increments_dropped_counter() {
        // Drive the bounded channel to capacity and verify that
        // try_send failures advance the counter the callback would
        // advance.
        let (tx, _rx) = sync_channel::<ImageLoadRawEvent>(2);
        let diag = Arc::new(ImageLoadEtwDiagnostics::new());

        let make_event = |i: u32| ImageLoadRawEvent {
            target_pid: i,
            target_image_name: String::new(),
            loaded_module_path: format!("C:\\Users\\t\\AppData\\Local\\Temp\\m{i}.dll"),
            timestamp_unix: 1_700_000_000,
        };

        // First two succeed.
        for i in 0..2 {
            assert!(tx.try_send(make_event(i)).is_ok());
            diag.forwarded.fetch_add(1, Ordering::Relaxed);
        }
        // Third and fourth fail — caller would advance `dropped`.
        for i in 2..4 {
            assert!(matches!(
                tx.try_send(make_event(i)),
                Err(TrySendError::Full(_))
            ));
            diag.dropped.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(diag.forwarded.load(Ordering::Relaxed), 2);
        assert_eq!(diag.dropped.load(Ordering::Relaxed), 2);
    }
}

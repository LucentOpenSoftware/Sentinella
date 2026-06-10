//! Windows kernel FileIO ETW pump for WeedHack wallet-harvest detection.
//!
//! ## Architecture (mirrors Wave 4 ImageLoad pump)
//!
//! ```text
//!  ┌────────────────────────────────────┐
//!  │  Shared SentinellaPLM ETW session  │
//!  │  flags |= EVENT_TRACE_FLAG_FILE_IO_INIT
//!  └──────────────┬─────────────────────┘
//!                 │  FileIo_Create EVENT_RECORD
//!                 v
//!  ┌────────────────────────────────────┐
//!  │  handle_file_io_event              │  Hot path. Aggressive
//!  │  - PID != 0                        │  source-side filtering:
//!  │  - parse wide-string path          │  ~99% of file opens drop
//!  │  - case-insensitive substring scan │  HERE before allocating
//!  │    against wallet markers          │  a channel slot.
//!  │  - rate limit + try_send           │
//!  └──────────────┬─────────────────────┘
//!                 │  FileIoRawEvent (path retained briefly in
//!                 │  memory, never logged, never persisted)
//!                 v
//!  ┌────────────────────────────────────┐
//!  │  Worker thread                     │
//!  │  - resolve target image (graph)    │
//!  │  - canonical_key → store key       │
//!  │    (paths become "chromium:login-data"
//!  │     etc — full path discarded)     │
//!  │  - WalletHarvestDetector           │
//!  │  - if Burst signal:                │
//!  │      WeedHackCampaignTracker       │
//!  └────────────────────────────────────┘
//! ```
//!
//! ## Privacy posture
//!
//! Full file paths are **never** stored in diagnostics, never logged. The
//! callback holds a path long enough to do a substring filter; the worker
//! holds it long enough to canonicalize it; both drop the raw string
//! immediately afterwards. Only `canonical_key` static strings
//! (`"chromium:login-data"`, `"discord:leveldb"`, …) appear in any
//! persistent counter or diagnostics surface.
//!
//! ## Why FileIo_Create and not Read?
//!
//! Classic-MOF FileIo Read events carry only a `FileObject` pointer — you
//! need a parallel FileIo_Name event stream to map pointer → path. That
//! doubles the kernel event volume and adds a per-FileObject map to the
//! callback. FileIo_Create events carry the path inline, fire once per
//! handle open, and provide functionally-equivalent visibility for our
//! purpose (WalletHarvestDetector counts distinct stores per PID, not
//! per individual read).

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use super::weedhack_campaign::{WeedHackCampaignDiagnostics, WeedHackCampaignTracker};
use super::weedhack_wallet_harvest::WalletHarvestDetector;
use super::LineageGraph;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────────────

/// `FileIo` MOF class kernel provider GUID for classic NT-Kernel-Logger
/// file-IO events (`{90cbdc39-4a3e-11d1-84f4-0000f80464e3}`).
#[cfg(target_os = "windows")]
pub(crate) const FILE_IO_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0x90cbdc39,
    0x4a3e,
    0x11d1,
    [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
);

/// Opcode for FileIo_Create — fires when a file handle is opened. The
/// path is embedded inline in the event payload, unlike FileIo_Read
/// events which only carry the FileObject pointer.
pub(crate) const OPCODE_FILE_CREATE: u8 = 64;

/// Bounded channel between the ETW callback and the worker. Higher than
/// ImageLoad's because callback-side filtering already collapses the
/// raw event torrent to a trickle — channel capacity exists for burst
/// absorption during actual wallet-harvest activity.
pub const CHANNEL_CAPACITY: usize = 2048;

/// Forwarding rate cap for the callback. Wallet-store opens on a clean
/// box are single-digit/sec; an active stealer touching all stores is
/// still well under this cap.
pub const MAX_FORWARDS_PER_SEC: u32 = 256;

/// Wallet/credential path markers the callback uses for case-insensitive
/// substring matching. Kept short and prefix-ordered most-common-first
/// so the typical clean-box load (no matches) short-circuits fast.
/// **Privacy note**: these markers are NOT logged with paths; only the
/// canonical-key resolution downstream is visible.
const WALLET_PATH_MARKERS: &[&str] = &[
    // Chromium-family browser credential stores (chrome / edge / brave /
    // opera / vivaldi all live under "user data").
    "\\user data\\",
    // Firefox profile dir.
    "\\mozilla\\firefox\\profiles\\",
    // Chromium extension settings (catches MetaMask / Phantom / etc).
    "\\local extension settings\\",
    // Desktop wallets.
    "\\exodus\\",
    "\\atomic\\",
    "\\electrum\\wallets\\",
    "\\bitcoin\\wallet.dat",
    "\\ethereum\\keystore\\",
    "\\daedalus\\wallets\\",
    "\\atomicwallet",
    // Messaging tokens.
    "\\discord\\local storage\\leveldb",
    "\\discordcanary\\local storage\\leveldb",
    "\\discordptb\\local storage\\leveldb",
    "\\telegram desktop\\tdata\\",
    // Steam sessions.
    "\\config\\loginusers.vdf",
    "\\config\\config.vdf",
    // Minecraft session theft (Stage 1).
    "\\.minecraft\\launcher_accounts.json",
    "\\.minecraft\\launcher_profiles.json",
    "\\.minecraft\\usercache.json",
];

// ─────────────────────────────────────────────────────────────────────
//  Raw event type — what the callback emits, the worker consumes
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FileIoRawEvent {
    pub pid: u32,
    pub path: String,
    pub timestamp_unix: i64,
}

// ─────────────────────────────────────────────────────────────────────
//  Diagnostics
// ─────────────────────────────────────────────────────────────────────

pub struct FileIoEtwDiagnostics {
    pub running: AtomicBool,
    pub access_denied: AtomicBool,
    pub gave_up: AtomicBool,
    /// Raw FileIo_Create events seen by the callback.
    pub events_seen: AtomicU64,
    /// Path parsed out of the event body successfully.
    pub events_parsed: AtomicU64,
    /// Callback-side wallet-marker substring filter mismatch — dropped.
    pub events_filtered: AtomicU64,
    /// Body parse failed.
    pub parse_errors: AtomicU64,
    /// try_send succeeded.
    pub forwarded: AtomicU64,
    /// try_send failed (channel full or worker disconnected).
    pub dropped: AtomicU64,
    /// Worker resolved a canonical wallet store key.
    pub wallet_store_hits: AtomicU64,
    /// Worker observed a WalletHarvestBurst from the detector.
    pub burst_signals: AtomicU64,
    /// Worker accepted an event but detector returned None
    /// (already-seen-store, below-threshold, or non-javaw process).
    pub deduped: AtomicU64,
    /// Callback rate-limit drops.
    pub rate_limited: AtomicU64,
    /// Worker couldn't resolve the target image name from the graph.
    pub events_dropped_no_image: AtomicU64,
    /// Shared-session reconnect proxy from `EtwIntakeDiagnostics`.
    pub reconnects: AtomicU64,
}

impl FileIoEtwDiagnostics {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            access_denied: AtomicBool::new(false),
            gave_up: AtomicBool::new(false),
            events_seen: AtomicU64::new(0),
            events_parsed: AtomicU64::new(0),
            events_filtered: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            wallet_store_hits: AtomicU64::new(0),
            burst_signals: AtomicU64::new(0),
            deduped: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            events_dropped_no_image: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "running": self.running.load(Ordering::Relaxed),
            "access_denied": self.access_denied.load(Ordering::Relaxed),
            "gave_up": self.gave_up.load(Ordering::Relaxed),
            "events_seen": self.events_seen.load(Ordering::Relaxed),
            "events_parsed": self.events_parsed.load(Ordering::Relaxed),
            "events_filtered": self.events_filtered.load(Ordering::Relaxed),
            "parse_errors": self.parse_errors.load(Ordering::Relaxed),
            "forwarded": self.forwarded.load(Ordering::Relaxed),
            "dropped": self.dropped.load(Ordering::Relaxed),
            "wallet_store_hits": self.wallet_store_hits.load(Ordering::Relaxed),
            "burst_signals": self.burst_signals.load(Ordering::Relaxed),
            "deduped": self.deduped.load(Ordering::Relaxed),
            "rate_limited": self.rate_limited.load(Ordering::Relaxed),
            "events_dropped_no_image": self.events_dropped_no_image.load(Ordering::Relaxed),
            "reconnects": self.reconnects.load(Ordering::Relaxed),
            "max_forwards_per_sec": MAX_FORWARDS_PER_SEC,
            "channel_capacity": CHANNEL_CAPACITY,
        })
    }
}

impl Default for FileIoEtwDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Aggressive substring filter — callback's only policy
// ─────────────────────────────────────────────────────────────────────

/// Case-insensitive substring match against the wallet-marker list.
/// Allocates one lowercased copy of the path. Public so it's also
/// callable from the worker for the defensive double-check.
pub fn path_looks_walletish(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    WALLET_PATH_MARKERS.iter().any(|m| lower.contains(m))
}

// ─────────────────────────────────────────────────────────────────────
//  Rate limit state
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct RateState {
    window_start: Instant,
    count: u32,
}

static RATE_STATE: OnceLock<Mutex<RateState>> = OnceLock::new();

fn rate_state() -> &'static Mutex<RateState> {
    RATE_STATE.get_or_init(|| {
        Mutex::new(RateState {
            window_start: Instant::now(),
            count: 0,
        })
    })
}

fn allow_rate_at(now: Instant) -> bool {
    let m = rate_state();
    let mut rs = m.lock().unwrap_or_else(|e| e.into_inner());
    if now.duration_since(rs.window_start) >= Duration::from_secs(1) {
        rs.window_start = now;
        rs.count = 0;
    }
    if rs.count >= MAX_FORWARDS_PER_SEC {
        return false;
    }
    rs.count += 1;
    true
}

// ─────────────────────────────────────────────────────────────────────
//  Worker thread
// ─────────────────────────────────────────────────────────────────────

pub struct FileIoWorkerArgs {
    pub rx: Receiver<FileIoRawEvent>,
    pub detector: Arc<WalletHarvestDetector>,
    pub tracker: Arc<WeedHackCampaignTracker>,
    pub campaign_diagnostics: Arc<WeedHackCampaignDiagnostics>,
    pub graph: Arc<LineageGraph>,
    pub etw_diagnostics: Arc<FileIoEtwDiagnostics>,
    pub running: Arc<AtomicBool>,
}

pub fn file_io_worker_loop(args: FileIoWorkerArgs) {
    tracing::debug!("WeedHack FileIO worker started");
    while args.running.load(Ordering::Relaxed) {
        match args.rx.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => process_one(&args, event),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    tracing::debug!("WeedHack FileIO worker stopped");
}

/// Per-event processing. Path is held in the local stack only — never
/// stored beyond the canonicalization step.
pub fn process_one(args: &FileIoWorkerArgs, event: FileIoRawEvent) {
    // Resolve target image from the lineage graph. Fail-closed.
    let image_name = match args.graph.get_node(event.pid) {
        Some(node) => node.image_name,
        None => {
            args.etw_diagnostics
                .events_dropped_no_image
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Defensive double-check on the path: the callback's substring
    // filter is fast but coarse; this confirms the path really is a
    // recognized wallet store before we even talk to the detector.
    if !path_looks_walletish(&event.path) {
        return;
    }
    args.etw_diagnostics
        .wallet_store_hits
        .fetch_add(1, Ordering::Relaxed);

    // Feed the canonical detector. Path is dropped after this call.
    let signal = args
        .detector
        .observe_file_read(event.pid, &image_name, &event.path);

    match signal {
        Some(sig) => {
            args.etw_diagnostics
                .burst_signals
                .fetch_add(1, Ordering::Relaxed);
            if let Some(finding) = args.tracker.ingest_signal(event.pid, sig) {
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
        None => {
            // Detector accepted but didn't escalate: either below the
            // threshold, already-seen store for this PID, or process is
            // not javaw. All three are operationally "deduped".
            args.etw_diagnostics
                .deduped
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    args.etw_diagnostics
        .events_parsed
        .fetch_add(1, Ordering::Relaxed);
}

// ─────────────────────────────────────────────────────────────────────
//  Static callback wiring
// ─────────────────────────────────────────────────────────────────────

static SENDER: OnceLock<SyncSender<FileIoRawEvent>> = OnceLock::new();
static DIAG: OnceLock<Arc<FileIoEtwDiagnostics>> = OnceLock::new();

pub fn install_callback_endpoints(
    diagnostics: Arc<FileIoEtwDiagnostics>,
) -> Receiver<FileIoRawEvent> {
    let (tx, rx) = sync_channel(CHANNEL_CAPACITY);
    let _ = SENDER.set(tx);
    let _ = DIAG.set(diagnostics);
    rx
}

// ─────────────────────────────────────────────────────────────────────
//  Windows ETW callback — hot path
// ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub(crate) unsafe fn handle_file_io_event(
    event: &windows::Win32::System::Diagnostics::Etw::EVENT_RECORD,
) {
    let Some(diag) = DIAG.get() else {
        return;
    };
    let Some(sender) = SENDER.get() else {
        return;
    };

    diag.events_seen.fetch_add(1, Ordering::Relaxed);

    let pid = event.EventHeader.ProcessId;
    if pid == 0 {
        return;
    }

    // Guard against null / zero-length UserData (from_raw_parts UB).
    if event.UserData.is_null() || event.UserDataLength == 0 {
        return;
    }
    let data = unsafe {
        std::slice::from_raw_parts(event.UserData as *const u8, event.UserDataLength as usize)
    };
    // NT+DOS-aware extractor: FileIo_Create carries `\Device\...` NT paths.
    let path = match super::etw_intake::extract_path_from_event(data) {
        Some(p) => p,
        None => {
            diag.parse_errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    // NOTE: `events_parsed` is incremented once, in the worker's
    // `process_one` — not here — to avoid double-counting a single event
    // across the callback + worker stages. `forwarded` counts callback
    // successes.

    // ── Aggressive callback-side filter ──
    // Drops the vast majority of file opens BEFORE rate-limit or
    // try_send. Wallet-marker substring scan is fast on ASCII paths.
    if !path_looks_walletish(&path) {
        diag.events_filtered.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if !allow_rate_at(Instant::now()) {
        diag.rate_limited.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let raw = FileIoRawEvent {
        pid,
        path,
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
pub(crate) unsafe fn handle_file_io_event(_event: &()) {}

// ─────────────────────────────────────────────────────────────────────
//  Lifecycle
// ─────────────────────────────────────────────────────────────────────

pub fn start_file_io_worker(
    detector: Arc<WalletHarvestDetector>,
    tracker: Arc<WeedHackCampaignTracker>,
    campaign_diagnostics: Arc<WeedHackCampaignDiagnostics>,
    graph: Arc<LineageGraph>,
    running: Arc<AtomicBool>,
) -> (
    Arc<FileIoEtwDiagnostics>,
    Option<std::thread::JoinHandle<()>>,
) {
    let diag = Arc::new(FileIoEtwDiagnostics::new());
    let rx = install_callback_endpoints(Arc::clone(&diag));

    let args = FileIoWorkerArgs {
        rx,
        detector,
        tracker,
        campaign_diagnostics,
        graph,
        etw_diagnostics: Arc::clone(&diag),
        running,
    };

    let handle = std::thread::Builder::new()
        .name("plm-file-io".into())
        .spawn(move || file_io_worker_loop(args))
        .ok();

    (diag, handle)
}

// ─────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::weedhack_runtime::WeedHackSignal;
    use std::time::Instant;

    struct NoOpResolver;
    impl super::super::weedhack_campaign::LineageResolver for NoOpResolver {
        fn resolve_campaign_root(
            &self,
            _pid: u32,
        ) -> Option<super::super::weedhack_campaign::CampaignRoot> {
            None
        }
    }

    fn build_args() -> FileIoWorkerArgs {
        let (_tx, rx) = sync_channel(64);
        FileIoWorkerArgs {
            rx,
            detector: Arc::new(WalletHarvestDetector::new()),
            tracker: Arc::new(WeedHackCampaignTracker::new(Arc::new(NoOpResolver))),
            campaign_diagnostics: Arc::new(WeedHackCampaignDiagnostics::new()),
            graph: Arc::new(LineageGraph::new()),
            etw_diagnostics: Arc::new(FileIoEtwDiagnostics::new()),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    fn record_javaw(graph: &LineageGraph, pid: u32) {
        graph.record_process(super::super::ProcessNode {
            pid,
            parent_pid: 0,
            image_path: "C:\\Program Files\\Java\\bin\\javaw.exe".into(),
            image_name: "javaw.exe".into(),
            command_line: None,
            is_signed: None,
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: 1_700_000_000,
        });
    }

    fn record_proc(graph: &LineageGraph, pid: u32, name: &str) {
        graph.record_process(super::super::ProcessNode {
            pid,
            parent_pid: 0,
            image_path: format!("C:\\{name}"),
            image_name: name.into(),
            command_line: None,
            is_signed: None,
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: 1_700_000_000,
        });
    }

    fn event(pid: u32, path: &str) -> FileIoRawEvent {
        FileIoRawEvent {
            pid,
            path: path.into(),
            timestamp_unix: 1_700_000_000,
        }
    }

    // ── Phase 7 required tests ────────────────────────────────────

    #[test]
    fn single_wallet_path_read_does_not_burst() {
        let args = build_args();
        record_javaw(&args.graph, 100);
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            ),
        );
        assert_eq!(
            args.etw_diagnostics.burst_signals.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            args.etw_diagnostics
                .wallet_store_hits
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn same_wallet_store_repeated_does_not_burst() {
        let args = build_args();
        record_javaw(&args.graph, 100);
        for _ in 0..5 {
            process_one(
                &args,
                event(
                    100,
                    "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
                ),
            );
        }
        assert_eq!(
            args.etw_diagnostics.burst_signals.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn three_distinct_stores_under_javaw_emits_burst() {
        let args = build_args();
        record_javaw(&args.graph, 100);

        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            ),
        );
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\000003.ldb",
            ),
        );
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco",
            ),
        );

        assert_eq!(
            args.etw_diagnostics.burst_signals.load(Ordering::Relaxed),
            1,
            "third distinct store must trigger Burst"
        );
    }

    #[test]
    fn three_stores_across_different_pids_does_not_burst() {
        let args = build_args();
        record_javaw(&args.graph, 100);
        record_javaw(&args.graph, 200);
        record_javaw(&args.graph, 300);

        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            ),
        );
        process_one(
            &args,
            event(
                200,
                "C:\\Users\\t\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\000003.ldb",
            ),
        );
        process_one(
            &args,
            event(
                300,
                "C:\\Users\\t\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco",
            ),
        );

        assert_eq!(
            args.etw_diagnostics.burst_signals.load(Ordering::Relaxed),
            0,
            "stores across DIFFERENT PIDs must not pool into one burst"
        );
    }

    #[test]
    fn burst_emitted_once_per_pid() {
        let args = build_args();
        record_javaw(&args.graph, 100);

        // Three stores → burst fires.
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            ),
        );
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\000003.ldb",
            ),
        );
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco",
            ),
        );
        let first_count = args.etw_diagnostics.burst_signals.load(Ordering::Relaxed);
        assert_eq!(first_count, 1);

        // Fourth distinct store: detector should NOT re-fire for same PID.
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\Telegram Desktop\\tdata\\key_datas",
            ),
        );
        assert_eq!(
            args.etw_diagnostics.burst_signals.load(Ordering::Relaxed),
            1,
            "same PID must not re-fire Burst after threshold"
        );
    }

    #[test]
    fn full_path_never_appears_in_diagnostics() {
        let args = build_args();
        record_javaw(&args.graph, 100);
        for _ in 0..3 {
            process_one(
                &args,
                event(
                    100,
                    "C:\\Users\\very_specific_username_marker_for_test\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
                ),
            );
            process_one(
                &args,
                event(
                    100,
                    "C:\\Users\\very_specific_username_marker_for_test\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\000003.ldb",
                ),
            );
            process_one(
                &args,
                event(
                    100,
                    "C:\\Users\\very_specific_username_marker_for_test\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco",
                ),
            );
        }
        let json = args.etw_diagnostics.to_json();
        let s = serde_json::to_string(&json).expect("serialize");
        assert!(
            !s.contains("very_specific_username_marker_for_test"),
            "diagnostics MUST NOT contain raw user paths — leaked into JSON: {s}"
        );
        assert!(
            !s.contains("Login Data") && !s.contains("Exodus") && !s.contains("discord"),
            "diagnostics MUST NOT contain wallet store identifiers — leaked: {s}"
        );
    }

    #[test]
    fn non_wallet_path_filtered_early() {
        // path_looks_walletish() is the only callback policy; system32 etc
        // are rejected without allocating a channel slot.
        assert!(!path_looks_walletish("C:\\Windows\\System32\\kernel32.dll"));
        assert!(!path_looks_walletish("C:\\Users\\t\\Documents\\note.txt"));
        assert!(!path_looks_walletish(
            "C:\\Program Files\\Application\\thing.exe"
        ));
    }

    #[test]
    fn wallet_path_substrings_are_case_insensitive() {
        assert!(path_looks_walletish(
            "C:\\Users\\T\\AppData\\Local\\GOOGLE\\CHROME\\User Data\\Default\\Login Data"
        ));
        assert!(path_looks_walletish(
            "C:\\Users\\t\\appdata\\roaming\\EXODUS\\exodus.wallet"
        ));
    }

    #[test]
    fn worker_drops_event_when_target_pid_missing_from_graph() {
        let args = build_args();
        process_one(
            &args,
            event(
                9999,
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            ),
        );
        assert_eq!(
            args.etw_diagnostics
                .events_dropped_no_image
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            args.etw_diagnostics.events_parsed.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn non_javaw_process_reading_wallets_does_not_burst() {
        let args = build_args();
        // Notepad reading three wallet stores in a row: bizarre but
        // bounded — detector requires javaw image to count.
        record_proc(&args.graph, 100, "notepad.exe");
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            ),
        );
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\000003.ldb",
            ),
        );
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco",
            ),
        );
        assert_eq!(
            args.etw_diagnostics.burst_signals.load(Ordering::Relaxed),
            0
        );
        // All three were canonical-wallet hits and incremented `deduped`.
        assert!(
            args.etw_diagnostics.deduped.load(Ordering::Relaxed) >= 3,
            "non-javaw events must be counted as deduped"
        );
    }

    #[test]
    fn campaign_tracker_records_burst_finding() {
        // End-to-end: three stores → burst → tracker emits Suspicious
        // finding (single non-pathognomonic signal → Suspicious tier).
        let args = build_args();
        record_javaw(&args.graph, 100);
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            ),
        );
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\000003.ldb",
            ),
        );
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco",
            ),
        );
        // Campaign-tracker side: WalletHarvestBurst alone (non-pathognomonic)
        // lands at Suspicious tier per Wave 1 rules.
        let campaign_json = args.campaign_diagnostics.to_json(1);
        let recent = campaign_json["recent_findings"].as_array().unwrap();
        assert_eq!(recent.len(), 1, "burst must produce a recorded finding");
        assert_eq!(recent[0]["tier"], "suspicious");
    }

    #[test]
    fn suspicious_remains_observe_only_without_corroboration() {
        // A burst alone lands Suspicious — verifying that ETW-only
        // signals don't auto-escalate to a quarantine-eligible tier
        // without a second distinct signal type.
        let args = build_args();
        record_javaw(&args.graph, 100);
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            ),
        );
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\000003.ldb",
            ),
        );
        process_one(
            &args,
            event(
                100,
                "C:\\Users\\t\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco",
            ),
        );
        let campaign_json = args.campaign_diagnostics.to_json(1);
        assert_eq!(campaign_json["high_confidence_total"], 0);
        assert_eq!(campaign_json["confirmed_total"], 0);
        assert_eq!(campaign_json["suspicious_total"], 1);
    }

    #[test]
    fn diagnostics_json_shape_covers_spec() {
        let d = FileIoEtwDiagnostics::new();
        let j = d.to_json();
        for k in [
            "running",
            "access_denied",
            "gave_up",
            "events_seen",
            "events_parsed",
            "events_filtered",
            "parse_errors",
            "forwarded",
            "dropped",
            "wallet_store_hits",
            "burst_signals",
            "deduped",
            "rate_limited",
        ] {
            assert!(j.get(k).is_some(), "missing diagnostics key: {k}");
        }
    }

    #[test]
    fn malformed_callback_parser_returns_none_on_short_body() {
        // Sanity: the shared parser handles short bodies safely. The
        // callback would increment parse_errors and bail.
        assert!(super::super::etw_image_load::parse_image_load_body(&[0u8; 8]).is_none());
    }

    #[test]
    fn forwarding_rate_limit_caps_per_second() {
        // RATE_STATE is process-global; use distinct timestamps so this
        // test isn't perturbed by other tests in the suite.
        let t0 = Instant::now() + Duration::from_secs(3600);
        let mut allowed = 0u32;
        let mut limited = 0u32;
        for _ in 0..(MAX_FORWARDS_PER_SEC + 50) {
            if allow_rate_at(t0) {
                allowed += 1;
            } else {
                limited += 1;
            }
        }
        assert_eq!(allowed, MAX_FORWARDS_PER_SEC);
        assert_eq!(limited, 50);
    }
}

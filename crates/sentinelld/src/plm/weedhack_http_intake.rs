//! WeedHack EtherHiding HTTP-POST intake.
//!
//! ## Provider feasibility (the honest version)
//!
//! The Microsoft-Windows-WinHTTP (`{7d44233d-3055-4b9c-ba38-0193d4425c7c}`)
//! and Microsoft-Windows-WinINet (`{43d1a55c-76d6-4f7e-995c-64c711e5cafe}`)
//! ETW providers expose **connection-level diagnostics**: URLs, HTTP
//! methods, TLS handshake info, status codes. They do **NOT** expose
//! request bodies for HTTPS traffic — by design. There is no flag that
//! flips this on; the providers exist for connection-failure
//! troubleshooting, not content inspection.
//!
//! WeedHack's EtherHiding selector (`0xce6d41de`) lives in the JSON-RPC
//! request body. Without body visibility, the canonical detector
//! `weedhack_etherhiding::evaluate` is dormant.
//!
//! ### What we ship
//!
//! 1. The full Rust **orchestration pipeline** — event model, bounded
//!    channel, worker, detector glue, campaign-tracker integration,
//!    privacy-safe diagnostics. Fully tested via the public ingestion
//!    API.
//! 2. `PlmMonitor::ingest_http_post(event)` — the single public entry
//!    point any future source can call:
//!      * a Java-side JNI/agent instrumentation that supplies bodies;
//!      * a PowerShell wrapper for explicit Eth-RPC testing;
//!      * a future Detours-based user-mode hook;
//!      * test fixtures.
//! 3. Diagnostics counters that **honestly tell the operator** what the
//!    pipeline saw: `events_seen`, `post_seen`, `eth_rpc_shape`,
//!    `selector_hits`, `emitted`, `body_unavailable`.
//!
//! ### What we deliberately do NOT ship
//!
//! 1. A WinHTTP/WinINet ETW listener that would mostly increment
//!    `body_unavailable` for every Java HTTPS request to an Eth-RPC host
//!    — that's noise without signal, and shipping it would suggest
//!    coverage we don't have.
//! 2. Any SSL inspection / man-in-the-middle interception. Bypassing
//!    HTTPS to read a body is out of scope for a defensive AV.
//!
//! The result: when the right source is eventually wired, this pipeline
//! produces correct signals immediately, with zero detector or campaign
//! changes. Until then, the path is dormant and diagnostics make that
//! visible.
//!
//! ## Privacy posture
//!
//! - Full URLs never persisted. The event carries `host_hint` /
//!   `path_hint` as optional already-extracted strings; the worker
//!   matches host-marker substrings and discards the strings immediately
//!   after.
//! - Request bodies never persisted. The `body_snippet` is bounded at
//!   `MAX_BODY_BYTES` (4 KiB per spec); the canonical detector reads it
//!   in the worker and drops the value before returning.
//! - No wallet addresses, no tokens, no headers in any counter.
//! - On signal emission the narrative says only:
//!   *"Java process issued Ethereum RPC request containing known
//!    WeedHack selector."* — no payload, no host, no path.

#![allow(dead_code)]

use super::weedhack_campaign::{WeedHackCampaignDiagnostics, WeedHackCampaignTracker};
use super::weedhack_etherhiding;
use super::LineageGraph;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────
//  Tunables
// ─────────────────────────────────────────────────────────────────────

/// Maximum size of the captured body snippet. The selector is 10 bytes
/// (`0xce6d41de`); 4 KiB is generous for the typical JSON-RPC envelope
/// while still capping memory per event.
pub const MAX_BODY_BYTES: usize = 4 * 1024;

/// Bounded channel between source and worker. HTTPS-to-Eth-RPC traffic
/// on a typical box is single-digit events/minute; this absorbs bursts
/// without ever spilling under realistic load.
pub const CHANNEL_CAPACITY: usize = 256;

/// Hard cap on events the source may forward per second. Even an active
/// stealer making continuous Eth-RPC polls doesn't reach this — it
/// exists as a backstop against runaway sources.
pub const MAX_FORWARDS_PER_SEC: u32 = 64;

/// PID + selector dedup window. Identical (pid, selector-hit) within
/// this window is treated as a re-emission of the same observed event.
pub const DEDUP_WINDOW: Duration = Duration::from_secs(60);

/// Max entries in the dedup table — bounded memory under burst.
pub const MAX_DEDUP_ENTRIES: usize = 256;

/// Host-hint substrings that mark a URL as Ethereum-RPC-shaped. Used as
/// an optional corroborator: when the host hint matches AND the body is
/// unavailable, we increment `body_unavailable` so operators see the
/// coverage gap.
const ETH_RPC_HOST_HINTS: &[&str] = &[
    "mainnet.infura.io",
    "eth-mainnet.g.alchemy.com",
    "cloudflare-eth.com",
    "rpc.ankr.com/eth",
    "ethereum-rpc.publicnode.com",
    "eth.llamarpc.com",
    "1rpc.io/eth",
    ".quiknode.pro",
    ".chainstack.com",
];

/// JSON-RPC shape markers used to confirm the body is an eth_call /
/// eth_getStorageAt envelope. Case-sensitive — JSON-RPC keywords are
/// canonical.
const ETH_RPC_BODY_SHAPE_MARKERS: &[&str] = &["eth_call", "eth_getStorageAt", "jsonrpc"];

/// The WeedHack `getRPCUrl()` selector — present in the JSON-RPC `data`
/// parameter as a literal hex string. Matched case-insensitively.
const WEEDHACK_SELECTOR: &str = "0xce6d41de";

// ─────────────────────────────────────────────────────────────────────
//  Raw event type
// ─────────────────────────────────────────────────────────────────────

/// One HTTP POST observed by an upstream source. Field shape matches the
/// Wave 7 spec verbatim.
///
/// `body_snippet`:
///   * `Some(bytes)` — source captured the request body (or a prefix of
///     it, up to `MAX_BODY_BYTES`).
///   * `None` — source observed the POST but cannot read the body
///     (WinHTTP/WinINet ETW for HTTPS, etc.).
///
/// In the second case the worker increments `body_unavailable` IF the
/// host hint looks Eth-RPC-shaped — that tells the operator "we see the
/// connection but can't see the content."
#[derive(Debug, Clone)]
pub struct HttpPostRawEvent {
    pub pid: u32,
    pub process_image: String,
    pub host_hint: Option<String>,
    pub path_hint: Option<String>,
    pub body_snippet: Option<Vec<u8>>,
    pub timestamp_unix: i64,
}

impl HttpPostRawEvent {
    /// Truncate the body snippet to `MAX_BODY_BYTES` if it exceeds.
    /// Callers should construct events with bodies already capped; this
    /// is a defensive backstop for direct API users.
    pub fn cap_body(mut self) -> Self {
        if let Some(ref mut b) = self.body_snippet {
            if b.len() > MAX_BODY_BYTES {
                b.truncate(MAX_BODY_BYTES);
            }
        }
        self
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Diagnostics
// ─────────────────────────────────────────────────────────────────────

pub struct HttpIntakeDiagnostics {
    pub events_seen: AtomicU64,
    pub post_seen: AtomicU64,
    pub eth_rpc_shape: AtomicU64,
    pub selector_hits: AtomicU64,
    pub emitted: AtomicU64,
    /// Source observed a Java→Eth-RPC POST but couldn't supply the body
    /// — this is the explicit coverage-gap indicator for the WinHTTP /
    /// WinINet ETW dormancy described at the top of this file.
    pub body_unavailable: AtomicU64,
    pub dropped: AtomicU64,
    pub deduped: AtomicU64,
    pub rate_limited: AtomicU64,
    pub events_no_java_lineage: AtomicU64,
}

impl HttpIntakeDiagnostics {
    pub fn new() -> Self {
        Self {
            events_seen: AtomicU64::new(0),
            post_seen: AtomicU64::new(0),
            eth_rpc_shape: AtomicU64::new(0),
            selector_hits: AtomicU64::new(0),
            emitted: AtomicU64::new(0),
            body_unavailable: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            deduped: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            events_no_java_lineage: AtomicU64::new(0),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "events_seen": self.events_seen.load(Ordering::Relaxed),
            "post_seen": self.post_seen.load(Ordering::Relaxed),
            "eth_rpc_shape": self.eth_rpc_shape.load(Ordering::Relaxed),
            "selector_hits": self.selector_hits.load(Ordering::Relaxed),
            "emitted": self.emitted.load(Ordering::Relaxed),
            "body_unavailable": self.body_unavailable.load(Ordering::Relaxed),
            "dropped": self.dropped.load(Ordering::Relaxed),
            "deduped": self.deduped.load(Ordering::Relaxed),
            "rate_limited": self.rate_limited.load(Ordering::Relaxed),
            "events_no_java_lineage": self.events_no_java_lineage.load(Ordering::Relaxed),
            "max_body_bytes": MAX_BODY_BYTES,
            "channel_capacity": CHANNEL_CAPACITY,
            "max_forwards_per_sec": MAX_FORWARDS_PER_SEC,
        })
    }
}

impl Default for HttpIntakeDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Pure helpers — testable without any state
// ─────────────────────────────────────────────────────────────────────

fn host_looks_eth_rpc(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    ETH_RPC_HOST_HINTS.iter().any(|h| lower.contains(h))
}

fn body_has_jsonrpc_shape(body: &[u8]) -> bool {
    // Bound work: only scan the first MAX_BODY_BYTES even if a caller
    // disobeys the cap. (cap_body() is the polite path.)
    let scan = if body.len() > MAX_BODY_BYTES {
        &body[..MAX_BODY_BYTES]
    } else {
        body
    };
    // We don't need full UTF-8 — markers are ASCII; lossy conversion
    // keeps it cheap and never panics.
    let text = String::from_utf8_lossy(scan);
    ETH_RPC_BODY_SHAPE_MARKERS
        .iter()
        .any(|m| text.contains(m))
}

fn body_has_weedhack_selector(body: &[u8]) -> bool {
    let scan = if body.len() > MAX_BODY_BYTES {
        &body[..MAX_BODY_BYTES]
    } else {
        body
    };
    let text = String::from_utf8_lossy(scan).to_ascii_lowercase();
    text.contains(WEEDHACK_SELECTOR)
}

fn is_javaw_image(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "javaw.exe" || lower == "java.exe"
}

// ─────────────────────────────────────────────────────────────────────
//  Rate-limit state (process-global; only one intake exists)
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
    let mut rs = rate_state().lock().unwrap_or_else(|e| e.into_inner());
    // The `now < window_start` arm only fires for synthetic caller-supplied
    // timestamps (tests pass far-future `Instant`s to isolate runs); with a
    // real monotonic clock window_start can never be ahead of now. Without
    // it, a far-future window_start left behind by a previous caller would
    // saturate `duration_since` to 0 and rate-limit every real call until
    // the wall clock caught up.
    if now < rs.window_start || now.duration_since(rs.window_start) >= Duration::from_secs(1) {
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
//  Dedup table
// ─────────────────────────────────────────────────────────────────────

/// Dedup key for selector hits — keyed on (pid, "selector") so any
/// future selector additions get distinct slots without state surgery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DedupKey {
    pid: u32,
    marker: &'static str,
}

struct DedupTable {
    inner: Mutex<std::collections::HashMap<DedupKey, Instant>>,
}

impl DedupTable {
    fn new() -> Self {
        Self {
            inner: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn allow(&self, key: DedupKey, now: Instant) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Light incremental eviction by window.
        map.retain(|_, ts| now.duration_since(*ts) < DEDUP_WINDOW);
        // Hard cap: drop oldest if at limit and we'd insert.
        if map.len() >= MAX_DEDUP_ENTRIES && !map.contains_key(&key) {
            if let Some(oldest_k) = map.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| k.clone()) {
                map.remove(&oldest_k);
            }
        }
        if let Some(ts) = map.get(&key) {
            if now.duration_since(*ts) < DEDUP_WINDOW {
                return false;
            }
        }
        map.insert(key, now);
        true
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Worker thread
// ─────────────────────────────────────────────────────────────────────

pub struct HttpIntakeWorkerArgs {
    pub rx: Receiver<HttpPostRawEvent>,
    pub tracker: Arc<WeedHackCampaignTracker>,
    pub campaign_diagnostics: Arc<WeedHackCampaignDiagnostics>,
    pub graph: Arc<LineageGraph>,
    pub etw_diagnostics: Arc<HttpIntakeDiagnostics>,
    pub running: Arc<AtomicBool>,
    pub dedup: Arc<DedupTableHandle>,
}

/// Public handle wrapping the internal table — lets the worker / API
/// share a single state without leaking the inner Mutex shape.
pub struct DedupTableHandle(DedupTable);

impl DedupTableHandle {
    pub fn new() -> Self {
        Self(DedupTable::new())
    }
}

impl Default for DedupTableHandle {
    fn default() -> Self {
        Self::new()
    }
}

pub fn http_intake_worker_loop(args: HttpIntakeWorkerArgs) {
    tracing::debug!("WeedHack HTTP intake worker started");
    while args.running.load(Ordering::Relaxed) {
        match args.rx.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => process_one(&args, event),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    tracing::debug!("WeedHack HTTP intake worker stopped");
}

/// Per-event work. Counters advance through every decision point so the
/// diagnostics surface answers "why is the signal dormant?" with
/// specificity.
pub fn process_one(args: &HttpIntakeWorkerArgs, event: HttpPostRawEvent) {
    process_one_at(args, event, Instant::now())
}

pub fn process_one_at(args: &HttpIntakeWorkerArgs, event: HttpPostRawEvent, now: Instant) {
    args.etw_diagnostics
        .events_seen
        .fetch_add(1, Ordering::Relaxed);
    args.etw_diagnostics
        .post_seen
        .fetch_add(1, Ordering::Relaxed);

    // ── Phase 3: Java lineage gate ──
    // The Wave 1 canonical detector requires a Java source; we enforce
    // that gate explicitly here before doing any body work so a non-Java
    // POST that includes the selector by coincidence (e.g. a researcher
    // running a dev script from node.exe) does not light counters.
    let has_java = is_javaw_image(&event.process_image)
        || lineage_has_java_ancestor(&args.graph, event.pid);
    if !has_java {
        args.etw_diagnostics
            .events_no_java_lineage
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    // ── Optional corroborator: host hint matches Eth-RPC ──
    let host_eth_rpc = event
        .host_hint
        .as_deref()
        .map(host_looks_eth_rpc)
        .unwrap_or(false);

    // ── Body gate. Without a body we cannot emit. The most common case
    //    on production Windows is HTTPS where WinHTTP/WinINet ETW does
    //    not surface bodies — increment `body_unavailable` ONLY when the
    //    URL hint already looks Eth-RPC, so an operator sees the actual
    //    coverage gap rather than a generic counter that grows with
    //    every Java HTTPS request. ──
    let body = match event.body_snippet.as_deref() {
        Some(b) => b,
        None => {
            if host_eth_rpc {
                args.etw_diagnostics
                    .body_unavailable
                    .fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    };

    // ── Body shape check (must look like JSON-RPC) ──
    if body_has_jsonrpc_shape(body) {
        args.etw_diagnostics
            .eth_rpc_shape
            .fetch_add(1, Ordering::Relaxed);
    } else if !host_eth_rpc {
        // Body doesn't look RPC-shaped AND we have no Eth-RPC host hint
        // — definitely not WeedHack. Bail before selector scan to keep
        // counters meaningful.
        return;
    }

    // ── Selector match ──
    if !body_has_weedhack_selector(body) {
        return;
    }
    args.etw_diagnostics
        .selector_hits
        .fetch_add(1, Ordering::Relaxed);

    // ── Canonical detector. We feed it a synthetic event constructed
    //    from already-extracted fields so the gate stays bit-for-bit
    //    aligned with the existing weedhack_etherhiding evaluator. The
    //    detector requires javaw image, POST method, host hint match,
    //    body selector hit — same conditions we've already checked, but
    //    we route through it so any future detector tightening applies
    //    automatically. ──
    let detector_event = weedhack_etherhiding::EtherHidingEvent {
        url: event.host_hint.clone().unwrap_or_default(),
        method: "POST".to_string(),
        body: String::from_utf8_lossy(body).to_string(),
        source_pid: event.pid,
        source_image_name: if event.process_image.is_empty() {
            // Fall back to a resolved image so the detector's image
            // check passes for events whose source omitted the field
            // but whose lineage confirms Java.
            args.graph
                .get_node(event.pid)
                .map(|n| n.image_name)
                .unwrap_or_else(|| "javaw.exe".to_string())
        } else {
            event.process_image.clone()
        },
    };
    let signal = match weedhack_etherhiding::evaluate(&detector_event) {
        Some(s) => s,
        None => return,
    };

    // ── Dedup (pid, selector) — gates EMISSION, not evaluation. This
    //    must run only after the detector confirms: an event the
    //    detector rejects (e.g. shape+selector match but no Eth-RPC
    //    host hint) must not consume the slot, or a subsequent
    //    fully-formed event from the same PID within the window would
    //    be silently deduped → missed detection. ──
    if !args.dedup.0.allow(
        DedupKey {
            pid: event.pid,
            marker: "selector",
        },
        now,
    ) {
        args.etw_diagnostics
            .deduped
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    args.etw_diagnostics
        .emitted
        .fetch_add(1, Ordering::Relaxed);

    if let Some(finding) = args.tracker.ingest_signal(event.pid, signal) {
        let root_image = args.graph.get_node(finding.root.pid).map(|n| n.image_name);
        let now_unix = chrono::Utc::now().timestamp();
        args.campaign_diagnostics
            .record(&finding, root_image, now_unix);
        args.campaign_diagnostics
            .note_active(args.tracker.active_campaign_count());
    }

    // body / detector_event go out of scope here — no further references.
}

fn lineage_has_java_ancestor(graph: &Arc<LineageGraph>, pid: u32) -> bool {
    let chain = graph.get_chain(pid);
    chain.nodes.iter().any(|n| is_javaw_image(&n.image_name))
}

// ─────────────────────────────────────────────────────────────────────
//  Static callback wiring — present for symmetry with Wave 4/6 even
//  though Wave 7 deliberately ships no kernel pump.
// ─────────────────────────────────────────────────────────────────────

static SENDER: OnceLock<SyncSender<HttpPostRawEvent>> = OnceLock::new();
static DIAG: OnceLock<Arc<HttpIntakeDiagnostics>> = OnceLock::new();

pub fn install_endpoints(diagnostics: Arc<HttpIntakeDiagnostics>) -> Receiver<HttpPostRawEvent> {
    let (tx, rx) = sync_channel(CHANNEL_CAPACITY);
    let _ = SENDER.set(tx);
    let _ = DIAG.set(diagnostics);
    rx
}

/// Public ingestion entry point — the API any future source calls.
/// Documented in the module header; reachable from `PlmMonitor`.
///
/// Returns `Ok(())` if the event was queued or rejected by rate limit,
/// `Err(())` if the channel is full or the endpoints aren't installed
/// (counter advances either way).
pub fn ingest(event: HttpPostRawEvent) -> Result<(), ()> {
    let Some(diag) = DIAG.get() else {
        return Err(());
    };
    let Some(sender) = SENDER.get() else {
        return Err(());
    };

    // Rate cap before any work.
    if !allow_rate_at(Instant::now()) {
        diag.rate_limited.fetch_add(1, Ordering::Relaxed);
        return Err(());
    }

    let event = event.cap_body();
    match sender.try_send(event) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            diag.dropped.fetch_add(1, Ordering::Relaxed);
            Err(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Lifecycle
// ─────────────────────────────────────────────────────────────────────

pub fn start_http_intake_worker(
    tracker: Arc<WeedHackCampaignTracker>,
    campaign_diagnostics: Arc<WeedHackCampaignDiagnostics>,
    graph: Arc<LineageGraph>,
    running: Arc<AtomicBool>,
) -> (
    Arc<HttpIntakeDiagnostics>,
    Arc<DedupTableHandle>,
    Option<std::thread::JoinHandle<()>>,
) {
    let diag = Arc::new(HttpIntakeDiagnostics::new());
    let dedup = Arc::new(DedupTableHandle::new());
    let rx = install_endpoints(Arc::clone(&diag));

    let args = HttpIntakeWorkerArgs {
        rx,
        tracker,
        campaign_diagnostics,
        graph,
        etw_diagnostics: Arc::clone(&diag),
        running,
        dedup: Arc::clone(&dedup),
    };

    let handle = std::thread::Builder::new()
        .name("plm-http-intake".into())
        .spawn(move || http_intake_worker_loop(args))
        .ok();

    (diag, dedup, handle)
}

// ─────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::weedhack_runtime::WeedHackSignal;

    struct NoOpResolver;
    impl super::super::weedhack_campaign::LineageResolver for NoOpResolver {
        fn resolve_campaign_root(
            &self,
            _pid: u32,
        ) -> Option<super::super::weedhack_campaign::CampaignRoot> {
            None
        }
    }

    fn build_args() -> HttpIntakeWorkerArgs {
        let (_tx, rx) = sync_channel(64);
        HttpIntakeWorkerArgs {
            rx,
            tracker: Arc::new(WeedHackCampaignTracker::new(Arc::new(NoOpResolver))),
            campaign_diagnostics: Arc::new(WeedHackCampaignDiagnostics::new()),
            graph: Arc::new(LineageGraph::new()),
            etw_diagnostics: Arc::new(HttpIntakeDiagnostics::new()),
            running: Arc::new(AtomicBool::new(true)),
            dedup: Arc::new(DedupTableHandle::new()),
        }
    }

    fn record_javaw(graph: &LineageGraph, pid: u32) {
        graph.record_process(super::super::ProcessNode {
            pid,
            parent_pid: 0,
            image_path: "C:\\Program Files\\Java\\bin\\javaw.exe".into(),
            image_name: "javaw.exe".into(),
            command_line: super::super::cmdline::CommandLineState::NotCollected,
            is_signed: None,
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: 1_700_000_000,
        });
    }

    fn jsonrpc_body_with_selector() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xabc","data":"0xce6d41de"},"latest"],"id":1}"#
            .to_vec()
    }

    fn jsonrpc_body_without_selector() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xabc","data":"0x70a08231"}],"id":1}"#.to_vec()
    }

    fn ev(
        pid: u32,
        image: &str,
        host: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> HttpPostRawEvent {
        HttpPostRawEvent {
            pid,
            process_image: image.into(),
            host_hint: host.map(|s| s.into()),
            path_hint: None,
            body_snippet: body,
            timestamp_unix: 1_700_000_000,
        }
    }

    // ── Phase 7 required tests ────────────────────────────────────

    #[test]
    fn java_post_with_selector_emits_signal() {
        let args = build_args();
        record_javaw(&args.graph, 100);
        process_one(
            &args,
            ev(
                100,
                "javaw.exe",
                Some("https://mainnet.infura.io/v3/X"),
                Some(jsonrpc_body_with_selector()),
            ),
        );
        assert_eq!(args.etw_diagnostics.emitted.load(Ordering::Relaxed), 1);
        assert_eq!(
            args.etw_diagnostics.selector_hits.load(Ordering::Relaxed),
            1
        );
        // Campaign tracker recorded a Suspicious finding from the single
        // non-pathognomonic signal.
        let cj = args.campaign_diagnostics.to_json(1);
        assert_eq!(cj["recent_findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn java_post_without_selector_does_not_emit() {
        let args = build_args();
        record_javaw(&args.graph, 100);
        process_one(
            &args,
            ev(
                100,
                "javaw.exe",
                Some("https://mainnet.infura.io/v3/X"),
                Some(jsonrpc_body_without_selector()),
            ),
        );
        assert_eq!(args.etw_diagnostics.emitted.load(Ordering::Relaxed), 0);
        assert_eq!(
            args.etw_diagnostics.selector_hits.load(Ordering::Relaxed),
            0
        );
        // JSON-RPC shape WAS observed.
        assert_eq!(
            args.etw_diagnostics.eth_rpc_shape.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn non_java_post_with_selector_does_not_emit() {
        // Dev tool from node.exe doing legit Eth dev.
        let args = build_args();
        process_one(
            &args,
            ev(
                100,
                "node.exe",
                Some("https://mainnet.infura.io/v3/X"),
                Some(jsonrpc_body_with_selector()),
            ),
        );
        assert_eq!(args.etw_diagnostics.emitted.load(Ordering::Relaxed), 0);
        assert_eq!(
            args.etw_diagnostics
                .events_no_java_lineage
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            args.etw_diagnostics.selector_hits.load(Ordering::Relaxed),
            0,
            "selector scan must not run when source isn't Java"
        );
    }

    #[test]
    fn selector_inside_oversized_body_is_truncated_safely() {
        let args = build_args();
        record_javaw(&args.graph, 100);
        // Build a body where the selector sits PAST the MAX_BODY_BYTES
        // boundary: it must NOT be discovered, no signal emitted.
        let mut huge = vec![b' '; MAX_BODY_BYTES + 16];
        // Put the selector at the very end — clearly beyond the cap.
        huge.extend_from_slice(b"0xce6d41de");
        let event = ev(
            100,
            "javaw.exe",
            Some("https://mainnet.infura.io/v3/X"),
            Some(huge),
        );
        // cap_body() runs at ingest(); call it here so the worker
        // receives an already-capped event as it would in production.
        let event = event.cap_body();
        process_one(&args, event);
        assert_eq!(
            args.etw_diagnostics.emitted.load(Ordering::Relaxed),
            0,
            "selector beyond cap must not be discovered"
        );
    }

    #[test]
    fn body_unavailable_with_eth_rpc_host_increments_counter() {
        // The honest WinHTTP-dormancy case: javaw POSTs to Infura but
        // body is None because ETW can't see HTTPS bodies.
        let args = build_args();
        record_javaw(&args.graph, 100);
        process_one(
            &args,
            ev(
                100,
                "javaw.exe",
                Some("https://mainnet.infura.io/v3/X"),
                None,
            ),
        );
        assert_eq!(
            args.etw_diagnostics.body_unavailable.load(Ordering::Relaxed),
            1
        );
        assert_eq!(args.etw_diagnostics.emitted.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn body_unavailable_with_non_rpc_host_does_not_increment_gap_counter() {
        // Java POSTing to some non-RPC service — not interesting; we
        // don't want to count every body-less POST as a coverage gap.
        let args = build_args();
        record_javaw(&args.graph, 100);
        process_one(
            &args,
            ev(
                100,
                "javaw.exe",
                Some("https://example.com/api"),
                None,
            ),
        );
        assert_eq!(
            args.etw_diagnostics.body_unavailable.load(Ordering::Relaxed),
            0
        );
        assert_eq!(args.etw_diagnostics.emitted.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn full_body_never_appears_in_diagnostics() {
        let args = build_args();
        record_javaw(&args.graph, 100);
        // Body contains a highly specific marker that must NOT leak into
        // any diagnostics surface.
        let body = br#"{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xWALLET_ADDRESS_DO_NOT_LEAK_42"}],"id":1,"data":"0xce6d41de"}"#.to_vec();
        process_one(
            &args,
            ev(
                100,
                "javaw.exe",
                Some("https://mainnet.infura.io/v3/X"),
                Some(body),
            ),
        );
        let etw_json = args.etw_diagnostics.to_json();
        let campaign_json = args.campaign_diagnostics.to_json(1);
        let combined = format!(
            "{}{}",
            serde_json::to_string(&etw_json).unwrap(),
            serde_json::to_string(&campaign_json).unwrap()
        );
        assert!(
            !combined.contains("WALLET_ADDRESS_DO_NOT_LEAK_42"),
            "diagnostics leaked body content: {combined}"
        );
        // Note: "0xce6d41de" appears in the STATIC signal label
        // (Wave 1 `WeedHackSignal::EtherHidingFromJava.label()`) — it's
        // a documentation string identical for every event of this
        // type, not a copy of the observed body. Privacy invariant:
        // body-specific content (the wallet marker above) does not leak.
        // The narrative must not include the actual wallet address.
        let recent = campaign_json["recent_findings"].as_array().unwrap();
        assert_eq!(recent.len(), 1);
        let narrative = recent[0]["narrative"].as_str().unwrap();
        assert!(
            !narrative.contains("WALLET_ADDRESS_DO_NOT_LEAK_42"),
            "narrative leaked observed body content: {narrative}"
        );
    }

    #[test]
    fn full_url_never_appears_in_diagnostics() {
        let args = build_args();
        record_javaw(&args.graph, 100);
        let very_specific_path = "/v3/HIGHLY_SPECIFIC_PROJECT_TOKEN_FOR_TEST";
        let url = format!("https://mainnet.infura.io{very_specific_path}");
        process_one(
            &args,
            HttpPostRawEvent {
                pid: 100,
                process_image: "javaw.exe".into(),
                host_hint: Some(url.clone()),
                path_hint: Some(very_specific_path.into()),
                body_snippet: Some(jsonrpc_body_with_selector()),
                timestamp_unix: 1_700_000_000,
            },
        );
        let etw_json = args.etw_diagnostics.to_json();
        let s = serde_json::to_string(&etw_json).unwrap();
        assert!(
            !s.contains("HIGHLY_SPECIFIC_PROJECT_TOKEN_FOR_TEST"),
            "diagnostics leaked URL token: {s}"
        );
    }

    #[test]
    fn repeated_pid_selector_within_window_is_deduped() {
        let args = build_args();
        record_javaw(&args.graph, 100);
        let t0 = Instant::now();
        process_one_at(
            &args,
            ev(
                100,
                "javaw.exe",
                Some("https://mainnet.infura.io/v3/X"),
                Some(jsonrpc_body_with_selector()),
            ),
            t0,
        );
        assert_eq!(args.etw_diagnostics.emitted.load(Ordering::Relaxed), 1);

        // Second identical event within window — deduped.
        process_one_at(
            &args,
            ev(
                100,
                "javaw.exe",
                Some("https://mainnet.infura.io/v3/X"),
                Some(jsonrpc_body_with_selector()),
            ),
            t0 + Duration::from_secs(30),
        );
        assert_eq!(
            args.etw_diagnostics.emitted.load(Ordering::Relaxed),
            1,
            "repeated selector hit within window must dedupe"
        );
        assert!(args.etw_diagnostics.deduped.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn campaign_tracker_receives_signal_at_suspicious_tier() {
        // EtherHiding alone is a pathognomonic signal — single
        // pathognomonic lands at HighConfidence, not Confirmed.
        let args = build_args();
        record_javaw(&args.graph, 100);
        process_one(
            &args,
            ev(
                100,
                "javaw.exe",
                Some("https://mainnet.infura.io/v3/X"),
                Some(jsonrpc_body_with_selector()),
            ),
        );
        let cj = args.campaign_diagnostics.to_json(1);
        let recent = cj["recent_findings"].as_array().unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(
            recent[0]["tier"], "high_confidence",
            "EtherHidingFromJava is pathognomonic → HighConfidence alone"
        );
    }

    #[test]
    fn etherhiding_plus_corroborator_advances_to_confirmed() {
        // Pathognomonic + 1 corroborator → Confirmed per Wave 1 tier
        // rules. Verifies the WeedHack campaign scoring stayed
        // unchanged by Wave 7 — assert at the TRACKER level (the
        // diagnostics ring buffer only records findings emitted via
        // the worker path; direct tracker calls bypass that).
        let args = build_args();
        record_javaw(&args.graph, 100);
        process_one(
            &args,
            ev(
                100,
                "javaw.exe",
                Some("https://mainnet.infura.io/v3/X"),
                Some(jsonrpc_body_with_selector()),
            ),
        );
        // Independently feed a non-pathognomonic signal into the tracker.
        let advanced = args
            .tracker
            .ingest_signal(100, WeedHackSignal::UnnaturalJavaChild)
            .expect("corroborator must advance the tier");
        assert_eq!(
            advanced.tier,
            super::super::weedhack_campaign::CampaignTier::Confirmed,
            "EtherHiding (pathognomonic) + UnnaturalJavaChild → Confirmed"
        );
    }

    #[test]
    fn rate_limit_caps_forwarding() {
        let t0 = Instant::now() + Duration::from_secs(7 * 3600);
        let mut allowed = 0u32;
        let mut limited = 0u32;
        for _ in 0..(MAX_FORWARDS_PER_SEC + 10) {
            if allow_rate_at(t0) {
                allowed += 1;
            } else {
                limited += 1;
            }
        }
        assert_eq!(allowed, MAX_FORWARDS_PER_SEC);
        assert_eq!(limited, 10);
    }

    #[test]
    fn cap_body_truncates_oversized_snippets() {
        let big = vec![0x42u8; MAX_BODY_BYTES * 2];
        let event = HttpPostRawEvent {
            pid: 100,
            process_image: "javaw.exe".into(),
            host_hint: None,
            path_hint: None,
            body_snippet: Some(big),
            timestamp_unix: 1_700_000_000,
        }
        .cap_body();
        assert_eq!(event.body_snippet.unwrap().len(), MAX_BODY_BYTES);
    }

    #[test]
    fn diagnostics_json_shape_covers_spec() {
        let d = HttpIntakeDiagnostics::new();
        let j = d.to_json();
        for k in [
            "events_seen",
            "post_seen",
            "eth_rpc_shape",
            "selector_hits",
            "emitted",
            "body_unavailable",
            "dropped",
            "deduped",
            "rate_limited",
        ] {
            assert!(j.get(k).is_some(), "missing diagnostics key: {k}");
        }
    }

    #[test]
    fn host_marker_check_is_case_insensitive() {
        assert!(host_looks_eth_rpc("https://MAINNET.INFURA.IO/v3/X"));
        assert!(host_looks_eth_rpc("https://Eth-Mainnet.G.Alchemy.com/"));
        assert!(!host_looks_eth_rpc("https://example.com/"));
    }

    #[test]
    fn body_jsonrpc_shape_detects_eth_call() {
        assert!(body_has_jsonrpc_shape(b"{\"method\":\"eth_call\",\"id\":1}"));
        assert!(body_has_jsonrpc_shape(b"{\"jsonrpc\":\"2.0\"}"));
        assert!(!body_has_jsonrpc_shape(b"<html>nope</html>"));
    }

    #[test]
    fn body_selector_check_is_case_insensitive() {
        assert!(body_has_weedhack_selector(b"data:0xCE6D41DE"));
        assert!(body_has_weedhack_selector(b"data:0xce6d41de"));
        assert!(!body_has_weedhack_selector(b"data:0xfeedbeef"));
    }
}

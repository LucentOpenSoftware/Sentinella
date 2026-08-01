//! Tokio DNS proxy: UDP + TCP listeners, filter decision, upstream
//! forwarding with UDP-first/TCP-fallback, TTL-respecting cache, bounded
//! in-flight queries, and graceful shutdown via a `watch` channel.
//!
//! Design doc §3/§5 invariants implemented here:
//! - fail-safe: malformed query → FORMERR, dead upstream → SERVFAIL,
//!   overload → SERVFAIL shed; the machine's DNS never hangs on us;
//! - bounded everything: in-flight semaphores (UDP and a SEPARATE, smaller
//!   TCP pool with a per-connection total-lifetime cap — dribbling TCP
//!   clients cannot starve UDP and thereby force the fail-open path, which
//!   would also bypass filtering: under `on_proxy_failure = "fallback"`,
//!   load that kills the proxy removes filtering; that policy knob is the
//!   control), cache capacity, upstream timeouts, datagram size;
//! - upstream responses are validated before use: QR set, transaction ID
//!   matching the per-query ID we generated upstream-side, question echoed
//!   (qname case-insensitive per RFC 4343, qtype/qclass exact); upstream
//!   queries are rebuilt CLEAN (fresh txid, RD=1, question only, no
//!   additional records/EDNS) so client-controlled bytes never leave the
//!   machine;
//! - no hardcoded public resolver: upstreams come from configuration.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::filter::{Decision, FilterEngine};
use crate::wire;

pub const DEFAULT_MAX_IN_FLIGHT: usize = 256;
/// Separate, smaller permit pool for client TCP connections (design §5):
/// loopback TCP connections are cheap to hold open, so they must not share
/// the UDP in-flight budget.
pub const DEFAULT_TCP_MAX_CONNECTIONS: usize = 32;
pub const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
/// Internal cache-lifetime cap: we cache a response for at most this long
/// (min(upstream TTL, 300s)). This clamps only how long WE serve a cached
/// entry; it never rewrites the TTL bytes inside the cached response,
/// which are forwarded to clients exactly as the upstream sent them.
pub const DEFAULT_MAX_TTL: Duration = Duration::from_secs(300);
/// Negative (NXDOMAIN) cache lifetime (design: min(60s)).
pub const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(60);
pub const DEFAULT_CACHE_CAPACITY: usize = 10_000;
/// Upper bound on UDP datagrams we read/write (DNS-over-UDP without EDNS is
/// 512; with EDNS up to 4096 — anything larger is nonsense).
const MAX_DATAGRAM: usize = 4096;
/// TTL stamped on zero-IP block answers.
const ZERO_IP_TTL: u32 = 60;
/// Bind attempts when the configured port is 0 and UDP/TCP must share one
/// ephemeral port.
const BIND_RETRIES: usize = 8;

/// What a blocked query gets (design doc §6 `block_response`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockResponse {
    #[default]
    Nxdomain,
    ZeroIp,
}

/// Proxy configuration. No public-resolver default on purpose (design §3):
/// upstream discovery is the daemon's job.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstreams: Vec<SocketAddr>,
    pub upstream_timeout: Duration,
    pub max_in_flight: usize,
    pub cache_capacity: usize,
    pub max_ttl: Duration,
    pub negative_ttl: Duration,
    pub block_response: BlockResponse,
    /// Inter-read idle timeout on client TCP connections.
    pub tcp_idle_timeout: Duration,
    /// HARD total-lifetime cap on a client TCP connection (design §5): a
    /// connection is closed once it is this old, no matter how active it
    /// is — an idle timeout alone lets dribbling connections hold a permit
    /// forever. EVERY socket operation on the connection — both reads and
    /// the response WRITES — is bounded by the time remaining until this
    /// deadline, so a pipelining client that never reads (kernel send
    /// buffer full, `write_all` parked) cannot hold its permit past the
    /// cap either.
    pub tcp_max_lifetime: Duration,
    /// Size of the SEPARATE TCP connection permit pool (design §5).
    /// Deliberately much smaller than `max_in_flight` and never shared with
    /// it, so TCP clients cannot starve UDP query handling.
    pub tcp_max_connections: usize,
    /// Name the [`Proxy::self_test`] health probes resolve
    /// (default `example.com` — IANA-reserved, stable, guaranteed to
    /// exist).
    ///
    /// What the two probe steps actually prove with this name: step (ii)
    /// forwards it DIRECTLY to each upstream, bypassing the listener, the
    /// cache, and the filter — it validates upstream reachability ONLY and
    /// says nothing about whether the listener can resolve anything. Step
    /// (iii) resolves it again THROUGH the listener (parse → decide →
    /// cache/forward → respond), so a name the filter blocks fails step
    /// (iii): pick a name you never intend to block.
    ///
    /// Validated at [`Proxy::bind`]: empty, root-only, unencodable, and
    /// backslash-bearing names are rejected. The backslash rejection is
    /// load-bearing, not cosmetic — [`wire::build_query`] is
    /// escape-unaware, so `exam\.ple.com` would be encoded with a literal
    /// `\` byte and the probe would silently resolve a DIFFERENT name than
    /// the operator configured.
    pub health_check_name: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            // NRPT NameServers have no port syntax — the DNS Client always
            // queries port 53, so production MUST listen on 127.0.0.1:53
            // (tests override with port 0 for an ephemeral port).
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            upstreams: Vec::new(),
            upstream_timeout: DEFAULT_UPSTREAM_TIMEOUT,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
            max_ttl: DEFAULT_MAX_TTL,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            block_response: BlockResponse::default(),
            tcp_idle_timeout: Duration::from_secs(10),
            tcp_max_lifetime: Duration::from_secs(60),
            tcp_max_connections: DEFAULT_TCP_MAX_CONNECTIONS,
            health_check_name: "example.com".to_string(),
        }
    }
}

/// Atomic counters, shared with the daemon for IPC status reporting.
#[derive(Debug, Default)]
pub struct Counters {
    pub queries: AtomicU64,
    pub forwarded: AtomicU64,
    pub blocked: AtomicU64,
    pub cache_hits: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub shed: AtomicU64,
    /// Client TCP connections force-closed by the hard lifetime cap.
    pub tcp_lifetime_kills: AtomicU64,
    /// Health-check canary probes answered with the local signature. This
    /// is deliberately SEPARATE from `queries`/`blocked`: canary answers
    /// are synthesized unconditionally (never a filter decision, never
    /// user traffic), so counting them as user-facing "blocked" would make
    /// the GUI/IPC "domains blocked" figure include probes no client ever
    /// issued. The self-test asserts a delta of EXACTLY 1 on this counter
    /// across its canary probe — a signal no upstream can fake.
    pub canary_probes: AtomicU64,
}

/// Point-in-time copy of [`Counters`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CountersSnapshot {
    pub queries: u64,
    pub forwarded: u64,
    pub blocked: u64,
    pub cache_hits: u64,
    pub upstream_errors: u64,
    pub shed: u64,
    pub tcp_lifetime_kills: u64,
    pub canary_probes: u64,
}

impl Counters {
    pub fn snapshot(&self) -> CountersSnapshot {
        CountersSnapshot {
            queries: self.queries.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            shed: self.shed.load(Ordering::Relaxed),
            tcp_lifetime_kills: self.tcp_lifetime_kills.load(Ordering::Relaxed),
            canary_probes: self.canary_probes.load(Ordering::Relaxed),
        }
    }

    fn bump(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// What happened to one query — the structured query-log record.
#[derive(Debug, Clone)]
pub struct DecisionEvent {
    pub client: SocketAddr,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub outcome: QueryOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryOutcome {
    Blocked,
    Forwarded,
    CacheHit,
    UpstreamError,
    Shed,
    Malformed,
}

/// Log sink for query decisions (design §6: full query log is privacy-
/// sensitive and off by default — hence a no-op default hook).
pub trait DecisionHook: Send + Sync + 'static {
    fn on_decision(&self, event: &DecisionEvent);
}

/// Default hook: records nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopDecisionHook;

impl DecisionHook for NoopDecisionHook {
    fn on_decision(&self, _event: &DecisionEvent) {}
}

impl<F> DecisionHook for F
where
    F: Fn(&DecisionEvent) + Send + Sync + 'static,
{
    fn on_decision(&self, event: &DecisionEvent) {
        self(event)
    }
}

/// Cache key: the RAW wire-format qname bytes plus qtype/qclass. Never a
/// presentation string — raw wire bytes are injective, so a hostile
/// dot-in-a-label encoding (the single label `microsoft.com`) gets its own
/// entry and can never alias the two-label victim domain's cached answer.
type CacheKey = (Vec<u8>, u16, u16);

/// Per-exchange transaction-ID generator for upstream queries.
///
/// A keyed PRF (SipHash-1-3, reached through `RandomState`) over a counter.
/// The 128-bit key comes from the OS CSPRNG, drawn by std on first use —
/// which is how this stays dependency-free without inventing its own
/// entropy. Still NOT a CSPRNG: do not describe the output as "random".
/// What it does give is the property the threat model actually needs — the
/// sequence is not derivable from observed outputs.
///
/// WHY NOT THE PREVIOUS SHAPE: a Weyl counter (`fetch_add(GOLDEN)`) pushed
/// through an invertible GF(2)-linear xorshift, seeded once with
/// `nanos ^ pid.rotate_left(32)`. `rotate_left(32)` puts the pid in the HIGH
/// 32 bits, so the low 32 bits of the seed were wall-clock nanoseconds and
/// nothing else. With 100 ns clock granularity a +/-1 s window is 2e7
/// candidates: two observed IDs plus the pid recovered the state by brute
/// force in 22.7 ms (measured) and predicted every subsequent ID.
struct UpstreamTxids {
    counter: AtomicU64,
    key: RandomState,
}

impl UpstreamTxids {
    fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
            key: RandomState::new(),
        }
    }

    fn next(&self) -> u16 {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut h = self.key.build_hasher();
        h.write_u64(n);
        (h.finish() >> 32) as u16
    }
}

struct CacheEntry {
    bytes: Vec<u8>,
    expires_at: Instant,
}

struct State {
    config: ProxyConfig,
    engine: Arc<RwLock<FilterEngine>>,
    /// Live upstream list, mutable via [`Proxy::set_upstreams`] so the
    /// daemon can re-read adapter DNS on network-change events without
    /// rebinding. `config.upstreams` is only the constructor input.
    upstreams: RwLock<Vec<SocketAddr>>,
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
    /// Permit pool bounding in-flight UDP queries.
    semaphore: Arc<Semaphore>,
    /// SEPARATE, smaller pool bounding concurrent client TCP connections.
    tcp_semaphore: Arc<Semaphore>,
    txids: UpstreamTxids,
    counters: Arc<Counters>,
    hook: Arc<dyn DecisionHook>,
    upstream_rr: AtomicUsize,
}

impl State {
    fn decide(&self, qname: &str) -> Decision {
        // Survive lock poisoning without panicking: a panicked writer must
        // not take down DNS for the whole machine.
        let engine = self.engine.read().unwrap_or_else(|p| p.into_inner());
        engine.decide(qname)
    }

    /// Current upstream list (poisoning-tolerant — see `decide`).
    fn upstreams(&self) -> Vec<SocketAddr> {
        self.upstreams
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn pick_upstream(&self) -> Option<SocketAddr> {
        let upstreams = self.upstreams.read().unwrap_or_else(|p| p.into_inner());
        if upstreams.is_empty() {
            return None;
        }
        let idx = self.upstream_rr.fetch_add(1, Ordering::Relaxed) % upstreams.len();
        upstreams.get(idx).copied()
    }

    fn cache_get(&self, key: &CacheKey, id: u16) -> Option<Vec<u8>> {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let entry = cache.get(key)?;
        if entry.expires_at <= Instant::now() {
            cache.remove(key);
            return None;
        }
        let mut bytes = entry.bytes.clone();
        // The cached response carries the original query's ID; patch in the
        // new requester's ID (first two bytes) before serving.
        if bytes.len() >= 2 {
            bytes[0..2].copy_from_slice(&id.to_be_bytes());
        }
        Some(bytes)
    }

    fn cache_store(&self, key: &CacheKey, response: &[u8]) {
        let Some(info) = wire::response_info(response) else {
            return;
        };
        let ttl = if info.rcode == wire::RCODE_NXDOMAIN {
            // WHY: negative answers are cached for a short fixed window
            // (design: min(60s)); we do not parse the SOA for its TTL.
            self.config.negative_ttl
        } else if info.rcode == wire::RCODE_NOERROR {
            let Some(min_ttl) = info.min_ttl else {
                return; // answerless NOERROR (NODATA): not cached in v1
            };
            if min_ttl == 0 {
                return;
            }
            Duration::from_secs(u64::from(min_ttl)).min(self.config.max_ttl)
        } else {
            return; // SERVFAIL and friends are never cached
        };
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= self.config.cache_capacity {
            let now = Instant::now();
            cache.retain(|_, entry| entry.expires_at > now);
            if cache.len() >= self.config.cache_capacity {
                // WHY: bounded memory beats perfect caching — drop the
                // insert rather than grow without limit.
                return;
            }
        }
        cache.insert(
            key.clone(),
            CacheEntry {
                bytes: response.to_vec(),
                expires_at: Instant::now() + ttl,
            },
        );
    }

    fn emit(&self, client: SocketAddr, query: &wire::Query, outcome: QueryOutcome) {
        self.hook.on_decision(&DecisionEvent {
            client,
            qname: query.qname.clone(),
            qtype: query.qtype,
            qclass: query.qclass,
            outcome,
        });
    }
}

/// A bound proxy, ready to [`run`](Proxy::run).
pub struct Proxy {
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    state: Arc<State>,
    local_addr: SocketAddr,
}

impl Proxy {
    /// Bind UDP and TCP on `config.listen`. With port 0 the UDP socket picks
    /// an ephemeral port and TCP follows it onto the same port (retrying on
    /// collision) so both protocols share one address.
    ///
    /// Refuses an EMPTY upstream list: a resolver with no upstream is a lie
    /// — it would pass bind and the filter self-test while SERVFAILing every
    /// real query, and the NRPT catch-all would then blackhole the machine's
    /// DNS behind a "healthy" status.
    ///
    /// Also refuses SELF-REFERENTIAL upstreams (see [`validate_upstreams`]):
    /// forwarding to our own listener amplifies one client query into a
    /// full in-flight pool of internal queries, and refuses an unusable
    /// `health_check_name` (see the field docs).
    pub async fn bind(
        config: ProxyConfig,
        engine: FilterEngine,
        hook: Arc<dyn DecisionHook>,
    ) -> io::Result<Self> {
        validate_health_check_name(&config.health_check_name)?;
        // Pre-bind check: with a fixed listen port this catches the
        // self-referential cases without binding anything. With port 0 the
        // listen port is not chosen yet; the post-bind check below covers
        // the actual ephemeral port.
        validate_upstreams(&config.upstreams, config.listen)?;
        let state = Arc::new(State {
            semaphore: Arc::new(Semaphore::new(config.max_in_flight)),
            tcp_semaphore: Arc::new(Semaphore::new(config.tcp_max_connections)),
            txids: UpstreamTxids::new(),
            upstreams: RwLock::new(config.upstreams.clone()),
            config,
            engine: Arc::new(RwLock::new(engine)),
            cache: Mutex::new(HashMap::new()),
            counters: Arc::new(Counters::default()),
            hook,
            upstream_rr: AtomicUsize::new(0),
        });
        let mut last_err: Option<io::Error> = None;
        for _ in 0..BIND_RETRIES {
            let udp = UdpSocket::bind(state.config.listen).await?;
            let port = udp.local_addr()?.port();
            let mut tcp_addr = state.config.listen;
            tcp_addr.set_port(port);
            match TcpListener::bind(tcp_addr).await {
                Ok(tcp) => {
                    let local_addr = SocketAddr::new(state.config.listen.ip(), port);
                    // Post-bind check with the ACTUAL bound port: covers the
                    // ephemeral-port case the pre-bind check could not see.
                    // (A test upstream already bound on this exact port is
                    // impossible — the OS would not have handed us the port.)
                    validate_upstreams(&state.upstreams(), local_addr)?;
                    info!(%local_addr, upstreams = state.upstreams().len(), "dnsguard bound");
                    return Ok(Self {
                        udp: Arc::new(udp),
                        tcp,
                        state,
                        local_addr,
                    });
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrInUse, "could not bind UDP+TCP pair")
        }))
    }

    /// Address clients should send queries to (both protocols).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shared counters handle (valid before and after `run`).
    pub fn counters(&self) -> Arc<Counters> {
        Arc::clone(&self.state.counters)
    }

    /// Shared engine handle for live rule updates (block/allow add/remove)
    /// from the daemon's IPC layer.
    pub fn engine_handle(&self) -> Arc<RwLock<FilterEngine>> {
        Arc::clone(&self.state.engine)
    }

    /// Replace the upstream list at runtime (design: the daemon re-reads
    /// adapter DNS on network-change events). Takes effect on the next
    /// forwarded query; no rebind, no restart.
    ///
    /// Validated EXACTLY like [`Proxy::bind`]: non-empty, and no
    /// self-referential address (checked against the address we are
    /// actually bound on). On error the previous list is kept.
    pub fn set_upstreams(&self, upstreams: Vec<SocketAddr>) -> io::Result<()> {
        validate_upstreams(&upstreams, self.local_addr)?;
        let mut live = self
            .state
            .upstreams
            .write()
            .unwrap_or_else(|p| p.into_inner());
        info!(old = live.len(), new = upstreams.len(), "dnsguard upstreams replaced");
        *live = upstreams;
        Ok(())
    }

    /// Three-step health check (design §5 self-test layer). Call BEFORE
    /// `run` (and before the NRPT rule is installed): it temporarily
    /// serves the UDP socket itself for step (iii), and that private
    /// serving loop marks every query it answers as SYNTHETIC (skipped
    /// from the user-facing counters and the decision hook). Running it
    /// concurrently with `run` would race the real serving loop on the
    /// same socket and could mislabel a real query as synthetic — don't.
    ///
    /// 1. `engine_ok` — the filter decides the always-blocked canary
    ///    ([`crate::filter::CANARY_DOMAIN`]) as Block.
    /// 2. `upstream_ok` — a LIVE query for `config.health_check_name`
    ///    (default `example.com`) comes back NOERROR from EVERY configured
    ///    upstream. This step forwards DIRECTLY to the upstreams: it
    ///    validates upstream reachability only, never the listener.
    ///    `upstreams_healthy`/`upstreams_total` carry the detail.
    /// 3. `filter_ok` — the end-to-end step, through the actual UDP
    ///    listener. ALL of: (a) the canary comes back with OUR
    ///    self-identifying signature (NOERROR, AA=1, ancount=1, A rdata
    ///    0.0.0.0) — the serving path short-circuits the canary before
    ///    cache/filter/forward and synthesizes that signature
    ///    unconditionally, under BOTH `block_response` policies, so it
    ///    identifies this listener positively and can never be satisfied
    ///    by an upstream answer or a cached entry (the canary never
    ///    reaches either); (b) `counters.canary_probes` moved by EXACTLY 1
    ///    across the probe while the user-facing `queries`/`blocked` did
    ///    not move — a counter delta no upstream can fake, and proof the
    ///    probe did not pollute user statistics; (c) `health_check_name`
    ///    resolves POSITIVELY (NOERROR with at least one answer) through
    ///    the LISTENER — a proxy that answers the canary but SERVFAILs
    ///    everything else fails here.
    ///
    /// The daemon/reconciler must probe the PUBLIC socket
    /// (`127.0.0.1:53`), not [`Proxy::local_addr`] — a health check aimed
    /// at the address the proxy CHOSE validates the wrong thing; the DNS
    /// Client uses port 53.
    pub async fn self_test(&self) -> SelfTestReport {
        let mut report = SelfTestReport {
            engine_ok: false,
            upstream_ok: false,
            filter_ok: false,
            upstreams_healthy: 0,
            upstreams_total: 0,
            detail: String::new(),
        };
        use std::fmt::Write as _;

        // (i) engine decision on the canary.
        report.engine_ok = self.state.decide(crate::filter::CANARY_DOMAIN) == Decision::Block;
        if !report.engine_ok {
            let _ = write!(report.detail, "canary not decided Block by engine; ");
        }

        // (ii) live upstream query for the health-check name.
        let upstream_probe = wire::build_query(
            self.state.txids.next(),
            &self.state.config.health_check_name,
            wire::TYPE_A,
            wire::CLASS_IN,
        )
        .and_then(|bytes| wire::parse_query(&bytes).ok().map(|q| (bytes, q)));
        // EVERY configured upstream is probed, not just the round-robin
        // head: `forward` has no failover, so a single unreachable server in
        // the adapter's list breaks its share of the machine's DNS while a
        // head-only probe stays green. `upstream_ok` therefore means ALL of
        // them answered; the counts let the daemon tell "all good" apart
        // from "one of two dead".
        let upstreams = self.state.upstreams();
        report.upstreams_total = upstreams.len();
        match upstream_probe {
            Some((bytes, query)) => {
                for up in &upstreams {
                    match forward_via(&self.state, &bytes, &query, false, *up).await {
                        Ok(resp)
                            if wire::response_info(&resp)
                                .is_some_and(|info| info.rcode == wire::RCODE_NOERROR) =>
                        {
                            report.upstreams_healthy += 1;
                        }
                        Ok(_) => {
                            let _ = write!(
                                report.detail,
                                "upstream {up} answered health check with non-NOERROR; "
                            );
                        }
                        Err(e) => {
                            let _ = write!(report.detail, "upstream {up} health check failed: {e}; ");
                        }
                    }
                }
                report.upstream_ok = report.upstreams_total > 0
                    && report.upstreams_healthy == report.upstreams_total;
            }
            None => {
                let _ = write!(
                    report.detail,
                    "health_check_name {:?} cannot be encoded; ",
                    self.state.config.health_check_name
                );
            }
        }

        // (iii) end-to-end through the listener. The private serving loop
        // marks every query it answers SYNTHETIC, so the probes below skip
        // the user-facing counters and the decision hook entirely.
        let (tx, rx) = watch::channel(false);
        let loop_task = tokio::spawn(udp_loop(
            Arc::clone(&self.udp),
            Arc::clone(&self.state),
            rx,
            true,
        ));
        let sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await;
        let before = self.state.counters.snapshot();

        // (a) canary signature: NOERROR + AA + ancount 1 + A 0.0.0.0.
        let canary_ok = match (&sock, wire::build_query(
            self.state.txids.next(),
            crate::filter::CANARY_DOMAIN,
            wire::TYPE_A,
            wire::CLASS_IN,
        )) {
            (Ok(sock), Some(probe)) => {
                let id = u16::from_be_bytes([probe[0], probe[1]]);
                match probe_exchange(sock, &probe, self.local_addr, self.state.config.upstream_timeout).await {
                    Some(resp) => is_canary_signature(&resp, id),
                    None => false,
                }
            }
            _ => false,
        };
        if !canary_ok {
            let _ = write!(
                report.detail,
                "canary through listener did not return the local signature (0.0.0.0 A, AA=1); "
            );
        }

        // (c) POSITIVE resolution of the health-check name through the
        // LISTENER (not the direct forward of step (ii)): proves the
        // serving path resolves real names end to end.
        let resolves_ok = match (&sock, wire::build_query(
            self.state.txids.next(),
            &self.state.config.health_check_name,
            wire::TYPE_A,
            wire::CLASS_IN,
        )) {
            (Ok(sock), Some(probe)) => {
                match probe_exchange(sock, &probe, self.local_addr, self.state.config.upstream_timeout).await {
                    Some(resp) => {
                        wire::response_info(&resp).is_some_and(|info| {
                            info.rcode == wire::RCODE_NOERROR && info.min_ttl.is_some()
                        })
                    }
                    None => false,
                }
            }
            _ => false,
        };
        if !resolves_ok {
            let _ = write!(
                report.detail,
                "health_check_name did not resolve positively through the listener; "
            );
        }

        // (b) counter deltas across the probe: the canary must be counted
        // EXACTLY once in its OWN counter, and the user-facing counters
        // must not have moved (synthetic traffic is invisible to them).
        let after = self.state.counters.snapshot();
        if after.canary_probes != before.canary_probes + 1 {
            let _ = write!(
                report.detail,
                "canary_probes delta {} != 1 across probe; ",
                after.canary_probes.wrapping_sub(before.canary_probes)
            );
        }
        if after.queries != before.queries || after.blocked != before.blocked {
            let _ = write!(
                report.detail,
                "self-test probes leaked into user-facing counters ({before:?} -> {after:?}); "
            );
        }
        report.filter_ok = canary_ok
            && resolves_ok
            && after.canary_probes == before.canary_probes + 1
            && after.queries == before.queries
            && after.blocked == before.blocked;

        let _ = tx.send(true);
        loop_task.abort();
        report
    }

    /// Serve until `shutdown` is set to `true` (or its sender is dropped).
    /// Stops accepting new work; in-flight queries finish on their own,
    /// bounded by the upstream timeout.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        info!(addr = %self.local_addr, "dnsguard proxy starting");
        let udp_task = tokio::spawn(udp_loop(
            self.udp,
            Arc::clone(&self.state),
            shutdown.clone(),
            false,
        ));
        let tcp_task = tokio::spawn(tcp_loop(self.tcp, self.state, shutdown.clone()));
        // changed() errors when the sender is dropped — treat as shutdown.
        let _ = shutdown.changed().await;
        info!("dnsguard proxy shutting down");
        udp_task.abort();
        tcp_task.abort();
        Ok(())
    }
}

/// Outcome of [`Proxy::self_test`] — the daemon/reconciler health surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestReport {
    /// The filter engine decides the canary as Block.
    pub engine_ok: bool,
    /// A live query for `health_check_name` returned NOERROR from EVERY
    /// configured upstream. False if any one of them is unreachable —
    /// `forward` does not fail over, so a dead upstream is a real partial
    /// outage, not a redundancy the proxy can absorb.
    pub upstream_ok: bool,
    /// End-to-end through the listener: the canary returns the LOCAL
    /// signature (0.0.0.0 A, AA=1 — impossible to satisfy from an upstream
    /// or the cache, under either `block_response` policy), the
    /// `canary_probes` counter moved by exactly 1 while the user-facing
    /// counters did not move, and `health_check_name` resolves POSITIVELY
    /// through the listener. False when the serving path is broken OR when
    /// real names do not resolve through it (e.g. every upstream dead).
    pub filter_ok: bool,
    /// Configured upstreams that answered the health check with NOERROR.
    pub upstreams_healthy: usize,
    /// Configured upstreams probed. `healthy < total` is a partial DNS
    /// outage for the whole machine and must not read as green.
    pub upstreams_total: usize,
    /// Human-readable failure detail (empty when all steps passed).
    pub detail: String,
}

impl SelfTestReport {
    /// All three steps passed.
    pub fn ok(&self) -> bool {
        self.engine_ok && self.upstream_ok && self.filter_ok
    }
}

/// Reject upstreams that would route our own forwarded queries back into
/// our listener — a self-referential upstream amplifies ONE client query
/// into a full in-flight pool of internal queries (measured: 65 internal
/// queries + 1 shed at `max_in_flight=64`) until the semaphore sheds.
///
/// Exact scope of the rule, and why:
/// - `upstream == listen` (address AND port): always refused — that IS us.
/// - ANY loopback upstream (all of 127.0.0.0/8 and ::1) on the LISTEN
///   PORT, when we listen on loopback or wildcard: refused. Adapter DNS
///   discovery legitimately returns 127.0.0.1 on any box that has run
///   dnscrypt-proxy/Acrylic/Pi-hole-on-host/a prior Sentinella, and the
///   whole 127/8 aliases the loopback interface, so bind-specificity
///   (127.0.0.1 vs 127.0.0.2) is not a safety boundary we rely on — a
///   second resolver on another loopback alias of the same port is either
///   us-after-rebind or a sibling proxy, and both loop.
/// - Loopback upstreams on OTHER ports are fine and heavily used: the
///   test-suite fake upstreams live on 127.0.0.1 with ephemeral ports.
///   The rule is about the LISTEN port, never about loopback in general.
/// - With `listen` port 0 the port is not chosen yet, so only the exact
///   `upstream == listen` case is caught here; `bind` re-runs this check
///   against the ACTUAL bound address.
///
/// NOT covered (documented, dependency-free code cannot see it): an
/// upstream on one of the machine's LAN interface addresses combined with
/// a wildcard listen. That shape needs interface enumeration; the daemon
/// is expected to refuse it when it discovers upstreams.
fn validate_upstreams(upstreams: &[SocketAddr], listen: SocketAddr) -> io::Result<()> {
    if upstreams.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no upstream configured: a resolver with no upstream is a lie",
        ));
    }
    for upstream in upstreams {
        let self_referential = *upstream == listen
            || (listen.port() != 0
                && upstream.port() == listen.port()
                && upstream.ip().is_loopback()
                && (listen.ip().is_loopback() || listen.ip().is_unspecified()));
        if self_referential {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "upstream {upstream} is self-referential (we listen on {listen}): \
                     forwarding to our own listener amplifies every query"
                ),
            ));
        }
    }
    Ok(())
}

/// Validate the configured `health_check_name` (see the field docs for the
/// contract). Rejects empty/root names, names `wire::build_query` cannot
/// encode, and any backslash — the query builder is escape-unaware, so a
/// `\` would silently turn the probe into a query for a DIFFERENT name.
fn validate_health_check_name(name: &str) -> io::Result<()> {
    let invalid = |msg: &str| io::Error::new(io::ErrorKind::InvalidInput, msg.to_string());
    if name.trim_end_matches('.').is_empty() {
        return Err(invalid(
            "health_check_name must not be empty or the root name: \
             the self-test needs a real name to resolve",
        ));
    }
    if name.contains('\\') {
        return Err(invalid(
            "health_check_name must not contain '\\': the query builder is \
             escape-unaware and would silently probe a different name",
        ));
    }
    if wire::build_query(0, name, wire::TYPE_A, wire::CLASS_IN).is_none() {
        return Err(invalid(
            "health_check_name cannot be encoded as a DNS wire name \
             (empty label, label > 63 octets, or name > 255 wire bytes)",
        ));
    }
    Ok(())
}

/// One UDP exchange against the listener during self-test step (iii):
/// send `probe`, wait up to `wait` for the answer. `None` on any failure.
async fn probe_exchange(
    sock: &UdpSocket,
    probe: &[u8],
    listener: SocketAddr,
    wait: Duration,
) -> Option<Vec<u8>> {
    sock.send_to(probe, listener).await.ok()?;
    let mut buf = [0u8; MAX_DATAGRAM];
    let n = timeout(wait, sock.recv(&mut buf)).await.ok()?.ok()?;
    Some(buf[..n].to_vec())
}

/// The canary signature only THIS proxy can produce: NOERROR, AA=1,
/// exactly one answer, A rdata 0.0.0.0, and the probe's own txid echoed.
/// `build_zero_ip_response` lays the answer record out last, so the rdata
/// is the final 4 bytes. No stock upstream satisfies this for an `.invalid`
/// name (they NXDOMAIN), and the short-circuit guarantees it never comes
/// from cache either.
fn is_canary_signature(resp: &[u8], probe_id: u16) -> bool {
    if resp.len() < wire::HEADER_LEN + 4 {
        return false;
    }
    if u16::from_be_bytes([resp[0], resp[1]]) != probe_id {
        return false;
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    flags & 0x000F == 0 // NOERROR
        && flags & wire::FLAG_AA != 0
        && u16::from_be_bytes([resp[6], resp[7]]) == 1 // ancount
        && resp[resp.len() - 4..] == [0, 0, 0, 0]
}

/// Serve one UDP socket until shutdown. When `synthetic` is true (the
/// self-test's private serving loop), every query answered here is a
/// health-check probe: it skips the user-facing counters and the decision
/// hook, so probes no client ever issued cannot leak into the GUI/IPC
/// statistics or the query log. The canary's OWN counter
/// (`canary_probes`) still moves — the self-test asserts on it.
async fn udp_loop(
    sock: Arc<UdpSocket>,
    state: Arc<State>,
    mut shutdown: watch::Receiver<bool>,
    synthetic: bool,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            received = sock.recv_from(&mut buf) => {
                let (n, peer) = match received {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "UDP recv failed");
                        continue;
                    }
                };
                let bytes = buf[..n].to_vec();
                match state.semaphore.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let state = Arc::clone(&state);
                        let sock = Arc::clone(&sock);
                        tokio::spawn(async move {
                            let _permit = permit; // released when the query completes
                            if let Some(resp) = handle_query(&state, &bytes, peer, false, synthetic).await {
                                // UDP payload limit (v1: a flat 512 — we
                                // strip EDNS0 from forwarded queries, so no
                                // client UDP size is ever negotiated; see
                                // wire::MAX_UDP_PAYLOAD). An oversized
                                // answer — e.g. a TCP-fallback answer of up
                                // to 65535 bytes replayed from cache —
                                // would be dropped by the client OS with TC
                                // clear and no retry signal. Emit an RFC
                                // 2181-style truncated response instead so
                                // the client retries over TCP, where the
                                // full answer is served.
                                let resp = if resp.len() > wire::MAX_UDP_PAYLOAD {
                                    wire::build_truncated_response(&bytes).unwrap_or(resp)
                                } else {
                                    resp
                                };
                                let _ = sock.send_to(&resp, peer).await;
                            }
                        });
                    }
                    Err(_) => shed(&state, &bytes, peer, &sock).await,
                }
            }
        }
    }
}

/// Overload path: answer immediately with SERVFAIL. WHY SERVFAIL and not a
/// drop: a dropped query leaves the client's resolver retrying for seconds;
/// SERVFAIL makes it move on (or fail over to the NRPT secondary) at once.
async fn shed(state: &Arc<State>, bytes: &[u8], peer: SocketAddr, sock: &UdpSocket) {
    state.counters.bump(&state.counters.shed);
    state.counters.bump(&state.counters.queries);
    if let Ok(query) = wire::parse_query(bytes) {
        state.emit(peer, &query, QueryOutcome::Shed);
    }
    if let Some(resp) = wire::build_error_response(bytes, wire::RCODE_SERVFAIL, false) {
        let _ = sock.send_to(&resp, peer).await;
    }
    debug!(%peer, "query shed: in-flight limit reached");
}

async fn tcp_loop(listener: TcpListener, state: Arc<State>, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "TCP accept failed");
                        continue;
                    }
                };
                match state.tcp_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            tcp_conn(stream, peer, state, permit).await;
                        });
                    }
                    Err(_) => {
                        // TCP pool exhausted (separate from UDP by design):
                        // close the connection. Clients retry or fall back
                        // to UDP; unbounded TCP tasks are worse.
                        state.counters.bump(&state.counters.shed);
                        drop(stream);
                    }
                }
            }
        }
    }
}

/// Serve one client TCP connection. Two independent clocks bound it
/// (design §5): an inter-read IDLE timeout (`tcp_idle_timeout`) and a HARD
/// total-lifetime cap (`tcp_max_lifetime`).
///
/// INVARIANT: the SUM of every wait on this connection is <= the hard cap.
/// Each await re-derives its budget from `deadline`. Computing one budget
/// and sharing it across two awaits is NOT equivalent: a client can land the
/// first await's completion just under the deadline and then start a second
/// full-length wait. That is not hypothetical — sharing one `read_budget`
/// between the length-prefix read and the body read measured 1.99x the cap
/// (split the 2-byte prefix across the deadline), and 6.99x once an
/// unbounded `handle_query` chained a slow upstream onto it.
async fn tcp_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<State>,
    _permit: OwnedSemaphorePermit,
) {
    /// Lifetime left, or `None` once the hard cap is spent.
    fn left(deadline: tokio::time::Instant) -> Option<Duration> {
        let d = deadline.saturating_duration_since(tokio::time::Instant::now());
        (!d.is_zero()).then_some(d)
    }

    let deadline = tokio::time::Instant::now() + state.config.tcp_max_lifetime;
    let idle = state.config.tcp_idle_timeout;

    // (1) 2-byte length prefix — the loop condition is also this step's
    // budget check, so a spent cap ends the connection before any new read.
    while let Some(budget) = left(deadline) {
        let mut len_buf = [0u8; 2];
        if !matches!(
            timeout(budget.min(idle), stream.read_exact(&mut len_buf)).await,
            Ok(Ok(_))
        ) {
            break; // EOF, peer error, idle timeout, or lifetime cap
        }

        // (2) message body.
        let Some(budget) = left(deadline) else { break };
        let mut buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        if !matches!(
            timeout(budget.min(idle), stream.read_exact(&mut buf)).await,
            Ok(Ok(_))
        ) {
            break;
        }

        // (3) resolve. Without the deadline this await is bounded only by
        // `upstream_timeout`, which then chains onto the read waits above.
        let Some(budget) = left(deadline) else { break };
        let Ok(Some(resp)) = timeout(budget, handle_query(&state, &buf, peer, true, false)).await else {
            break; // over budget, or not even a header to echo an ID for
        };

        // (4) write back. An unbounded `write_all` lets a pipelining client
        // that never reads park the permit forever on a full send buffer.
        let Some(budget) = left(deadline) else { break };
        let framed_len = (resp.len() as u16).to_be_bytes();
        let written = timeout(budget, async {
            stream.write_all(&framed_len).await?;
            stream.write_all(&resp).await
        })
        .await;
        if !matches!(written, Ok(Ok(()))) {
            break;
        }
    }

    // ONE exit point, so the counter cannot disagree with the clock. Each
    // site used to bump on `timeout_elapsed && deadline_passed`, which
    // reported a successful cap kill for a connection that had ALREADY
    // outlived the cap — and `tcp_lifetime_kills` is exactly what the
    // certifying test asserts on, so the test passed on the very connection
    // that proved the bug.
    if tokio::time::Instant::now() >= deadline {
        debug!(%peer, "TCP connection closed: hard lifetime cap reached");
        state.counters.bump(&state.counters.tcp_lifetime_kills);
    }
}

/// Core pipeline, shared by UDP and TCP clients: parse → decide → answer.
/// Returns `None` only when the input is too short to echo an ID for.
///
/// `synthetic` marks health-check probes (the self-test's private serving
/// loop): synthetic queries skip the user-facing counters and the decision
/// hook so probe traffic never lands in the GUI/IPC statistics or the
/// query log.
async fn handle_query(
    state: &Arc<State>,
    bytes: &[u8],
    client: SocketAddr,
    via_tcp: bool,
    synthetic: bool,
) -> Option<Vec<u8>> {
    let query = match wire::parse_query(bytes) {
        Ok(q) => q,
        Err(e) => {
            if !synthetic {
                state.counters.bump(&state.counters.queries);
            }
            debug!(error = %e, %client, "malformed DNS query");
            return wire::build_error_response(bytes, wire::RCODE_FORMERR, false);
        }
    };

    // CANARY SHORT-CIRCUIT — by name identity, BEFORE decide/cache/forward
    // and before any user-facing counter. The canary is answered with the
    // zero-IP signature UNCONDITIONALLY (independent of `block_response`
    // and of the engine's own canary rule), so:
    //   - it can never leak upstream or be cached (L07: a forwarded canary
    //     used to ride the negative cache for 60 s);
    //   - "canary → 0.0.0.0 A with AA=1" positively identifies THIS
    //     listener — no stock upstream produces it, and `.invalid`
    //     NXDOMAINs everywhere else (L12);
    //   - the answer is the same under both block policies, which is what
    //     makes the health check policy-independent (A3).
    // The wire decoder's escaped presentation is injective, and the canary
    // is plain ASCII, so a case-insensitive compare matches exactly the
    // canary's wire encodings — nothing else.
    if query
        .qname
        .eq_ignore_ascii_case(crate::filter::CANARY_DOMAIN)
    {
        state.counters.bump(&state.counters.canary_probes);
        debug!(%client, "canary probe answered with local signature");
        return wire::build_zero_ip_response(bytes, ZERO_IP_TTL);
    }

    if !synthetic {
        state.counters.bump(&state.counters.queries);
    }

    if state.decide(&query.qname) == Decision::Block {
        if !synthetic {
            state.counters.bump(&state.counters.blocked);
            state.emit(client, &query, QueryOutcome::Blocked);
        }
        debug!(qname = %query.qname, %client, "blocked");
        // Locally synthesized block answers carry AA=1: the self-identifying
        // mark that distinguishes "our filter fired" from "an upstream
        // returned the same rcode" (L07).
        return match state.config.block_response {
            BlockResponse::Nxdomain => {
                wire::build_error_response(bytes, wire::RCODE_NXDOMAIN, true)
            }
            BlockResponse::ZeroIp => wire::build_zero_ip_response(bytes, ZERO_IP_TTL),
        };
    }

    // Cache key: raw wire-format qname bytes (injective — see CacheKey) so
    // case variants do NOT collapse; upstreams answer case-insensitively
    // but keying on bytes is the safe direction (no aliasing, ever).
    let cache_key: CacheKey = (query.qname_wire.clone(), query.qtype, query.qclass);
    if let Some(resp) = state.cache_get(&cache_key, query.id) {
        if !synthetic {
            state.counters.bump(&state.counters.cache_hits);
            state.emit(client, &query, QueryOutcome::CacheHit);
        }
        return Some(resp);
    }

    match forward(state, bytes, &query, via_tcp).await {
        Ok(mut resp) => {
            if !synthetic {
                state.counters.bump(&state.counters.forwarded);
            }
            // Restore the client's original txid: the wire bytes went
            // upstream with OUR generated ID (see forward).
            if resp.len() >= 2 {
                resp[0..2].copy_from_slice(&query.id.to_be_bytes());
            }
            // Only validated responses reach this point (forward drops
            // anything failing txid/QR/question checks), so caching here
            // can never poison the cache with a forgery.
            state.cache_store(&cache_key, &resp);
            if !synthetic {
                state.emit(client, &query, QueryOutcome::Forwarded);
            }
            Some(resp)
        }
        Err(e) => {
            if !synthetic {
                state.counters.bump(&state.counters.upstream_errors);
                state.emit(client, &query, QueryOutcome::UpstreamError);
            }
            warn!(error = %e, qname = %query.qname, "upstream exchange failed");
            wire::build_error_response(bytes, wire::RCODE_SERVFAIL, false)
        }
    }
}

/// Forward to the upstream pool: UDP first, TCP when the client is TCP or
/// the UDP answer comes back truncated (TC bit).
///
/// The upstream sees a CLEAN query built from scratch
/// ([`wire::build_upstream_query`]): a freshly GENERATED transaction ID
/// (never the client's verbatim), standard flags (RD=1 only), the
/// question section, and NOTHING else — the client's flag byte,
/// additional sections, and any EDNS0 OPT (including ECS, which would
/// steer the answer we then cache machine-wide) are never forwarded.
///
/// Every response is validated ([`wire::validate_response`]: QR set, our
/// txid, question echoed — qname case-insensitive per RFC 4343, qtype/
/// qclass exact) before it is accepted. An invalid response is dropped —
/// counted as an upstream error by the caller, never answered, never
/// cached.
async fn forward(
    state: &Arc<State>,
    query_bytes: &[u8],
    query: &wire::Query,
    via_tcp: bool,
) -> io::Result<Vec<u8>> {
    let upstream = state
        .pick_upstream()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no upstream configured"))?;
    forward_via(state, query_bytes, query, via_tcp, upstream).await
}

/// [`forward`] against a SPECIFIC upstream.
///
/// Split out so the health check can probe EVERY configured upstream rather
/// than whichever one round-robin happens to hand it. `forward` has no
/// failover: one dead server in a two-server adapter list SERVFAILs its
/// share of the machine's queries, and a head-only probe reported that as
/// green (`engine_ok`/`upstream_ok`/`filter_ok` all true, empty detail,
/// while 4 of 8 real names SERVFAILed).
async fn forward_via(
    state: &Arc<State>,
    query_bytes: &[u8],
    query: &wire::Query,
    via_tcp: bool,
    upstream: SocketAddr,
) -> io::Result<Vec<u8>> {
    let upstream_id = state.txids.next();
    let question = &query_bytes[wire::HEADER_LEN..query.question_end];
    let forwarded = wire::build_upstream_query(upstream_id, question);

    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream response failed validation (txid/QR/question)",
        )
    };
    if !via_tcp {
        match udp_exchange(upstream, &forwarded, upstream_id, state.config.upstream_timeout).await {
            Ok(resp) if wire::validate_response(&resp, upstream_id, question).is_none() => {
                return Err(invalid());
            }
            Ok(resp) if !wire::is_truncated_response(&resp) => return Ok(resp),
            Ok(_) => {
                debug!(%upstream, "TC bit set, retrying over TCP");
            }
            Err(e) => {
                // WHY no TCP retry on UDP timeout: a silent upstream over
                // UDP is silent over TCP too; retrying would double the
                // latency budget for nothing.
                return Err(e);
            }
        }
    }
    let resp = tcp_exchange(upstream, &forwarded, state.config.upstream_timeout).await?;
    if wire::validate_response(&resp, upstream_id, question).is_none() {
        return Err(invalid());
    }
    Ok(resp)
}

async fn udp_exchange(
    upstream: SocketAddr,
    query: &[u8],
    expected_id: u16,
    wait: Duration,
) -> io::Result<Vec<u8>> {
    // Ephemeral socket per query: no shared-socket ID demultiplexing, and
    // the in-flight semaphore bounds how many exist at once.
    let bind_addr = if upstream.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(upstream).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; MAX_DATAGRAM];
    // Receive LOOP within the exchange deadline: a stray/invalid datagram
    // (off-path garbage, a late answer from a previous exchange, a packet
    // with the wrong txid) is dropped and we keep waiting — one stray
    // datagram must not kill a healthy exchange. Only the deadline gives
    // up. Deeper validation (QR, question echo) happens in the caller.
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "upstream UDP timeout"));
        }
        let n = timeout(remaining, sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream UDP timeout"))??;
        if n < wire::HEADER_LEN {
            continue; // not even a header: stray garbage, keep waiting
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        if id != expected_id {
            continue; // not ours: stray or spoof attempt, keep waiting
        }
        buf.truncate(n);
        return Ok(buf);
    }
}

async fn tcp_exchange(upstream: SocketAddr, query: &[u8], wait: Duration) -> io::Result<Vec<u8>> {
    timeout(wait, async {
        let mut stream = TcpStream::connect(upstream).await?;
        let len = (query.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(query).await?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await?;
        Ok(buf)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream TCP timeout"))?
}


#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((ip, port))
    }

    #[test]
    fn validate_upstreams_rejects_empty() {
        assert!(validate_upstreams(&[], addr([127, 0, 0, 1], 53)).is_err());
        assert!(validate_upstreams(&[], addr([127, 0, 0, 1], 0)).is_err());
    }

    #[test]
    fn validate_upstreams_rejects_listen_identity_and_loopback_on_listen_port() {
        let listen = addr([127, 0, 0, 1], 53);
        // Exact identity.
        assert!(validate_upstreams(&[listen], listen).is_err());
        // Another loopback alias on the listen port (127/8 is all loopback).
        assert!(validate_upstreams(&[addr([127, 0, 0, 2], 53)], listen).is_err());
        assert!(validate_upstreams(&[addr([127, 44, 0, 9], 53)], listen).is_err());
        // IPv6 loopback on the listen port, with a wildcard listen.
        let wildcard = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53);
        assert!(validate_upstreams(&[SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53)], wildcard).is_err());
        assert!(validate_upstreams(&[addr([127, 0, 0, 1], 53)], addr([0, 0, 0, 0], 53)).is_err());
        // One bad apple in a longer list fails the whole list.
        assert!(validate_upstreams(&[addr([9, 9, 9, 9], 53), listen], listen).is_err());
    }

    #[test]
    fn validate_upstreams_accepts_legit_loopback_and_remote() {
        let listen = addr([127, 0, 0, 1], 53);
        // THE TEST-SUITE SHAPE: loopback upstream on a DIFFERENT port must
        // stay legal — the rule is about the listen port, not loopback.
        assert!(validate_upstreams(&[addr([127, 0, 0, 1], 5353)], listen).is_ok());
        assert!(validate_upstreams(&[addr([127, 0, 0, 1], 9)], listen).is_ok());
        // Remote upstreams.
        assert!(validate_upstreams(&[addr([9, 9, 9, 9], 53), addr([1, 1, 1, 1], 53)], listen).is_ok());
        // Non-loopback listen: a loopback upstream on the listen port is
        // NOT us (a socket bound to 192.0.2.1 does not receive 127/8
        // traffic) — accepted; the daemon owns the LAN-address case.
        let lan_listen = addr([192, 0, 2, 1], 53);
        assert!(validate_upstreams(&[addr([127, 0, 0, 1], 53)], lan_listen).is_ok());
        assert!(validate_upstreams(&[lan_listen], lan_listen).is_err(), "identity still refused");
    }

    #[test]
    fn validate_upstreams_with_ephemeral_listen_port_only_catches_identity() {
        // Port 0: the port is not chosen yet, so port-based checks are
        // skipped (the post-bind re-check covers the actual port).
        let listen = addr([127, 0, 0, 1], 0);
        assert!(validate_upstreams(&[listen], listen).is_err(), "identity still refused");
        assert!(validate_upstreams(&[addr([127, 0, 0, 1], 53)], listen).is_ok());
    }

    #[test]
    fn validate_health_check_name_rejects_empty_root_unencodable_backslash() {
        assert!(validate_health_check_name("").is_err());
        assert!(validate_health_check_name(".").is_err());
        assert!(validate_health_check_name("a..b").is_err());
        // Escape-unaware encoding would silently probe a different name.
        assert!(validate_health_check_name("exam\\.ple.com").is_err());
        assert!(validate_health_check_name("dangling\\").is_err());
        // Overlong label / name.
        assert!(validate_health_check_name(&"a".repeat(64)).is_err());
        assert!(
            validate_health_check_name(&format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(63)
            ))
            .is_err()
        );
        // Legit names, with and without the trailing root dot.
        assert!(validate_health_check_name("example.com").is_ok());
        assert!(validate_health_check_name("example.com.").is_ok());
    }

    #[test]
    fn canary_signature_check_is_strict() {
        let query = wire::build_query(0x1234, crate::filter::CANARY_DOMAIN, wire::TYPE_A, wire::CLASS_IN)
            .expect("build");
        let good = wire::build_zero_ip_response(&query, 60).expect("signature");
        assert!(is_canary_signature(&good, 0x1234));

        // Wrong txid.
        assert!(!is_canary_signature(&good, 0x9999));
        // Upstream-style NXDOMAIN for the same name: not the signature.
        let nxdomain = wire::build_error_response(&query, wire::RCODE_NXDOMAIN, false).expect("nx");
        assert!(!is_canary_signature(&nxdomain, 0x1234));
        // Zero-IP WITHOUT AA (a hypothetical relayed/mocked answer): rejected.
        let mut no_aa = good.clone();
        no_aa[2] &= !(wire::FLAG_AA >> 8) as u8;
        assert!(!is_canary_signature(&no_aa, 0x1234));
        // Non-zero rdata.
        let mut bad_rdata = good.clone();
        let n = bad_rdata.len();
        bad_rdata[n - 1] = 1;
        assert!(!is_canary_signature(&bad_rdata, 0x1234));
        // Total on short input.
        for len in 0..wire::HEADER_LEN + 4 {
            assert!(!is_canary_signature(&good[..len], 0x1234));
        }
    }
}

//! Tokio DNS proxy: UDP + TCP listeners, filter decision, upstream
//! forwarding with UDP-first/TCP-fallback, TTL-respecting cache, bounded
//! in-flight queries, and graceful shutdown via a `watch` channel.
//!
//! Design doc §3/§5 invariants implemented here:
//! - fail-safe: malformed query → FORMERR, dead upstream → SERVFAIL,
//!   overload → SERVFAIL shed, TCP-pool exhaustion → a bounded FIFO wait
//!   then SERVFAIL, so the path truncation sent the client to answers
//!   rather than resetting. The one remaining bare close is when the WAIT
//!   QUEUE is also full (`tcp_max_queued` waiters already pending), which
//!   is a connect flood rather than pool pressure — not "never", and the
//!   accept loop counts it in `tcp_pool_full`; the machine's DNS never
//!   hangs on us;
//! - bounded everything: in-flight semaphores (UDP and a SEPARATE TCP pool
//!   with a per-connection total-lifetime cap and a bounded accept queue —
//!   dribbling TCP clients cannot starve UDP and thereby force the
//!   fail-open path, which would also bypass filtering: under
//!   `on_proxy_failure = "fallback"`, load that kills the proxy removes
//!   filtering; that policy knob is the control), cache capacity, upstream
//!   timeouts, datagram size;
//! - upstream responses are validated before use: QR set, transaction ID
//!   matching the per-query ID we generated upstream-side, question echoed
//!   (qname case-insensitive per RFC 4343, qtype/qclass exact); upstream
//!   queries are rebuilt CLEAN (fresh txid, RD=1, question only) — the only
//!   client-controlled bits that leave the machine are CD (RFC 4035) and a
//!   single self-constructed OPT carrying the client's clamped UDP size and
//!   DO bit (round-3 L01 decision: relay DO/CD so self-validating stubs are
//!   not silently downgraded; AD is cleared on every response because we
//!   validate nothing; ECS and all other options are never relayed);
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
/// Separate permit pool for client TCP connections (design §5): loopback
/// TCP connections are cheap to hold open, so they must not share the UDP
/// in-flight budget.
///
/// WHY 128 (raised from 32 in round 3, A1/A2): truncation routes every
/// UDP answer that exceeds the client's advertised payload size onto this
/// listener, so the pool now serves ordinary retry traffic, not only
/// deliberate TCP clients. EDNS-aware truncation keeps 513–4096-byte
/// answers on UDP, so what remains is non-EDNS stubs (>512) and EDNS
/// clients past 4096 — but a burst of those must not self-DoS. Worst-case
/// transient memory is bounded: 128 connections × ≤64 KiB body buffer ≈
/// 8 MiB under maximal pipelining, typically a few KiB each; idle and
/// lifetime caps bound how long a squatter can hold a permit, and the
/// bounded FIFO queue plus SERVFAIL-on-overflow make exhaustion
/// survivable rather than a connection reset.
pub const DEFAULT_TCP_MAX_CONNECTIONS: usize = 128;
/// How long an accepted TCP connection waits in the FIFO queue for a
/// connection permit before it is answered SERVFAIL (fail-safe overflow,
/// never a bare reset). Short on purpose: a queued client is better off
/// retrying than holding a socket open.
pub const DEFAULT_TCP_QUEUE_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
/// Internal cache-lifetime cap: we cache a response for at most this long
/// (min(upstream TTL, 300s)). This clamps only how long WE serve a cached
/// entry; it never rewrites the TTL bytes inside the cached response,
/// which are forwarded to clients exactly as the upstream sent them.
pub const DEFAULT_MAX_TTL: Duration = Duration::from_secs(300);
/// Negative (NXDOMAIN) cache lifetime (design: min(60s)).
pub const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(60);
pub const DEFAULT_CACHE_CAPACITY: usize = 10_000;
/// SECOND cache bound, in BYTES of stored response — the entry cap alone
/// does not bound memory.
///
/// WHY: a cached entry holds the response verbatim, and `tcp_exchange`
/// accepts a full u16-framed answer, so ONE entry can be 65535 bytes. At
/// the entry cap alone, 10_000 such entries are ~640 MB resident in a
/// service running as SYSTEM, and any unprivileged local process can drive
/// it there by resolving 10_000 distinct names under a zone that serves
/// ~64 KB TXT RRsets — refreshable for as long as it keeps asking. This is
/// the same entries-vs-bytes mistake `filter.rs` documents for
/// `MAX_HOSTS_BYTES`: memory is proportional to BYTES, not to entries.
///
/// 8 MiB is chosen so the ENTRY cap is what binds in ordinary operation
/// (a typical answer is a few hundred bytes, so 10_000 of them are ~3 MB)
/// and this cap binds only on the abusive shape.
pub const CACHE_MAX_BYTES: usize = 8 * 1024 * 1024;
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
    /// HARD cap on a client TCP connection's SERVICE time (design §5). The
    /// clock starts when the connection WINS ITS POOL PERMIT, not at
    /// accept: a connection's total accept-to-close age is therefore
    /// bounded by `tcp_queue_timeout + tcp_max_lifetime`, not by this value
    /// alone (round-3 closure review, U08 — measured 2.28x when the two
    /// were confused). Starting the clock at accept would be worse, not
    /// better: a client that waited out most of the queue window would then
    /// be served for the remainder and killed mid-answer, which is exactly
    /// the bare-reset failure the FIFO+SERVFAIL fail-safe exists to avoid.
    /// Once serving, the connection is closed when it is this old no matter
    /// how active it is — an idle timeout alone lets dribbling connections
    /// hold a permit forever. EVERY socket operation on the connection — both reads and
    /// the response WRITES — is bounded by the time remaining until this
    /// deadline, so a pipelining client that never reads (kernel send
    /// buffer full, `write_all` parked) cannot hold its permit past the
    /// cap either.
    pub tcp_max_lifetime: Duration,
    /// Size of the SEPARATE TCP connection permit pool (design §5).
    /// Deliberately smaller than `max_in_flight` and never shared with
    /// it, so TCP clients cannot starve UDP query handling.
    pub tcp_max_connections: usize,
    /// Bounded FIFO wait for a TCP connection permit (round 3, A2):
    /// accepted connections queue (fair, arrival-ordered) for at most this
    /// long; on timeout the client gets SERVFAIL for its pending query —
    /// a retryable answer, never a bare RST/EOF on the path truncation
    /// sent it to. Tokio's semaphore queue is FIFO, so a reconnecting
    /// squatter cannot jump ahead of clients that arrived earlier.
    pub tcp_queue_timeout: Duration,
    /// Maximum number of TCP connections queued waiting for a permit.
    /// Bounds the tasks a connect flood can make us spawn; connections
    /// beyond it are dropped (counted in `tcp_pool_full`).
    pub tcp_max_queued: usize,
    /// Name the [`Proxy::self_test`] health probes resolve
    /// (default `example.com` — IANA-reserved, stable, guaranteed to
    /// exist).
    ///
    /// What the two probe steps actually prove with this name: step (ii)
    /// forwards it DIRECTLY to each upstream, bypassing the listener, the
    /// cache, and the filter — it validates upstream reachability ONLY and
    /// says nothing about whether the listener can resolve anything. Step
    /// (iii) resolves it again THROUGH the listener (parse → decide →
    /// cache/forward → respond) AND requires the engine to decide it
    /// `Allow`, so a name the filter blocks fails step (iii) under BOTH
    /// block policies: pick a name you never intend to block. The engine
    /// check is what makes that true — the answer's shape alone cannot
    /// carry it, because a ZeroIp block answer is NOERROR with an A record
    /// and is therefore indistinguishable from a resolution.
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
            tcp_queue_timeout: DEFAULT_TCP_QUEUE_TIMEOUT,
            tcp_max_queued: DEFAULT_TCP_MAX_CONNECTIONS,
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
    /// Client TCP connections that hit a FULL pool: waited out the bounded
    /// FIFO queue (answered SERVFAIL) or found the queue itself full
    /// (dropped). Deliberately SEPARATE from `shed` (round 3, A2): TCP-pool
    /// exhaustion must be distinguishable from UDP in-flight shedding in
    /// the daemon's health surface.
    pub tcp_pool_full: AtomicU64,
    /// Health-check canary probes answered with the local signature. This
    /// is deliberately SEPARATE from `queries`/`blocked`: canary answers
    /// are synthesized unconditionally (never a filter decision, never
    /// user traffic), so counting them as user-facing "blocked" would make
    /// the GUI/IPC "domains blocked" figure include probes no client ever
    /// issued. The self-test asserts a delta of AT LEAST the number of its
    /// own canary probes that SUCCEEDED — the UDP one in step (iii) plus
    /// the TCP one in step (iv), so up to 2, and fewer when a probe failed
    /// (a starved TCP pool SERVFAILs before the query is ever counted).
    /// A LOWER BOUND and not equality, deliberately (U01): this counter is
    /// NOT gated on `synthetic`, so any other local process querying the
    /// canary inside the self-test window inflates it — and the design's
    /// own operator acceptance test sends exactly that query, so equality
    /// would red a healthy proxy on concurrent traffic.
    /// A signal no upstream can fake: an impostor owning port 53 can forge
    /// the signature but leaves THIS counter at 0.
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
    pub tcp_pool_full: u64,
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
            tcp_pool_full: self.tcp_pool_full.load(Ordering::Relaxed),
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
    /// Query with an opcode other than QUERY (0): refused with NOTIMP
    /// before any filter/cache/forward work (round 3, L04).
    NotImplemented,
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
///
/// The trailing byte forks the entry on the client's DNSSEC posture (round
/// 3, L01): bit 0 = DO, bit 1 = CD. A DO=1 answer carries RRSIGs a DO=0
/// client must not be served spuriously, and a self-validating (DO=1) stub
/// must never be served a signature-less answer cached for a DO=0 client —
/// its validation would spuriously fail. CD forks because a CD=1 answer
/// was returned WITHOUT upstream validation and must not leak to clients
/// that asked for validation.
type CacheKey = (Vec<u8>, u16, u16, u8);

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

/// The response cache and its running BYTE total.
///
/// The total is maintained incrementally on every insert/remove rather than
/// summed on demand: `cache_store` runs on every cache miss, and walking
/// 10_000 entries there would put an O(capacity) loop on the hot path.
/// INVARIANT: `bytes == entries.values().map(|e| e.bytes.len()).sum()`. If
/// it drifts low the cap stops binding (the bug this type exists to fix
/// comes back); if it drifts high the cache stops accepting entries early.
/// Every mutation of `entries` therefore goes through the methods below.
#[derive(Default)]
struct ResponseCache {
    entries: HashMap<CacheKey, CacheEntry>,
    bytes: usize,
}

impl ResponseCache {
    fn get(&self, key: &CacheKey) -> Option<&CacheEntry> {
        self.entries.get(key)
    }

    fn remove(&mut self, key: &CacheKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.bytes -= entry.bytes.len();
        }
    }

    /// Drop every entry that has expired by `now`.
    fn purge_expired(&mut self, now: Instant) {
        let mut freed = 0usize;
        self.entries.retain(|_, entry| {
            if entry.expires_at > now {
                true
            } else {
                freed += entry.bytes.len();
                false
            }
        });
        self.bytes -= freed;
    }

    /// Insert, accounting for the bytes an entry under the same key frees.
    fn insert(&mut self, key: CacheKey, entry: CacheEntry) {
        self.bytes += entry.bytes.len();
        if let Some(old) = self.entries.insert(key, entry) {
            self.bytes -= old.bytes.len();
        }
    }
}

struct State {
    config: ProxyConfig,
    engine: Arc<RwLock<FilterEngine>>,
    /// Live upstream list, mutable via [`Proxy::set_upstreams`] so the
    /// daemon can re-read adapter DNS on network-change events without
    /// rebinding. `config.upstreams` is only the constructor input.
    upstreams: RwLock<Vec<SocketAddr>>,
    cache: Mutex<ResponseCache>,
    /// Permit pool bounding in-flight UDP queries.
    semaphore: Arc<Semaphore>,
    /// SEPARATE pool bounding concurrent client TCP connections.
    tcp_semaphore: Arc<Semaphore>,
    /// Bounds connections QUEUED waiting for a TCP permit, so a connect
    /// flood cannot make us spawn unbounded tasks while the pool is full.
    tcp_queue_semaphore: Arc<Semaphore>,
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

    fn cache_get(&self, key: &CacheKey, id: u16, rd: bool, cd: bool) -> Option<Vec<u8>> {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let entry = cache.get(key)?;
        if entry.expires_at <= Instant::now() {
            cache.remove(key);
            return None;
        }
        let mut bytes = entry.bytes.clone();
        // The cached response carries the original query's header state;
        // patch in the new requester's ID (first two bytes) and echo ITS
        // RD/CD (and keep AD cleared) before serving — same treatment as a
        // freshly relayed response, so cached and forwarded paths agree.
        wire::rewrite_response_flags_for_client(&mut bytes, rd, cd);
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
        // BOTH bounds are checked, because neither implies the other: the
        // entry cap bounds a flood of small answers, and the byte cap bounds
        // a flood of maximal (up to 65535-byte, TCP-fetched) ones, which the
        // entry cap alone would let reach ~640 MB resident. An insert that
        // REPLACES an entry frees that entry's bytes, so it is charged the
        // difference — otherwise a large name refreshing itself would be
        // refused by a budget it does not actually grow.
        let would_be = |cache: &ResponseCache| {
            cache.bytes - cache.get(key).map_or(0, |e| e.bytes.len()) + response.len()
        };
        if cache.entries.len() >= self.config.cache_capacity || would_be(&cache) > CACHE_MAX_BYTES {
            cache.purge_expired(Instant::now());
            if cache.entries.len() >= self.config.cache_capacity
                || would_be(&cache) > CACHE_MAX_BYTES
            {
                // WHY: bounded memory beats perfect caching — drop the
                // insert rather than grow without limit. Note this makes a
                // FULL cache stop accepting new names until entries expire
                // (there is no eviction policy); that is a hit-rate loss,
                // never a correctness or memory problem.
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
    tcp: Arc<TcpListener>,
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
            tcp_queue_semaphore: Arc::new(Semaphore::new(config.tcp_max_queued)),
            txids: UpstreamTxids::new(),
            upstreams: RwLock::new(config.upstreams.clone()),
            config,
            engine: Arc::new(RwLock::new(engine)),
            cache: Mutex::new(ResponseCache::default()),
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
                        tcp: Arc::new(tcp),
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

    /// Handle for replacing the upstream list, valid BEFORE **and AFTER**
    /// `run`.
    ///
    /// WHY THIS EXISTS AND `set_upstreams` IS NOT ENOUGH: `run` takes
    /// `self` by value, so every `&self` method — including
    /// [`Proxy::set_upstreams`] — becomes uncallable the moment the daemon
    /// spawns the serving future. The design requires re-reading adapter
    /// DNS on network-change events, which happens only while serving, so
    /// a `&self` setter could never satisfy it: the natural wiring failed
    /// to compile with `error[E0382]: borrow of moved value`. Same shape,
    /// and same remedy, as [`Proxy::counters`] and
    /// [`Proxy::engine_handle`] — capture it BEFORE `run`:
    ///
    /// ```ignore
    /// let upstreams = proxy.upstreams_handle();
    /// let counters  = proxy.counters();
    /// tokio::spawn(proxy.run(rx));
    /// // ... on a network-change event, from anywhere:
    /// upstreams.set(adapter_dns_servers)?;
    /// ```
    pub fn upstreams_handle(&self) -> UpstreamsHandle {
        UpstreamsHandle {
            state: Arc::clone(&self.state),
            listen: self.local_addr,
        }
    }

    /// Replace the upstream list before `run` consumes the proxy. Prefer
    /// [`Proxy::upstreams_handle`]: this method is unreachable once the
    /// daemon is serving, which is the only time network-change re-reads
    /// actually happen.
    ///
    /// Validated EXACTLY like [`Proxy::bind`]: non-empty, and no
    /// self-referential address (checked against the address we are
    /// actually bound on). On error the previous list is kept.
    pub fn set_upstreams(&self, upstreams: Vec<SocketAddr>) -> io::Result<()> {
        self.upstreams_handle().set(upstreams)
    }

    /// Four-step health check (design §5 self-test layer). Call BEFORE
    /// `run` (and before the NRPT rule is installed): it temporarily
    /// serves the UDP and TCP sockets itself for steps (iii)/(iv), and
    /// that private serving loop marks every query it answers as
    /// SYNTHETIC (skipped from the user-facing counters and the decision
    /// hook). Running it concurrently with `run` would race the real
    /// serving loop on the same sockets and could mislabel a real query
    /// as synthetic — don't.
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
    ///    reaches either); (b) `counters.canary_probes` moved by AT LEAST
    ///    the number of canary probes that SUCCEEDED (the UDP one here plus
    ///    the TCP one of step (iv), so up to 2) while the user-facing
    ///    `queries`/`blocked` did not move — a counter delta no upstream
    ///    can fake, and proof the probe did not pollute user statistics.
    ///    A lower bound, never equality: the canary counter is not gated on
    ///    `synthetic`, so concurrent local canary traffic inflates it;
    ///    (c) the engine decides
    ///    `health_check_name` as `Allow` AND it resolves POSITIVELY
    ///    (NOERROR with at least one answer) through the LISTENER — a proxy
    ///    that answers the canary but SERVFAILs everything else fails here,
    ///    and so does one whose filter blocks the health-check name, which
    ///    under `zero_ip` would otherwise be indistinguishable from a
    ///    resolution.
    /// 4. `tcp_ok` — the canary returns the LOCAL signature through the
    ///    actual TCP listener (round 3, A2): truncation routes oversized
    ///    answers onto DNS-over-TCP, so a health surface that probes only
    ///    UDP can stay green while the TCP path — accept loop, permit
    ///    pool, framing — is dead. The canary (not health_check_name) is
    ///    the probe because the signature is synthesized by the serving
    ///    path itself: it cannot be satisfied from cache or an upstream.
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
            tcp_ok: false,
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
                        Ok(fw)
                            if wire::response_info(&fw.bytes)
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
            rx.clone(),
            true,
        ));
        // (iv) needs the TCP listener served too — same synthetic marking.
        let tcp_loop_task = tokio::spawn(tcp_loop(
            Arc::clone(&self.tcp),
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
        //
        // The ENGINE PRECONDITION below is load-bearing, not a nicety.
        // `answered_positively` accepts NOERROR-with-a-TTL, and a ZeroIp
        // BLOCK answer is exactly that (NOERROR, ancount 1, A 0.0.0.0,
        // TTL 60). So under the supported `block_response = "zero_ip"`, a
        // filter that blocks `health_check_name` used to read as "resolves
        // positively": one bad suffix rule turned EVERY name on the machine
        // into 0.0.0.0 with all four steps green and an empty detail — and
        // nothing SERVFAILs, so not even a client that treats SERVFAIL as
        // "try something else" gets a hint that the answers are ours. There
        // is nothing else to try in any case: the NRPT rule this product
        // installs carries exactly ONE server (see
        // `sentinelld/web_protection/rule.rs`), and an NRPT rule overrides
        // the adapter's DNS for every matching name.
        //
        // WHY the decision and not the answer's shape: locally synthesized
        // block answers do carry AA=1, but an upstream that is authoritative
        // for the operator's chosen name legitimately sets AA=1 too, so an
        // `AA == 0` test would red a healthy proxy — the same
        // gate-rejects-healthy-proxy shape this step exists to avoid. If the
        // engine ALLOWS the name, the block branch provably did not produce
        // the answer, so a NOERROR really is a resolution.
        let health_allowed =
            self.state.decide(&self.state.config.health_check_name) == Decision::Allow;
        if !health_allowed {
            let _ = write!(
                report.detail,
                "health_check_name {:?} is BLOCKED by the filter, so step (iii) cannot \
                 tell a block answer from a resolution — pick a name you never block; ",
                self.state.config.health_check_name
            );
        }
        let answered_positively = match (&sock, wire::build_query(
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
        if !answered_positively {
            let _ = write!(
                report.detail,
                "health_check_name did not resolve positively through the listener; "
            );
        }
        let resolves_ok = health_allowed && answered_positively;

        // (iv) the CANARY through the TCP listener (round 3, A2). WHY the
        // canary and not health_check_name: the signature is synthesized
        // by the serving path itself — it can never come from the cache or
        // an upstream — so this probe exercises accept → queue → permit
        // pool → framing → handle_query → write and NOTHING else can
        // satisfy it. A health_check_name probe could be answered from
        // cache (step (iii) just populated it), masking a dead TCP path
        // — measured: with a UDP-only upstream the name probe passed via
        // cache hit while every real TCP client got SERVFAIL.
        report.tcp_ok = match wire::build_query(
            self.state.txids.next(),
            crate::filter::CANARY_DOMAIN,
            wire::TYPE_A,
            wire::CLASS_IN,
        ) {
            Some(probe) => {
                let id = u16::from_be_bytes([probe[0], probe[1]]);
                tcp_probe_exchange(&probe, self.local_addr, self.state.config.upstream_timeout)
                    .await
                    .is_some_and(|resp| is_canary_signature(&resp, id))
            }
            None => false,
        };
        if !report.tcp_ok {
            let _ = write!(
                report.detail,
                "canary through TCP listener did not return the local signature; "
            );
        }

        // (b) counter deltas across the probes: each canary probe that was
        // actually SERVED (UDP in step (iii); TCP in step (iv) — a starved
        // TCP pool SERVFAILs before `handle_query`, so there the probe is
        // never counted) must be reflected in the canary's OWN counter — as
        // a LOWER bound, since other local processes may query the canary
        // concurrently — and the user-facing counters must not have moved
        // at all (synthetic traffic is invisible to them).
        let after = self.state.counters.snapshot();
        let expected_delta = u64::from(canary_ok) + u64::from(report.tcp_ok);
        let actual_delta = after.canary_probes.wrapping_sub(before.canary_probes);
        // LOWER BOUND, not equality (round-3 closure review, U01). The
        // canary bump is not gated on `synthetic`, so a canary query from
        // ANY other local process inside the window inflates the counter —
        // and the design's own operator acceptance test is defined to send
        // exactly that query. Exact equality therefore reds a healthy proxy
        // on concurrent traffic.
        //
        // Inflation cannot disprove what this check is for: an impostor
        // owning port 53 can forge the signature but leaves OUR counter at
        // 0, and `0 >= 2` is false, so it still reds. A probe served but
        // lost in flight still reds via `canary_ok`/`tcp_ok`.
        if actual_delta < expected_delta {
            let _ = write!(
                report.detail,
                "canary_probes moved {actual_delta}, fewer than the {expected_delta} probes we served; "
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
            && actual_delta >= expected_delta
            && after.queries == before.queries
            && after.blocked == before.blocked;

        let _ = tx.send(true);
        loop_task.abort();
        tcp_loop_task.abort();
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
        let tcp_task = tokio::spawn(tcp_loop(self.tcp, self.state, shutdown.clone(), false));
        // changed() errors when the sender is dropped — treat as shutdown.
        let _ = shutdown.changed().await;
        info!("dnsguard proxy shutting down");
        udp_task.abort();
        tcp_task.abort();
        Ok(())
    }
}

/// Live handle to the proxy's upstream list, obtained from
/// [`Proxy::upstreams_handle`] and valid for the life of the proxy —
/// including after `run` has consumed it.
///
/// Holds the validation itself rather than exposing the lock, so a caller
/// cannot install a list `bind` would have refused. Cheap to clone; every
/// clone writes the same live list.
#[derive(Clone)]
pub struct UpstreamsHandle {
    state: Arc<State>,
    /// The address we are actually bound on — the reference point for the
    /// self-referential check. Not `config.listen`: with a port-0 listen
    /// those differ, and the bound address is the one that matters.
    listen: SocketAddr,
}

impl UpstreamsHandle {
    /// Replace the upstream list. Takes effect on the next forwarded
    /// query; no rebind, no restart, no dropped in-flight query (each one
    /// already picked its upstream before the swap).
    ///
    /// Validated EXACTLY like [`Proxy::bind`]: non-empty, and no
    /// self-referential address. On error the previous list is kept, which
    /// is the safe direction — a network-change event that hands us a
    /// garbage list must not leave the machine with no resolver.
    pub fn set(&self, upstreams: Vec<SocketAddr>) -> io::Result<()> {
        validate_upstreams(&upstreams, self.listen)?;
        let mut live = self
            .state
            .upstreams
            .write()
            .unwrap_or_else(|p| p.into_inner());
        info!(
            old = live.len(),
            new = upstreams.len(),
            "dnsguard upstreams replaced"
        );
        *live = upstreams;
        Ok(())
    }

    /// The upstream list currently in force.
    pub fn get(&self) -> Vec<SocketAddr> {
        self.state.upstreams()
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
    /// `canary_probes` counter moved by AT LEAST the number of canary
    /// probes that succeeded (up to 2: UDP here, TCP in step (iv)) —
    /// a lower bound, because concurrent local canary traffic inflates that
    /// counter and equality would red a healthy proxy — while the
    /// user-facing counters did not move, and `health_check_name` is
    /// decided `Allow`
    /// AND resolves POSITIVELY through the listener. False when the serving
    /// path is broken, when real names do not resolve through it (e.g.
    /// every upstream dead), or when the filter blocks the health-check
    /// name — the last case reads as a resolution under `zero_ip` unless
    /// the engine decision is checked separately.
    pub filter_ok: bool,
    /// The canary returns the LOCAL signature (0.0.0.0 A, AA=1) through
    /// the TCP listener (round 3, A2): truncation routes oversized answers
    /// onto DNS-over-TCP, so a green report without this step would
    /// certify a proxy whose mandated retry path is dead. The canary is
    /// the probe because only the serving path can produce the signature
    /// — a cache hit or an upstream cannot mask a dead TCP path.
    pub tcp_ok: bool,
    /// Configured upstreams that answered the health check with NOERROR.
    pub upstreams_healthy: usize,
    /// Configured upstreams probed. `healthy < total` is a partial DNS
    /// outage for the whole machine and must not read as green.
    pub upstreams_total: usize,
    /// Human-readable failure detail (empty when all steps passed).
    pub detail: String,
}

impl SelfTestReport {
    /// All four steps passed.
    pub fn ok(&self) -> bool {
        self.engine_ok && self.upstream_ok && self.filter_ok && self.tcp_ok
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

/// One framed DNS-over-TCP exchange against the listener during self-test
/// step (iv): connect, send `probe`, read one framed answer, all bounded
/// by `wait`. `None` on any failure.
async fn tcp_probe_exchange(probe: &[u8], listener: SocketAddr, wait: Duration) -> Option<Vec<u8>> {
    timeout(wait, async {
        let mut stream = TcpStream::connect(listener).await.ok()?;
        let framed = (probe.len() as u16).to_be_bytes();
        stream.write_all(&framed).await.ok()?;
        stream.write_all(probe).await.ok()?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.ok()?;
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await.ok()?;
        Some(buf)
    })
    .await
    .ok()?
}

/// The canary signature only THIS proxy can produce: NOERROR, AA=1,
/// exactly one answer, A rdata 0.0.0.0, and the probe's own txid echoed.
/// `build_zero_ip_response` lays the answer record out last, so the rdata
/// is the final 4 bytes. No stock upstream satisfies this for an `.invalid`
/// name (they NXDOMAIN), and the short-circuit guarantees it never comes
/// from cache either.
///
/// PUBLIC because the out-of-process reconciler must ask the same question
/// of `127.0.0.1:53` that the self-test asks internally, and two
/// implementations of a security predicate drift. Build the probe with
/// [`crate::wire::build_query`], which emits NO EDNS0 OPT — the trailing-4-
/// bytes test is only valid for a response that carries none, and
/// `handle_query` appends one whenever the requester sent one.
pub fn is_canary_signature(resp: &[u8], probe_id: u16) -> bool {
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
/// statistics or the query log — the overload (`shed`) path included, which
/// is served here and not by `handle_query`. Two counters still move: the
/// canary's own (`canary_probes`), which the self-test asserts on, and
/// `shed`, which is a liveness signal rather than a user-facing statistic.
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
                            if let Some((resp, udp_limit)) = handle_query(&state, &bytes, peer, false, synthetic).await {
                                // Truncate against the CLIENT's advertised
                                // EDNS0 payload size (clamped to [512,
                                // 4096]), or 512 for clients without EDNS
                                // (round 3, A1): a flat-512 limit forced
                                // ordinary 513–4096-byte answers onto the
                                // bounded TCP pool, coupling machine-wide
                                // UDP resolution to pool exhaustion. An
                                // answer that still exceeds the limit gets
                                // an RFC 2181-style truncated response (TC
                                // set, real rcode preserved — L02) so the
                                // client retries over TCP, where the full
                                // answer is served.
                                let resp = if resp.len() > udp_limit {
                                    match truncate_for_client(&bytes, &resp) {
                                        Some(truncated) => truncated,
                                        None => return,
                                    }
                                } else {
                                    resp
                                };
                                let _ = sock.send_to(&resp, peer).await;
                            }
                        });
                    }
                    Err(_) => shed(&state, &bytes, peer, &sock, synthetic).await,
                }
            }
        }
    }
}

/// Rebuild an answer that does not fit the transport as a TC=1 response to
/// `request`, so the client retries where the full answer does fit (UDP →
/// TCP; on TCP itself, TC is RFC 2181 §9's "it does not fit at all").
///
/// `None` only when `request` is too short to echo an ID from — the caller
/// must then drop, and must NEVER fall back to sending `oversized`, which is
/// the thing this protects against (L03).
///
/// The rebuild goes through [`normalize_client_edns`] like every other
/// egress: `build_truncated_response` emits ARCOUNT 0, so without it an
/// EDNS/DO client would receive a TC answer carrying no OPT — which RFC
/// 8906-style probers read as "this server does not implement EDNS" and
/// cache per-server, downgrading later queries to the 512-byte limit and
/// pushing far more traffic onto the bounded TCP pool. The result stays
/// well inside any UDP limit: header + question + one OPT is at most
/// 12 + 259 + 11 bytes, and the smallest limit is 512.
fn truncate_for_client(request: &[u8], oversized: &[u8]) -> Option<Vec<u8>> {
    let rcode = wire::response_info(oversized).map_or(wire::RCODE_NOERROR, |info| info.rcode);
    let resp = match wire::build_truncated_response(request, rcode) {
        Some(truncated) => truncated,
        None => wire::build_error_response(request, wire::RCODE_SERVFAIL, false)?,
    };
    Some(normalize_client_edns(request, resp))
}

/// Overload path: answer immediately with SERVFAIL. WHY SERVFAIL and not a
/// drop: a dropped query leaves the client's resolver retrying for seconds;
/// SERVFAIL makes it move on at once. It does NOT make it resolve the name
/// elsewhere — the NRPT rule this product installs carries exactly one
/// server (ours) and overrides the adapter's DNS for every matching name,
/// so under shedding the machine degrades to NO DNS for the shed queries,
/// not to unfiltered DNS. That is the whole reason the pool sizes and the
/// watchdog's strike count are what they are.
///
/// `synthetic` has the same meaning as in [`udp_loop`]: a shed inside the
/// self-test's private serving loop must not move the user-facing counters
/// or fire the decision hook, because `self_test` asserts those did not
/// move. Dropping the flag here made any concurrent local flood that
/// saturated the in-flight pool during the self-test window fail the
/// self-test — and web protection then refuses to serve for the whole
/// daemon lifetime.
async fn shed(state: &Arc<State>, bytes: &[u8], peer: SocketAddr, sock: &UdpSocket, synthetic: bool) {
    // NOT gated on `synthetic`, like `canary_probes`: `shed` is the liveness
    // signal the watchdog reads to tell "shedding" from "gone"
    // (`rule.rs`: `after.shed > before.shed`), and the self-test does not
    // assert on it.
    state.counters.bump(&state.counters.shed);
    if !synthetic {
        state.counters.bump(&state.counters.queries);
        if let Ok(query) = wire::parse_query(bytes) {
            state.emit(peer, &query, QueryOutcome::Shed);
        }
    }
    if let Some(resp) = wire::build_error_response(bytes, wire::RCODE_SERVFAIL, false) {
        // Same egress normalization as every other response we emit: this
        // one is built here, after `handle_query`, so it does not inherit it.
        let _ = sock.send_to(&normalize_client_edns(bytes, resp), peer).await;
    }
    debug!(%peer, "query shed: in-flight limit reached");
}

/// Accept client TCP connections until shutdown.
///
/// Overload policy (round 3, A1/A2 — replaces drop-on-full): accepted
/// connections wait in a BOUNDED FIFO queue (tokio's semaphore acquire is
/// arrival-ordered, so a reconnecting squatter cannot jump ahead of
/// clients that have been waiting longer) for at most
/// `tcp_queue_timeout`. On timeout the client is answered SERVFAIL for its
/// pending query — a retryable answer, never a bare RST/EOF on the very
/// path truncation ordered it to take — and `tcp_pool_full` (a dedicated
/// counter, NOT the shared `shed`) moves. The queue itself is bounded by
/// `tcp_max_queued` so a connect flood cannot spawn unbounded tasks; only
/// connections beyond THAT bound are dropped, still counted.
///
/// NOTE on per-source caps (A1(c), considered and rejected): on the
/// production deployment every client connects from 127.0.0.1 — the whole
/// machine shares one source address, so a per-source-IP cap is either a
/// no-op (cap ≥ pool) or tightens the entire machine to the cap. It
/// cannot tell the OS resolver apart from a squatter process; only the OS
/// can (per-process socket accounting needs platform APIs this crate may
/// not take on). What actually prevents one peer from monopolizing freed
/// permits is the FIFO order plus the lifetime cap, and what makes POOL
/// exhaustion survivable is the fail-safe SERVFAIL. QUEUE exhaustion —
/// `tcp_max_queued` connections already waiting — is still a bare close;
/// that is a connect flood, not pool pressure, and it is counted.
async fn tcp_loop(listener: Arc<TcpListener>, state: Arc<State>, mut shutdown: watch::Receiver<bool>, synthetic: bool) {
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
                // Bounded queue: one slot per waiting connection. No slot →
                // the queue itself is full (a real flood) → drop, counted.
                let Ok(waiter) = state.tcp_queue_semaphore.clone().try_acquire_owned() else {
                    state.counters.bump(&state.counters.tcp_pool_full);
                    drop(stream);
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let acquired = timeout(
                        state.config.tcp_queue_timeout,
                        state.tcp_semaphore.clone().acquire_owned(),
                    )
                    .await;
                    // The queue slot bounds how many connections may WAIT for
                    // a pool permit — NOT how many may be served. Holding it
                    // for the whole connection made queue occupancy identical
                    // to pool occupancy, so at the shipped default
                    // (`tcp_max_queued == tcp_max_connections`) the queue was
                    // full exactly when the pool was: `try_acquire_owned`
                    // above always failed, the `drop(stream)` branch ran, and
                    // the client got the bare RST this design exists to
                    // prevent — `serve_overflow_servfail` was unreachable in
                    // production. Released here, before either outcome, the
                    // two bounds are independent as intended and total tasks
                    // stay bounded by queued + connections.
                    drop(waiter);
                    match acquired {
                        Ok(Ok(permit)) => tcp_conn(stream, peer, state, permit, synthetic).await,
                        Ok(Err(_closed)) => drop(stream), // semaphore closed: shutting down
                        Err(_) => {
                            // Pool stayed full for the whole queue window:
                            // fail-safe — SERVFAIL the pending query, never
                            // a bare reset.
                            state.counters.bump(&state.counters.tcp_pool_full);
                            debug!(%peer, "TCP pool exhausted: queued client answered SERVFAIL");
                            serve_overflow_servfail(stream).await;
                        }
                    }
                });
            }
        }
    }
}

/// Fail-safe answer for a client that waited out the TCP queue (round 3,
/// A1/A2): read ONE framed query (bounded — a client that sends nothing
/// gets closed silently) and answer SERVFAIL, so a TC-honouring resolver
/// can RETRY instead of hitting a connection reset on the path truncation
/// sent it to. Retry is all it can do: the NRPT rule names exactly one
/// server, so there is nowhere else for the name to resolve. Holds no pool
/// permit; fully bounded.
async fn serve_overflow_servfail(mut stream: TcpStream) {
    /// Total budget for the whole overflow exchange.
    const OVERFLOW_BUDGET: Duration = Duration::from_secs(2);
    let _ = timeout(OVERFLOW_BUDGET, async {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await?;
        if let Some(resp) = wire::build_error_response(&buf, wire::RCODE_SERVFAIL, false) {
            // Built here rather than by `handle_query`, so the egress EDNS
            // normalization has to be applied explicitly — an EDNS client
            // must not read our overload answer as "no EDNS support here".
            let resp = normalize_client_edns(&buf, resp);
            // Header + question + one OPT; `as u16` cannot wrap on it.
            let framed = (resp.len() as u16).to_be_bytes();
            stream.write_all(&framed).await?;
            stream.write_all(&resp).await?;
        }
        io::Result::Ok(())
    })
    .await;
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
    synthetic: bool,
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
        let Ok(Some((resp, _udp_limit))) = timeout(budget, handle_query(&state, &buf, peer, true, synthetic)).await else {
            break; // over budget, or not even a header to echo an ID for
        };

        // (4) write back. An unbounded `write_all` lets a pipelining client
        // that never reads park the permit forever on a full send buffer.
        let Some(budget) = left(deadline) else { break };
        // A DNS-over-TCP message is framed by a 2-byte length, so anything
        // past 65535 bytes HAS NO FRAME. `resp.len() as u16` would wrap
        // silently (65541 -> 5) and we would announce 5 bytes and then write
        // 65541: the client reads 5 bytes as a whole message and re-frames
        // the rest of OUR answer as further messages — the stream is
        // desynchronized for its whole lifetime and every pipelined query on
        // it is answered from garbage. No hostile upstream needed:
        // `tcp_exchange` accepts a 65535-byte answer, and the egress OPT
        // `normalize_client_edns` appends for an EDNS requester adds 11 more.
        let (resp, len) = match u16::try_from(resp.len()) {
            Ok(len) => (resp, len),
            Err(_) => {
                debug!(%peer, len = resp.len(), "answer exceeds the DNS-over-TCP frame limit: truncating");
                // TC=1 over TCP is RFC 2181 §9's "the answer does not fit",
                // which is exactly true here — a truthful failure the client
                // can act on, instead of a corrupted stream.
                let Some(truncated) = truncate_for_client(&buf, &resp) else {
                    break;
                };
                let Ok(len) = u16::try_from(truncated.len()) else {
                    break; // unreachable: header + question + OPT
                };
                (truncated, len)
            }
        };
        let framed_len = len.to_be_bytes();
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
/// Returns `(response, udp_limit)` — the response bytes plus the maximum
/// UDP payload the client negotiated (its EDNS0-advertised size clamped to
/// [512, 4096], or 512 without EDNS); the limit matters only to the UDP
/// caller's truncation decision. Returns `None` only when the input is too
/// short to echo an ID for.
///
/// `synthetic` marks health-check probes (the self-test's private serving
/// loop): synthetic queries skip the user-facing counters and the decision
/// hook so probe traffic never lands in the GUI/IPC statistics or the
/// query log.
/// Core pipeline plus the ONE egress point where EDNS0 OPT presence is
/// normalized.
///
/// WHY a wrapper (round-3 closure review, U06): OPT is a per-hop transport
/// negotiation, and the cache used to store whatever OPT the upstream sent,
/// so the FIRST client to populate an entry decided what every later client
/// received — a classic stub that sent no OPT was handed one it never asked
/// for, and an EDNS client could be served an answer with none. The obvious
/// fix, adding a "client sent an OPT" bit to the cache key, fixes one sink
/// and leaves four (block NXDOMAIN, block zero-IP, canary, error/NOTIMP),
/// and doubles the cache fan-out. So the DATA is fixed once, here: every
/// response that leaves this function has inherited OPTs removed and then
/// exactly one OPT appended iff THIS requester sent one.
///
/// THE RESPONSES BUILT AFTER IT RETURNS ARE NOT COVERED BY IT and call
/// [`normalize_client_edns`] themselves — the TC rebuild and the overload
/// SERVFAILs, which are constructed from the raw REQUEST by their callers
/// ([`truncate_for_client`], [`shed`], [`serve_overflow_servfail`]) and
/// never pass through here. An earlier revision of this comment claimed
/// "the TC response" was one of the sinks fixed here; it was not, and an
/// EDNS client's truncated answer went out with ARCOUNT 0.
///
/// Ordering note: this runs BEFORE the caller's size check, so the OPT's 11
/// bytes are counted against the client's advertised limit rather than
/// pushing the datagram over it.
async fn handle_query(
    state: &Arc<State>,
    bytes: &[u8],
    client: SocketAddr,
    via_tcp: bool,
    synthetic: bool,
) -> Option<(Vec<u8>, usize)> {
    let (resp, udp_limit) = handle_query_inner(state, bytes, client, via_tcp, synthetic).await?;
    Some((normalize_client_edns(bytes, resp), udp_limit))
}

/// Strip inherited OPTs, then re-add one iff the requester sent one.
fn normalize_client_edns(request: &[u8], resp: Vec<u8>) -> Vec<u8> {
    let mut out = wire::strip_opt_records(&resp);
    if let Ok(q) = wire::parse_query(request)
        && let Some(size) = q.edns_udp_size
    {
        wire::append_client_opt(&mut out, wire::clamp_edns_udp_size(size) as u16, q.dnssec_ok);
    }
    out
}

async fn handle_query_inner(
    state: &Arc<State>,
    bytes: &[u8],
    client: SocketAddr,
    via_tcp: bool,
    synthetic: bool,
) -> Option<(Vec<u8>, usize)> {
    let query = match wire::parse_query(bytes) {
        Ok(q) => q,
        Err(e) => {
            if !synthetic {
                state.counters.bump(&state.counters.queries);
            }
            debug!(error = %e, %client, "malformed DNS query");
            return wire::build_error_response(bytes, wire::RCODE_FORMERR, false)
                .map(|resp| (resp, wire::MAX_UDP_PAYLOAD));
        }
    };

    // Opcodes other than QUERY (0) — STATUS/NOTIFY/UPDATE/... — are
    // refused with NOTIMP BEFORE canary/filter/cache/forward (round 3,
    // L04): the old code silently rewrote the opcode to 0 on the rebuilt
    // upstream query, so a conforming client discarded the forwarded
    // answer while the BLOCKED path echoed the client's opcode — the two
    // paths disagreed about the same query. NOTIMP echoes the opcode
    // (`build_error_response` preserves it), so the refusal matches the
    // client's own state machine.
    if query.opcode != 0 {
        if !synthetic {
            state.counters.bump(&state.counters.queries);
            state.emit(client, &query, QueryOutcome::NotImplemented);
        }
        debug!(%client, opcode = query.opcode, "unsupported opcode: NOTIMP");
        return wire::build_error_response(bytes, wire::RCODE_NOTIMP, false)
            .map(|resp| (resp, wire::MAX_UDP_PAYLOAD));
    }

    // The UDP payload limit this client negotiated (A1a): its advertised
    // EDNS0 size, clamped to what we can buffer, else the classic 512.
    let udp_limit = query
        .edns_udp_size
        .map_or(wire::MAX_UDP_PAYLOAD, wire::clamp_edns_udp_size);

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
        return wire::build_zero_ip_response(bytes, ZERO_IP_TTL).map(|resp| (resp, udp_limit));
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
        }
        .map(|resp| (resp, udp_limit));
    }

    // Cache key: raw wire-format qname bytes (injective — see CacheKey) so
    // case variants do NOT collapse; upstreams answer case-insensitively
    // but keying on bytes is the safe direction (no aliasing, ever).
    let cache_key: CacheKey = (
        query.qname_wire.clone(),
        query.qtype,
        query.qclass,
        u8::from(query.dnssec_ok) | u8::from(query.checking_disabled) << 1,
    );
    if let Some(resp) = state.cache_get(&cache_key, query.id, query.recursion_desired, query.checking_disabled) {
        if !synthetic {
            state.counters.bump(&state.counters.cache_hits);
            state.emit(client, &query, QueryOutcome::CacheHit);
        }
        return Some((resp, udp_limit));
    }

    match forward(state, bytes, &query, via_tcp).await {
        Ok(fw) => {
            let mut resp = fw.bytes;
            if !synthetic {
                state.counters.bump(&state.counters.forwarded);
            }
            // Restore the client's original txid: the wire bytes went
            // upstream with OUR generated ID (see forward).
            if resp.len() >= 2 {
                resp[0..2].copy_from_slice(&query.id.to_be_bytes());
            }
            // Echo the CLIENT's RD/CD and clear AD (L01/L04): the upstream
            // answered the clean query WE built, so its flag echo describes
            // our exchange, not the client's. Done BEFORE caching so the
            // cached copy never carries a spurious AD.
            wire::rewrite_response_flags_for_client(
                &mut resp,
                query.recursion_desired,
                query.checking_disabled,
            );
            // Only validated responses reach this point (forward drops
            // anything failing txid/QR/question checks), so caching here
            // can never poison the cache with a forgery.
            //
            // CACHE SLOT (round-3 closure review, finding 2): an answer
            // fetched through the EDNS fallback was obtained with the OPT
            // — and therefore the client's DO bit — stripped, so it carries
            // no RRSIGs. Filing it under the DO=1 key would hand the NEXT
            // self-validating stub a signature-less answer from the slot
            // that promises signatures, and its validation would spuriously
            // fail. That is precisely the invariant the (DO,CD) cache fork
            // exists to guarantee, and the fork alone did not deliver it:
            // it closed the cross-slot case and left the in-slot case open,
            // so ONE transient upstream failure downgraded DNSSEC for every
            // DO=1 client for up to max_ttl.
            //
            // The answer is still perfectly good as a NON-DNSSEC answer, so
            // it is filed in the DO=0 slot (same CD) rather than dropped:
            // DO=0 clients get the cache hit they should, and DO=1 clients
            // miss and re-ask. The client that triggered the fallback is
            // served directly, once — with no signatures, because against a
            // pre-EDNS upstream there are none to be had.
            let store_key = if fw.edns_stripped && query.dnssec_ok {
                let mut k = cache_key.clone();
                k.3 &= !1; // clear the DO bit of the slot discriminator
                k
            } else {
                cache_key.clone()
            };
            // RFC 6891 §6.1.1: OPT MUST NOT be cached. Storing it is what
            // let the first requester's EDNS posture leak to every later
            // one; the egress normalization in `handle_query` re-adds the
            // right OPT for whoever is actually asking.
            state.cache_store(&store_key, &wire::strip_opt_records(&resp));
            if !synthetic {
                state.emit(client, &query, QueryOutcome::Forwarded);
            }
            Some((resp, udp_limit))
        }
        Err(e) => {
            if !synthetic {
                state.counters.bump(&state.counters.upstream_errors);
                state.emit(client, &query, QueryOutcome::UpstreamError);
            }
            warn!(error = %e, qname = %query.qname, "upstream exchange failed");
            wire::build_error_response(bytes, wire::RCODE_SERVFAIL, false)
                .map(|resp| (resp, udp_limit))
        }
    }
}

/// Forward to the upstream pool: UDP first, TCP when the client is TCP or
/// the UDP answer comes back truncated (TC bit).
///
/// The upstream sees a CLEAN query built from scratch
/// ([`wire::build_upstream_query`]): a freshly GENERATED transaction ID
/// (never the client's verbatim), rebuilt flags (RD=1, plus the client's
/// CD bit — RFC 4035 §3.1.6), the question section, and — only when the
/// client sent EDNS0 — ONE self-constructed OPT carrying the client's
/// clamped UDP size and DO bit (round-3 L01 decision: a client asking for
/// DNSSEC records gets them; a silent strip would be a downgrade). No
/// other client-controlled bytes leave the machine: no ECS (it would steer
/// the answer we then cache machine-wide), no cookies, no options.
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
) -> io::Result<Forwarded> {
    let upstream = state
        .pick_upstream()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no upstream configured"))?;
    forward_via(state, query_bytes, query, via_tcp, upstream).await
}

/// One upstream answer, plus how we had to obtain it.
struct Forwarded {
    bytes: Vec<u8>,
    /// The answer came from the EDNS fallback, i.e. it was re-fetched with
    /// the OPT record — and therefore the client's DO bit — STRIPPED. Such
    /// an answer carries no RRSIGs, so it must never be filed in a
    /// DNSSEC-requesting cache slot. See the store-key choice in
    /// `handle_query`.
    edns_stripped: bool,
}

impl Forwarded {
    fn intact(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            edns_stripped: false,
        }
    }
    fn edns_stripped(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            edns_stripped: true,
        }
    }
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
) -> io::Result<Forwarded> {
    let upstream_id = state.txids.next();
    let question = &query_bytes[wire::HEADER_LEN..query.question_end];
    let edns = query.edns_udp_size.map(|size| (size, query.dnssec_ok));
    let forwarded = wire::build_upstream_query(upstream_id, question, query.checking_disabled, edns);

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
            // RFC 6891 §6.2.2: a responder that does not implement EDNS
            // answers FORMERR to a query carrying an OPT record, and the
            // requester retries without EDNS. Retry once, plain; without
            // this every EDNS client behind a pre-EDNS upstream hard-fails.
            //
            // SERVFAIL IS DELIBERATELY NOT IN THIS SET (round-3 closure
            // review). It is the ordinary soft-failure rcode of the whole
            // DNS — lame delegations, DNSSEC-bogus names, cold or loaded
            // resolvers, response-rate limiting — not an EDNS-unsupported
            // signal, and RFC 8906 §5 warns against treating it as one.
            // Including it cost every EDNS query against a SERVFAILing
            // upstream TWO full exchanges, each with a fresh
            // `upstream_timeout` and the in-flight permit held across both:
            // measured 8.83 s for a single query and 20% shed at 40
            // concurrent. It also fed finding 2 below, since the retry
            // strips DO. (NOTIMP is the other legacy no-EDNS signal; it is
            // not included either, for want of evidence that any upstream
            // we target needs it — every rcode added here doubles upstream
            // load for that rcode.)
            Ok(resp)
                if edns.is_some()
                    && wire::response_info(&resp)
                        .is_some_and(|info| info.rcode == wire::RCODE_FORMERR) =>
            {
                debug!(%upstream, "EDNS query refused: retrying without OPT");
                let plain = wire::build_upstream_query(upstream_id, question, query.checking_disabled, None);
                let resp = udp_exchange(upstream, &plain, upstream_id, state.config.upstream_timeout).await?;
                if wire::validate_response(&resp, upstream_id, question).is_none() {
                    return Err(invalid());
                }
                if !wire::is_truncated_response(&resp) {
                    return Ok(Forwarded::edns_stripped(resp));
                }
                debug!(%upstream, "TC bit set, retrying over TCP");
                let resp = tcp_exchange(upstream, &plain, state.config.upstream_timeout).await?;
                if wire::validate_response(&resp, upstream_id, question).is_none() {
                    return Err(invalid());
                }
                return Ok(Forwarded::edns_stripped(resp));
            }
            Ok(resp) if !wire::is_truncated_response(&resp) => return Ok(Forwarded::intact(resp)),
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
    // The SAME EDNS fallback as the UDP path (round-3 closure review): a
    // pre-EDNS upstream FORMERRs our OPT over TCP too. The retry used to
    // live only inside the `!via_tcp` block above, so this tail relayed
    // the FORMERR verbatim — sink fixed, sibling left.
    //
    // It is reachable in ordinary operation, not just by deliberate TCP
    // clients: this tail is also where the TC->TCP escalation lands, so a
    // >512-byte name behind a pre-EDNS upstream hard-failed for EVERY
    // client, including plain UDP ones.
    if edns.is_some()
        && wire::response_info(&resp).is_some_and(|info| info.rcode == wire::RCODE_FORMERR)
    {
        debug!(%upstream, "EDNS query refused over TCP: retrying without OPT");
        let plain =
            wire::build_upstream_query(upstream_id, question, query.checking_disabled, None);
        let resp = tcp_exchange(upstream, &plain, state.config.upstream_timeout).await?;
        if wire::validate_response(&resp, upstream_id, question).is_none() {
            return Err(invalid());
        }
        return Ok(Forwarded::edns_stripped(resp));
    }
    Ok(Forwarded::intact(resp))
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

    /// A `State` built without binding anything: enough for the parts of the
    /// pipeline that are driven directly (`udp_loop`, `tcp_conn`, the cache),
    /// with no upstream reachable — every test below answers from the cache,
    /// the shed path, or the truncation path.
    fn test_state(config: ProxyConfig, hook: Arc<dyn DecisionHook>) -> Arc<State> {
        Arc::new(State {
            semaphore: Arc::new(Semaphore::new(config.max_in_flight)),
            tcp_semaphore: Arc::new(Semaphore::new(config.tcp_max_connections)),
            tcp_queue_semaphore: Arc::new(Semaphore::new(config.tcp_max_queued)),
            txids: UpstreamTxids::new(),
            upstreams: RwLock::new(config.upstreams.clone()),
            config,
            engine: Arc::new(RwLock::new(FilterEngine::new())),
            cache: Mutex::new(ResponseCache::default()),
            counters: Arc::new(Counters::default()),
            hook,
            upstream_rr: AtomicUsize::new(0),
        })
    }

    /// A query carrying an EDNS0 OPT that advertises `udp_size` — what a
    /// Windows stub actually sends. `build_query` deliberately emits none,
    /// so the upstream builder is the one that can produce this shape.
    fn edns_query(id: u16, name: &str, udp_size: u16) -> Vec<u8> {
        let plain = wire::build_query(id, name, wire::TYPE_A, wire::CLASS_IN).expect("build query");
        let q = wire::parse_query(&plain).expect("parse query");
        wire::build_upstream_query(
            id,
            &plain[wire::HEADER_LEN..q.question_end],
            false,
            Some((udp_size, false)),
        )
    }

    /// A cacheable NOERROR answer for `query`, padded out to `len` bytes.
    /// The padding is trailing (past the single answer record), so it parses
    /// exactly like the real TCP-fetched answers this crate already caches —
    /// `response_info` reads its TTL, and `strip_opt_records` leaves it
    /// alone because ARCOUNT is 0.
    fn padded_answer(query: &[u8], len: usize) -> Vec<u8> {
        let mut resp = wire::build_zero_ip_response(query, 60).expect("answer");
        assert!(resp.len() <= len, "padding target must exceed the answer");
        resp.resize(len, 0);
        assert!(
            wire::response_info(&resp).and_then(|info| info.min_ttl).is_some(),
            "the padded answer must still parse as a cacheable NOERROR"
        );
        resp
    }

    /// Put `bytes` in the cache under the key `handle_query` computes for
    /// `query`, so the serving path returns it without any upstream.
    fn seed_cache(state: &State, query: &[u8], bytes: Vec<u8>) {
        let q = wire::parse_query(query).expect("parse query");
        let key: CacheKey = (
            q.qname_wire.clone(),
            q.qtype,
            q.qclass,
            u8::from(q.dnssec_ok) | u8::from(q.checking_disabled) << 1,
        );
        state.cache.lock().expect("cache").insert(
            key,
            CacheEntry {
                bytes,
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
    }

    /// REGRESSION. DNS-over-TCP frames each message with a 2-byte length,
    /// and the frame length used to be `resp.len() as u16` — which WRAPS.
    /// An upstream answer may be 65535 bytes (that is the framing limit on
    /// the way in too) and the egress OPT adds 11, so a 65530-byte answer
    /// went out announced as 5 bytes: the client read 5 bytes as a whole
    /// message and then re-framed the remaining 65536 bytes of our answer as
    /// further messages, desynchronizing the connection for its lifetime.
    ///
    /// The property asserted is the one that matters to the client: the
    /// frame length describes the whole message, and nothing follows it.
    #[tokio::test]
    async fn an_answer_too_large_to_frame_never_desynchronizes_the_tcp_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let listen_addr = listener.local_addr().expect("addr");
        let state = test_state(
            ProxyConfig {
                tcp_idle_timeout: Duration::from_millis(200),
                tcp_max_lifetime: Duration::from_secs(5),
                ..ProxyConfig::default()
            },
            Arc::new(NoopDecisionHook),
        );

        // The maximal answer a `tcp_exchange` can hand us. With the client's
        // OPT appended on egress this is 65546 bytes — unframeable.
        let query = edns_query(0x4242, "big.example", 4096);
        seed_cache(&state, &query, padded_answer(&query, 65_535));

        let served = Arc::clone(&state);
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            let permit = Arc::clone(&served.tcp_semaphore)
                .try_acquire_owned()
                .expect("permit");
            tcp_conn(stream, peer, served, permit, false).await;
        });

        let mut client = TcpStream::connect(listen_addr).await.expect("connect");
        client
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .expect("write length");
        client.write_all(&query).await.expect("write query");

        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await.expect("frame length");
        let framed = usize::from(u16::from_be_bytes(len_buf));
        let mut message = vec![0u8; framed];
        client.read_exact(&mut message).await.expect("framed message");

        // THE ASSERTION: the frame was the whole message. Anything left on
        // the wire is answer bytes the client will re-frame as garbage.
        let mut trailing = Vec::new();
        timeout(Duration::from_secs(3), client.read_to_end(&mut trailing))
            .await
            .expect("connection must close on the idle timeout")
            .expect("read to end");
        assert!(
            trailing.is_empty(),
            "framed {framed} bytes but {} more followed: the client's next \
             length prefix is our answer's payload",
            trailing.len()
        );
        assert_eq!(
            u16::from_be_bytes([message[0], message[1]]),
            0x4242,
            "the framed message must be the answer to our query"
        );
        assert!(
            wire::is_truncated_response(&message),
            "TC=1 is how the client learns the answer did not fit (RFC 2181 §9)"
        );
        server.await.expect("server task");
    }

    /// REGRESSION. The UDP truncation path rebuilds the response from the
    /// raw REQUEST after `handle_query` has returned, so it bypassed the
    /// egress EDNS normalization: an EDNS/DO client got TC=1 with ARCOUNT 0,
    /// which RFC 8906-style probers read as "this server does not implement
    /// EDNS" and cache per-server — downgrading later queries to the classic
    /// 512-byte limit and pushing far more traffic onto the bounded TCP pool.
    #[tokio::test]
    async fn a_truncated_udp_answer_still_carries_the_requesters_opt() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let listen_addr = sock.local_addr().expect("addr");
        let state = test_state(ProxyConfig::default(), Arc::new(NoopDecisionHook));

        // Advertise 1232 (the common stub value) and cache a 2000-byte
        // answer, so the size check trips.
        let query = edns_query(0x1234, "big.example", 1232);
        seed_cache(&state, &query, padded_answer(&query, 2000));

        let (tx, rx) = watch::channel(false);
        let loop_task = tokio::spawn(udp_loop(Arc::clone(&sock), Arc::clone(&state), rx, false));

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        client.send_to(&query, listen_addr).await.expect("send");
        let mut buf = [0u8; MAX_DATAGRAM];
        let n = timeout(Duration::from_secs(3), client.recv(&mut buf))
            .await
            .expect("proxy must answer")
            .expect("recv");
        let resp = &buf[..n];

        assert!(wire::is_truncated_response(resp), "the answer must be truncated");
        assert!(n <= 1232, "the truncated answer must fit the advertised size");
        assert_eq!(
            u16::from_be_bytes([resp[10], resp[11]]),
            1,
            "ARCOUNT: the TC answer must carry exactly one OPT for this requester"
        );
        // Root name + type 41 opens the OPT record, which is the last 11
        // bytes `append_client_opt` wrote.
        assert_eq!(
            &resp[n - 11..n - 8],
            &[0x00, 0x00, 0x29],
            "the additional record must actually be an OPT"
        );

        let _ = tx.send(true);
        loop_task.abort();
    }

    /// Drive one query into a proxy whose in-flight pool is exhausted, and
    /// report what the shed left behind: the counters and how many decision
    /// events the hook saw.
    async fn shed_one_query(synthetic: bool) -> (CountersSnapshot, usize) {
        let events = Arc::new(Mutex::new(Vec::<QueryOutcome>::new()));
        let sink = Arc::clone(&events);
        let hook: Arc<dyn DecisionHook> =
            Arc::new(move |event: &DecisionEvent| sink.lock().expect("events").push(event.outcome));
        // Zero permits: `try_acquire_owned` always fails, so every query
        // takes the overload path.
        let state = test_state(
            ProxyConfig {
                max_in_flight: 0,
                ..ProxyConfig::default()
            },
            hook,
        );
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let listen_addr = sock.local_addr().expect("addr");
        let (tx, rx) = watch::channel(false);
        let loop_task = tokio::spawn(udp_loop(
            Arc::clone(&sock),
            Arc::clone(&state),
            rx,
            synthetic,
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        let query =
            wire::build_query(0x77, "example.com", wire::TYPE_A, wire::CLASS_IN).expect("query");
        client.send_to(&query, listen_addr).await.expect("send");
        let mut buf = [0u8; MAX_DATAGRAM];
        let n = timeout(Duration::from_secs(3), client.recv(&mut buf))
            .await
            .expect("a shed query must be ANSWERED, never dropped")
            .expect("recv");
        assert_eq!(
            wire::response_info(&buf[..n]).expect("response").rcode,
            wire::RCODE_SERVFAIL,
            "the overload answer is SERVFAIL"
        );

        let _ = tx.send(true);
        loop_task.abort();
        let seen = events.lock().expect("events").len();
        (state.counters.snapshot(), seen)
    }

    /// REGRESSION. `shed` never received `synthetic`, so a query shed inside
    /// the self-test's private serving loop bumped the user-facing `queries`
    /// counter and fired the decision hook — and `self_test` requires those
    /// NOT to move. Any concurrent local traffic that saturated the 256-permit
    /// pool during the self-test window therefore reded a healthy proxy, and
    /// `WebProtection::start` refuses to serve for the whole daemon lifetime
    /// on that verdict: sustained flood, no web protection, ever.
    #[tokio::test]
    async fn a_synthetic_shed_stays_out_of_the_user_facing_counters() {
        let (counters, events) = shed_one_query(true).await;
        assert_eq!(
            counters.queries, 0,
            "self_test asserts queries did not move across its probes"
        );
        assert_eq!(counters.blocked, 0);
        assert_eq!(events, 0, "probe traffic must not reach the query log");
        assert_eq!(
            counters.shed, 1,
            "shed is a liveness signal the watchdog reads: it must still move"
        );
    }

    /// The other half: a REAL client's shed is user traffic and must be
    /// counted and logged, or the overload becomes invisible.
    #[tokio::test]
    async fn a_real_shed_is_counted_and_logged() {
        let (counters, events) = shed_one_query(false).await;
        assert_eq!(counters.queries, 1);
        assert_eq!(counters.shed, 1);
        assert_eq!(events, 1);
    }

    /// REGRESSION. The cache was bounded in ENTRIES only. One entry holds a
    /// whole response, and a TCP-fetched answer can be 65535 bytes, so the
    /// 10_000-entry cap allowed ~640 MB resident in a service running as
    /// SYSTEM — reachable by any local process resolving distinct names
    /// under a zone that serves large RRsets. Measured before the fix, with
    /// this test's 400 x 60 KiB answers: 24.6 MB stored under an 8 MiB
    /// budget, and nothing to stop it scaling to the entry cap.
    #[test]
    fn the_cache_is_bounded_in_bytes_not_only_in_entries() {
        let state = test_state(ProxyConfig::default(), Arc::new(NoopDecisionHook));
        let query =
            wire::build_query(1, "big.example", wire::TYPE_A, wire::CLASS_IN).expect("query");
        let big = padded_answer(&query, 60 * 1024);

        for i in 0..400u32 {
            // Distinct names, one entry each — the shape a hostile zone
            // drives. 400 x 60 KiB is 24 MB, three times the byte budget.
            let key: CacheKey = (i.to_be_bytes().to_vec(), wire::TYPE_A, wire::CLASS_IN, 0);
            state.cache_store(&key, &big);
        }

        let cache = state.cache.lock().expect("cache");
        assert_eq!(
            cache.bytes,
            cache.entries.values().map(|e| e.bytes.len()).sum::<usize>(),
            "the running byte total must equal the contents, or the cap stops binding"
        );
        assert!(
            cache.bytes <= CACHE_MAX_BYTES,
            "cache holds {} bytes, over the {CACHE_MAX_BYTES}-byte budget",
            cache.bytes
        );
        assert!(
            !cache.entries.is_empty() && cache.entries.len() < 400,
            "the byte cap must bind before the entry cap does: {} entries",
            cache.entries.len()
        );
    }

    /// The byte total must survive the operations that REMOVE entries, or it
    /// drifts up and the cache silently stops accepting anything.
    #[test]
    fn cache_byte_accounting_survives_expiry_and_replacement() {
        let state = test_state(ProxyConfig::default(), Arc::new(NoopDecisionHook));
        let query =
            wire::build_query(1, "big.example", wire::TYPE_A, wire::CLASS_IN).expect("query");
        let answer = padded_answer(&query, 4096);
        let key: CacheKey = (vec![1, 2, 3], wire::TYPE_A, wire::CLASS_IN, 0);

        state.cache_store(&key, &answer);
        state.cache_store(&key, &answer); // same key: replaces, does not add
        {
            let cache = state.cache.lock().expect("cache");
            assert_eq!(cache.entries.len(), 1);
            assert_eq!(cache.bytes, answer.len());
        }

        // Expire it by hand and purge: the total must come back to zero.
        {
            let mut cache = state.cache.lock().expect("cache");
            let entry = cache.entries.get_mut(&key).expect("entry");
            entry.expires_at = Instant::now() - Duration::from_secs(1);
            cache.purge_expired(Instant::now());
            assert!(cache.entries.is_empty());
            assert_eq!(cache.bytes, 0, "freed bytes must be credited back");
        }

        // And through the read path's expiry removal.
        state.cache_store(&key, &answer);
        {
            let mut cache = state.cache.lock().expect("cache");
            cache.remove(&key);
            assert_eq!(cache.bytes, 0);
        }
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

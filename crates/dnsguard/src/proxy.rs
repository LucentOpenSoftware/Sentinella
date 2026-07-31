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
//!   matching the per-query ID we generated upstream-side (the client's ID
//!   is never forwarded verbatim), question echoed byte-for-byte;
//! - no hardcoded public resolver: upstreams come from configuration.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// forever.
    pub tcp_max_lifetime: Duration,
    /// Size of the SEPARATE TCP connection permit pool (design §5).
    /// Deliberately much smaller than `max_in_flight` and never shared with
    /// it, so TCP clients cannot starve UDP query handling.
    pub tcp_max_connections: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353),
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
/// NOT cryptographic — deliberately dependency-free (the crate has no RNG
/// dependency): a xorshift64 mixer over an atomic counter, seeded from the
/// wall clock and process ID. What matters for the threat model (design §5)
/// is that the ID sequence is not attacker-controlled or trivially
/// predictable from the client's own ID — the client's txid is never
/// forwarded verbatim. Combined with the question-echo check and
/// per-query ephemeral connected sockets this restores the standard
/// resolver defense-in-depth; DNSSEC validation remains a v2 item.
struct UpstreamTxids {
    state: AtomicU64,
}

impl UpstreamTxids {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        let seed = nanos ^ u64::from(std::process::id()).rotate_left(32);
        // xorshift state must be nonzero.
        Self {
            state: AtomicU64::new(seed | 1),
        }
    }

    fn next(&self) -> u16 {
        // Each caller mixes a different counter value, so IDs do not repeat
        // in lockstep even though the mix is deterministic.
        let mut x = self
            .state
            .fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x >> 32) as u16
    }
}

struct CacheEntry {
    bytes: Vec<u8>,
    expires_at: Instant,
}

struct State {
    config: ProxyConfig,
    engine: Arc<RwLock<FilterEngine>>,
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

    fn pick_upstream(&self) -> Option<SocketAddr> {
        let upstreams = &self.config.upstreams;
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
    udp: UdpSocket,
    tcp: TcpListener,
    state: Arc<State>,
    local_addr: SocketAddr,
}

impl Proxy {
    /// Bind UDP and TCP on `config.listen`. With port 0 the UDP socket picks
    /// an ephemeral port and TCP follows it onto the same port (retrying on
    /// collision) so both protocols share one address.
    pub async fn bind(
        config: ProxyConfig,
        engine: FilterEngine,
        hook: Arc<dyn DecisionHook>,
    ) -> io::Result<Self> {
        let state = Arc::new(State {
            semaphore: Arc::new(Semaphore::new(config.max_in_flight)),
            tcp_semaphore: Arc::new(Semaphore::new(config.tcp_max_connections)),
            txids: UpstreamTxids::new(),
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
                    info!(%local_addr, upstreams = state.config.upstreams.len(), "dnsguard bound");
                    return Ok(Self {
                        udp,
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

    /// Serve until `shutdown` is set to `true` (or its sender is dropped).
    /// Stops accepting new work; in-flight queries finish on their own,
    /// bounded by the upstream timeout.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        info!(addr = %self.local_addr, "dnsguard proxy starting");
        let udp = Arc::new(self.udp);
        let udp_task = tokio::spawn(udp_loop(
            udp,
            Arc::clone(&self.state),
            shutdown.clone(),
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

async fn udp_loop(sock: Arc<UdpSocket>, state: Arc<State>, mut shutdown: watch::Receiver<bool>) {
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
                            if let Some(resp) = handle_query(&state, &bytes, peer, false).await {
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
    if let Some(resp) = wire::build_error_response(bytes, wire::RCODE_SERVFAIL) {
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
/// total-lifetime cap (`tcp_max_lifetime`) — without the latter, a
/// dribbling connection could hold its permit indefinitely.
async fn tcp_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<State>,
    _permit: OwnedSemaphorePermit,
) {
    let deadline = tokio::time::Instant::now() + state.config.tcp_max_lifetime;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            debug!(%peer, "TCP connection closed: hard lifetime cap reached");
            return;
        }
        let read_budget = remaining.min(state.config.tcp_idle_timeout);
        let mut len_buf = [0u8; 2];
        let read_len = timeout(read_budget, stream.read_exact(&mut len_buf)).await;
        if !matches!(read_len, Ok(Ok(_))) {
            return; // EOF, peer error, idle timeout, or lifetime cap
        }
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; n];
        let read_body = timeout(read_budget, stream.read_exact(&mut buf)).await;
        if !matches!(read_body, Ok(Ok(_))) {
            return;
        }
        let Some(resp) = handle_query(&state, &buf, peer, true).await else {
            return; // not even a header: nothing safe to answer
        };
        let framed_len = (resp.len() as u16).to_be_bytes();
        if stream.write_all(&framed_len).await.is_err()
            || stream.write_all(&resp).await.is_err()
        {
            return;
        }
    }
}

/// Core pipeline, shared by UDP and TCP clients: parse → decide → answer.
/// Returns `None` only when the input is too short to echo an ID for.
async fn handle_query(
    state: &Arc<State>,
    bytes: &[u8],
    client: SocketAddr,
    via_tcp: bool,
) -> Option<Vec<u8>> {
    state.counters.bump(&state.counters.queries);
    let query = match wire::parse_query(bytes) {
        Ok(q) => q,
        Err(e) => {
            debug!(error = %e, %client, "malformed DNS query");
            return wire::build_error_response(bytes, wire::RCODE_FORMERR);
        }
    };

    if state.decide(&query.qname) == Decision::Block {
        state.counters.bump(&state.counters.blocked);
        state.emit(client, &query, QueryOutcome::Blocked);
        debug!(qname = %query.qname, %client, "blocked");
        return match state.config.block_response {
            BlockResponse::Nxdomain => wire::build_error_response(bytes, wire::RCODE_NXDOMAIN),
            BlockResponse::ZeroIp => wire::build_zero_ip_response(bytes, ZERO_IP_TTL),
        };
    }

    // Cache key: raw wire-format qname bytes (injective — see CacheKey) so
    // case variants do NOT collapse; upstreams answer case-insensitively
    // but keying on bytes is the safe direction (no aliasing, ever).
    let cache_key: CacheKey = (query.qname_wire.clone(), query.qtype, query.qclass);
    if let Some(resp) = state.cache_get(&cache_key, query.id) {
        state.counters.bump(&state.counters.cache_hits);
        state.emit(client, &query, QueryOutcome::CacheHit);
        return Some(resp);
    }

    match forward(state, bytes, &query, via_tcp).await {
        Ok(mut resp) => {
            state.counters.bump(&state.counters.forwarded);
            // Restore the client's original txid: the wire bytes went
            // upstream with OUR generated ID (see forward).
            if resp.len() >= 2 {
                resp[0..2].copy_from_slice(&query.id.to_be_bytes());
            }
            // Only validated responses reach this point (forward drops
            // anything failing txid/QR/question checks), so caching here
            // can never poison the cache with a forgery.
            state.cache_store(&cache_key, &resp);
            state.emit(client, &query, QueryOutcome::Forwarded);
            Some(resp)
        }
        Err(e) => {
            state.counters.bump(&state.counters.upstream_errors);
            state.emit(client, &query, QueryOutcome::UpstreamError);
            warn!(error = %e, qname = %query.qname, "upstream exchange failed");
            wire::build_error_response(bytes, wire::RCODE_SERVFAIL)
        }
    }
}

/// Forward to the upstream pool: UDP first, TCP when the client is TCP or
/// the UDP answer comes back truncated (TC bit).
///
/// The packet goes out with a freshly GENERATED transaction ID (never the
/// client's verbatim), and every response is validated
/// ([`wire::validate_response`]: QR set, our txid, question echoed
/// byte-for-byte) before it is accepted. An invalid response is dropped —
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
    let upstream_id = state.txids.next();
    let mut forwarded = query_bytes.to_vec();
    forwarded[0..2].copy_from_slice(&upstream_id.to_be_bytes());
    let question = &forwarded[wire::HEADER_LEN..query.question_end];

    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream response failed validation (txid/QR/question)",
        )
    };
    if !via_tcp {
        match udp_exchange(upstream, &forwarded, state.config.upstream_timeout).await {
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

async fn udp_exchange(upstream: SocketAddr, query: &[u8], wait: Duration) -> io::Result<Vec<u8>> {
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
    let n = timeout(wait, sock.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream UDP timeout"))??;
    buf.truncate(n);
    Ok(buf)
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

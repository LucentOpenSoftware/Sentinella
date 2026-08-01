//! Loopback integration tests for the dnsguard proxy. All traffic stays on
//! 127.0.0.1; fake upstreams run on ephemeral ports. Tests are deterministic
//! — the only sleep is the TTL-expiry one, everything else is bounded by
//! short timeouts.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use dnsguard::filter::{CANARY_DOMAIN, FilterEngine};
use dnsguard::proxy::{
    BlockResponse, Counters, NoopDecisionHook, Proxy, ProxyConfig,
};
use dnsguard::wire::{self, CLASS_IN, RCODE_NXDOMAIN, RCODE_NOERROR, RCODE_SERVFAIL, TYPE_A};

const TEST_IP: [u8; 4] = [93, 184, 216, 34];

fn rcode_of(response: &[u8]) -> u8 {
    (u16::from_be_bytes([response[2], response[3]]) & 0x000F) as u8
}

fn id_of(response: &[u8]) -> u16 {
    u16::from_be_bytes([response[0], response[1]])
}

/// Canned NOERROR A-record response for a query, with configurable TTL and
/// TC flag (TC variant carries no answers, like a real truncated response).
fn canned_a_response(query: &[u8], ttl: u32, truncated: bool) -> Vec<u8> {
    let q = wire::parse_query(query).expect("test queries are valid");
    let mut out = Vec::new();
    out.extend_from_slice(&q.id.to_be_bytes());
    let flags: u16 = 0x8180 | if truncated { 0x0200 } else { 0 };
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&(if truncated { 0u16 } else { 1u16 }).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // ns/ar
    out.extend_from_slice(&query[wire::HEADER_LEN..q.question_end]);
    if !truncated {
        out.extend_from_slice(&[0xC0, 0x0C]); // name → question
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&TEST_IP);
    }
    out
}

/// Fake upstream: UDP responder with a call counter — PLUS a TCP responder
/// on the SAME port (real resolvers speak both; the self-test's step (iv)
/// resolves through our TCP listener, and TCP clients are forwarded to the
/// upstream over TCP). The responder decides per query; returning `None`
/// simulates a never-answering upstream (UDP: silence; TCP: connection
/// accepted, no answer).
async fn spawn_udp_upstream<F>(responder: F) -> (SocketAddr, Arc<AtomicUsize>)
where
    F: Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
    let addr = sock.local_addr().expect("addr");
    // TCP side on the same port (loopback port allocation is per-protocol).
    let tcp = TcpListener::bind(("127.0.0.1", addr.port()))
        .await
        .expect("bind upstream tcp side");
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_task = Arc::clone(&calls);
    let responder = Arc::new(responder);
    let responder_udp = Arc::clone(&responder);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            calls_task.fetch_add(1, Ordering::SeqCst);
            if let Some(resp) = responder_udp(&buf[..n]) {
                let _ = sock.send_to(&resp, peer).await;
            }
        }
    });
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            let responder = Arc::clone(&responder);
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let n = u16::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; n];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
                if let Some(resp) = responder(&buf) {
                    let framed = (resp.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&framed).await;
                    let _ = stream.write_all(&resp).await;
                }
            });
        }
    });
    (addr, calls)
}

/// Fake upstream speaking DNS-over-TCP (framed); sets `hit` on first
/// connection so tests can assert the fallback happened.
async fn spawn_tcp_upstream(hit: Arc<AtomicBool>, ttl: u32) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp upstream");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            hit.store(true, Ordering::SeqCst);
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let n = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; n];
            if stream.read_exact(&mut buf).await.is_err() {
                continue;
            }
            let resp = canned_a_response(&buf, ttl, false);
            let framed = (resp.len() as u16).to_be_bytes();
            let _ = stream.write_all(&framed).await;
            let _ = stream.write_all(&resp).await;
        }
    });
    addr
}

/// Bind a UDP socket and TCP listener on the SAME ephemeral port — needed
/// for the TC-fallback test, where the proxy retries the same upstream
/// address over TCP.
async fn bind_udp_tcp_pair() -> (UdpSocket, TcpListener, SocketAddr) {
    for _ in 0..16 {
        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let port = udp.local_addr().expect("addr").port();
        if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)).await {
            return (udp, tcp, SocketAddr::from(([127, 0, 0, 1], port)));
        }
    }
    panic!("could not bind udp+tcp pair");
}

struct TestProxy {
    addr: SocketAddr,
    counters: Arc<Counters>,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<std::io::Result<()>>,
}

async fn start_proxy(engine: FilterEngine, config: ProxyConfig) -> TestProxy {
    let proxy = Proxy::bind(config, engine, Arc::new(NoopDecisionHook))
        .await
        .expect("bind proxy");
    let addr = proxy.local_addr();
    let counters = proxy.counters();
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(proxy.run(rx));
    TestProxy {
        addr,
        counters,
        shutdown: tx,
        task,
    }
}

impl TestProxy {
    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

fn config_for(upstreams: Vec<SocketAddr>) -> ProxyConfig {
    ProxyConfig {
        listen: "127.0.0.1:0".parse().expect("literal addr"),
        upstreams,
        upstream_timeout: Duration::from_millis(500),
        ..ProxyConfig::default()
    }
}

/// A blackhole "upstream" (RFC 863 discard port) for tests whose queries
/// never leave the proxy (bind refuses an EMPTY upstream list).
fn dead_upstream() -> SocketAddr {
    "127.0.0.1:9".parse().expect("literal addr")
}

/// One-shot UDP query against the proxy from an ephemeral client socket.
async fn udp_query(addr: SocketAddr, query: &[u8], wait: Duration) -> Vec<u8> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    sock.send_to(query, addr).await.expect("send");
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(wait, sock.recv(&mut buf))
        .await
        .expect("proxy did not answer")
        .expect("recv");
    buf[..n].to_vec()
}

#[tokio::test]
async fn blocked_domain_responds_nxdomain_with_matching_id_and_question() {
    let mut engine = FilterEngine::new();
    engine.add_block("evil.example");
    let proxy = start_proxy(engine, config_for(vec![dead_upstream()])).await;

    let query = wire::build_query(0x1234, "evil.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;

    assert_eq!(id_of(&resp), 0x1234, "response ID must match request");
    assert_eq!(rcode_of(&resp), RCODE_NXDOMAIN);
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    assert_ne!(
        flags & wire::FLAG_AA,
        0,
        "locally synthesized block answer carries AA=1 (L07 self-identification)"
    );
    let parsed = wire::parse_query(&query).expect("parse");
    assert_eq!(
        &resp[wire::HEADER_LEN..],
        &query[wire::HEADER_LEN..parsed.question_end],
        "question echoed verbatim"
    );
    assert_eq!(proxy.counters.snapshot().blocked, 1);
    proxy.stop().await;
}

#[tokio::test]
async fn subdomain_of_blocked_suffix_is_blocked_but_not_superstring() {
    let mut engine = FilterEngine::new();
    engine.add_block("evil.example");
    let (upstream, calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let proxy = start_proxy(engine, config_for(vec![upstream])).await;

    let sub = wire::build_query(1, "a.b.evil.example", TYPE_A, CLASS_IN).expect("build");
    assert_eq!(
        rcode_of(&udp_query(proxy.addr, &sub, Duration::from_secs(2)).await),
        RCODE_NXDOMAIN
    );
    let superstring = wire::build_query(2, "notevil.example", TYPE_A, CLASS_IN).expect("build");
    assert_eq!(
        rcode_of(&udp_query(proxy.addr, &superstring, Duration::from_secs(2)).await),
        RCODE_NOERROR
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "only the allowed query went upstream");
    proxy.stop().await;
}

#[tokio::test]
async fn allowed_domain_is_forwarded_byte_equivalent() {
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 120, false))).await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    let query = wire::build_query(0xABCD, "example.com", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(resp, canned_a_response(&query, 120, false));
    assert_eq!(proxy.counters.snapshot().forwarded, 1);
    proxy.stop().await;
}

#[tokio::test]
async fn canary_is_blocked_even_with_empty_blocklist() {
    // UPDATED (round 3, A3/L07/L12): the canary is now SHORT-CIRCUITED by
    // the serving path before cache/filter/forward and answered with the
    // self-identifying zero-IP signature (NOERROR, AA=1, ancount=1,
    // 0.0.0.0) under EITHER block policy. The old assertion (NXDOMAIN)
    // codified the bug: a hard-coded NXDOMAIN expectation is what made the
    // self-test permanently red under `block_response = "zero_ip"`.
    let (upstream, calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    let query = wire::build_query(7, CANARY_DOMAIN, TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(id_of(&resp), 7);
    assert_eq!(rcode_of(&resp), RCODE_NOERROR, "canary gets the zero-IP signature");
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    assert_ne!(flags & wire::FLAG_AA, 0, "locally synthesized answer is authoritative");
    assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "one answer");
    assert_eq!(&resp[resp.len() - 4..], &[0, 0, 0, 0], "A rdata 0.0.0.0");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "canary never reaches upstream");

    // The signature is independent of the configured block policy.
    let snap = proxy.counters.snapshot();
    assert_eq!(snap.canary_probes, 1, "counted in the canary's OWN counter");
    assert_eq!(snap.blocked, 0, "never a user-facing block");
    proxy.stop().await;
}

#[tokio::test]
async fn canary_never_touches_cache_even_when_engine_lost_the_rule() {
    // L07: with an engine that lost its canary rule (FilterEngine::default,
    // zero rules — models a blocklist load that failed), the OLD code
    // forwarded the canary upstream and cached the upstream's NXDOMAIN for
    // 60 s. The short-circuit must answer from the signature regardless:
    // upstream untouched, no cache entry, identical signature twice.
    let (upstream, calls) = spawn_udp_upstream(|q| {
        let mut resp = canned_a_response(q, 60, false);
        resp[3] = 0x83; // NXDOMAIN, like any resolver for .invalid
        resp[7] = 0; // ancount = 0
        resp.truncate(resp.len() - 16);
        Some(resp)
    })
    .await;
    let proxy = start_proxy(FilterEngine::default(), config_for(vec![upstream])).await;

    for id in [1u16, 2] {
        let query = wire::build_query(id, CANARY_DOMAIN, TYPE_A, CLASS_IN).expect("build");
        let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
        assert_eq!(rcode_of(&resp), RCODE_NOERROR, "signature even without the engine rule");
        assert_eq!(&resp[resp.len() - 4..], &[0, 0, 0, 0]);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "canary never leaks upstream");
    let snap = proxy.counters.snapshot();
    assert_eq!(snap.canary_probes, 2);
    assert_eq!(snap.cache_hits, 0, "canary answers are never served from cache");
    proxy.stop().await;
}

#[tokio::test]
async fn zero_ip_policy_answers_zero_a_record() {
    let mut engine = FilterEngine::new();
    engine.add_block("evil.example");
    let mut config = config_for(vec![dead_upstream()]);
    config.block_response = BlockResponse::ZeroIp;
    let proxy = start_proxy(engine, config).await;

    let query = wire::build_query(9, "evil.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(&resp[resp.len() - 4..], &[0, 0, 0, 0], "A rdata is 0.0.0.0");
    let info = wire::response_info(&resp).expect("walkable");
    assert_eq!(info.min_ttl, Some(60));
    proxy.stop().await;
}

#[tokio::test]
async fn second_identical_query_is_served_from_cache() {
    let (upstream, calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 300, false))).await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    let q1 = wire::build_query(1, "cache-me.example", TYPE_A, CLASS_IN).expect("build");
    let first = udp_query(proxy.addr, &q1, Duration::from_secs(2)).await;
    // Different ID, same key: cache must patch the response ID.
    let q2 = wire::build_query(2, "cache-me.example", TYPE_A, CLASS_IN).expect("build");
    let second = udp_query(proxy.addr, &q2, Duration::from_secs(2)).await;

    assert_eq!(calls.load(Ordering::SeqCst), 1, "second query must not hit upstream");
    assert_eq!(id_of(&second), 2, "cached response carries the new ID");
    assert_eq!(second[2..], first[2..], "rest of the cached response is identical");
    assert_eq!(proxy.counters.snapshot().cache_hits, 1);
    proxy.stop().await;
}

#[tokio::test]
async fn cache_entry_expires_with_upstream_ttl() {
    // TTL=1s ⇒ proxy caches for min(1s, 300s cap) = 1s.
    let (upstream, calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 1, false))).await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    let query = wire::build_query(1, "short-lived.example", TYPE_A, CLASS_IN).expect("build");
    udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_millis(1100)).await;

    let query = wire::build_query(2, "short-lived.example", TYPE_A, CLASS_IN).expect("build");
    udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2, "expired entry must refetch");
    proxy.stop().await;
}

#[tokio::test]
async fn tc_bit_response_triggers_tcp_fallback() {
    let (udp, tcp, addr) = bind_udp_tcp_pair().await;
    let tcp_hit = Arc::new(AtomicBool::new(false));
    let tcp_hit_task = Arc::clone(&tcp_hit);
    // UDP side always answers with TC set; TCP side answers for real.
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
            let resp = canned_a_response(&buf[..n], 0, true);
            let _ = udp.send_to(&resp, peer).await;
        }
    });
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            tcp_hit_task.store(true, Ordering::SeqCst);
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let n = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; n];
            if stream.read_exact(&mut buf).await.is_err() {
                continue;
            }
            let resp = canned_a_response(&buf, 120, false);
            let framed = (resp.len() as u16).to_be_bytes();
            let _ = stream.write_all(&framed).await;
            let _ = stream.write_all(&resp).await;
        }
    });

    let proxy = start_proxy(FilterEngine::new(), config_for(vec![addr])).await;
    let query = wire::build_query(3, "big-response.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;

    assert!(tcp_hit.load(Ordering::SeqCst), "proxy must retry over TCP");
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(resp, canned_a_response(&query, 120, false));
    proxy.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_bound_sheds_excess_with_servfail_without_hanging() {
    // Slow-but-healthy upstream: every answer takes ~300ms, so the 256
    // permit-holders occupy the semaphore long enough to force shedding —
    // while still proving the proxy forwards correctly. WHY the healthy
    // assertions: a test that only checks SERVFAIL is vacuous, because a
    // fully broken proxy also emits SERVFAIL for everything.
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream"));
    let upstream = sock.local_addr().expect("addr");
    tokio::spawn({
        let sock = Arc::clone(&sock);
        async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let bytes = buf[..n].to_vec();
                let sock = Arc::clone(&sock);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let resp = canned_a_response(&bytes, 60, false);
                    let _ = sock.send_to(&resp, peer).await;
                });
            }
        }
    });
    let mut config = config_for(vec![upstream]);
    config.upstream_timeout = Duration::from_secs(5);
    let proxy = start_proxy(FilterEngine::new(), config).await;

    // BEFORE: a healthy query forwards and returns the canned A record.
    let probe = wire::build_query(0xF0, "before.shed.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &probe, Duration::from_secs(5)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR, "healthy query must forward BEFORE the flood");
    assert_eq!(&resp[resp.len() - 4..], &TEST_IP, "canned A record");

    const TOTAL: u16 = 300;
    let mut handles = Vec::new();
    for i in 0..TOTAL {
        let addr = proxy.addr;
        let query =
            wire::build_query(i, &format!("host-{i}.shed.example"), TYPE_A, CLASS_IN).expect("build");
        handles.push(tokio::spawn(async move {
            udp_query(addr, &query, Duration::from_secs(10)).await
        }));
    }
    let mut responses = 0u32;
    for handle in handles {
        let resp = handle.await.expect("client task");
        let rcode = rcode_of(&resp);
        assert!(
            rcode == RCODE_SERVFAIL || rcode == RCODE_NOERROR,
            "answers are either forwarded or shed, never garbage: rcode={rcode}"
        );
        responses += 1;
    }
    assert_eq!(responses, u32::from(TOTAL), "every query got an answer — no hang");
    let snap = proxy.counters.snapshot();
    assert!(snap.shed >= 1, "excess over the semaphore must be shed: {snap:?}");
    assert_eq!(snap.queries, u64::from(TOTAL) + 1);

    // AFTER: the proxy is still healthy — a fresh query forwards with the
    // canned A record (a broken proxy emitting SERVFAIL fails here).
    let probe = wire::build_query(0xF1, "after.shed.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &probe, Duration::from_secs(5)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR, "healthy query must forward AFTER the flood");
    assert_eq!(&resp[resp.len() - 4..], &TEST_IP, "canned A record");
    proxy.stop().await;
}

#[tokio::test]
async fn tcp_client_end_to_end_blocked_and_allowed() {
    let tcp_hit = Arc::new(AtomicBool::new(false));
    let upstream = spawn_tcp_upstream(Arc::clone(&tcp_hit), 120).await;
    let mut engine = FilterEngine::new();
    engine.add_block("evil.example");
    let proxy = start_proxy(engine, config_for(vec![upstream])).await;

    let mut stream = TcpStream::connect(proxy.addr).await.expect("connect");

    // Blocked over TCP: framed NXDOMAIN, upstream untouched.
    let blocked = wire::build_query(0x1111, "evil.example", TYPE_A, CLASS_IN).expect("build");
    stream
        .write_all(&(blocked.len() as u16).to_be_bytes())
        .await
        .expect("write len");
    stream.write_all(&blocked).await.expect("write query");
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut len_buf))
        .await
        .expect("no response")
        .expect("read len");
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await.expect("read body");
    assert_eq!(id_of(&buf), 0x1111);
    assert_eq!(rcode_of(&buf), RCODE_NXDOMAIN);
    assert!(!tcp_hit.load(Ordering::SeqCst));

    // Allowed over TCP on the same connection: forwarded over TCP upstream.
    let allowed = wire::build_query(0x2222, "example.com", TYPE_A, CLASS_IN).expect("build");
    stream
        .write_all(&(allowed.len() as u16).to_be_bytes())
        .await
        .expect("write len");
    stream.write_all(&allowed).await.expect("write query");
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut len_buf))
        .await
        .expect("no response")
        .expect("read len");
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await.expect("read body");
    assert_eq!(buf, canned_a_response(&allowed, 120, false));
    assert!(tcp_hit.load(Ordering::SeqCst), "TCP client must use TCP upstream");
    proxy.stop().await;
}

#[tokio::test]
async fn malformed_query_gets_formerr_and_dead_upstream_gets_servfail() {
    // Upstream that never answers ⇒ SERVFAIL after the timeout.
    let (upstream, _calls) = spawn_udp_upstream(|_q| None).await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    // Garbage with a plausible header (qdcount=2) ⇒ FORMERR with echoed ID.
    let mut garbage = vec![0xDE, 0xAD, 0x01, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0];
    garbage.extend_from_slice(&[0; 8]);
    let resp = udp_query(proxy.addr, &garbage, Duration::from_secs(2)).await;
    assert_eq!(id_of(&resp), 0xDEAD);
    assert_eq!(rcode_of(&resp), 1, "FORMERR");

    // Valid query, dead upstream ⇒ SERVFAIL, counted as upstream error.
    let query = wire::build_query(5, "lonely.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_SERVFAIL);
    assert_eq!(proxy.counters.snapshot().upstream_errors, 1);
    proxy.stop().await;
}

/// Build a query whose qname is a SINGLE wire label containing `label`
/// verbatim — e.g. b"microsoft.com" as one 13-byte label. Legal on the
/// wire; this is the cache-poisoning encoding from the threat model.
fn single_label_query(id: u16, label: &[u8]) -> Vec<u8> {
    assert!(label.len() <= 63, "test label must fit one wire label");
    let mut v = vec![
        (id >> 8) as u8, (id & 0xFF) as u8, // id
        0x01, 0x00, // flags: RD
        0x00, 0x01, // qdcount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    v.push(label.len() as u8);
    v.extend_from_slice(label);
    v.push(0); // root
    v.extend_from_slice(&TYPE_A.to_be_bytes());
    v.extend_from_slice(&CLASS_IN.to_be_bytes());
    v
}

#[tokio::test]
async fn dot_in_label_encoding_gets_separate_cache_entry_from_victim() {
    // The single label "microsoft.com" and the two-label name must live
    // under DIFFERENT cache keys (raw wire bytes), so the hostile encoding
    // can neither read nor poison the victim's entry.
    let (upstream, calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 300, false))).await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    // Victim: two-label name, gets cached.
    let victim = wire::build_query(1, "microsoft.com", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &victim, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Hostile: one label carrying "microsoft.com". Must reach upstream —
    // a cache hit here would mean the keys collide.
    let hostile = single_label_query(2, b"microsoft.com");
    let resp = udp_query(proxy.addr, &hostile, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(id_of(&resp), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "hostile encoding must not hit the victim's entry");

    // Both repeat: each is served from its OWN entry, upstream untouched.
    let victim = wire::build_query(3, "microsoft.com", TYPE_A, CLASS_IN).expect("build");
    udp_query(proxy.addr, &victim, Duration::from_secs(2)).await;
    let hostile = single_label_query(4, b"microsoft.com");
    let resp = udp_query(proxy.addr, &hostile, Duration::from_secs(2)).await;
    assert_eq!(id_of(&resp), 4, "hostile entry cached under its own key");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "no further upstream traffic");
    assert_eq!(proxy.counters.snapshot().cache_hits, 2);
    proxy.stop().await;
}

#[tokio::test]
async fn hostile_nxdomain_cannot_poison_victim_cache() {
    // Original attack shape: the hostile encoding resolves to NXDOMAIN at
    // the upstream; that negative answer must be cached under the hostile
    // wire name only, never blackholing the victim.
    let (upstream, calls) = spawn_udp_upstream(|q| {
        let mut resp = canned_a_response(q, 60, false);
        resp[3] = 0x83; // rcode NXDOMAIN
        resp[7] = 0; // ancount = 0
        resp.truncate(resp.len() - 16); // drop the answer record
        Some(resp)
    })
    .await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    let hostile = single_label_query(1, b"blackhole.example");
    let resp = udp_query(proxy.addr, &hostile, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NXDOMAIN);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Victim (two labels) must still reach upstream — not the cached
    // negative answer keyed by the hostile encoding.
    let victim = wire::build_query(2, "blackhole.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &victim, Duration::from_secs(2)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2, "victim query refetched, not poisoned");
    assert_eq!(id_of(&resp), 2);
    proxy.stop().await;
}

#[tokio::test]
async fn dot_in_label_does_not_match_two_label_block_rule() {
    // The filter sees the escaped presentation ("microsoft\.com"); it must
    // NOT match the two-label suffix rule "microsoft.com", so the hostile
    // encoding is forwarded while the genuine name is blocked.
    let mut engine = FilterEngine::new();
    engine.add_block("microsoft.com");
    let (upstream, calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let proxy = start_proxy(engine, config_for(vec![upstream])).await;

    let genuine = wire::build_query(1, "microsoft.com", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &genuine, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NXDOMAIN, "genuine name blocked");
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let hostile = single_label_query(2, b"microsoft.com");
    let resp = udp_query(proxy.addr, &hostile, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR, "hostile single label is a different name: forwarded");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    proxy.stop().await;
}

/// Upstream that records the txid of every query it sees.
async fn spawn_txid_recorder() -> (SocketAddr, Arc<std::sync::Mutex<Vec<u16>>>) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_task = Arc::clone(&seen);
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
    let addr = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            seen_task
                .lock()
                .expect("mutex")
                .push(u16::from_be_bytes([buf[0], buf[1]]));
            let _ = sock.send_to(&canned_a_response(&buf[..n], 60, false), peer).await;
        }
    });
    (addr, seen)
}

#[tokio::test]
async fn upstream_txid_is_generated_not_client_controlled() {
    let (upstream, seen) = spawn_txid_recorder().await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    // Distinct names per attempt avoid cache hits; a random collision
    // (generated id == client id) has probability 1/65536 per attempt.
    let mut observed_rewrite = false;
    for (i, client_id) in [0x0000u16, 0x1234, 0xBEEF].into_iter().enumerate() {
        let query = wire::build_query(
            client_id,
            &format!("txid-{i}.example"),
            TYPE_A,
            CLASS_IN,
        )
        .expect("build");
        let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
        assert_eq!(id_of(&resp), client_id, "client gets its own txid back");
        assert_eq!(rcode_of(&resp), RCODE_NOERROR);
        let seen = seen.lock().expect("mutex");
        let &upstream_id = seen.last().expect("upstream saw the query");
        if upstream_id != client_id {
            observed_rewrite = true;
        }
    }
    assert!(
        observed_rewrite,
        "the client's txid is never forwarded verbatim: {:?}",
        seen.lock().expect("mutex")
    );
    proxy.stop().await;
}

/// One bad-response case: a mutator applied to the otherwise-valid canned
/// response; the proxy must drop it (SERVFAIL to the client, upstream
/// error counted) and NEVER cache it — a repeat query goes upstream again.
async fn assert_bad_response_dropped_and_not_cached<F>(name: &str, corrupt: F)
where
    F: Fn(&mut Vec<u8>) + Send + Sync + 'static,
{
    let (upstream, calls) = spawn_udp_upstream(move |q| {
        let mut resp = canned_a_response(q, 300, false);
        corrupt(&mut resp);
        Some(resp)
    })
    .await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    let query = wire::build_query(1, name, TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_SERVFAIL, "invalid upstream response dropped");
    assert_eq!(proxy.counters.snapshot().upstream_errors, 1);

    // Repeat with a different txid: must hit upstream AGAIN (nothing was
    // cached from the invalid response).
    let query = wire::build_query(2, name, TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_SERVFAIL);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "invalid response was not cached");
    assert_eq!(proxy.counters.snapshot().upstream_errors, 2);
    proxy.stop().await;
}

#[tokio::test]
async fn wrong_txid_response_is_dropped_and_never_cached() {
    assert_bad_response_dropped_and_not_cached("wrong-txid.example", |resp| {
        resp[0] ^= 0x5A; // break the txid echo
    })
    .await;
}

#[tokio::test]
async fn qr_unset_response_is_dropped_and_never_cached() {
    assert_bad_response_dropped_and_not_cached("qr-unset.example", |resp| {
        resp[2] &= 0x7F; // clear QR
    })
    .await;
}

#[tokio::test]
async fn mismatched_question_response_is_dropped_and_never_cached() {
    assert_bad_response_dropped_and_not_cached("mismatched-q.example", |resp| {
        // WHY not `^= 0x20`: a case flip is LEGAL (RFC 4343 — qname echo is
        // case-insensitive; case-normalizing upstreams must be accepted).
        // A real letter change breaks the question under any comparison.
        resp[wire::HEADER_LEN + 1] = b'z';
    })
    .await;
}

#[tokio::test]
async fn valid_upstream_response_is_accepted() {
    // Companion to the drop tests: the same validation path accepts a
    // well-formed response (QR set, generated txid echoed, question
    // byte-equal) — otherwise the drop tests would be vacuous.
    let (upstream, calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 120, false))).await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;
    let query = wire::build_query(0x4242, "valid.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(id_of(&resp), 0x4242);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.counters.snapshot().forwarded, 1);
    assert_eq!(proxy.counters.snapshot().upstream_errors, 0);
    proxy.stop().await;
}

/// Open `n` TCP connections to the proxy and dribble bytes of a query
/// frame that never completes within the test window — the classic
/// slowloris shape against a DNS listener (a 0x0100 = 256-byte body,
/// delivered one byte at a time).
async fn spawn_dribblers(addr: SocketAddr, n: usize, interval: Duration) -> Vec<JoinHandle<()>> {
    let mut tasks = Vec::new();
    for _ in 0..n {
        tasks.push(tokio::spawn(async move {
            let Ok(mut stream) = TcpStream::connect(addr).await else {
                return; // pool-full connections are closed; that's fine
            };
            // Length-prefix high byte: announces a ≥256-byte body.
            if stream.write_all(&[0x01]).await.is_err() {
                return;
            }
            loop {
                if stream.write_all(&[0x00]).await.is_err() {
                    return;
                }
                tokio::time::sleep(interval).await;
            }
        }));
    }
    tasks
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dribbling_tcp_connections_do_not_starve_udp() {
    // Exhaustion MUST be real for this test to certify anything (a pool
    // with free permits left proves nothing): tiny pools — 8 UDP in-flight
    // permits, 8 TCP connection permits — and 16 dribblers, so the TCP
    // pool is provably saturated. If the TCP pool were ever merged with
    // the UDP pool (or sized from it), the dribblers would eat the 8
    // shared permits and the UDP assertions below would fail.
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let mut engine = FilterEngine::new();
    engine.add_block("evil.example");
    let mut config = config_for(vec![upstream]);
    config.max_in_flight = 8;
    config.tcp_max_connections = 8;
    config.tcp_queue_timeout = Duration::from_millis(300);
    let proxy = start_proxy(engine, config).await;

    let dribblers = spawn_dribblers(proxy.addr, 16, Duration::from_millis(200)).await;
    // Give the dribblers a moment to occupy the TCP pool.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Proof of exhaustion AND of the fail-safe (round 3, A1/A2): a fresh
    // TCP connection waits out the bounded queue and is answered SERVFAIL
    // for its pending query — a retryable answer, counted in the DEDICATED
    // `tcp_pool_full` counter. The pre-fix behaviour was a bare RST/EOF
    // folded into the shared `shed` counter; asserting SERVFAIL +
    // tcp_pool_full fails on that code on both counts.
    let shed_before = proxy.counters.snapshot().shed;
    let mut stream = TcpStream::connect(proxy.addr)
        .await
        .expect("connect must succeed — the listener accepts and queues");
    let query = wire::build_query(9, "fine.example", TYPE_A, CLASS_IN).expect("build");
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .expect("write len");
    stream.write_all(&query).await.expect("write query");
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut len_buf))
        .await
        .expect("pool-full client must be ANSWERED (SERVFAIL), not reset")
        .expect("read len");
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await.expect("read body");
    assert_eq!(id_of(&buf), 9, "SERVFAIL echoes the pending query's ID");
    assert_eq!(
        rcode_of(&buf),
        RCODE_SERVFAIL,
        "pool exhaustion is fail-safe: SERVFAIL, never a bare RST/EOF"
    );
    let snap = proxy.counters.snapshot();
    assert!(
        snap.tcp_pool_full >= 1,
        "exhaustion is counted in the DEDICATED counter: {snap:?}"
    );
    assert_eq!(
        snap.shed, shed_before,
        "TCP pool exhaustion must NOT be folded into the UDP shed counter: {snap:?}"
    );

    // The UDP path keeps working while the TCP pool is saturated
    // (forwarding AND blocking). Precisely: UDP answers that fit the
    // negotiated payload size never touch the TCP pool at all; only a
    // UDP answer EXCEEDING it is truncated onto TCP, and there the retry
    // is now fail-safe (SERVFAIL above) rather than a connection reset.
    let allowed = wire::build_query(1, "fine.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &allowed, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR, "UDP forwarding unaffected by TCP pressure");

    let blocked = wire::build_query(2, "evil.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &blocked, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NXDOMAIN, "UDP blocking unaffected by TCP pressure");

    for task in dribblers {
        task.abort();
    }
    proxy.stop().await;
}

#[tokio::test]
async fn tcp_hard_lifetime_cap_closes_dribbling_connection() {
    // Idle timeout long, lifetime cap short: the connection must die at the
    // lifetime cap even though it never goes idle.
    let tcp_hit = Arc::new(AtomicBool::new(false));
    let upstream = spawn_tcp_upstream(tcp_hit, 60).await;
    let mut config = config_for(vec![upstream]);
    config.tcp_idle_timeout = Duration::from_secs(60);
    config.tcp_max_lifetime = Duration::from_millis(500);
    let proxy = start_proxy(FilterEngine::new(), config).await;

    let mut stream = TcpStream::connect(proxy.addr).await.expect("connect");

    // First query succeeds well within the lifetime.
    let query = wire::build_query(0x3333, "lifetime.example", TYPE_A, CLASS_IN).expect("build");
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .expect("write len");
    stream.write_all(&query).await.expect("write query");
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut len_buf))
        .await
        .expect("first answer")
        .expect("read len");
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await.expect("read body");
    assert_eq!(rcode_of(&buf), RCODE_NOERROR);

    // Past the hard lifetime the proxy must have closed the connection,
    // despite it never being idle that long.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let query = wire::build_query(0x4444, "lifetime.example", TYPE_A, CLASS_IN).expect("build");
    let _ = stream.write_all(&(query.len() as u16).to_be_bytes()).await;
    let _ = stream.write_all(&query).await;
    let mut len_buf = [0u8; 2];
    let closed = tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut len_buf)).await;
    assert!(
        closed.is_err() || closed.expect("io").is_err(),
        "connection must be closed by the hard lifetime cap"
    );
    proxy.stop().await;
}

const TYPE_TXT: u16 = 16;

/// Canned NOERROR response with ONE TXT record carrying `rdata_len` bytes
/// of rdata (chunked into ≤255-byte character-strings, as the wire format
/// requires) — the oversized-answer fixture.
fn canned_big_txt_response(query: &[u8], ttl: u32, rdata_len: usize) -> Vec<u8> {
    let q = wire::parse_query(query).expect("test queries are valid");
    let mut out = Vec::new();
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR|RD|RA, NOERROR
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&1u16.to_be_bytes()); // ancount
    out.extend_from_slice(&[0, 0, 0, 0]); // ns/ar
    out.extend_from_slice(&query[wire::HEADER_LEN..q.question_end]);
    out.extend_from_slice(&[0xC0, 0x0C]); // name → question
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata_len as u16).to_be_bytes());
    let mut remaining = rdata_len;
    while remaining > 0 {
        let chunk = remaining.min(255);
        out.push(chunk as u8);
        out.extend(std::iter::repeat_n(b'x', chunk));
        remaining -= chunk;
    }
    out
}

/// Fake upstream speaking DNS-over-TCP (framed) with a per-query responder.
/// Returns the address and a connection counter.
async fn spawn_tcp_upstream_with<F>(responder: F) -> (SocketAddr, Arc<AtomicUsize>)
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp upstream");
    let addr = listener.local_addr().expect("addr");
    let conns = Arc::new(AtomicUsize::new(0));
    let conns_task = Arc::clone(&conns);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            conns_task.fetch_add(1, Ordering::SeqCst);
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let n = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; n];
            if stream.read_exact(&mut buf).await.is_err() {
                continue;
            }
            let resp = responder(&buf);
            let framed = (resp.len() as u16).to_be_bytes();
            let _ = stream.write_all(&framed).await;
            let _ = stream.write_all(&resp).await;
        }
    });
    (addr, conns)
}

/// Build a query from raw wire labels (bytes taken verbatim per label).
fn raw_label_query(id: u16, labels: &[&[u8]], qtype: u16) -> Vec<u8> {
    let mut v = vec![
        (id >> 8) as u8, (id & 0xFF) as u8, // id
        0x01, 0x00, // flags: RD
        0x00, 0x01, // qdcount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in labels {
        assert!(label.len() <= 63, "test label must fit one wire label");
        v.push(label.len() as u8);
        v.extend_from_slice(label);
    }
    v.push(0); // root
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&CLASS_IN.to_be_bytes());
    v
}

/// One framed TCP query against the proxy; returns the response body.
async fn tcp_query(stream: &mut TcpStream, query: &[u8], wait: Duration) -> Vec<u8> {
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .expect("write len");
    stream.write_all(query).await.expect("write query");
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(wait, stream.read_exact(&mut len_buf))
        .await
        .expect("no response")
        .expect("read len");
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; n];
    tokio::time::timeout(wait, stream.read_exact(&mut buf))
        .await
        .expect("short response")
        .expect("read body");
    buf
}

#[tokio::test]
async fn tcp_hard_lifetime_cap_kills_connection_blocked_on_write() {
    // The WRITE-path half of the hard cap (the read-path half is
    // tcp_hard_lifetime_cap_closes_dribbling_connection): the client sends
    // a query and then NEVER reads, so the 60KB answer fills the kernel
    // send buffer and an unbounded write_all would park forever, holding
    // the (single) TCP permit. The cap must kill the connection anyway:
    // the kill counter moves AND the freed permit serves a fresh client.
    //
    // Verified to FAIL on the pre-fix code: with an unbounded write the
    // permit is never freed, the fresh probe connection is closed at
    // accept, and tcp_query times out.
    let (upstream, _conns) = spawn_tcp_upstream_with(|q| {
        let parsed = wire::parse_query(q).expect("valid");
        if parsed.qtype == TYPE_TXT {
            canned_big_txt_response(q, 300, 60_000)
        } else {
            canned_a_response(q, 60, false)
        }
    })
    .await;
    let mut config = config_for(vec![upstream]);
    config.tcp_idle_timeout = Duration::from_secs(60);
    config.tcp_max_lifetime = Duration::from_millis(500);
    config.tcp_max_connections = 1; // permit starvation is observable
    let proxy = start_proxy(FilterEngine::new(), config).await;

    // The blocker: PIPELINES 100 queries for the 60KB TXT answer (~6MB of
    // response traffic) and then never reads — far beyond any loopback
    // send/receive buffer autotuning, so the server's write side is
    // guaranteed to park once the buffers fill. (A single 60KB answer is
    // NOT enough: Windows loopback autotuning absorbs it and the test
    // cannot tell a bounded write from an unbounded one.)
    let mut blocker = TcpStream::connect(proxy.addr).await.expect("connect");
    let mut pipeline = Vec::new();
    for i in 0..100u16 {
        let query =
            wire::build_query(0x1000 + i, "huge-txt.example", TYPE_TXT, CLASS_IN).expect("build");
        pipeline.extend_from_slice(&(query.len() as u16).to_be_bytes());
        pipeline.extend_from_slice(&query);
    }
    blocker.write_all(&pipeline).await.expect("write pipeline");
    // Deliberately no read.

    // Well past the hard cap: the connection must be dead, permit freed.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let kills = proxy.counters.snapshot().tcp_lifetime_kills;
    assert!(kills >= 1, "blocked-on-write connection must be killed by the cap");

    // The freed permit serves a fresh client (fails on pre-fix code: the
    // pool is still exhausted, the probe is closed at accept).
    let mut fresh = TcpStream::connect(proxy.addr).await.expect("connect");
    let probe = wire::build_query(0x2020, "after-kill.example", TYPE_A, CLASS_IN).expect("build");
    let resp = tcp_query(&mut fresh, &probe, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR, "fresh connection served after the kill");
    drop(blocker);
    proxy.stop().await;
}

#[tokio::test]
async fn tcp_fetched_oversized_answer_is_truncated_for_udp_full_for_tcp() {
    // RFC 2181-style truncation: an answer fetched via the TCP fallback
    // (here ~60KB) must NOT be replayed whole to UDP clients (the OS
    // drops the oversized datagram with TC clear — a hard failure with no
    // retry signal). UDP gets TC=1, ≤512 bytes, question intact, zero
    // answers; TCP clients get the full answer; the full answer is what
    // is cached (exactly ONE upstream TCP fetch for all three queries).
    //
    // Verified to FAIL on the pre-fix code: the UDP client received the
    // whole 60KB datagram with TC clear.
    let (udp, tcp, addr) = bind_udp_tcp_pair().await;
    let tcp_conns = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
            // UDP side: always truncated, no answers — forces TCP fallback.
            let resp = canned_a_response(&buf[..n], 0, true);
            let _ = udp.send_to(&resp, peer).await;
        }
    });
    tokio::spawn({
        let tcp_conns = Arc::clone(&tcp_conns);
        async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                tcp_conns.fetch_add(1, Ordering::SeqCst);
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    continue;
                }
                let n = u16::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; n];
                if stream.read_exact(&mut buf).await.is_err() {
                    continue;
                }
                let resp = canned_big_txt_response(&buf, 300, 60_000);
                let framed = (resp.len() as u16).to_be_bytes();
                let _ = stream.write_all(&framed).await;
                let _ = stream.write_all(&resp).await;
            }
        }
    });

    let proxy = start_proxy(FilterEngine::new(), config_for(vec![addr])).await;
    let query = wire::build_query(0xAAAA, "huge-txt.example", TYPE_TXT, CLASS_IN).expect("build");
    let parsed = wire::parse_query(&query).expect("parse");
    let question = &query[wire::HEADER_LEN..parsed.question_end];

    // UDP client: truncated response, never the oversized answer.
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert!(resp.len() <= 512, "UDP answer must fit the payload limit: {}", resp.len());
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    assert_ne!(flags & wire::FLAG_TC, 0, "TC bit set so the client retries over TCP");
    assert_eq!(&resp[6..12], &[0; 6], "AN/NS/AR zeroed");
    assert_eq!(&resp[wire::HEADER_LEN..], question, "question intact");
    assert_eq!(tcp_conns.load(Ordering::SeqCst), 1, "fetched once over TCP");

    // TCP client (cache hit): the FULL 60KB answer.
    let mut stream = TcpStream::connect(proxy.addr).await.expect("connect");
    let query2 = wire::build_query(0xBBBB, "huge-txt.example", TYPE_TXT, CLASS_IN).expect("build");
    let resp = tcp_query(&mut stream, &query2, Duration::from_secs(2)).await;
    assert!(resp.len() > 60_000, "TCP client gets the full answer: {}", resp.len());
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(tcp_conns.load(Ordering::SeqCst), 1, "served from cache, not refetched");

    // UDP again (cache hit): still a proper truncation, still no refetch.
    let query3 = wire::build_query(0xCCCC, "huge-txt.example", TYPE_TXT, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query3, Duration::from_secs(2)).await;
    assert!(resp.len() <= 512);
    assert_ne!(u16::from_be_bytes([resp[2], resp[3]]) & wire::FLAG_TC, 0, "TC set from cache too");
    assert_eq!(tcp_conns.load(Ordering::SeqCst), 1);
    proxy.stop().await;
}

#[tokio::test]
async fn edns_ecs_additional_section_is_stripped_before_forwarding() {
    // UPDATED (round 3, L01): the guarantee narrowed, not removed. The old
    // test asserted the forwarded query carries ARCOUNT=0 — true when we
    // stripped EDNS entirely. The round-3 AD/DO/CD decision relays a
    // MINIMAL, SELF-CONSTRUCTED OPT (clamped size + the client's DO bit),
    // so ARCOUNT is now 1. What must NEVER leave the machine is unchanged:
    // the client's OPTION PAYLOAD — ECS above all, which would steer the
    // answer we then cache machine-wide. This test now asserts the OPT we
    // emit is exactly our own 11-byte construction with empty rdata.
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_task = Arc::clone(&seen);
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
    let upstream = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let arcount = u16::from_be_bytes([buf[10], buf[11]]);
            seen_task.lock().expect("mutex").push((arcount, buf[..n].to_vec()));
            let _ = sock.send_to(&canned_a_response(&buf[..n], 300, false), peer).await;
        }
    });
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    // Client query with an EDNS0 OPT additional record carrying ECS.
    let mut query = wire::build_query(0x7777, "ecs.example", TYPE_A, CLASS_IN).expect("build");
    let parsed = wire::parse_query(&query).expect("parse");
    let question_len = parsed.question_end - wire::HEADER_LEN;
    query[11] = 1; // arcount = 1
    query.extend_from_slice(&[
        0x00, // name: root
        0x00, 0x29, // type OPT (41)
        0x10, 0x00, // class: 4096 UDP payload
        0, 0, 0, 0, // ttl (DO clear)
        0x00, 0x0B, // rdlength 11
        0x00, 0x08, // OPTION-CODE: ECS (8)
        0x00, 0x07, // OPTION-LENGTH 7
        0x00, 0x01, // FAMILY: IPv4
        24, 0, // source /24, scope 0
        203, 0, 113, // 203.0.113.0/24
    ]);

    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    {
        let seen = seen.lock().expect("mutex");
        let (arcount, forwarded) = seen.last().expect("upstream saw the query");
        assert_eq!(*arcount, 1, "one self-constructed OPT is relayed (L01 decision)");
        assert_eq!(
            forwarded.len(),
            wire::HEADER_LEN + question_len + 11,
            "header + question + exactly one minimal OPT — nothing else"
        );
        assert_eq!(
            &forwarded[wire::HEADER_LEN + question_len..],
            &[
                0x00, // root name
                0x00, 0x29, // type OPT
                0x10, 0x00, // class: 4096 (client's size, clamped)
                0, 0, 0, 0, // ttl: ext-rcode 0, version 0, DO clear
                0, 0, // rdlength 0 — NO OPTIONS: the ECS is gone
            ],
            "the relayed OPT is self-constructed and carries no option payload"
        );
        assert!(
            !forwarded.windows(3).any(|w| w == [203, 0, 113]),
            "no ECS bytes anywhere in the forwarded query"
        );
    }

    // The cached answer is keyed on the question only (plus DO/CD posture,
    // identical here): a second client with a DIFFERENT ECS gets the same
    // cached entry (no per-ECS fork).
    let mut query2 = wire::build_query(0x7778, "ecs.example", TYPE_A, CLASS_IN).expect("build");
    query2[11] = 1;
    query2.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0x00, 0x0B, 0x00, 0x08, 0x00, 0x07, 0x00, 0x01,
        24, 0, 198, 51, 100, // a different ECS prefix
    ]);
    let resp = udp_query(proxy.addr, &query2, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(seen.lock().expect("mutex").len(), 1, "second query served from cache");
    assert_eq!(proxy.counters.snapshot().cache_hits, 1);
    proxy.stop().await;
}

#[tokio::test]
async fn case_normalizing_upstream_answer_is_accepted() {
    // Home CPE forwarders lowercase the echoed question; RFC 4343 says
    // qname comparison is case-insensitive. Verified to FAIL on the
    // pre-fix (byte-exact echo) code with SERVFAIL.
    let (upstream, calls) = spawn_udp_upstream(|q| {
        let mut resp = canned_a_response(q, 60, false);
        let parsed = wire::parse_query(q).expect("valid");
        for byte in &mut resp[wire::HEADER_LEN..parsed.question_end - 4] {
            *byte = byte.to_ascii_lowercase();
        }
        Some(resp)
    })
    .await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    let query = wire::build_query(0x5151, "MiXeD-CaSe.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR, "case-only echo difference must be accepted");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.counters.snapshot().upstream_errors, 0);
    proxy.stop().await;
}

#[tokio::test]
async fn stray_datagrams_before_the_real_answer_are_tolerated() {
    // One stray/invalid datagram must not kill a healthy exchange: the
    // upstream first sends sub-header garbage, then a valid answer with
    // the WRONG txid, then the real answer — the exchange succeeds.
    // Verified to FAIL on the pre-fix (single-recv) code: the garbage
    // datagram ended the exchange with SERVFAIL.
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
    let upstream = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let query = buf[..n].to_vec();
            let mut wrong_txid = canned_a_response(&query, 60, false);
            wrong_txid[0] ^= 0xFF;
            let _ = sock.send_to(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00], peer).await; // garbage
            let _ = sock.send_to(&wrong_txid, peer).await; // wrong txid
            let _ = sock.send_to(&canned_a_response(&query, 60, false), peer).await; // real
        }
    });
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    let query = wire::build_query(0x6161, "stray.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR, "stray datagrams dropped, real answer accepted");
    assert_eq!(id_of(&resp), 0x6161);
    assert_eq!(proxy.counters.snapshot().upstream_errors, 0);
    proxy.stop().await;
}

#[tokio::test]
async fn wire_legal_name_with_escaped_label_past_253_chars_is_blocked() {
    // End-to-end regression for the Block→Allow fail-open: the label of
    // 61 × 0x00 octets is wire-legal but escapes to 244 presentation
    // chars (255 with the suffix) — the filter must still decide it
    // against the suffix rule, never return None and fail open.
    let mut engine = FilterEngine::new();
    engine.add_block("c2.example");
    let (upstream, calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let proxy = start_proxy(engine, config_for(vec![upstream])).await;

    let query = raw_label_query(0x7171, &[&[0u8; 61], b"c2", b"example"], TYPE_A);
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NXDOMAIN, "wire-legal name must reach the block decision");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "blocked name never goes upstream");
    proxy.stop().await;
}

#[tokio::test]
async fn bind_refuses_empty_upstream_list() {
    // A resolver with no upstream is a lie: it would pass bind and the
    // filter self-test while SERVFAILing every real query.
    let result = Proxy::bind(
        config_for(vec![]),
        FilterEngine::new(),
        Arc::new(NoopDecisionHook),
    )
    .await;
    assert!(result.is_err(), "empty upstream list must be refused at bind");
}

#[tokio::test]
async fn self_test_is_green_against_a_healthy_fake_upstream() {
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let proxy = Proxy::bind(
        config_for(vec![upstream]),
        FilterEngine::new(),
        Arc::new(NoopDecisionHook),
    )
    .await
    .expect("bind");
    let report = proxy.self_test().await;
    assert!(report.engine_ok, "{report:?}");
    assert!(report.upstream_ok, "{report:?}");
    assert!(report.filter_ok, "{report:?}");
    assert!(
        report.tcp_ok,
        "step (iv): health_check_name resolves through the TCP listener (A2): {report:?}"
    );
    assert!(report.ok(), "{report:?}");
    assert!(report.detail.is_empty(), "{report:?}");
}

#[tokio::test]
async fn self_test_reports_dead_upstream() {
    // The discard port never answers: upstream_ok must be false. The
    // engine step stays green — it is purely in-process.
    //
    // UPDATED (round 3, A3/L12): this test used to assert filter_ok=true
    // ("plumbing works even though the upstream is dead"). Step (iii) now
    // ALSO requires a POSITIVE resolution of health_check_name THROUGH the
    // listener — a proxy that answers the canary but SERVFAILs everything
    // else must fail — so with a dead upstream filter_ok is false too.
    // The granularity the old test relied on ("plumbing vs upstream") is
    // preserved in `detail`, which names the failing sub-checks.
    let proxy = Proxy::bind(
        config_for(vec![dead_upstream()]),
        FilterEngine::new(),
        Arc::new(NoopDecisionHook),
    )
    .await
    .expect("bind");
    let report = proxy.self_test().await;
    assert!(report.engine_ok, "{report:?}");
    assert!(!report.upstream_ok, "dead upstream must be reported: {report:?}");
    assert!(
        !report.filter_ok,
        "nothing resolves through the listener with a dead upstream: {report:?}"
    );
    assert!(!report.ok());
    assert!(!report.detail.is_empty());
}

/// REGRESSION (round-3 HIGH). The hard lifetime cap was computed once into a
/// single `read_budget` shared by the length-prefix read AND the body read,
/// so a client that landed the second prefix byte just under the deadline
/// started a FRESH full-length body wait. Measured at 1.99x the cap.
///
/// The idle timeout is set FAR above the cap so that if the connection dies
/// on time, only the cap can have done it. On the pre-fix code this test
/// fails on the elapsed-time assertion (~740ms against a 400ms cap); the
/// counter assertion alone would NOT have caught it, because the old code
/// bumped `tcp_lifetime_kills` for the very connection that outlived the cap.
#[tokio::test]
async fn split_length_prefix_cannot_extend_the_hard_lifetime_cap() {
    const CAP: Duration = Duration::from_millis(400);
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let proxy = start_proxy(
        FilterEngine::new(),
        ProxyConfig {
            tcp_max_lifetime: CAP,
            tcp_idle_timeout: Duration::from_secs(10),
            ..config_for(vec![upstream])
        },
    )
    .await;

    let started = tokio::time::Instant::now();
    let mut stream = TcpStream::connect(proxy.addr).await.expect("connect");
    // Byte 1 of the 2-byte length prefix now...
    stream.write_all(&[0x00]).await.expect("write len hi");
    // ...byte 2 just under the deadline, then never send the body at all.
    tokio::time::sleep(CAP.mul_f32(0.85)).await;
    stream.write_all(&[0x20]).await.expect("write len lo");

    // The server dropping its side is what ends this read.
    let mut sink = [0u8; 1];
    let _ = tokio::time::timeout(CAP * 4, stream.read(&mut sink)).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < CAP.mul_f32(1.5),
        "connection lived {elapsed:?} against a {CAP:?} hard cap — the body \
         read started a fresh budget instead of the remaining lifetime"
    );
    let snap = proxy.counters.snapshot();
    assert!(
        snap.tcp_lifetime_kills >= 1,
        "a cap kill must be counted: {snap:?}"
    );
    proxy.stop().await;
}

/// REGRESSION (round-3 HIGH). `self_test` step (ii) probed only the
/// round-robin HEAD, so `[live, dead]` reported engine/upstream/filter all
/// green with an EMPTY detail while `forward` — which has no failover —
/// SERVFAILed every query that round-robin sent to the dead server.
///
/// The live upstream is deliberately FIRST: the old head-only probe would
/// have picked it and passed.
#[tokio::test]
async fn self_test_is_red_when_only_one_of_two_upstreams_answers() {
    let (live, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let proxy = Proxy::bind(
        config_for(vec![live, dead_upstream()]),
        FilterEngine::new(),
        Arc::new(NoopDecisionHook),
    )
    .await
    .expect("bind");

    let report = proxy.self_test().await;
    assert!(report.engine_ok, "{report:?}");
    assert!(report.filter_ok, "{report:?}");
    assert!(
        !report.upstream_ok,
        "one dead upstream is a real partial outage, not green: {report:?}"
    );
    assert_eq!(report.upstreams_total, 2, "{report:?}");
    assert_eq!(report.upstreams_healthy, 1, "{report:?}");
    assert!(!report.ok(), "{report:?}");
    assert!(
        report.detail.contains(&dead_upstream().to_string()),
        "the detail must name WHICH upstream is dead: {report:?}"
    );
}

// ---------------------------------------------------------------------------
// Round 3: A3 + L07 + L12 (unified canary/self-test fix), L10, L05/L09, L08
// ---------------------------------------------------------------------------

/// REGRESSION (round-3 A3). Step (iii) used to hard-code
/// `rcode == NXDOMAIN`, so the supported `block_response = "zero_ip"` knob
/// made the self-test permanently red on a 100%-healthy proxy — and the
/// design's runtime watchdog would have fired `remove_rule`/`fallback` on
/// it. The canary is now answered with the zero-IP signature under BOTH
/// policies, and step (iii) asserts the signature.
///
/// Revert-checked: with the old step (iii) assertion this test fails with
/// `filter_ok: false, detail: "canary through listener did not return
/// NXDOMAIN"`.
#[tokio::test]
async fn self_test_is_green_with_zero_ip_policy() {
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let mut config = config_for(vec![upstream]);
    config.block_response = BlockResponse::ZeroIp;
    let proxy = Proxy::bind(config, FilterEngine::new(), Arc::new(NoopDecisionHook))
        .await
        .expect("bind");
    let report = proxy.self_test().await;
    assert!(report.engine_ok, "{report:?}");
    assert!(report.upstream_ok, "{report:?}");
    assert!(report.filter_ok, "zero_ip policy must not break the self-test: {report:?}");
    assert!(report.ok(), "{report:?}");
    assert!(report.detail.is_empty(), "{report:?}");
}

/// REGRESSION (round-3 L07). With an engine that lost its canary rule
/// (`FilterEngine::default`, zero rules — a blocklist load that failed)
/// and an upstream that NXDOMAINs like any real resolver, the OLD step
/// (iii) accepted the upstream's NXDOMAIN as "our block fired"
/// (filter_ok=TRUE), leaked the canary upstream, and cached the negative
/// answer for 60 s. Now: filter_ok must be FALSE (nothing resolves
/// positively through the listener) and the upstream must NEVER see the
/// canary name.
///
/// Revert-checked: against the old step (iii) this fails — filter_ok was
/// true and the upstream recorded the canary query.
#[tokio::test]
async fn self_test_red_when_engine_empty_and_upstream_nxdomains() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_task = Arc::clone(&seen);
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
    let upstream = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            if let Ok(q) = wire::parse_query(&buf[..n]) {
                seen_task.lock().expect("mutex").push(q.qname);
            }
            let mut resp = canned_a_response(&buf[..n], 60, false);
            resp[3] = 0x83; // NXDOMAIN
            resp[7] = 0; // ancount = 0
            resp.truncate(resp.len() - 16);
            let _ = sock.send_to(&resp, peer).await;
        }
    });
    let proxy = Proxy::bind(
        config_for(vec![upstream]),
        FilterEngine::default(), // zero rules: no canary rule at all
        Arc::new(NoopDecisionHook),
    )
    .await
    .expect("bind");
    let report = proxy.self_test().await;
    assert!(!report.engine_ok, "empty engine has no canary rule: {report:?}");
    assert!(!report.upstream_ok, "NXDOMAIN is not NOERROR: {report:?}");
    assert!(
        !report.filter_ok,
        "an upstream NXDOMAIN must never read as 'our filter works': {report:?}"
    );
    assert!(!report.ok(), "{report:?}");
    let seen = seen.lock().expect("mutex");
    assert!(
        !seen.iter().any(|n| n.eq_ignore_ascii_case(CANARY_DOMAIN)),
        "the canary must never leak upstream: {seen:?}"
    );
}

/// REGRESSION (round-3 L12, positive-resolution half). Step (ii) forwards
/// health_check_name DIRECTLY to the upstreams — it never traverses the
/// filter — so an operator who blocks their own health-check name still
/// gets upstream_ok=true. Step (iii) resolves the same name THROUGH the
/// listener, where the filter applies, so the misconfiguration surfaces as
/// filter_ok=false. This is what makes the (rewritten) health_check_name
/// doc comment true.
#[tokio::test]
async fn self_test_red_when_filter_blocks_health_check_name() {
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let mut engine = FilterEngine::new();
    engine.add_block("example.com"); // the default health_check_name
    let proxy = Proxy::bind(
        config_for(vec![upstream]),
        engine,
        Arc::new(NoopDecisionHook),
    )
    .await
    .expect("bind");
    let report = proxy.self_test().await;
    assert!(report.engine_ok, "{report:?}");
    assert!(
        report.upstream_ok,
        "step (ii) forwards directly, bypassing the filter: {report:?}"
    );
    assert!(
        !report.filter_ok,
        "step (iii) resolves through the listener, where the name IS blocked: {report:?}"
    );
    assert!(!report.ok(), "{report:?}");
}

/// REGRESSION (round-3 L10). The self-test's probes are SYNTHETIC: they
/// must not move the user-facing counters (queries/blocked/forwarded/...)
/// and must not emit DecisionHook events for queries no client issued.
/// Only the canary's own counter moves — exactly one PER LISTENER (UDP
/// step iii, TCP step iv).
/// must not move the user-facing counters (queries/blocked/forwarded/...)
/// and must not emit DecisionHook events for queries no client issued.
/// Only the canary's own counter moves, by exactly one.
///
/// Revert-checked: against the old code the counters show
/// `{queries:1, blocked:1}` after self_test and the hook records a Blocked
/// event for the canary.
#[tokio::test]
async fn self_test_does_not_pollute_user_counters_or_hook() {
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let events = Arc::new(AtomicUsize::new(0));
    let events_hook = Arc::clone(&events);
    let hook: Arc<dyn dnsguard::proxy::DecisionHook> =
        Arc::new(move |_e: &dnsguard::proxy::DecisionEvent| {
            events_hook.fetch_add(1, Ordering::SeqCst);
        });
    let proxy = Proxy::bind(config_for(vec![upstream]), FilterEngine::new(), hook)
        .await
        .expect("bind");
    let report = proxy.self_test().await;
    assert!(report.ok(), "{report:?}");
    let snap = proxy.counters().snapshot();
    assert_eq!(snap.queries, 0, "probes are not user queries: {snap:?}");
    assert_eq!(snap.blocked, 0, "the canary is not a user-facing block: {snap:?}");
    assert_eq!(snap.forwarded, 0, "{snap:?}");
    assert_eq!(snap.cache_hits, 0, "{snap:?}");
    assert_eq!(snap.upstream_errors, 0, "{snap:?}");
    assert_eq!(snap.shed, 0, "{snap:?}");
    assert_eq!(
        snap.canary_probes, 2,
        "exactly one canary probe per listener (UDP step iii, TCP step iv): {snap:?}"
    );
    assert_eq!(
        events.load(Ordering::SeqCst),
        0,
        "no DecisionHook events for queries no client issued"
    );
}

/// REGRESSION (round-3 L05/L09). `health_check_name` is validated at bind:
/// empty, root-only, unencodable, and backslash-bearing names are refused.
/// The backslash case is the load-bearing one: `wire::build_query` is
/// escape-unaware, so `exam\.ple.com` would silently probe a DIFFERENT
/// name than the operator configured.
#[tokio::test]
async fn bind_rejects_unusable_health_check_names() {
    for bad in ["", ".", "a..b", "exam\\.ple.com", "trailing\\"] {
        let mut config = config_for(vec![dead_upstream()]);
        config.health_check_name = bad.to_string();
        let result = Proxy::bind(config, FilterEngine::new(), Arc::new(NoopDecisionHook)).await;
        assert!(
            result.is_err(),
            "health_check_name {bad:?} must be rejected at bind"
        );
    }
    // A well-formed name (with and without the trailing root dot) binds.
    for good in ["example.com", "example.com."] {
        let mut config = config_for(vec![dead_upstream()]);
        config.health_check_name = good.to_string();
        Proxy::bind(config, FilterEngine::new(), Arc::new(NoopDecisionHook))
            .await
            .unwrap_or_else(|e| panic!("health_check_name {good:?} must be accepted: {e}"));
    }
}

/// REGRESSION (round-3 L08). A self-referential upstream must be refused
/// at bind: the old code accepted `listen == upstreams[0]`, and ONE client
/// query then produced 65 internal queries + 1 shed at `max_in_flight=64`.
#[tokio::test]
async fn bind_refuses_self_referential_upstreams() {
    // Exact identity: upstream == listen (port 0 on both sides — caught by
    // the pre-bind identity check).
    let result = Proxy::bind(
        config_for(vec!["127.0.0.1:0".parse().expect("addr")]),
        FilterEngine::new(),
        Arc::new(NoopDecisionHook),
    )
    .await;
    assert!(result.is_err(), "upstream == listen must be refused");

    // Loopback on the listen port, even on a DIFFERENT loopback alias:
    // grab a free port, then try to listen on it with 127.0.0.2:<port> as
    // the upstream.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);
    let mut config = config_for(vec![SocketAddr::from(([127, 0, 0, 2], port))]);
    config.listen = SocketAddr::from(([127, 0, 0, 1], port));
    let result = Proxy::bind(config, FilterEngine::new(), Arc::new(NoopDecisionHook)).await;
    assert!(
        result.is_err(),
        "loopback upstream on the listen port must be refused"
    );
}

/// REGRESSION (round-3 L08, second half). The wiring needs to re-read
/// adapter DNS on network-change events: `set_upstreams` swaps the live
/// list with the SAME validation as bind, keeping the old list on error.
/// Loopback upstreams on OTHER ports — the test-suite fake upstreams —
/// remain perfectly legal (and the whole suite runs on them).
///
/// The swap is observed through `self_test`: step (ii) reads the live
/// list, and step (iii)(c) resolves through the LISTENER (full serving
/// path → forward → the same live list), so a swap that did not take
/// effect would keep filter_ok green.
#[tokio::test]
async fn set_upstreams_replaces_validates_and_keeps_old_on_error() {
    // TTL=0 answers: never cached, so step (iii)(c) ALWAYS forwards live
    // and the swap is observable through the listener, not masked by the
    // cache.
    let (live, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 0, false))).await;
    let proxy = Proxy::bind(
        config_for(vec![live]),
        FilterEngine::new(),
        Arc::new(NoopDecisionHook),
    )
    .await
    .expect("bind");

    // Refused: the proxy's own address, a loopback alias on the listen
    // port, and the empty list.
    let own = proxy.local_addr();
    let alias = SocketAddr::from(([127, 0, 0, 2], own.port()));
    for bad in [vec![own], vec![alias], vec![]] {
        assert!(
            proxy.set_upstreams(bad).is_err(),
            "self-referential/empty upstream list must be refused"
        );
    }
    // The old list survived every failed replacement.
    let report = proxy.self_test().await;
    assert!(report.ok(), "previous list kept after failed swaps: {report:?}");

    // Swap to a dead upstream: BOTH the direct probes and the listener
    // resolution fail — proof the serving path really uses the new list.
    proxy
        .set_upstreams(vec![dead_upstream()])
        .expect("dead upstream is a valid (if useless) list");
    let report = proxy.self_test().await;
    assert!(report.engine_ok, "{report:?}");
    assert!(!report.upstream_ok, "swapped list must be live: {report:?}");
    assert!(!report.filter_ok, "listener resolution follows the swap: {report:?}");

    // Swap back to the legit loopback upstream: green again.
    proxy.set_upstreams(vec![live]).expect("swap back");
    let report = proxy.self_test().await;
    assert!(report.ok(), "{report:?}");
}


// ---------------------------------------------------------------------------
// Round 3, Grupo 2: A1 (EDNS-aware truncation + fail-safe TCP pool),
// A2 (FIFO queue + tcp_pool_full + self-test step (iv)), L01 (AD/DO/CD),
// L02 (truncation rcode), L04 (opcode NOTIMP / RD echo)
// ---------------------------------------------------------------------------

/// Build a query with an EDNS0 OPT record advertising `size` and the given
/// DO bit (and CD in the header when `cd` is set).
fn edns_query(id: u16, name: &str, qtype: u16, size: u16, do_bit: bool, cd: bool) -> Vec<u8> {
    let mut q = wire::build_query(id, name, qtype, CLASS_IN).expect("build");
    if cd {
        q[3] |= 0x10;
    }
    q[11] = 1; // arcount = 1
    q.extend_from_slice(&[
        0x00, // root name
        0x00, 0x29, // type OPT
        (size >> 8) as u8, (size & 0xFF) as u8, // class: UDP payload size
        0, 0, if do_bit { 0x80 } else { 0 }, 0, // ttl: DO flag
        0, 0, // rdlength 0
    ]);
    q
}

/// REGRESSION (round-3 A1a). Truncation must be decided against the
/// CLIENT's advertised EDNS0 payload size, not a flat 512: an EDNS client
/// with a 4096 buffer gets a ~900-byte answer in ONE UDP datagram and
/// never touches the TCP pool; only a client without EDNS (or past its
/// advertised size) gets TC=1. The old flat-512 code truncated BOTH
/// clients, coupling ordinary 513–4096-byte answers to the bounded TCP
/// pool.
///
/// Revert-checked: with the flat-512 limit the first assertion fails
/// (the EDNS client receives a ≤512-byte TC=1 truncation).
#[tokio::test]
async fn edns_client_gets_large_answer_over_udp_non_edns_gets_tc() {
    let (upstream, calls) =
        spawn_udp_upstream(|q| Some(canned_big_txt_response(q, 300, 850))).await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    // EDNS client (4096): full answer over UDP, TC clear, one datagram.
    let query = edns_query(0x1001, "big-txt.example", TYPE_TXT, 4096, false, false);
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert!(resp.len() > 512, "EDNS client gets the full answer: {}", resp.len());
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]) & wire::FLAG_TC,
        0,
        "no truncation against a 4096-byte client buffer"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Same name, client WITHOUT EDNS (cache hit): TC=1, ≤512 bytes.
    let query = wire::build_query(0x1002, "big-txt.example", TYPE_TXT, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert!(resp.len() <= 512, "non-EDNS client is truncated: {}", resp.len());
    assert_ne!(
        u16::from_be_bytes([resp[2], resp[3]]) & wire::FLAG_TC,
        0,
        "TC set for the classic-512 client"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "served from cache, no refetch");

    // EDNS client advertising only 600: a ~900-byte answer exceeds ITS
    // buffer → TC=1 even though 4096-clients get it whole.
    let query = edns_query(0x1003, "big-txt.example", TYPE_TXT, 600, false, false);
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert!(resp.len() <= 512);
    assert_ne!(u16::from_be_bytes([resp[2], resp[3]]) & wire::FLAG_TC, 0, "TC past the advertised size");
    proxy.stop().await;
}

/// REGRESSION (round-3 A1d + A2). THE decoupling test: with the TCP pool
/// PROVABLY saturated (tcp_pool_full > 0 — queued clients already timed
/// out), a name whose answer is >512 bytes STILL resolves over UDP for an
/// EDNS client, in full, because EDNS-sized answers never touch the pool.
/// The old code truncated every >512 answer onto the saturated listener,
/// where the mandated retry died with a connection reset.
///
/// Revert-checked: with the flat-512 limit the EDNS client gets TC=1 here
/// (and its TCP retry would hit the saturated pool).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_answer_resolves_over_udp_while_tcp_pool_saturated() {
    let (upstream, _calls) =
        spawn_udp_upstream(|q| Some(canned_big_txt_response(q, 300, 850))).await;
    let mut config = config_for(vec![upstream]);
    config.tcp_max_connections = 8;
    config.tcp_queue_timeout = Duration::from_millis(300);
    let proxy = start_proxy(FilterEngine::new(), config).await;

    let dribblers = spawn_dribblers(proxy.addr, 16, Duration::from_millis(200)).await;
    // Wait long enough that queued dribblers have TIMED OUT the queue:
    // tcp_pool_full > 0 is only possible once the pool has been full for a
    // whole queue window — proof of saturation by counter, not by timing
    // luck.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let snap = proxy.counters.snapshot();
    assert!(
        snap.tcp_pool_full >= 1,
        "pool provably saturated (queued clients timed out): {snap:?}"
    );

    // The >512-byte name still resolves over UDP, in full.
    let query = edns_query(0x2001, "big-txt.example", TYPE_TXT, 4096, false, false);
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert!(
        resp.len() > 512,
        "EDNS client gets the full answer despite the saturated TCP pool: {}",
        resp.len()
    );
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(u16::from_be_bytes([resp[2], resp[3]]) & wire::FLAG_TC, 0);

    for task in dribblers {
        task.abort();
    }
    proxy.stop().await;
}

/// REGRESSION (round-3 A1b/A2). Pool exhaustion is fail-safe AND
/// recoverable: the client queued behind a full pool gets SERVFAIL (not a
/// reset), the dedicated counter moves, and once the hog's permit is freed
/// by the lifetime cap, a queued retry is served — the FIFO queue orders
/// waiters ahead of any reconnect spinner.
///
/// Revert-checked: on the drop-on-full code the first attempt gets EOF,
/// failing "must be ANSWERED (SERVFAIL)".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_pool_full_is_failsafe_and_recovers_after_lifetime_kill() {
    let tcp_hit = Arc::new(AtomicBool::new(false));
    let upstream = spawn_tcp_upstream(tcp_hit, 60).await;
    let mut config = config_for(vec![upstream]);
    config.tcp_max_connections = 1;
    config.tcp_queue_timeout = Duration::from_millis(300);
    config.tcp_idle_timeout = Duration::from_secs(60);
    config.tcp_max_lifetime = Duration::from_millis(1000);
    let proxy = start_proxy(FilterEngine::new(), config).await;

    // The hog: one quick query, then holds the single permit idle until
    // the lifetime cap kills it at ~1s.
    let mut hog = TcpStream::connect(proxy.addr).await.expect("hog connect");
    let query = wire::build_query(0x3001, "hog.example", TYPE_A, CLASS_IN).expect("build");
    let resp = tcp_query(&mut hog, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR, "hog served while the pool is free");

    // Legit client, attempt 1: queued behind the full pool, answered
    // SERVFAIL after the queue timeout — never a bare reset.
    let mut legit = TcpStream::connect(proxy.addr).await.expect("legit connect");
    let query = wire::build_query(0x3002, "legit.example", TYPE_A, CLASS_IN).expect("build");
    let started = tokio::time::Instant::now();
    let resp = tcp_query(&mut legit, &query, Duration::from_secs(2)).await;
    assert_eq!(
        rcode_of(&resp),
        RCODE_SERVFAIL,
        "pool-full client gets a retryable SERVFAIL"
    );
    assert_eq!(id_of(&resp), 0x3002, "the SERVFAIL matches the pending query");
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "the client waited out the bounded queue before the SERVFAIL"
    );
    let snap = proxy.counters.snapshot();
    assert!(snap.tcp_pool_full >= 1, "dedicated counter moved: {snap:?}");
    assert_eq!(snap.shed, 0, "not folded into shed: {snap:?}");
    drop(legit);

    // Retry (as a real resolver would after SERVFAIL): eventually the
    // hog's lifetime kill frees the permit and a queued attempt wins it —
    // the FIFO queue orders waiters ahead of any reconnect spinner.
    let mut served = false;
    for attempt in 0..6 {
        let mut legit = TcpStream::connect(proxy.addr).await.expect("legit reconnect");
        let query =
            wire::build_query(0x3003 + attempt, "legit.example", TYPE_A, CLASS_IN).expect("build");
        let resp = tcp_query(&mut legit, &query, Duration::from_secs(3)).await;
        if rcode_of(&resp) == RCODE_NOERROR {
            served = true;
            break;
        }
        assert_eq!(rcode_of(&resp), RCODE_SERVFAIL, "failures are retryable SERVFAILs");
    }
    assert!(served, "served once the hog's permit is freed by the lifetime cap");
    let snap = proxy.counters.snapshot();
    assert!(snap.tcp_lifetime_kills >= 1, "the hog was cap-killed: {snap:?}");
    drop(hog);
    proxy.stop().await;
}

/// REGRESSION (round-3 L01). The DNSSEC bits, end to end: a client with
/// CD=1 + EDNS0 DO=1 has both relayed (CD in the header, DO in ONE
/// self-constructed OPT with its clamped size), the upstream's AD=1 is
/// CLEARED toward the client (we validate nothing — relaying it would be
/// a lie over loopback), and the cache is forked on the DO/CD posture so
/// a DO=0 client never gets the DO=1 entry (nor vice versa).
///
/// Revert-checked: without the flag rewrite the client sees AD=1; without
/// the OPT relay the upstream sees ARCOUNT=0.
#[tokio::test]
async fn dnssec_do_and_cd_relayed_ad_cleared_cache_forked() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_task = Arc::clone(&seen);
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
    let upstream = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            seen_task.lock().expect("mutex").push(buf[..n].to_vec());
            let mut resp = canned_a_response(&buf[..n], 300, false);
            resp[3] |= 0x20; // AD=1 — the upstream "validated"
            let _ = sock.send_to(&resp, peer).await;
        }
    });
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    // Client: RD=1, CD=1, EDNS 1232 with DO=1.
    let query = edns_query(0x4001, "signed.example", TYPE_A, 1232, true, true);
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    assert_eq!(flags & 0x0020, 0, "AD CLEARED — we validate nothing (L01)");
    assert_ne!(flags & 0x0010, 0, "client CD echoed");
    assert_ne!(flags & 0x0100, 0, "client RD echoed");

    {
        let seen = seen.lock().expect("mutex");
        let forwarded = seen.last().expect("upstream saw the query");
        let up_flags = u16::from_be_bytes([forwarded[2], forwarded[3]]);
        assert_ne!(up_flags & 0x0010, 0, "CD relayed to the upstream");
        assert_ne!(up_flags & 0x0100, 0, "RD=1 upstream (we recurse for the client)");
        assert_eq!(u16::from_be_bytes([forwarded[10], forwarded[11]]), 1, "one OPT relayed");
        let opt = &forwarded[forwarded.len() - 11..];
        assert_eq!(opt[0], 0, "OPT root name");
        assert_eq!(&opt[1..3], &[0x00, 0x29], "OPT type 41");
        assert_eq!(&opt[3..5], &1232u16.to_be_bytes(), "client's advertised size relayed");
        assert_eq!(opt[7], 0x80, "DO bit relayed");
        assert_eq!(&opt[9..11], &[0, 0], "no option payload");
    }

    // Cache fork: the SAME name from a plain client (no DO, no CD) must
    // MISS the DO=1 entry and go upstream again.
    let query = wire::build_query(0x4002, "signed.example", TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]) & 0x0020,
        0,
        "AD cleared on the plain path too"
    );
    assert_eq!(seen.lock().expect("mutex").len(), 2, "DO=0 client must not hit the DO=1 entry");

    // And the original DO=1/CD=1 query now hits its own entry.
    let query = edns_query(0x4003, "signed.example", TYPE_A, 1232, true, true);
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_ne!(u16::from_be_bytes([resp[2], resp[3]]) & 0x0010, 0, "CD echoed from cache");
    assert_eq!(seen.lock().expect("mutex").len(), 2, "DO=1 entry served from cache");
    proxy.stop().await;
}

/// REGRESSION (round-3 L01, robustness half). RFC 6891 §6.1.3: an
/// upstream that does not implement EDNS answers FORMERR to a query with
/// an OPT record, and the requester retries without it. Without the
/// retry, every EDNS client behind a pre-EDNS upstream would hard-fail.
#[tokio::test]
async fn formerr_to_edns_query_is_retried_without_opt() {
    let shapes = Arc::new(AtomicUsize::new(0)); // bit0: saw OPT query, bit1: saw plain
    let shapes_task = Arc::clone(&shapes);
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
    let upstream = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let arcount = u16::from_be_bytes([buf[10], buf[11]]);
            if arcount > 0 {
                shapes_task.fetch_or(1, Ordering::SeqCst);
                // Pre-EDNS responder: FORMERR anything with an OPT.
                let mut resp = canned_a_response(&buf[..n], 60, false);
                resp[3] = 0x81; // RA | FORMERR
                resp[7] = 0; // ancount = 0
                resp.truncate(resp.len() - 16);
                let _ = sock.send_to(&resp, peer).await;
            } else {
                shapes_task.fetch_or(2, Ordering::SeqCst);
                let _ = sock.send_to(&canned_a_response(&buf[..n], 60, false), peer).await;
            }
        }
    });
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    let query = edns_query(0x5001, "old-upstream.example", TYPE_A, 4096, true, false);
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(
        rcode_of(&resp),
        RCODE_NOERROR,
        "FORMERR to the EDNS query is retried plain, not surfaced"
    );
    let shapes = shapes.load(Ordering::SeqCst);
    assert_eq!(shapes, 3, "upstream saw the OPT query AND the plain retry");
    proxy.stop().await;
}

/// REGRESSION (round-3 L02). A cached NXDOMAIN larger than 512 bytes must
/// truncate with rcode=3, not the hardcoded NOERROR: a client reading
/// TC=1/NOERROR/ANCOUNT=0 as NODATA would record "exists, no records" for
/// a name that does not exist, for the whole negative-cache window.
///
/// Revert-checked: with the hardcoded-NOERROR builder this fails with
/// rcode 0.
#[tokio::test]
async fn truncated_cached_nxdomain_keeps_rcode() {
    let (upstream, calls) = spawn_udp_upstream(|q| {
        let mut resp = canned_big_txt_response(q, 60, 850);
        resp[3] = 0x83; // RA | NXDOMAIN
        Some(resp)
    })
    .await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    for id in [0x6001u16, 0x6002] {
        let query = wire::build_query(id, "gone.example", TYPE_TXT, CLASS_IN).expect("build");
        let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
        assert!(resp.len() <= 512, "truncated: {}", resp.len());
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & wire::FLAG_TC, 0, "TC set");
        assert_eq!(
            rcode_of(&resp),
            RCODE_NXDOMAIN,
            "the truncated answer keeps the REAL rcode (L02)"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "second query was a cache hit — the rcode came through the cache path too"
    );
    proxy.stop().await;
}

/// REGRESSION (round-3 L04). Opcodes other than QUERY are refused with
/// NOTIMP before canary/filter/cache/forward (echoing the client's
/// opcode, so the refusal matches its state machine), and RD is echoed
/// from the CLIENT on every path — forwarded (rewritten, since we force
/// RD=1 upstream) and blocked (preserved) — so the two paths agree.
///
/// Revert-checked: without the NOTIMP gate the opcode=2 query is
/// forwarded and the response carries opcode 0 (and the upstream counter
/// moves); without the RD rewrite the RD=0 client gets RD=1 back.
#[tokio::test]
async fn nonzero_opcode_gets_notimp_and_rd_is_echoed_everywhere() {
    let (upstream, calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let mut engine = FilterEngine::new();
    engine.add_block("evil.example");
    let proxy = start_proxy(engine, config_for(vec![upstream])).await;

    // opcode=2 (STATUS) on an ordinary name: NOTIMP, opcode echoed,
    // upstream untouched.
    let mut query = wire::build_query(0x7001, "example.com", TYPE_A, CLASS_IN).expect("build");
    query[2] |= 0x10; // opcode 2 (0b0010 << 11 = 0x1000)
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(id_of(&resp), 0x7001);
    assert_eq!(rcode_of(&resp), 4, "NOTIMP");
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]) & 0x7800,
        0x1000,
        "the refusal echoes the client's opcode"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "never forwarded");

    // opcode=2 on the CANARY: NOTIMP too — the gate runs before the
    // canary short-circuit, so a STATUS query never gets the QUERY-shaped
    // signature answer.
    let mut query = wire::build_query(0x7002, CANARY_DOMAIN, TYPE_A, CLASS_IN).expect("build");
    query[2] |= 0x10;
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), 4, "NOTIMP before the canary short-circuit");

    // RD=0 (+norecurse) forwarded: the client gets RD=0 back (we asked
    // recursion upstream on its behalf; the response must echo the
    // CLIENT's RD per RFC 1035 §4.1.1).
    let mut query = wire::build_query(0x7003, "norecurse.example", TYPE_A, CLASS_IN).expect("build");
    query[2] &= 0xFE; // RD=0
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NOERROR);
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]) & 0x0100,
        0,
        "forwarded response echoes the client's RD=0"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // RD=0 blocked: same echo — the paths agree.
    let mut query = wire::build_query(0x7004, "evil.example", TYPE_A, CLASS_IN).expect("build");
    query[2] &= 0xFE;
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NXDOMAIN);
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]) & 0x0100,
        0,
        "blocked response also echoes RD=0"
    );
    proxy.stop().await;
}


/// REGRESSION (round-3 A2, step (iv) must be able to fail). THE A2
/// scenario end to end: a squatter holds the whole TCP pool (16 dribblers
/// against 8 permits), so every new TCP connection waits out the queue
/// and gets SERVFAIL — while UDP stays green. Before step (iv) this exact
/// shape reported all-green (the health surface was UDP-only); now
/// `tcp_ok` goes red because the canary signature cannot be produced
/// through a starved TCP listener, and the detail names it.
///
/// Revert-checked: with step (iv) skipped (`tcp_ok` forced true) the
/// `!report.tcp_ok` assertion fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_test_red_when_tcp_pool_is_saturated() {
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let mut config = config_for(vec![upstream]);
    config.tcp_max_connections = 8;
    config.tcp_queue_timeout = Duration::from_millis(100);
    let proxy = Proxy::bind(config, FilterEngine::new(), Arc::new(NoopDecisionHook))
        .await
        .expect("bind");

    // Squatters: they sit in the listen backlog until the self-test's
    // private TCP loop accepts them and they take every permit.
    let dribblers = spawn_dribblers(proxy.local_addr(), 16, Duration::from_millis(200)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let report = proxy.self_test().await;
    assert!(report.engine_ok, "{report:?}");
    assert!(report.upstream_ok, "{report:?}");
    assert!(report.filter_ok, "UDP through the listener stays green: {report:?}");
    assert!(
        !report.tcp_ok,
        "a starved TCP pool must turn the health surface red (A2): {report:?}"
    );
    assert!(!report.ok(), "{report:?}");
    assert!(
        report.detail.contains("TCP listener"),
        "the detail names the failing step: {report:?}"
    );
    let snap = proxy.counters().snapshot();
    assert!(
        snap.tcp_pool_full >= 1,
        "the saturation is visible in the dedicated counter: {snap:?}"
    );

    for task in dribblers {
        task.abort();
    }
}

/// REGRESSION (round-3 closure review, HIGH). Step (iii)(c) accepted any
/// NOERROR-with-a-TTL answer, and a ZeroIp BLOCK answer is exactly that
/// (NOERROR, ancount 1, A 0.0.0.0, TTL 60). So under the supported
/// `block_response = "zero_ip"`, a filter that blocks `health_check_name`
/// read as "resolves positively" and the whole report came back green with
/// an EMPTY detail — while a single bad suffix rule blackholed the machine.
///
/// The two round-3 tests miss this by construction: one blocks the health
/// name under the DEFAULT nxdomain policy, the other uses ZeroIp with a
/// clean engine. Neither crosses them. This is that cell.
#[tokio::test]
async fn self_test_is_red_when_zero_ip_policy_blocks_the_health_check_name() {
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let mut engine = FilterEngine::new();
    // A single suffix rule that happens to cover the health-check name —
    // the machine-wide blackhole shape, not a contrived exact rule.
    assert!(engine.add_block("com"));
    let proxy = Proxy::bind(
        ProxyConfig {
            block_response: BlockResponse::ZeroIp,
            ..config_for(vec![upstream])
        },
        engine,
        Arc::new(NoopDecisionHook),
    )
    .await
    .expect("bind");

    let report = proxy.self_test().await;
    assert!(
        !report.filter_ok,
        "a blocked health_check_name under zero_ip must NOT read as a resolution: {report:?}"
    );
    assert!(!report.ok(), "{report:?}");
    assert!(
        report.detail.contains("BLOCKED by the filter"),
        "the detail must name the real cause: {report:?}"
    );
}

/// REGRESSION (round-3 closure review, HIGH). The queue permit was held for
/// the whole connection, so queue occupancy equalled pool occupancy. At the
/// SHIPPED default relation (`tcp_max_queued == tcp_max_connections`) the
/// queue was full exactly when the pool was, `try_acquire_owned` always
/// failed, and the client got a bare RST — `serve_overflow_servfail` was
/// unreachable in production.
///
/// Every round-3 test that certified "pool-full => SERVFAIL, never RST"
/// shrank `tcp_max_connections` to 1 or 8 while leaving `tcp_max_queued` at
/// 128 — a 16x-128x ratio, the only regime where the SERVFAIL path runs.
/// This test pins the DEFAULT relation instead: queued == connections.
#[tokio::test]
async fn pool_full_answers_servfail_at_the_shipped_queue_to_pool_ratio() {
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let proxy = start_proxy(
        FilterEngine::new(),
        ProxyConfig {
            tcp_max_connections: 2,
            // THE POINT: identical, exactly as ProxyConfig::default ships it.
            tcp_max_queued: 2,
            tcp_queue_timeout: Duration::from_millis(300),
            tcp_max_lifetime: Duration::from_secs(30),
            tcp_idle_timeout: Duration::from_secs(30),
            ..config_for(vec![upstream])
        },
    )
    .await;

    // Fill the pool: two connections that open and never speak, so each
    // holds a pool permit for the whole test.
    let mut hogs = Vec::new();
    for _ in 0..2 {
        hogs.push(TcpStream::connect(proxy.addr).await.expect("hog connect"));
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A third client asks a real question. It must get an ANSWER — SERVFAIL
    // is fine, a reset is not: truncation is what routes clients onto TCP,
    // so a reset here is an unresolvable name with no retry signal.
    let mut client = TcpStream::connect(proxy.addr).await.expect("client connect");
    let query = wire::build_query(0x4242, "example.com", TYPE_A, CLASS_IN).expect("build");
    let framed = (query.len() as u16).to_be_bytes();
    client.write_all(&framed).await.expect("write len");
    client.write_all(&query).await.expect("write body");

    let mut len_buf = [0u8; 2];
    let read = tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut len_buf)).await;
    assert!(
        matches!(read, Ok(Ok(_))),
        "pool-full client got a reset instead of an answer: {read:?}"
    );
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut resp))
        .await
        .expect("no response body")
        .expect("read body");
    assert_eq!(rcode_of(&resp), RCODE_SERVFAIL, "expected the fail-safe answer");
    assert_eq!(id_of(&resp), 0x4242, "the fail-safe must echo the client's ID");

    drop(hogs);
    proxy.stop().await;
}

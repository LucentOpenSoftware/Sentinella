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

/// Fake upstream: UDP responder with a call counter. The responder decides
/// per query; returning `None` simulates a never-answering upstream.
async fn spawn_udp_upstream<F>(responder: F) -> (SocketAddr, Arc<AtomicUsize>)
where
    F: Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
    let addr = sock.local_addr().expect("addr");
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_task = Arc::clone(&calls);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            calls_task.fetch_add(1, Ordering::SeqCst);
            if let Some(resp) = responder(&buf[..n]) {
                let _ = sock.send_to(&resp, peer).await;
            }
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
    let (upstream, calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let proxy = start_proxy(FilterEngine::new(), config_for(vec![upstream])).await;

    let query = wire::build_query(7, CANARY_DOMAIN, TYPE_A, CLASS_IN).expect("build");
    let resp = udp_query(proxy.addr, &query, Duration::from_secs(2)).await;
    assert_eq!(rcode_of(&resp), RCODE_NXDOMAIN);
    assert_eq!(id_of(&resp), 7);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "canary never reaches upstream");
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
    let proxy = start_proxy(engine, config).await;

    let dribblers = spawn_dribblers(proxy.addr, 16, Duration::from_millis(200)).await;
    // Give the dribblers a moment to occupy the TCP pool.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Proof of exhaustion: a fresh TCP connection gets NO service (the
    // pool is full, so it is closed without an answer — or the connect is
    // refused outright). Without this the test could pass with every
    // dribbler stuck outside the pool.
    if let Ok(mut stream) = TcpStream::connect(proxy.addr).await {
        let query = wire::build_query(9, "fine.example", TYPE_A, CLASS_IN).expect("build");
        let _ = stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await;
        let _ = stream.write_all(&query).await;
        let mut len_buf = [0u8; 2];
        let answered =
            tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await;
        assert!(
            !matches!(answered, Ok(Ok(_))),
            "TCP pool must be exhausted — no permit for a fresh connection"
        );
    }

    // UDP — the machine's actual DNS path — is completely unaffected:
    // forwarding AND blocking both keep working.
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
    // Client-controlled bytes beyond the question must never reach the
    // upstream: the forwarded packet is rebuilt CLEAN (question only,
    // ARCOUNT=0, no OPT/ECS). ECS in particular would steer the answer we
    // then cache machine-wide.
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_task = Arc::clone(&seen);
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
    let upstream = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let arcount = u16::from_be_bytes([buf[10], buf[11]]);
            seen_task.lock().expect("mutex").push((arcount, n));
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
        0, 0, 0, 0, // ttl
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
        let &(arcount, len) = seen.last().expect("upstream saw the query");
        assert_eq!(arcount, 0, "forwarded query must have ARCOUNT=0 (no OPT/ECS)");
        assert_eq!(
            len,
            wire::HEADER_LEN + question_len,
            "forwarded query is exactly header + question — nothing else"
        );
    }

    // The cached answer is keyed on the question only: a second client
    // with a DIFFERENT ECS gets the same cached entry (no per-ECS fork).
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
    assert!(report.ok(), "{report:?}");
    assert!(report.detail.is_empty(), "{report:?}");
}

#[tokio::test]
async fn self_test_reports_dead_upstream_but_healthy_filter() {
    // The discard port never answers: upstream_ok must be false while the
    // engine and listener (filter) steps stay green — the report
    // distinguishes "plumbing works" from "upstream dead".
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
    assert!(report.filter_ok, "{report:?}");
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

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
    let proxy = start_proxy(engine, config_for(vec![])).await;

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
    let mut config = config_for(vec![]);
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
        resp[wire::HEADER_LEN + 1] ^= 0x20; // case-flip a question name byte
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
    // 40 dribbling TCP connections against a 32-permit TCP pool: UDP query
    // handling (the machine's actual DNS path) must be completely
    // unaffected — forwarding AND blocking both keep working.
    let (upstream, _calls) = spawn_udp_upstream(|q| Some(canned_a_response(q, 60, false))).await;
    let mut engine = FilterEngine::new();
    engine.add_block("evil.example");
    let proxy = start_proxy(engine, config_for(vec![upstream])).await;

    let dribblers = spawn_dribblers(proxy.addr, 40, Duration::from_millis(200)).await;
    // Give the dribblers a moment to occupy the TCP pool.
    tokio::time::sleep(Duration::from_millis(300)).await;

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

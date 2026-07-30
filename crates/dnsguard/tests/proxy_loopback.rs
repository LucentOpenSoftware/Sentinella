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
    // Never-answering upstream + short timeout: the 256 permit-holders wait
    // out the timeout, the excess is shed immediately.
    let (upstream, _calls) = spawn_udp_upstream(|_q| None).await;
    let mut config = config_for(vec![upstream]);
    config.upstream_timeout = Duration::from_millis(300);
    let proxy = start_proxy(FilterEngine::new(), config).await;

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
        assert_eq!(rcode_of(&resp), RCODE_SERVFAIL, "shed/timeout answers are SERVFAIL");
        responses += 1;
    }
    assert_eq!(responses, u32::from(TOTAL), "every query got an answer — no hang");
    let snap = proxy.counters.snapshot();
    assert!(snap.shed >= 1, "excess over the semaphore must be shed: {snap:?}");
    assert_eq!(snap.queries, u64::from(TOTAL));
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

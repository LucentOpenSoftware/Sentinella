//! Installing, watching and removing the NRPT rule.
//!
//! This is the file where the product can break a machine's DNS, so the
//! rules it follows are written down rather than implied.
//!
//! # Preconditions, both hard
//!
//! 1. The four-step self-test passed. A rule pointing at a listener we
//!    could not prove works is the whole hazard.
//! 2. The boot reconciler's scheduled task exists. It is the only thing
//!    that removes the rule when this process is not around to do it —
//!    after a crash, a kill, a disabled service, a quarantined binary, a
//!    power loss. Installing without it means a rule that can outlive
//!    every mechanism able to undo it.
//!
//! # Orderings, both of which strand a rule if reversed
//!
//! INSTALL: record the GUID, THEN write the rule. A crash between the two
//! leaves a recorded GUID naming nothing, which the reconciler cleans up
//! harmlessly. The reverse leaves a rule nothing can name.
//!
//! SHUTDOWN: remove the rule, THEN stop serving. Between those two the
//! machine resolves through its normal upstreams while we are still
//! answering — harmless. The reverse leaves a window where the rule points
//! at sockets that are already closed.
//!
//! # There is no "fail open" here, and there cannot be
//!
//! The rule we install carries exactly ONE server: our own proxy. An NRPT
//! rule overrides the adapter's DNS configuration for every matching name —
//! that is what NRPT is for — so there is no secondary to fall back to.
//! Leaving a rule in place when the proxy has died therefore yields NO DNS,
//! not unfiltered DNS. An earlier version of this file offered exactly that
//! as the "fail open" option; see `config.rs` for why the knob is gone.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use dnsguard::filter::{CANARY_DOMAIN, Decision, FilterEngine};
use dnsguard::proxy::{Counters, is_canary_signature};
use dnsguard::wire;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{error, info, warn};

use super::config::DNS_PORT;

/// How often the watchdog asks whether we are still working.
///
/// The reconciler covers the boot case; this covers the one it cannot —
/// the daemon alive while the serving path is broken. Without it a proxy
/// that dies mid-session leaves the machine without DNS until the next
/// reboot.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(20);

/// Consecutive failures before acting.
///
/// One failed check is not proof of death. NOTE, because the comment here
/// used to claim otherwise: the canary signature and the counter delta are
/// NOT independent corroboration. Under UDP overload the shed path answers
/// SERVFAIL without ever reaching `handle_query`, so neither the signature
/// nor the counter bump happens — both halves fail together, and a local
/// process can drive the proxy into shedding at will. Measured: one
/// unprivileged process with eight sender tasks flipped a healthy proxy to
/// `answered=false, moved=false` within one tick. The strike counter is
/// what absorbs that, so it must stay generous.
const WATCHDOG_STRIKES: u32 = 3;

const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// The resolution probe emits a REAL upstream query, so it runs on every
/// Nth tick rather than every one: at 20s intervals that is one extra
/// outbound query per minute, which is noise next to ordinary browsing.
const RESOLVE_EVERY: u64 = 3;

/// More patience than the canary probe: this one waits on an upstream
/// across the real network, not on a loopback short-circuit.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Install the rule, honouring both preconditions and the record-first
/// ordering. Returns the GUID actually in force.
///
/// Refusing is always safe here: it costs FILTERING, never DNS.
pub fn install(listen: SocketAddr, existing: Option<String>) -> Result<String, String> {
    // SECOND GATE on the port. Config validation refuses a non-53 listen,
    // and this refuses it again, because the failure is invisible: the rule
    // records only the IP, so a proxy on 5353 installs a rule the DNS
    // Client queries on 53 — where nothing is listening — while the
    // watchdog probes the address we BOUND and reports healthy. Two gates
    // because one of them is a config file a user edits.
    if listen.port() != DNS_PORT {
        return Err(format!(
            "refusing to install a rule for a proxy on port {}: NRPT records only the IP and \
             the DNS Client always queries {DNS_PORT}",
            listen.port()
        ));
    }
    if !nrpt::reconciler_task_installed() {
        return Err(
            "the boot reconciler task is not registered, so nothing could remove this rule if \
             the service stopped. Reinstall Sentinella with the MSI, which registers it. \
             (Running from a development build? That is expected — web protection installs no \
             rule without it.)"
                .into(),
        );
    }

    // One rule per installation: reuse the recorded GUID so a restart
    // rewrites its own rule instead of accumulating a new one each time.
    let guid = existing.unwrap_or_else(new_guid);

    // RECORD FIRST. A crash between here and the write leaves a GUID naming
    // nothing, which the reconciler tidies away; the reverse order leaves a
    // rule that nothing can name.
    let state_file = nrpt::default_state_file();
    nrpt::record_guid(&state_file, &guid).map_err(|e| format!("cannot record rule GUID: {e}"))?;

    // Only the IP goes into the rule — NRPT has nowhere to put a port. The
    // gate above is what makes that correct.
    let servers: Vec<IpAddr> = vec![listen.ip()];
    nrpt::install_rule(&guid, nrpt::NAMESPACE_ALL, &servers)
        .map_err(|e| format!("cannot install NRPT rule: {e}"))?;

    info!(
        %guid,
        %listen,
        "web protection: NRPT rule installed — the machine's DNS now goes through this proxy"
    );
    Ok(guid)
}

/// Remove the rule and forget it. Idempotent, and safe to call when no rule
/// was ever installed.
pub fn remove(guid: &str) -> Result<(), String> {
    nrpt::remove_rule(guid).map_err(|e| format!("cannot remove NRPT rule: {e}"))?;
    // Rule first, record second — the reverse leaves a moment where the
    // rule exists and nothing names it.
    let _ = nrpt::clear_guid(&nrpt::default_state_file());
    info!(%guid, "web protection: NRPT rule removed — DNS restored to system defaults");
    Ok(())
}

/// Is a rule of ours present RIGHT NOW? Read from the system, never
/// inferred from configuration. `None` means we could not tell, which is
/// not the same as absent.
pub fn installed_now(guid: Option<&str>) -> Option<bool> {
    let guid = guid?;
    nrpt::rule_exists(guid).ok()
}

/// Watch the listener and tear the rule down if it stops working.
///
/// # It asks TWO different questions, because the canary answers only one
///
/// The canary is short-circuited inside `handle_query` BEFORE
/// decide/cache/forward. That is what makes its signature unforgeable — and
/// exactly what makes it useless as evidence that DNS works. A proxy whose
/// every upstream is dead answers the canary perfectly while SERVFAILing
/// every real name. Measured on this branch: canary signature ok, counter
/// moved, and `www.microsoft.com` returning SERVFAIL with zero answers,
/// indefinitely, with every guard reporting green.
///
/// So the canary probe proves "our process is serving this socket", and a
/// periodic RESOLUTION probe proves "and it can actually resolve". Neither
/// alone is enough, and the first alone is what an earlier version of this
/// file certified as healthy.
pub fn spawn_watchdog(
    guid: String,
    listen: SocketAddr,
    counters: Arc<Counters>,
    engine: Arc<RwLock<FilterEngine>>,
    health_check_name: String,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut strikes = 0u32;
        let mut tick = 0u64;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(WATCHDOG_INTERVAL) => {}
            }
            tick += 1;

            let before = counters.snapshot().canary_probes;
            let answered = probe_canary(listen).await;
            let moved = counters.snapshot().canary_probes > before;
            // The signature alone can be forged by whatever owns the port;
            // the counter delta proves OUR process served it. See the note
            // on WATCHDOG_STRIKES for why these two fail together rather
            // than independently.
            let serving = answered && moved;

            let resolving = if tick.is_multiple_of(RESOLVE_EVERY) {
                if health_name_is_allowed(&engine, &health_check_name) {
                    probe_resolves(listen, &health_check_name).await
                } else {
                    // A `zero_ip` block answer is NOERROR with one A record,
                    // so if the engine blocks this name the probe cannot
                    // tell a block from a resolution. Skip rather than
                    // guess — and say so, because it means this half of the
                    // check is not running.
                    warn!(
                        name = %health_check_name,
                        "web protection: health_check_name is blocked by the filter, so the \
                         watchdog cannot verify resolution — pick a name you never block"
                    );
                    true
                }
            } else {
                true
            };

            if serving && resolving {
                strikes = 0;
                continue;
            }
            strikes += 1;
            warn!(
                strikes,
                answered,
                counter_moved = moved,
                resolving,
                "web protection: watchdog check failed"
            );
            if strikes < WATCHDOG_STRIKES {
                continue;
            }

            error!(
                %guid,
                "web protection: proxy unhealthy for {}s — removing the NRPT rule so the machine \
                 keeps working DNS",
                WATCHDOG_INTERVAL.as_secs() * WATCHDOG_STRIKES as u64
            );
            if let Err(e) = remove(&guid) {
                // The rule is still live and we could not remove it. The
                // boot reconciler is the backstop; say so rather than
                // pretending this was handled.
                error!(%e, "web protection: COULD NOT remove the rule — the boot reconciler will \
                            remove it at next startup");
            }
            return;
        }
    })
}

/// Can a NOERROR answer for this name be read as proof of resolution?
///
/// Only if the engine ALLOWS it. A `zero_ip` block answer is NOERROR with
/// one A record and is otherwise indistinguishable from a real resolution —
/// the same trap the proxy's own self-test step (iii)(c) had to close.
fn health_name_is_allowed(engine: &Arc<RwLock<FilterEngine>>, name: &str) -> bool {
    let e = engine.read().unwrap_or_else(|p| p.into_inner());
    e.decide(name) == Decision::Allow
}

/// One canary probe against the public address.
async fn probe_canary(addr: SocketAddr) -> bool {
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    if sock.connect(addr).await.is_err() {
        return false;
    }
    let id = rand_id();
    // build_query emits no EDNS0 OPT, which the signature check requires:
    // the proxy appends an OPT whenever the requester sent one, and that
    // moves the trailing rdata the check looks at.
    let Some(q) = wire::build_query(id, CANARY_DOMAIN, wire::TYPE_A, wire::CLASS_IN) else {
        return false;
    };
    if sock.send(&q).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 1500];
    match tokio::time::timeout(PROBE_TIMEOUT, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => is_canary_signature(&buf[..n], id),
        _ => false,
    }
}

/// Ask the listener to actually RESOLVE a name, and require a real answer.
async fn probe_resolves(addr: SocketAddr, name: &str) -> bool {
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    if sock.connect(addr).await.is_err() {
        return false;
    }
    let id = rand_id();
    let Some(q) = wire::build_query(id, name, wire::TYPE_A, wire::CLASS_IN) else {
        return false;
    };
    if sock.send(&q).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 1500];
    let n = match tokio::time::timeout(RESOLVE_TIMEOUT, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return false,
    };
    let resp = &buf[..n];
    if resp.len() < wire::HEADER_LEN || u16::from_be_bytes([resp[0], resp[1]]) != id {
        return false;
    }
    let rcode = (u16::from_be_bytes([resp[2], resp[3]]) & 0x000F) as u8;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    // NOERROR alone is not resolution: NODATA is NOERROR with no answers,
    // and so is the shape a dead-upstream proxy would love to return.
    rcode == wire::RCODE_NOERROR && ancount >= 1
}

fn rand_id() -> u16 {
    // Loopback, connected socket: this only needs to differ between probes
    // so a late reply to a previous one cannot satisfy the current check.
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .elapsed()
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    (h.finish() >> 16) as u16
}

fn new_guid() -> String {
    format!("{{{}}}", uuid::Uuid::new_v4()).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_guids_are_the_shape_nrpt_accepts() {
        for _ in 0..8 {
            let g = new_guid();
            assert!(
                nrpt::validate_guid(&g).is_ok(),
                "generated GUID is not registry-safe: {g}"
            );
        }
    }

    #[test]
    fn generated_guids_differ() {
        assert_ne!(new_guid(), new_guid());
    }

    /// REGRESSION. A non-53 listen used to reach `install_rule`, which
    /// records only the IP — so the DNS Client would query 53 where nothing
    /// listens, while the watchdog probed the bound port and reported
    /// healthy. Config validation refuses it now, and so does this, because
    /// the config is a file a user edits.
    #[test]
    fn install_refuses_any_port_but_53() {
        for port in [5353u16, 5300, 1, 65535] {
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let err = install(addr, None).expect_err("must refuse a non-53 listen");
            assert!(
                err.contains("NRPT records only the IP"),
                "the refusal must name the reason: {err}"
            );
        }
    }

    /// The precondition must hold even when everything else is fine. On a
    /// development machine the task is absent, so this is also what stops
    /// `cargo run` from installing a rule nothing would clean up.
    #[test]
    fn install_refuses_without_the_reconciler_task() {
        if nrpt::reconciler_task_installed() {
            return;
        }
        let err = install("127.0.0.1:53".parse().unwrap(), None)
            .expect_err("must refuse with no reconciler task");
        assert!(
            err.contains("reconciler task is not registered"),
            "the refusal must say WHY: {err}"
        );
    }

    /// Probing something that is not a DNS server must be false, not a
    /// hang: the watchdog runs forever and a stuck probe would stop it
    /// noticing anything again.
    #[tokio::test]
    async fn probe_of_a_dead_port_is_false_and_bounded() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead = sock.local_addr().unwrap();
        drop(sock);
        let started = std::time::Instant::now();
        assert!(!probe_canary(dead).await);
        assert!(started.elapsed() < PROBE_TIMEOUT * 3);
    }

    /// THE FINDING THIS TEST EXISTS FOR: a proxy that answers the canary
    /// but resolves nothing used to pass every guard. The resolution probe
    /// must reject NODATA (NOERROR with zero answers) and SERVFAIL, which
    /// is exactly the shape a dead-upstream proxy returns.
    #[tokio::test]
    async fn resolution_probe_rejects_answers_that_are_not_resolutions() {
        for (label, rcode, ancount) in [
            ("SERVFAIL", 2u8, 0u16),
            ("NODATA (NOERROR, no answers)", 0, 0),
            ("NXDOMAIN", 3, 0),
        ] {
            let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = server.local_addr().unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1500];
                if let Ok((n, peer)) = server.recv_from(&mut buf) {
                    let mut resp = buf[..n].to_vec();
                    if resp.len() >= 8 {
                        resp[2] = 0x81;
                        resp[3] = rcode;
                        resp[6..8].copy_from_slice(&ancount.to_be_bytes());
                    }
                    let _ = server.send_to(&resp, peer);
                }
            });
            assert!(
                !probe_resolves(addr, "example.com").await,
                "{label} must not count as a resolution"
            );
        }
    }

    /// A blocked health-check name makes the resolution probe unable to
    /// distinguish a block from a resolution, so the watchdog must detect
    /// that rather than trusting the answer.
    #[test]
    fn a_blocked_health_name_is_detected() {
        let mut e = FilterEngine::new();
        assert!(e.add_block("blocked.example"));
        let engine = Arc::new(RwLock::new(e));
        assert!(!health_name_is_allowed(&engine, "blocked.example"));
        assert!(health_name_is_allowed(&engine, "example.com"));
    }

    /// A minute of no answers is the threshold. Pinned so a later tweak to
    /// either constant cannot silently make the watchdog trigger-happy
    /// (removing the rule during a load spike) or useless.
    #[test]
    fn watchdog_threshold_is_about_a_minute() {
        let total = WATCHDOG_INTERVAL * WATCHDOG_STRIKES;
        assert!(total >= Duration::from_secs(45), "too twitchy: {total:?}");
        assert!(total <= Duration::from_secs(120), "too slow: {total:?}");
    }
}

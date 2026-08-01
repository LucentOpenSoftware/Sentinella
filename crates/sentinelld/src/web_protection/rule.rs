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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dnsguard::filter::CANARY_DOMAIN;
use dnsguard::proxy::{Counters, is_canary_signature};
use dnsguard::wire;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{error, info, warn};

use super::config::{ON_FAILURE_FALLBACK, WebProtectionConfig};

/// How often the watchdog asks whether we are still answering.
///
/// The reconciler covers the boot case; this covers the one it cannot —
/// the daemon alive while the serving task is dead. Without it a proxy that
/// dies mid-session leaves the machine without DNS until the next reboot.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(20);

/// Consecutive failures before acting. One failed probe is not proof of
/// death: the proxy sheds under load and a shed probe is indistinguishable
/// from a dead one. Three misses at 20s is about a minute of genuinely no
/// answers, which no amount of load produces.
const WATCHDOG_STRIKES: u32 = 3;

const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Install the rule, honouring both preconditions and the record-first
/// ordering. Returns the GUID actually in force.
///
/// Refusing is always safe here: it costs FILTERING, never DNS.
pub fn install(listen: SocketAddr, existing: Option<String>) -> Result<String, String> {
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
    let guid = match existing {
        Some(g) => g,
        None => new_guid(),
    };

    // RECORD FIRST. A crash between here and the write leaves a GUID naming
    // nothing, which the reconciler tidies away; the reverse order leaves a
    // rule that nothing can name.
    let state_file = nrpt::default_state_file();
    nrpt::record_guid(&state_file, &guid).map_err(|e| format!("cannot record rule GUID: {e}"))?;

    // The rule points at the address the DNS Client will use, which is the
    // listen address — NRPT carries no port, so this is only ever correct
    // when that port is 53. Config validation enforces that.
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

/// Watch the listener and tear the rule down if it stops answering.
///
/// This is the failure the boot reconciler cannot cover: the daemon alive
/// while the serving task is dead. It probes the PUBLIC address rather than
/// anything derived from our own handles, because the question is "does the
/// address the DNS Client uses answer", not "does our config look right".
pub fn spawn_watchdog(
    guid: String,
    listen: SocketAddr,
    counters: Arc<Counters>,
    cfg: &WebProtectionConfig,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let fallback = cfg.on_proxy_failure == ON_FAILURE_FALLBACK;
    tokio::spawn(async move {
        let mut strikes = 0u32;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(WATCHDOG_INTERVAL) => {}
            }

            let before = counters.snapshot().canary_probes;
            let answered = probe(listen).await;
            let moved = counters.snapshot().canary_probes > before;

            // BOTH conditions. A correct signature alone can be forged by
            // whatever owns the port; a counter delta proves OUR process
            // served it. Requiring both is what distinguishes "our proxy is
            // fine" from "something else answers on 53 now".
            if answered && moved {
                strikes = 0;
                continue;
            }
            strikes += 1;
            warn!(
                strikes,
                answered,
                counter_moved = moved,
                "web protection: watchdog probe failed"
            );
            if strikes < WATCHDOG_STRIKES {
                continue;
            }

            if fallback {
                // on_proxy_failure = "fallback": leave the rule and let the
                // NRPT secondary carry the machine. Filtering is bypassed
                // but DNS keeps working. Logged loudly because a silent
                // filter bypass is worse than a noisy one.
                error!(
                    %guid,
                    "web protection: proxy unresponsive; on_proxy_failure=fallback, LEAVING the \
                     rule in place — DNS is now unfiltered via the NRPT secondary"
                );
                return;
            }
            error!(
                %guid,
                "web protection: proxy unresponsive for {}s — removing the NRPT rule so the \
                 machine keeps working DNS",
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

/// One canary probe against the public address.
async fn probe(addr: SocketAddr) -> bool {
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

fn rand_id() -> u16 {
    // Loopback, connected socket: this only needs to differ between probes
    // so a late reply to a previous one cannot satisfy the current check.
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(std::time::SystemTime::now().elapsed().map(|d| d.as_nanos() as u64).unwrap_or(0));
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
        let a = new_guid();
        let b = new_guid();
        assert_ne!(a, b);
    }

    /// The precondition must hold even when everything else is fine. On a
    /// development machine the task is absent, so this is also what stops
    /// `cargo run` from installing a rule nothing would clean up.
    #[test]
    fn install_refuses_without_the_reconciler_task() {
        if nrpt::reconciler_task_installed() {
            // A machine with Sentinella properly installed; the refusal
            // cannot be exercised here.
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
        assert!(!probe(dead).await);
        assert!(started.elapsed() < PROBE_TIMEOUT * 3);
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

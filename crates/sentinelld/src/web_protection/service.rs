//! Starting, holding and stopping the DNS proxy.
//!
//! # The ordering that must not be got wrong
//!
//! `dnsguard::proxy::Proxy::run` takes `self` BY VALUE. Every accessor —
//! `counters()`, `engine_handle()`, `upstreams_handle()` — is `&self` and
//! becomes uncallable the moment the serving future is spawned. So the
//! handles are captured first, and the natural-looking alternative does not
//! compile (`error[E0382]: borrow of moved value`). That is deliberate on
//! dnsguard's part: it is the same move that makes it impossible to run the
//! self-test concurrently with the serving loops, which would put two
//! `recv_from` calls on one socket and mislabel real user queries as
//! synthetic.
//!
//! # Why a failed self-test means NOT serving
//!
//! It would be friendlier to bind, fail the self-test, and serve anyway so
//! the user can poke at it. We do not, because a later commit installs an
//! NRPT rule on exactly this signal — and a listener we could not prove
//! works is the precise thing that must never end up with the machine's DNS
//! pointed at it. Refusing to serve keeps "enabled but not working" in the
//! degrade-to-no-filtering direction.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;

use dnsguard::filter::{FilterEngine, ListKind};
use dnsguard::proxy::{
    BlockResponse, Counters, NoopDecisionHook, Proxy, ProxyConfig, UpstreamsHandle,
};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use super::config::{self, WebProtectionConfig};
use super::status::{ProxyState, WebProtectionStatus};
use super::upstreams;

/// A running (or refused) web-protection subsystem.
///
/// Holding this holds the proxy alive: dropping `shutdown` signals the
/// serving loops to stop.
pub struct WebProtection {
    state: ProxyState,
    detail: String,
    listen: Option<SocketAddr>,
    resolved_upstreams: Vec<SocketAddr>,
    upstreams_healthy: usize,
    upstreams_total: usize,
    rules_loaded: u64,

    // Captured BEFORE `run` consumed the proxy — see the module docs.
    counters: Option<Arc<Counters>>,
    engine: Option<Arc<RwLock<FilterEngine>>>,
    #[allow(dead_code)] // consumed by the network-change re-read in commit C
    upstreams_handle: Option<UpstreamsHandle>,

    /// Dropping or sending on this stops the serving loops. This is the
    /// daemon's FIRST `watch` channel — every other subsystem here polls an
    /// `AtomicBool` — so the sender must be kept alive for as long as the
    /// proxy should serve. Storing it in the struct is what does that.
    shutdown: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}

impl WebProtection {
    /// Not enabled, nothing running. Cheap and infallible.
    pub fn disabled() -> Self {
        Self {
            state: ProxyState::Disabled,
            detail: String::new(),
            listen: None,
            resolved_upstreams: Vec::new(),
            upstreams_healthy: 0,
            upstreams_total: 0,
            rules_loaded: 0,
            counters: None,
            engine: None,
            upstreams_handle: None,
            shutdown: None,
            task: None,
        }
    }

    fn refused(state: ProxyState, detail: impl Into<String>) -> Self {
        let mut s = Self::disabled();
        s.state = state;
        s.detail = detail.into();
        s
    }

    /// Bring web protection up, or explain precisely why not.
    ///
    /// Never returns an error: a daemon that will not start because its DNS
    /// filter could not is worse than one that starts with filtering off.
    /// The refusal is reported through [`Self::status`] and the log.
    pub async fn start(cfg: &WebProtectionConfig) -> Self {
        if !cfg.enabled {
            return Self::disabled();
        }

        // Validation has already forced `enabled = false` on a malformed
        // listen, so this parse cannot realistically fail — but unwrapping
        // here would make a future validation gap a panic in a service.
        let listen: SocketAddr = match cfg.listen.parse() {
            Ok(a) => a,
            Err(e) => {
                error!(listen = %cfg.listen, %e, "web protection: unparseable listen address");
                return Self::refused(ProxyState::Disabled, format!("listen: {e}"));
            }
        };

        let resolved = match upstreams::resolve(&cfg.upstreams, listen) {
            Ok(u) => u,
            Err(e) => {
                warn!(%e, "web protection: no usable upstreams — not starting");
                return Self::refused(ProxyState::Disabled, e.to_string());
            }
        };
        info!(
            upstreams = ?resolved,
            "web protection: resolved upstreams"
        );

        // FilterEngine::new(), NEVER default(). `default()` is the derived
        // empty engine and carries no rules — not even the canary — which
        // would make the self-test's engine step false forever and, worse,
        // would block nothing while reporting success.
        let mut engine = FilterEngine::new();
        let rules_loaded = load_lists(&mut engine, cfg);

        let proxy_cfg = ProxyConfig {
            listen,
            upstreams: resolved.clone(),
            block_response: match cfg.block_response.as_str() {
                config::BLOCK_RESPONSE_ZERO_IP => BlockResponse::ZeroIp,
                _ => BlockResponse::Nxdomain,
            },
            health_check_name: cfg.health_check_name.clone(),
            ..ProxyConfig::default()
        };

        // NoopDecisionHook: no query logging in this commit. `log_queries`
        // is accepted in config so a user's setting is never silently
        // dropped, but the storage it needs — a retention-capped table
        // behind the authenticated IPC tier — does not exist yet, and
        // inventing an unbounded one would be worse than not logging at
        // all: this is browsing history.
        let proxy = match Proxy::bind(proxy_cfg, engine, Arc::new(NoopDecisionHook)).await {
            Ok(p) => p,
            Err(e) => {
                // Overwhelmingly the "something else owns 53" case. Say so,
                // because the fix is to find that something, not to retry.
                error!(%listen, %e, "web protection: bind failed — not starting");
                return Self::refused(ProxyState::BindFailed, format!("bind {listen}: {e}"));
            }
        };

        // CAPTURE BEFORE RUN. These are `&self` methods and `run` consumes
        // the proxy; taking them afterwards does not compile.
        let counters = proxy.counters();
        let engine_handle = proxy.engine_handle();
        let upstreams_handle = proxy.upstreams_handle();
        let bound = proxy.local_addr();

        // The four-step gate. Runs while nothing else is serving these
        // sockets — self_test spawns its own private loops, which is why it
        // must never overlap `run`.
        let report = proxy.self_test().await;
        if !report.ok() {
            error!(
                detail = %report.detail,
                engine_ok = report.engine_ok,
                upstream_ok = report.upstream_ok,
                filter_ok = report.filter_ok,
                tcp_ok = report.tcp_ok,
                "web protection: self-test failed — NOT serving"
            );
            let mut s = Self::refused(ProxyState::SelfTestFailed, report.detail.clone());
            s.listen = Some(bound);
            s.resolved_upstreams = resolved;
            s.upstreams_healthy = report.upstreams_healthy;
            s.upstreams_total = report.upstreams_total;
            s.rules_loaded = rules_loaded;
            return s;
        }

        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(proxy.run(rx));
        info!(
            %bound,
            upstreams = report.upstreams_total,
            rules = rules_loaded,
            "web protection: serving (no NRPT rule — nothing is pointed here yet)"
        );

        Self {
            state: ProxyState::Serving,
            detail: String::new(),
            listen: Some(bound),
            resolved_upstreams: resolved,
            upstreams_healthy: report.upstreams_healthy,
            upstreams_total: report.upstreams_total,
            rules_loaded,
            counters: Some(counters),
            engine: Some(engine_handle),
            upstreams_handle: Some(upstreams_handle),
            shutdown: Some(tx),
            task: Some(task),
        }
    }

    /// A point-in-time status, reading live counters when serving.
    pub fn status(&self, enabled: bool) -> WebProtectionStatus {
        let snap = self.counters.as_ref().map(|c| c.snapshot());
        WebProtectionStatus {
            enabled,
            // Still genuinely unknown: no NRPT code exists in this commit,
            // and reporting `Some(false)` would be an assertion we cannot
            // support.
            nrpt_installed: None,
            state: self.state,
            listen: self.listen.map(|a| a.to_string()),
            upstreams: self
                .resolved_upstreams
                .iter()
                .map(|a| a.to_string())
                .collect(),
            upstreams_healthy: self.upstreams_healthy,
            upstreams_total: self.upstreams_total,
            rules_loaded: self
                .engine
                .as_ref()
                .map(|e| {
                    e.read()
                        .unwrap_or_else(|p| p.into_inner())
                        .rule_count() as u64
                })
                .unwrap_or(self.rules_loaded),
            detail: self.detail.clone(),
            queries: snap.as_ref().map(|s| s.queries).unwrap_or(0),
            blocked: snap.as_ref().map(|s| s.blocked).unwrap_or(0),
            cache_hits: snap.as_ref().map(|s| s.cache_hits).unwrap_or(0),
            upstream_errors: snap.as_ref().map(|s| s.upstream_errors).unwrap_or(0),
        }
    }

    /// Stop serving and WAIT for the loops to finish.
    ///
    /// This is a rendezvous, not a flag store. Every other `stop()` in this
    /// crate — Scheduler, RealtimeWatcher, IdleScanner — just sets an
    /// `AtomicBool` and returns, which is fine for them and will NOT be
    /// fine here: commit C removes the NRPT rule during shutdown, and
    /// removing it while the sockets are still bound would leave a window
    /// where the machine's DNS points at a listener that is going away. The
    /// join is bounded because the SCM stop budget is 30 s in total.
    pub async fn stop(&mut self) {
        let Some(tx) = self.shutdown.take() else {
            return;
        };
        let _ = tx.send(true);
        if let Some(task) = self.task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(_)) => info!("web protection: stopped"),
                Ok(Err(e)) => warn!(%e, "web protection: serving task ended abnormally"),
                Err(_) => warn!("web protection: serving task did not stop within 5s"),
            }
        }
        self.state = ProxyState::Disabled;
    }
}

/// Load the configured lists into a fresh engine, returning the rule count.
///
/// Failures are warned and skipped rather than aborting startup: a
/// missing blocklist file means less filtering, and less filtering is the
/// direction this subsystem is allowed to fail in.
fn load_lists(engine: &mut FilterEngine, cfg: &WebProtectionConfig) -> u64 {
    for entry in &cfg.allowlist {
        // Config syntax: bare = exact, leading dot = suffix. `false` here
        // means the operator's rule vanished, which is a config error and
        // must be loud — not a debug line.
        if !engine.add_allow_rule(entry) {
            warn!(entry = %entry, "web_protection.allowlist entry is malformed — IGNORED");
        }
    }
    for spec in &cfg.blocklists {
        // `path` or `path|suffix`; the exact/suffix policy is a property of
        // the SOURCE, never of the data.
        let (path, suffix) = match spec.split_once('|') {
            Some((p, "suffix")) => (p, true),
            Some((p, "exact")) => (p, false),
            Some((p, other)) => {
                warn!(spec = %spec, policy = %other, "unknown blocklist policy — using exact");
                (p, false)
            }
            None => (spec.as_str(), false),
        };
        match std::fs::File::open(path) {
            Ok(f) => {
                let reader = std::io::BufReader::new(f);
                let policy = if suffix {
                    dnsguard::filter::DomainListPolicy::Suffix
                } else {
                    dnsguard::filter::DomainListPolicy::Exact
                };
                let res = if path.ends_with(".hosts") || path.ends_with("hosts") {
                    engine.load_hosts(ListKind::Block, reader)
                } else {
                    engine.load_domain_list(ListKind::Block, reader, policy)
                };
                match res {
                    Ok(stats) => {
                        if stats.truncated {
                            warn!(
                                path = %path,
                                rules = stats.rules_added,
                                "blocklist hit a load budget and was TRUNCATED — protection is partial"
                            );
                        }
                        if stats.hosts_rejected != 0 {
                            warn!(
                                path = %path,
                                rejected = stats.hosts_rejected,
                                "blocklist contained malformed entries that were dropped"
                            );
                        }
                        info!(path = %path, rules = stats.rules_added, "blocklist loaded");
                    }
                    Err(e) => warn!(path = %path, %e, "blocklist read failed — SKIPPED"),
                }
            }
            Err(e) => warn!(path = %path, %e, "blocklist not readable — SKIPPED"),
        }
    }
    engine.rule_count() as u64
}


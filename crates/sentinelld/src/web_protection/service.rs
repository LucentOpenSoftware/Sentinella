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
use std::time::Duration;
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

/// The READ-ONLY half of the subsystem, shareable with the IPC layer.
///
/// WHY THIS IS SEPARATE. The IPC handler needs the status, and `AppState`
/// is `Arc`-shared by the server, its per-connection tasks and the Ctrl+C
/// task — it outlives process exit, which is why `plm/mod.rs:910-922`
/// documents that `Drop` is unreachable for anything it owns. Putting the
/// subsystem itself in `AppState` would therefore make `stop()` unable to
/// take `&mut`, and `stop()` MUST be a rendezvous (commit C removes the
/// NRPT rule during shutdown; removing it while the sockets are still
/// bound leaves the machine's DNS pointed at a listener that is going
/// away). So the owner keeps the shutdown side and shares this.
///
/// Everything here is either fixed at start or read through an `Arc` the
/// serving loops also hold, so it is always live without a lock of ours.
pub struct WebProtectionHandle {
    /// `enabled` AS OF START. A config edit since then is deliberately not
    /// reflected: it has not taken effect either, and reporting the edited
    /// value would claim a state the daemon is not in.
    enabled: bool,
    state: ProxyState,
    detail: String,
    listen: Option<SocketAddr>,
    resolved_upstreams: Vec<SocketAddr>,
    upstreams_healthy: usize,
    upstreams_total: usize,
    rules_loaded: u64,
    counters: Option<Arc<Counters>>,
    engine: Option<Arc<RwLock<FilterEngine>>>,
    /// The NRPT rule GUID in force, if one was installed. `None` means no
    /// rule — which is a normal, safe state, not a failure.
    rule_guid: Option<String>,
}

impl WebProtectionHandle {
    /// A point-in-time status, reading live counters when serving.
    pub fn status(&self) -> WebProtectionStatus {
        let snap = self.counters.as_ref().map(|c| c.snapshot());
        WebProtectionStatus {
            enabled: self.enabled,
            // Read from the system, never inferred from config. `None`
            // still means "could not tell", which is not `Some(false)`.
            nrpt_installed: super::rule::installed_now(self.rule_guid.as_deref()),
            state: self.state,
            listen: self.listen.map(|a| a.to_string()),
            upstreams: self.resolved_upstreams.iter().map(|a| a.to_string()).collect(),
            upstreams_healthy: self.upstreams_healthy,
            upstreams_total: self.upstreams_total,
            rules_loaded: self
                .engine
                .as_ref()
                .map(|e| e.read().unwrap_or_else(|p| p.into_inner()).rule_count() as u64)
                .unwrap_or(self.rules_loaded),
            detail: self.detail.clone(),
            queries: snap.as_ref().map(|s| s.queries).unwrap_or(0),
            blocked: snap.as_ref().map(|s| s.blocked).unwrap_or(0),
            cache_hits: snap.as_ref().map(|s| s.cache_hits).unwrap_or(0),
            upstream_errors: snap.as_ref().map(|s| s.upstream_errors).unwrap_or(0),
        }
    }
}

/// A running (or refused) web-protection subsystem.
///
/// Holding this holds the proxy alive: dropping `shutdown` signals the
/// serving loops to stop.
pub struct WebProtection {
    handle: Arc<WebProtectionHandle>,
    watchdog: Option<tokio::task::JoinHandle<()>>,
    /// Periodic upstream re-discovery. Aborted in `stop`, like the watchdog.
    ///
    /// The `UpstreamsHandle` lives INSIDE this task, not beside it. A copy
    /// was kept here once, `#[allow(dead_code)]`, with a comment promising a
    /// future consumer — which is how the stale-upstream outage stayed
    /// invisible for a release: the field made the wiring look done. There
    /// is nothing for an owner-side copy to do (the handle is `Clone` over
    /// an `Arc` the proxy holds, so holding one keeps nothing alive), so the
    /// only holder is the only caller.
    refresher: Option<tokio::task::JoinHandle<()>>,

    /// Dropping or sending on this stops the serving loops. This is the
    /// daemon's FIRST `watch` channel — every other subsystem here polls an
    /// `AtomicBool` — so the sender must be kept alive for as long as the
    /// proxy should serve. Storing it in the struct is what does that.
    shutdown: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}

/// How often to re-discover the system resolvers.
///
/// The upstream list was resolved once at daemon start and never re-read.
/// `UpstreamsHandle` exists precisely to fix that and was stored, unused —
/// dead code that looked like the feature was implemented. Meanwhile the NRPT
/// rule routes EVERY name on the machine at us, so once the list goes stale
/// the machine cannot resolve anything: connect to a VPN, switch Wi-Fi, dock,
/// or just renew a DHCP lease onto a different resolver, and the proxy keeps
/// forwarding to addresses that no longer answer.
///
/// 30 s is a compromise. `GetAdaptersAddresses` is cheap, but this is a
/// poll — a proper `NotifyIpInterfaceChange` subscription would react
/// immediately and is the better long-term answer. Polling closes the
/// indefinite outage now without adding an FFI callback surface.
const UPSTREAM_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Re-discover upstreams periodically and push them at the proxy.
///
/// Deliberately quiet and deliberately conservative. `UpstreamsHandle::set`
/// validates and KEEPS THE PREVIOUS LIST on error, so a transient discovery
/// failure — every adapter down mid-roam — cannot leave the proxy with no
/// resolver at all. That is the same "degrade to no filtering, never to no
/// DNS" rule the rest of this module runs on: a stale-but-working list beats
/// an empty one.
fn spawn_upstream_refresh(
    configured: Vec<String>,
    listen: SocketAddr,
    handle: UpstreamsHandle,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut current: Vec<SocketAddr> = Vec::new();
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(UPSTREAM_REFRESH_INTERVAL) => {}
            }
            let discovered = match upstreams::resolve(&configured, listen) {
                Ok(u) => u,
                Err(e) => {
                    // Keep serving with what we have. An empty list here
                    // would be worse than a stale one.
                    warn!(%e, "web protection: upstream re-discovery failed — keeping the current list");
                    continue;
                }
            };
            if discovered == current {
                continue;
            }
            match handle.set(discovered.clone()) {
                Ok(()) => {
                    info!(
                        upstreams = ?discovered,
                        "web protection: upstream list changed — proxy updated"
                    );
                    current = discovered;
                }
                Err(e) => warn!(
                    %e,
                    "web protection: rediscovered upstreams were rejected — keeping the current list"
                ),
            }
        }
    })
}

/// Remove a rule that some PREVIOUS run of this daemon installed, when this
/// run is not going to serve.
///
/// THE HOLE THIS FILLS. `stop()` removes the rule on an orderly shutdown, and
/// the boot reconciler removes it at the next boot. Nothing covered the gap
/// between them: the daemon dying without running `stop()` and then being
/// restarted IN THE SAME BOOT. That is not exotic — the SCM restarts the
/// service on failure after 5 s, and the installer's PREINSTALL hook
/// `taskkill /F`s the daemon on every upgrade. If the restarted process then
/// refuses to serve for any reason (no adapters up yet on a laptop resuming,
/// port taken, self-test fail), the old rule stayed live in the registry
/// pointing every name on the machine at a port with nothing behind it, and
/// the new process had `rule_guid: None` so `stop()` would not remove it
/// either — the daemon was structurally incapable of ever taking it away.
/// The machine had no DNS until a reboot, which is the one outcome this
/// design says must never happen.
///
/// Best-effort by construction: a failure here leaves us exactly where we
/// already were, so it logs and moves on rather than blocking startup.
fn reconcile_orphan_rule(reason: &str) {
    let state_file = nrpt::default_state_file();
    let Some(guid) = nrpt::recorded_guid(&state_file) else {
        return;
    };
    match nrpt::rule_exists(&guid) {
        Ok(false) => {}
        Ok(true) => {
            warn!(
                %guid, reason,
                "web protection: a rule from a previous run is still live and this run is not \
                 serving — removing it so the machine keeps working DNS"
            );
            match super::rule::remove(&guid) {
                Ok(()) => info!(%guid, "web protection: orphaned rule removed"),
                Err(e) => error!(
                    %guid, %e,
                    "web protection: COULD NOT remove the orphaned rule — DNS on this machine is \
                     pointed at a port we are not serving; the boot reconciler is the backstop"
                ),
            }
        }
        Err(e) => warn!(
            %guid, %e,
            "web protection: could not tell whether a previous rule is still live"
        ),
    }
}

impl WebProtection {
    /// Not enabled, nothing running. Cheap and infallible.
    ///
    /// Still reconciles: `enabled = false` is one of the ways a live rule
    /// from a previous run gets orphaned (the user turned it off, or
    /// validation forced it off, while a rule was installed).
    pub fn disabled() -> Self {
        reconcile_orphan_rule("web protection disabled");
        Self::inert(false, ProxyState::Disabled, String::new(), None)
    }

    /// Enabled but refused, with the reason. `enabled` stays TRUE: the user
    /// did ask for this, and a status that reported `enabled: false` here
    /// would hide the refusal behind what looks like an untouched setting.
    fn refused(state: ProxyState, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        reconcile_orphan_rule(&detail);
        Self::inert(true, state, detail, None)
    }

    fn inert(
        enabled: bool,
        state: ProxyState,
        detail: String,
        listen: Option<SocketAddr>,
    ) -> Self {
        Self {
            handle: Arc::new(WebProtectionHandle {
                enabled,
                state,
                detail,
                listen,
                resolved_upstreams: Vec::new(),
                upstreams_healthy: 0,
                upstreams_total: 0,
                rules_loaded: 0,
                counters: None,
                engine: None,
                rule_guid: None,
            }),
            watchdog: None,
            refresher: None,
            shutdown: None,
            task: None,
        }
    }

    /// Share the read-only half with the IPC layer. See
    /// [`WebProtectionHandle`] for why this is not just `&self`.
    pub fn handle(&self) -> Arc<WebProtectionHandle> {
        Arc::clone(&self.handle)
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
            // This path builds its handle by hand rather than through
            // `inert` (it keeps the engine handle so status can distinguish
            // "rules did not load" from "upstream is dead"), so it needs the
            // reconcile call explicitly. Bound socket or not, we are not
            // serving, and a rule pointing here would black-hole DNS.
            reconcile_orphan_rule("self-test failed");
            return Self {
                handle: Arc::new(WebProtectionHandle {
                    enabled: true,
                    state: ProxyState::SelfTestFailed,
                    detail: report.detail.clone(),
                    listen: Some(bound),
                    resolved_upstreams: resolved,
                    upstreams_healthy: report.upstreams_healthy,
                    upstreams_total: report.upstreams_total,
                    rules_loaded,
                    // The engine handle survives so status can still report
                    // how many rules loaded — useful for telling "the list
                    // did not load" apart from "the upstream is dead".
                    counters: None,
                    engine: Some(engine_handle),
                    rule_guid: None,
                }),
                watchdog: None,
                refresher: None,
                shutdown: None,
                task: None,
            };
        }

        let (tx, rx) = watch::channel(false);
        // Spawned BEFORE `proxy.run` consumes the proxy, and given its own
        // shutdown receiver so it dies with the rest of the service rather
        // than outliving it and pushing upstreams at a stopped proxy.
        let refresher = spawn_upstream_refresh(
            cfg.upstreams.clone(),
            listen,
            upstreams_handle,
            tx.subscribe(),
        );
        let task = tokio::spawn(proxy.run(rx));

        // ONLY NOW, with the self-test passed and the listener serving, may
        // a rule be installed. `install` enforces the other hard
        // precondition itself — the boot reconciler's task must exist,
        // because it is the only thing that removes the rule when this
        // process is not around to.
        //
        // A refusal here is SAFE: it costs filtering, never DNS. So it is a
        // warning and the proxy keeps serving; anyone who wants to use it
        // can still point a resolver at it by hand.
        let (rule_guid, watchdog) = match super::rule::install(bound, nrpt::recorded_guid(&nrpt::default_state_file())) {
            Ok(guid) => {
                let wd = super::rule::spawn_watchdog(
                    guid.clone(),
                    bound,
                    Arc::clone(&counters),
                    Arc::clone(&engine_handle),
                    cfg.health_check_name.clone(),
                    tx.subscribe(),
                );
                (Some(guid), Some(wd))
            }
            Err(e) => {
                warn!(%e, "web protection: serving, but NO NRPT rule installed — the machine's DNS does not go through this proxy");
                (None, None)
            }
        };

        info!(
            %bound,
            upstreams = report.upstreams_total,
            rules = rules_loaded,
            nrpt = rule_guid.is_some(),
            "web protection: serving"
        );

        Self {
            handle: Arc::new(WebProtectionHandle {
                enabled: true,
                state: ProxyState::Serving,
                detail: String::new(),
                listen: Some(bound),
                resolved_upstreams: resolved,
                upstreams_healthy: report.upstreams_healthy,
                upstreams_total: report.upstreams_total,
                rules_loaded,
                counters: Some(counters),
                engine: Some(engine_handle),
                rule_guid,
            }),
            watchdog,
            refresher: Some(refresher),
            shutdown: Some(tx),
            task: Some(task),
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
        // RULE FIRST, SOCKETS SECOND. Between these two the machine
        // resolves through its normal upstreams while we are still
        // answering, which is harmless. The reverse order leaves a window
        // where the rule points at sockets that are already closed — the
        // exact state this whole design exists to prevent, reached during
        // an ORDERLY shutdown, which would be an embarrassing way to get
        // there.
        if let Some(guid) = self.handle.rule_guid.clone()
            && let Err(e) = super::rule::remove(&guid)
        {
            error!(%e, %guid, "web protection: could not remove the NRPT rule on shutdown —                    the boot reconciler will remove it at next startup");
        }
        let Some(tx) = self.shutdown.take() else {
            return;
        };
        let _ = tx.send(true);
        if let Some(wd) = self.watchdog.take() {
            wd.abort();
        }
        // Same treatment as the watchdog: it holds an UpstreamsHandle into a
        // proxy that is going away, and its `watch` receiver would otherwise
        // let it survive one more sleep and push a list at a stopped proxy.
        if let Some(rf) = self.refresher.take() {
            rf.abort();
        }
        if let Some(task) = self.task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(_)) => info!("web protection: stopped"),
                Ok(Err(e)) => warn!(%e, "web protection: serving task ended abnormally"),
                Err(_) => warn!("web protection: serving task did not stop within 5s"),
            }
        }
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


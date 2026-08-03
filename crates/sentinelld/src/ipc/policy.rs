//! IPC Control Plane Policy — method registry, rate limiting, payload caps.
//!
//! Every IPC method has a declared class, auth requirements, payload limit,
//! and rate limit bucket. The dispatcher checks policy BEFORE dispatching.
//!
//! # Rate limiter map (v0.1.12, workstream K/L)
//!
//! Precise semantics of the request-rate limiter (`RateLimiter`), as
//! enforced by `dispatch_sync` (ipc/mod.rs) on EVERY request whose method
//! is in the registry:
//!
//! - **Scope/key**: two layers. (1) a GLOBAL token bucket per `RateBucket`
//!   class (one `RateLimiter` lives in `AppState`, shared by all
//!   connections) — the hard ceiling, unchanged since introduction;
//!   (2) a PER-PRINCIPAL sub-bucket per (`RateBucket`, client SID) added
//!   in v0.1.12. Before v0.1.12 only layer (1) existed, so one caller
//!   draining ScanControl (10/min, burst 3) starved every other caller's
//!   scan.start / scan.cancel / update.start / argus.analyze / engine.reload
//!   (matrix row C-5). The per-principal layer caps any single SID at
//!   roughly half the steady-state budget of each bucket.
//! - **Identity source**: the accept-time `ClientIdentity` resolved from
//!   the named-pipe client process token (same SID fairness.rs keys
//!   connection quotas on) — kernel-owned, not client-choosable, and NOT
//!   derived from the `auth` param, so an auth failure cannot rotate
//!   identities to mint fresh budgets. Unresolved identities (fail-open
//!   path, non-Windows) share one conservative `Unidentified` bucket with
//!   the same per-principal numbers — never a per-PID bucket (a PID-keyed
//!   quota is void on arrival: spawn N processes, get N budgets).
//! - **Reset interval**: continuous refill, `max_per_minute` tokens/min,
//!   fractional remainder preserved (v0.1.9 MED-12 fix); burst = initial
//!   and max accumulated tokens.
//! - **Check order**: per-principal first, then global. A request rejected
//!   by EITHER layer consumes NO token from that layer; a per-principal
//!   rejection consumes no global token either (rejected requests are
//!   free for the victim's budget — they only cost the flooder CPU).
//! - **Failure response**: JSON-RPC error `RATE_LIMITED` (-32020) with
//!   `retry after Ns` where N = max(60/rate_per_minute, 1) of the layer
//!   that rejected.
//! - **Memory accounting**: the global layer is a fixed 8-entry map. The
//!   per-principal layer is bounded by `MAX_PRINCIPAL_ENTRIES` (256)
//!   (bucket, principal) pairs with LRU eviction — a high-cardinality
//!   SID spray cannot grow memory unboundedly (and SIDs come from real
//!   process tokens, so cardinality is naturally small).
//! - **Relation to the connection semaphore / fairness quota**: fully
//!   independent. Connection limits (mod.rs `conn_sem` + fairness.rs)
//!   bound concurrent SESSIONS per principal; this limiter bounds
//!   REQUESTS within and across sessions. One connection may issue
//!   unlimited requests — each passes through here.
//! - **Auth-vs-rate ordering (finding, deliberately kept)**: the rate
//!   check runs BEFORE the central MethodClass auth gate (dispatch_sync
//!   Phase 3 before Phase 8), so an unauthenticated request DOES consume
//!   a token. Pre-v0.1.12 that let an unauthenticated flooder drain the
//!   shared global bucket; with per-principal keying the flooder now only
//!   burns their own sub-budget (the IPC secret is world-readable anyway,
//!   so "authenticated" was never a meaningful rate boundary). Keeping
//!   rate-first also throttles UNAUTHORIZED-response generation for
//!   unauthenticated garbage, and preserves the historical error
//!   precedence (RATE_LIMITED before UNAUTHORIZED). The elevation gate
//!   for challengeable methods still runs before BOTH, so unelevated
//!   callers never consume tokens for privileged methods.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use super::client_auth::ClientIdentity;

/// Method security class — determines auth + challenge requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodClass {
    /// No auth needed. Status/health endpoints.
    PublicStatus,
    /// IPC auth required. Read-only queries.
    AuthenticatedRead,
    /// IPC auth required. State-changing actions.
    AuthenticatedAction,
    /// Challenge token required. Modifies security posture.
    PrivilegedMutation,
    /// Challenge token required. Irreversible or high-risk.
    DangerousOperation,
}

/// Policy for a single IPC method.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MethodPolicy {
    pub class: MethodClass,
    pub max_payload_bytes: usize,
    pub rate_bucket: RateBucket,
    pub audit_log: bool,
    pub allowed_while_reloading: bool,
    pub allowed_while_degraded: bool,
}

/// Rate limit bucket — groups methods that share a rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateBucket {
    Status,
    ScanControl,
    QuarantineOps,
    ConfigMutation,
    DiagnosticsExport,
    SourcesMutation,
    MemoryScan,
    Unlimited,
}

/// Rate limit configuration per bucket.
struct BucketConfig {
    max_per_minute: u32,
    burst: u32,
    /// Per-principal sub-budget (v0.1.12): the most ONE resolved SID (or
    /// the shared unidentified bucket) may draw from this bucket.
    per_principal_max_per_minute: u32,
    per_principal_burst: u32,
}

impl BucketConfig {
    const fn new(
        max_per_minute: u32,
        burst: u32,
        per_principal_max_per_minute: u32,
        per_principal_burst: u32,
    ) -> Self {
        Self {
            max_per_minute,
            burst,
            per_principal_max_per_minute,
            per_principal_burst,
        }
    }
}

fn bucket_config(bucket: RateBucket) -> BucketConfig {
    // Per-principal sizing rule: ~half the steady-state global rate, so a
    // single principal can never consume the whole bucket and a second
    // principal always has headroom; the global bucket stays the ceiling
    // (its numbers are UNCHANGED). Where the per-principal burst is one
    // below the global burst (ScanControl, QuarantineOps) a cold-start
    // flooder cannot drain the initial global tokens — one is reserved
    // for a second principal. For 2-token-burst buckets we keep pairs
    // working (settings.set→protection.disable, sources.set→sources.update,
    // memory.list_processes→memory.scan_process): the flooder can take the
    // whole cold-start burst but steady state stays ≤ half, so a second
    // principal waits at most one global refill interval (≤ 12s).
    match bucket {
        // v0.1.8: bumped 120/20 -> 300/40 to absorb v0.1.8 Settings page
        // bursts (3 extra reads on every Settings open: settings.get_full,
        // settings.get_defaults, settings.restart_requirements). The
        // dashboard already polls 9 status endpoints every 5s (~108/min
        // steady), so the old 120/min cap with 2/sec refill gave only a
        // 12/min cushion for everything else. New 300/min cushion is
        // 192/min above dashboard baseline, plenty for Settings + ad-hoc
        // user-driven status queries from other pages.
        //
        // Per-principal 150/min: the dashboard's ~108/min all comes from
        // ONE user SID and must keep fitting; 150 leaves the other half
        // of the global budget for a second session/CLI.
        RateBucket::Status => BucketConfig::new(300, 40, 150, 40),
        // Per-principal burst 2 (not 3): reserves one cold-start token so
        // a second principal's first scan.start/update.start always goes
        // through; a scan.start+scan.cancel pair still fits.
        RateBucket::ScanControl => BucketConfig::new(10, 3, 5, 2),
        RateBucket::QuarantineOps => BucketConfig::new(30, 5, 15, 4),
        RateBucket::ConfigMutation => BucketConfig::new(10, 2, 5, 2),
        RateBucket::DiagnosticsExport => BucketConfig::new(6, 2, 3, 2),
        RateBucket::SourcesMutation => BucketConfig::new(5, 2, 2, 2),
        RateBucket::MemoryScan => BucketConfig::new(10, 2, 5, 2),
        RateBucket::Unlimited => BucketConfig::new(u32::MAX, u32::MAX, u32::MAX, u32::MAX),
    }
}

/// Per-principal identity key for request-rate accounting. Deliberately
/// mirrors `fairness::PrincipalKey` (same Sid/Unidentified split, same
/// no-PID-fallback rationale) but is defined locally so the policy module
/// stays self-contained; fairness.rs keeps its key private. First-party
/// clients bypass this layer entirely (see `check`), so no FirstParty
/// variant is needed here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PrincipalKey {
    /// String SID from the client process's token (e.g. `S-1-5-21-…`).
    Sid(String),
    /// Identity unresolved (fail-open path) or non-Windows — one shared,
    /// conservatively-capped bucket, never a bypass.
    Unidentified,
}

impl PrincipalKey {
    fn from_identity(id: Option<&ClientIdentity>) -> Self {
        match id {
            Some(i) => PrincipalKey::Sid(i.sid.clone()),
            None => PrincipalKey::Unidentified,
        }
    }
}

/// Hard bound on tracked (bucket, principal) sub-buckets. 256 entries ×
/// ~100 bytes is ~25 KB worst case; beyond it the LRU entry is evicted.
/// Real cardinality is tiny (SIDs come from kernel-owned process tokens,
/// not from anything the client chooses), so eviction should never fire
/// outside an artificial SID spray — and even then memory stays flat.
const MAX_PRINCIPAL_ENTRIES: usize = 256;

/// Per-principal token bucket state. Lives behind the table mutex, so no
/// atomics are needed; `last_used` is an LRU tick (table clock value).
struct PrincipalBucket {
    tokens: u64,
    last_refill: Instant,
    last_used: u64,
}

#[derive(Default)]
struct PrincipalTable {
    map: HashMap<(RateBucket, PrincipalKey), PrincipalBucket>,
    clock: u64,
}

/// Two-layer rate limiter: per-principal sub-budgets over per-bucket
/// global token buckets. The GLOBAL layer keeps its exact pre-v0.1.12
/// semantics (same numbers, same atomic refill algorithm); the
/// per-principal layer sits in front of it — see module docs.
pub struct RateLimiter {
    buckets: HashMap<RateBucket, BucketState>,
    principals: Mutex<PrincipalTable>,
}

struct BucketState {
    tokens: AtomicU64,
    last_refill: std::sync::Mutex<Instant>,
    config: BucketConfig,
}

impl RateLimiter {
    pub fn new() -> Self {
        let mut buckets = HashMap::new();
        for bucket in [
            RateBucket::Status,
            RateBucket::ScanControl,
            RateBucket::QuarantineOps,
            RateBucket::ConfigMutation,
            RateBucket::DiagnosticsExport,
            RateBucket::SourcesMutation,
            RateBucket::MemoryScan,
            RateBucket::Unlimited,
        ] {
            let config = bucket_config(bucket);
            buckets.insert(
                bucket,
                BucketState {
                    tokens: AtomicU64::new(config.burst as u64),
                    last_refill: std::sync::Mutex::new(Instant::now()),
                    config,
                },
            );
        }
                Self {
            buckets,
            principals: Mutex::new(PrincipalTable::default()),
        }
    }

    /// Per-principal phase: refill + consume one token from the caller's
    /// sub-bucket for `bucket`. Returns Err(retry_after_secs) WITHOUT
    /// touching the global bucket when the principal's share is spent, so
    /// a flooder's rejected requests never eat into anyone else's budget.
    fn check_principal(
        &self,
        bucket: RateBucket,
        config: &BucketConfig,
        principal: Option<&ClientIdentity>,
    ) -> Result<(), u32> {
        let mut table = self.principals.lock().unwrap_or_else(|e| e.into_inner());
        table.clock += 1;
        let tick = table.clock;
        let key = (bucket, PrincipalKey::from_identity(principal));
        if !table.map.contains_key(&key) && table.map.len() >= MAX_PRINCIPAL_ENTRIES {
            // LRU eviction — O(n) scan over at most 256 entries, only on
            // insert-when-full. Bound, not clever, on purpose.
            if let Some(victim) = table
                .map
                .iter()
                .min_by_key(|(_, b)| b.last_used)
                .map(|(k, _)| k.clone())
            {
                table.map.remove(&victim);
            }
        }
        let entry = table.map.entry(key).or_insert_with(|| PrincipalBucket {
            tokens: config.per_principal_burst as u64,
            last_refill: Instant::now(),
            last_used: tick,
        });
        entry.last_used = tick;
        // Same fractional-remainder-preserving refill as the global layer
        // (v0.1.9 MED-12): advance `last_refill` by exactly the time the
        // whole minted tokens account for.
        let elapsed = entry.last_refill.elapsed();
        let refill =
            (elapsed.as_secs_f64() * config.per_principal_max_per_minute as f64 / 60.0) as u64;
        if refill > 0 {
            entry.tokens = entry
                .tokens
                .saturating_add(refill)
                .min(config.per_principal_burst as u64);
            let mpm = config.per_principal_max_per_minute.max(1) as f64;
            entry.last_refill += std::time::Duration::from_secs_f64(refill as f64 * 60.0 / mpm);
        }
        if entry.tokens == 0 {
            let retry_secs = (60 / config.per_principal_max_per_minute.max(1)).max(1);
            return Err(retry_secs);
        }
        entry.tokens -= 1;
        Ok(())
    }

    /// Try to consume one token for `principal` (accept-time identity;
    /// `None` = unresolved → shared unidentified bucket). Returns Ok(())
    /// or Err with retry_after_secs. Per-principal budget is checked
    /// first, then the global bucket ceiling.
    pub fn check(
        &self,
        bucket: RateBucket,
        principal: Option<&ClientIdentity>,
    ) -> Result<(), u32> {
        if bucket == RateBucket::Unlimited {
            return Ok(());
        }
        let state = match self.buckets.get(&bucket) {
            Some(s) => s,
            None => return Ok(()),
        };

        // First-party clients (installed GUI/CLI by kernel-reported image
        // path — see ClientIdentity::is_first_party) skip the per-principal
        // layer: same-user malware cannot enter this pool, and the management
        // client must not be throttled by a same-SID flooder draining its
        // own sub-bucket (the re-key finding from adversarial re-review).
        // The GLOBAL ceiling below still applies to everyone.
        if !principal.map(|p| p.is_first_party()).unwrap_or(false) {
            self.check_principal(bucket, &state.config, principal)?;
        }

        // Refill tokens based on elapsed time.
        //
        // Race fix: the previous `load` + `store(current + refill)` lost any
        // concurrent consume that happened in between (consume's CAS succeeded,
        // refill's store then overwrote it with the pre-consume value + refill
        // → token went back up, request was effectively free → rate limit
        // weakened under load). `fetch_update` retries until it observes the
        // latest value, so concurrent consumes are never overwritten.
        //
        // v0.1.9 Phase 5 (audit MED-12): the float-to-u64 cast on `refill`
        // truncated fractional tokens, AND the unconditional
        // `*last = Instant::now()` discarded the elapsed remainder.
        // Worked example: ConfigMutation = 10/min = 1 token per 6s. A
        // request at t=6.5s got +1 token but lost 0.5s of progress; the
        // next refill needed another full 6s instead of 5.5s. Sustained
        // effective rate drifted to ~half the declared cap. Fix: advance
        // `last_refill` by EXACTLY the time the integer-truncated refill
        // accounts for (`refill * 60s / max_per_minute`), preserving the
        // fractional remainder for the next call.
        {
            let mut last = state.last_refill.lock().unwrap_or_else(|e| e.into_inner());
            let elapsed = last.elapsed();
            let refill = (elapsed.as_secs_f64() * state.config.max_per_minute as f64 / 60.0) as u64;
            if refill > 0 {
                let burst = state.config.burst as u64;
                let _ = state.tokens.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |cur| Some(cur.saturating_add(refill).min(burst)),
                );
                // Advance by the EXACT time those `refill` whole tokens
                // represent (not `now()`), so the unconsumed fractional
                // remainder rolls into the next refill window. max_per_minute
                // is non-zero in every defined bucket; the `.max(1)` guard
                // keeps a configuration typo from panicking on Duration::from_secs_f64.
                let mpm = state.config.max_per_minute.max(1) as f64;
                let consumed_secs = refill as f64 * 60.0 / mpm;
                *last += std::time::Duration::from_secs_f64(consumed_secs);
            }
        }

        // Try to consume one token without underflowing under concurrent callers.
        loop {
            let current = state.tokens.load(Ordering::Relaxed);
            if current == 0 {
                // Audit fix: for buckets >60/min, `60 / max_per_minute` is 0
                // → client told to retry after 0s → immediate retry storm
                // with no backoff. Floor at 1s.
                let retry_secs = (60 / state.config.max_per_minute.max(1)).max(1);
                return Err(retry_secs);
            }
            if state
                .tokens
                .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
        }
    }
}

/// Build the method registry — maps method name → policy.
pub fn method_registry() -> HashMap<&'static str, MethodPolicy> {
    let mut m = HashMap::new();

    let pub_status = |max_payload: usize| MethodPolicy {
        class: MethodClass::PublicStatus,
        max_payload_bytes: max_payload,
        rate_bucket: RateBucket::Status,
        audit_log: false,
        allowed_while_reloading: true,
        allowed_while_degraded: true,
    };

    let auth_read = |max_payload: usize, bucket: RateBucket| MethodPolicy {
        class: MethodClass::AuthenticatedRead,
        max_payload_bytes: max_payload,
        rate_bucket: bucket,
        audit_log: false,
        allowed_while_reloading: true,
        allowed_while_degraded: true,
    };

    let auth_action = |max_payload: usize, bucket: RateBucket, audit: bool| MethodPolicy {
        class: MethodClass::AuthenticatedAction,
        max_payload_bytes: max_payload,
        rate_bucket: bucket,
        audit_log: audit,
        allowed_while_reloading: false,
        allowed_while_degraded: false,
    };

    let priv_mutation = |max_payload: usize, bucket: RateBucket| MethodPolicy {
        class: MethodClass::PrivilegedMutation,
        max_payload_bytes: max_payload,
        rate_bucket: bucket,
        audit_log: true,
        allowed_while_reloading: false,
        allowed_while_degraded: false,
    };

    let dangerous = |max_payload: usize, bucket: RateBucket| MethodPolicy {
        class: MethodClass::DangerousOperation,
        max_payload_bytes: max_payload,
        rate_bucket: bucket,
        audit_log: true,
        allowed_while_reloading: false,
        allowed_while_degraded: false,
    };

    // ── Public status (no auth) ────────────────────────
    m.insert("health", pub_status(512));
    m.insert("engine.status", pub_status(512));
    m.insert("scan.status", pub_status(512));
    // Scanner-B Finding 2/3: previously PublicStatus — leaked watched_roots
    // and current_target to any unauth local caller (oracle for "where the
    // scanner isn't looking"). Now auth-gated.
    m.insert("watcher.status", auth_read(512, RateBucket::Status));
    // Web protection. AuthenticatedRead, not PublicStatus: the response
    // names the machine's upstream DNS servers and the loaded rule count,
    // which is network topology an unauthenticated local caller should not
    // get for free.
    m.insert("webprotection.status", auth_read(512, RateBucket::Status));
    m.insert("idle_scanner.status", auth_read(512, RateBucket::Status));
    m.insert("update.status", pub_status(512));
    m.insert("argus.version", pub_status(512));
    m.insert("security.challenge", pub_status(1024));

    // ── Authenticated reads ────────────────────────────
    m.insert("scan.history", auth_read(1024, RateBucket::Status));
    m.insert("activity.list", auth_read(1024, RateBucket::Status));
    m.insert("stats.runtime", auth_read(1024, RateBucket::Status));
    m.insert("runtime.status", auth_read(1024, RateBucket::Status));
    m.insert("trust.status", auth_read(1024, RateBucket::Status));
    m.insert("detections.list", auth_read(4096, RateBucket::Status));
    m.insert(
        "quarantine.list",
        auth_read(1024, RateBucket::QuarantineOps),
    );
    m.insert("sources.status", auth_read(1024, RateBucket::Status));
    m.insert("sources.list", auth_read(1024, RateBucket::Status));
    m.insert("argus.packs", auth_read(1024, RateBucket::Status));
    m.insert("argus.verdicts", auth_read(4096, RateBucket::Status));
    m.insert(
        "memory.list_processes",
        auth_read(1024, RateBucket::MemoryScan),
    );
    m.insert("settings.get", auth_read(512, RateBucket::Status));
    // v0.1.9 Phase 4 (audit MED-8): GUI pushes fullscreen verdict every
    // ~5s. Small payload (one bool), Status bucket is fine (300/min).
    m.insert(
        "system.fullscreen_report",
        auth_action(256, RateBucket::Status, false),
    );
    // v0.1.8 FullConfig surface — larger payload than settings.get because
    // the response includes every TOML knob, but still a read-only listing.
    m.insert("settings.get_full", auth_read(16384, RateBucket::Status));
    m.insert("settings.get_defaults", auth_read(8192, RateBucket::Status));
    m.insert(
        "settings.restart_requirements",
        auth_read(8192, RateBucket::Status),
    );
    m.insert("dev.status", auth_read(512, RateBucket::Status));

    // ── Authenticated actions ──────────────────────────
    m.insert(
        "scan.start",
        auth_action(4096, RateBucket::ScanControl, true),
    );
    m.insert(
        "scan.cancel",
        auth_action(512, RateBucket::ScanControl, true),
    );
    // Scanner-B Finding 4: update.start was pub_status (no audit, allowed
    // while reloading, Status bucket = 120/min). An auth'd-but-malicious
    // caller could stack engine reloads back-to-back to extend the scan-blind
    // window indefinitely. Now auth_action with ScanControl bucket (10/min,
    // burst 3), audit_log=true, allowed_while_reloading=false.
    m.insert(
        "update.start",
        auth_action(1024, RateBucket::ScanControl, true),
    );
    // Scanner-B Finding 5: activity.log was Unlimited + no audit. Attacker
    // with IPC secret could flood the DB or inject fake severity entries
    // impersonating internal categories ("security", "engine"). Now bounded
    // by DiagnosticsExport bucket (6/min, burst 2); handler restricts
    // severity to info|warning and prefixes user-supplied category with "gui:".
    m.insert(
        "activity.log",
        auth_action(4096, RateBucket::DiagnosticsExport, false),
    );
    m.insert(
        "argus.analyze",
        auth_action(8192, RateBucket::ScanControl, false),
    );
    // Adversary A3: argus.reload is the unfixed sibling of update.start /
    // engine.reload — it triggers a YARA reload + ARGUS trusted-cache wipe
    // (~seconds of degraded detection per call). Without challenge-token
    // gating an attacker who learned the IPC secret could chain
    // update.start + engine.reload + argus.reload to multiply the
    // reload-stacking budget. Now PrivilegedMutation, matching engine.reload.
    m.insert(
        "argus.reload",
        priv_mutation(1024, RateBucket::ScanControl),
    );
    m.insert(
        "runtime.scan_buffer",
        auth_action(1024 * 1024, RateBucket::MemoryScan, true),
    );
    // memory.scan_process: response includes ModuleInfo.base_address —
    // a cross-privilege ASLR layout disclosure when the caller is an
    // unelevated user process. Additionally gated by the v0.1.9 elevation
    // check (is_challengeable_method) in the dispatcher; auth alone (the
    // world-readable IPC secret) is not sufficient.
    m.insert(
        "memory.scan_process",
        auth_action(1024, RateBucket::MemoryScan, true),
    );
    // quarantine.add authenticates via a one-shot challenge token (issued
    // only to authenticated + elevated callers via security.challenge), NOT
    // via the `auth` param — its IPC envelope carries `token`, not `auth`.
    // Declared PrivilegedMutation so the dispatcher's central MethodClass
    // gate (which validates `auth` for Authenticated* classes) doesn't
    // reject the legitimate token-only flow. is_challengeable_method and
    // the v0.1.9 elevation gate already cover it.
    m.insert(
        "quarantine.add",
        priv_mutation(4096, RateBucket::QuarantineOps),
    );
    m.insert(
        "calibration.report_safe",
        auth_action(4096, RateBucket::QuarantineOps, true),
    );
    m.insert(
        "diagnostics.export",
        auth_action(1024, RateBucket::DiagnosticsExport, false),
    );
    // Developer-mode toggle: password-gated, local-only, low-harm (it enables a
    // perf dump, not an auth boundary). AuthenticatedAction + the ConfigMutation
    // bucket rate-limits password guessing of the unlock gate.
    m.insert(
        "dev.set_developer_mode",
        auth_action(1024, RateBucket::ConfigMutation, true),
    );
    // Benchmark: spins up the worker to scan a corpus (CPU/IO heavy). Gated to
    // developer mode in the handler; the DiagnosticsExport bucket throttles it.
    m.insert(
        "benchmark.run",
        auth_action(1024, RateBucket::DiagnosticsExport, false),
    );

    // ── Privileged mutations (challenge required) ──────
    m.insert(
        "settings.set",
        priv_mutation(16384, RateBucket::ConfigMutation),
    );
    // v0.1.8: full-config write. Larger payload (~30 KB worst case with full
    // exclusion/hash lists), same defence-in-depth as settings.set —
    // ConfigMutation rate bucket + challenge token gating + kill-vector pin
    // in the handler. NOTE: actually NEVER mutates critical fields itself;
    // it just refuses the request if any critical field differs from current.
    m.insert(
        "settings.set_full",
        priv_mutation(32768, RateBucket::ConfigMutation),
    );
    m.insert(
        "protection.set_critical",
        // v0.1.8 expansion: now accepts list fields (excluded_paths,
        // trusted_hashes, realtime_roots, etc.). Worst-case payload is 64
        // entries × ~256 bytes/entry = ~16 KB, plus envelope overhead.
        priv_mutation(32768, RateBucket::ConfigMutation),
    );
    m.insert(
        "protection.disable",
        priv_mutation(1024, RateBucket::ConfigMutation),
    );
    m.insert(
        "protection.enable",
        priv_mutation(1024, RateBucket::ConfigMutation),
    );
    m.insert(
        "sources.set",
        priv_mutation(4096, RateBucket::SourcesMutation),
    );
    m.insert(
        "sources.update",
        priv_mutation(1024, RateBucket::SourcesMutation),
    );
    m.insert(
        "sources.rollback",
        priv_mutation(1024, RateBucket::SourcesMutation),
    );
    m.insert(
        "engine.reload",
        priv_mutation(1024, RateBucket::ScanControl),
    );

    // ── Dangerous operations (challenge + irreversible) ─
    m.insert(
        "quarantine.restore",
        dangerous(1024, RateBucket::QuarantineOps),
    );
    m.insert(
        "quarantine.restore_as",
        dangerous(4096, RateBucket::QuarantineOps),
    );
    m.insert(
        "quarantine.delete",
        dangerous(1024, RateBucket::QuarantineOps),
    );

    m
}

/// Structured IPC error codes (application-layer).
#[allow(dead_code)]
pub mod ipc_errors {
    pub const RATE_LIMITED: i32 = -32020;
    pub const PAYLOAD_TOO_LARGE: i32 = -32021;
    pub const ENGINE_RELOADING: i32 = -32022;
    pub const DEGRADED_MODE: i32 = -32023;
    pub const CHALLENGE_REQUIRED: i32 = -32024;
    pub const UNAUTHORIZED: i32 = -32025;
    pub const METHOD_DISABLED: i32 = -32026;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_covers_all_methods() {
        let reg = method_registry();
        assert!(
            reg.len() >= 35,
            "expected at least 35 methods, got {}",
            reg.len()
        );
        assert!(reg.contains_key("health"));
        assert!(reg.contains_key("scan.start"));
        assert!(reg.contains_key("idle_scanner.status"));
        assert!(reg.contains_key("runtime.scan_buffer"));
        assert!(reg.contains_key("quarantine.delete"));
        assert!(reg.contains_key("sources.set"));
    }

    #[test]
    fn public_methods_no_auth() {
        let reg = method_registry();
        let health = &reg["health"];
        assert_eq!(health.class, MethodClass::PublicStatus);
        assert!(health.allowed_while_reloading);
        assert!(health.allowed_while_degraded);
    }

    #[test]
    fn dangerous_methods_audit_logged() {
        let reg = method_registry();
        for method in [
            "quarantine.restore",
            "quarantine.delete",
            "quarantine.restore_as",
        ] {
            let policy = &reg[method];
            assert_eq!(policy.class, MethodClass::DangerousOperation);
            assert!(policy.audit_log);
        }
    }

    /// A dispatch arm with NO registry entry is not a warning — it is a
    /// method that runs with no payload cap, no rate limit, no
    /// reload/degraded gate and outside the central auth phase, silently.
    /// `dispatch_sync` gates all of that behind `reg.get(method)`, so the
    /// registry entry IS the enforcement. This test is the only thing
    /// standing between "I added a handler" and that outcome.
    #[test]
    fn webprotection_status_is_registered_and_authenticated() {
        let reg = method_registry();
        let p = reg
            .get("webprotection.status")
            .expect("dispatch arm exists with no registry entry — see the doc above");
        // Read tier, not PublicStatus: the response names the machine's
        // upstream DNS servers and its loaded rule count.
        assert_eq!(p.class, MethodClass::AuthenticatedRead);
        assert_eq!(p.rate_bucket, RateBucket::Status);
        // A status poll must keep working while config reloads and while
        // the daemon is degraded — that is exactly when someone is asking
        // "is my DNS still going through this thing?".
        assert!(p.allowed_while_reloading);
        assert!(p.allowed_while_degraded);
    }

    #[test]
    fn dev_mode_methods_registered() {
        let reg = method_registry();
        // Status read: authenticated, allowed while reloading/degraded.
        let status = &reg["dev.status"];
        assert_eq!(status.class, MethodClass::AuthenticatedRead);
        assert!(status.allowed_while_reloading);
        // Toggle: authenticated action, audit-logged, rate-limited via
        // ConfigMutation to blunt password guessing.
        let toggle = &reg["dev.set_developer_mode"];
        assert_eq!(toggle.class, MethodClass::AuthenticatedAction);
        assert!(toggle.audit_log);
        assert_eq!(toggle.rate_bucket, RateBucket::ConfigMutation);
        // Benchmark: heavy, authenticated, throttled via DiagnosticsExport,
        // blocked while reloading.
        let bench = &reg["benchmark.run"];
        assert_eq!(bench.class, MethodClass::AuthenticatedAction);
        assert_eq!(bench.rate_bucket, RateBucket::DiagnosticsExport);
        assert!(!bench.allowed_while_reloading);
    }

    #[test]
    fn privileged_mutations_challenge_required() {
        let reg = method_registry();
        for method in ["settings.set", "sources.set", "protection.disable"] {
            let policy = &reg[method];
            assert!(matches!(policy.class, MethodClass::PrivilegedMutation));
        }
    }

    #[test]
    fn payload_limits_sane() {
        let reg = method_registry();
        assert!(reg["health"].max_payload_bytes <= 1024);
        assert!(reg["settings.set"].max_payload_bytes <= 32768);
        assert!(reg["diagnostics.export"].max_payload_bytes <= 4096);
    }

    #[test]
    fn rate_limiter_allows_burst() {
        let limiter = RateLimiter::new();
        // v0.1.12: per-principal burst for QuarantineOps is 4 (global
        // burst 5 minus the one reserved cold-start token); the global
        // burst of 5 is still reachable ACROSS two principals (see
        // global_ceiling_unchanged_across_many_principals for the
        // ScanControl equivalent).
        for _ in 0..4 {
            assert!(limiter.check(RateBucket::QuarantineOps, None).is_ok());
        }
    }

    #[test]
    fn rate_limiter_blocks_excess() {
        let limiter = RateLimiter::new();
        // Exhaust SourcesMutation bucket (burst=2).
        assert!(limiter.check(RateBucket::SourcesMutation, None).is_ok());
        assert!(limiter.check(RateBucket::SourcesMutation, None).is_ok());
        assert!(limiter.check(RateBucket::SourcesMutation, None).is_err());
    }

    #[test]
    fn rate_limiter_never_underflows() {
        let limiter = RateLimiter::new();
        assert!(limiter.check(RateBucket::SourcesMutation, None).is_ok());
        assert!(limiter.check(RateBucket::SourcesMutation, None).is_ok());
        for _ in 0..10 {
            assert!(limiter.check(RateBucket::SourcesMutation, None).is_err());
        }
        let bucket = limiter.buckets.get(&RateBucket::SourcesMutation).unwrap();
        assert_eq!(bucket.tokens.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rate_limiter_unlimited_never_blocks() {
        let limiter = RateLimiter::new();
        for _ in 0..100 {
            assert!(limiter.check(RateBucket::Unlimited, None).is_ok());
        }
    }

    #[test]
    fn rate_limiter_preserves_sub_token_remainder() {
        // v0.1.9 audit MED-12 regression test.
        //
        // Pre-fix: every refill that produced N whole tokens reset
        // `last_refill` to `Instant::now()`, discarding the fractional
        // elapsed time. For ConfigMutation (10/min = 1 token per 6s),
        // a probe at t=6.5s would mint 1 token and lose 0.5s of
        // progress — the next refill needed another full 6s instead
        // of 5.5s. Sustained effective rate drifted to ~half the
        // declared cap.
        //
        // Post-fix: `last_refill` advances by EXACTLY the time the
        // integer-truncated refill accounts for, so the unconsumed
        // fractional remainder rolls forward.
        //
        // White-box assertion: after a fake elapsed of 6.5s on a 10/min
        // bucket (6s per token), exactly 1 token should be added and
        // `last_refill` should be exactly 0.5s in the past — NOT
        // `now()`. We verify by reading the post-refill `last_refill`
        // and computing the remaining elapsed.
        let limiter = RateLimiter::new();
        let bucket = limiter.buckets.get(&RateBucket::ConfigMutation).unwrap();
        // Drain initial tokens so the first refill is observable.
        for _ in 0..10 {
            let _ = limiter.check(RateBucket::ConfigMutation, None);
        }
        // Set last_refill to 6.5s ago via the only mutable backdoor:
        // the lock guard.
        {
            let mut last = bucket.last_refill.lock().unwrap();
            *last = std::time::Instant::now() - std::time::Duration::from_millis(6_500);
        }
        // v0.1.12: the drain above also spent the per-principal
        // (unidentified) sub-bucket, which is checked FIRST — a probe
        // with a spent sub-bucket would be rejected before ever reaching
        // the global refill this test observes. Reset the principal
        // table so the probe gets a fresh sub-bucket; the global state
        // under test is untouched.
        limiter
            .principals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .clear();
        // Trigger a refill check.
        let _ = limiter.check(RateBucket::ConfigMutation, None);
        // After: should have minted 1 token (6.5s / 6s per token = 1
        // whole) and rolled last_refill forward by exactly 6s, leaving
        // ~0.5s of remainder.
        let last_after = *bucket.last_refill.lock().unwrap();
        let remainder = last_after.elapsed();
        // Allow generous slack for test-host scheduling jitter. The
        // critical property is `remainder > 0.2s` — pre-fix this would
        // be near-zero because last_refill was reset to now().
        assert!(
            remainder >= std::time::Duration::from_millis(200),
            "sub-token remainder lost: got {remainder:?}, expected ~500ms"
        );
        assert!(
            remainder <= std::time::Duration::from_millis(1500),
            "remainder unexpectedly large: got {remainder:?}, expected ~500ms"
        );
    }

    #[test]
    fn reloading_blocks_mutations() {
        let reg = method_registry();
        assert!(!reg["scan.start"].allowed_while_reloading);
        assert!(!reg["sources.set"].allowed_while_reloading);
        assert!(reg["health"].allowed_while_reloading);
        assert!(reg["scan.status"].allowed_while_reloading);
    }

    // ── v0.1.12 workstream K/L: per-principal starvation harness ─────
    //
    // These tests are the executable starvation demonstration for matrix
    // row C-5. They drive the REAL RateLimiter code path — the exact
    // `RateLimiter::check` call `dispatch_sync` makes for every request
    // (a full in-process daemon harness is impractical: AppState::new
    // spawns the PLM monitor, opens the trust-graph DB and reads vault
    // keys; the entire rate path is this one call, so exercising it
    // directly loses no fidelity). A live end-to-end probe against a
    // running daemon is scripts/probe-request-rate-fairness.ps1.

    fn sid(s: &str) -> ClientIdentity {
        ClientIdentity {
            sid: s.into(),
            session_id: 1,
            is_elevated: false,
            is_system: false,
            well_known_untrusted: false,
            image_path: None,
        }
    }

    /// White-box helper: backdate a principal's sub-bucket clock so the
    /// next check observes `ms` of refill, without sleeping.
    fn backdate_principal(
        limiter: &RateLimiter,
        bucket: RateBucket,
        id: Option<&ClientIdentity>,
        ms: u64,
    ) {
        let mut t = limiter.principals.lock().unwrap_or_else(|e| e.into_inner());
        let key = (bucket, PrincipalKey::from_identity(id));
        if let Some(b) = t.map.get_mut(&key) {
            b.last_refill -= std::time::Duration::from_millis(ms);
        }
    }

    /// White-box helper: backdate the GLOBAL bucket clock.
    fn backdate_global(limiter: &RateLimiter, bucket: RateBucket, ms: u64) {
        let state = limiter.buckets.get(&bucket).unwrap();
        let mut last = state.last_refill.lock().unwrap_or_else(|e| e.into_inner());
        *last -= std::time::Duration::from_millis(ms);
    }

    fn global_tokens(limiter: &RateLimiter, bucket: RateBucket) -> u64 {
        limiter
            .buckets
            .get(&bucket)
            .unwrap()
            .tokens
            .load(Ordering::Relaxed)
    }

    #[test]
    fn scancontrol_one_principal_cannot_starve_another() {
        // THE C-5 demonstration. Pre-v0.1.12 (global bucket only):
        // ScanControl = 10/min burst 3 shared by everyone — the flooder's
        // first 3 requests drained the ENTIRE global budget and a second
        // principal's scan.start was rejected with RATE_LIMITED. Post-fix:
        // the flooder's per-principal share is 5/min burst 2, one
        // cold-start global token is reserved, and the victim is served.
        let limiter = RateLimiter::new();
        let flooder = sid("S-1-5-21-1-2-3-1100");
        let victim = sid("S-1-5-21-1-2-3-1200");

        let mut accepted = 0;
        for _ in 0..20 {
            if limiter.check(RateBucket::ScanControl, Some(&flooder)).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(
            accepted, 2,
            "flooder must be capped at its per-principal burst (2), not the global burst (3)"
        );
        assert_eq!(
            global_tokens(&limiter, RateBucket::ScanControl),
            1,
            "one cold-start global token is reserved for other principals"
        );
        // The victim's first scan.start goes through even while the
        // flooder is mid-flood.
        assert!(
            limiter.check(RateBucket::ScanControl, Some(&victim)).is_ok(),
            "second principal must be served while the first is capped"
        );
    }

    #[test]
    fn two_principals_split_steady_state() {
        // Steady-state fairness: over successive 12s windows (ScanControl
        // refills 2 global + 1 per-principal token per window), the
        // flooder can never take more than its 5/min share and the victim
        // gets served every window.
        let limiter = RateLimiter::new();
        let flooder = sid("S-1-5-21-1-2-3-1100");
        let victim = sid("S-1-5-21-1-2-3-1200");
        // Burn the cold-start bursts first.
        while limiter.check(RateBucket::ScanControl, Some(&flooder)).is_ok() {}
        while limiter.check(RateBucket::ScanControl, Some(&victim)).is_ok() {}

        for round in 0..3 {
            backdate_principal(&limiter, RateBucket::ScanControl, Some(&flooder), 12_000);
            backdate_principal(&limiter, RateBucket::ScanControl, Some(&victim), 12_000);
            backdate_global(&limiter, RateBucket::ScanControl, 12_000);
            // Flooder gets exactly its 1-token refill share, no more.
            assert!(
                limiter.check(RateBucket::ScanControl, Some(&flooder)).is_ok(),
                "round {round}: flooder share"
            );
            assert!(
                limiter.check(RateBucket::ScanControl, Some(&flooder)).is_err(),
                "round {round}: flooder beyond share must be rejected"
            );
            assert!(
                limiter.check(RateBucket::ScanControl, Some(&victim)).is_ok(),
                "round {round}: victim must be served every window"
            );
        }
    }

    #[test]
    fn rejected_requests_consume_no_tokens() {
        // A request rejected by the per-principal layer must not consume
        // a GLOBAL token (rejected requests are free for everyone else's
        // budget), and must not consume a per-principal token either.
        let limiter = RateLimiter::new();
        let flooder = sid("S-1-5-21-1-2-3-1100");
        while limiter.check(RateBucket::ScanControl, Some(&flooder)).is_ok() {}
        let before = global_tokens(&limiter, RateBucket::ScanControl);
        for _ in 0..50 {
            assert!(limiter.check(RateBucket::ScanControl, Some(&flooder)).is_err());
        }
        assert_eq!(
            global_tokens(&limiter, RateBucket::ScanControl),
            before,
            "50 rejected requests must not move the global token count"
        );
    }

    #[test]
    fn retry_after_reflects_per_principal_rate() {
        let limiter = RateLimiter::new();
        let flooder = sid("S-1-5-21-1-2-3-1100");
        while limiter.check(RateBucket::ScanControl, Some(&flooder)).is_ok() {}
        // ScanControl per-principal = 5/min → one token per 12s.
        assert_eq!(
            limiter.check(RateBucket::ScanControl, Some(&flooder)),
            Err(12)
        );
    }

    #[test]
    fn global_ceiling_unchanged_across_many_principals() {
        // The global bucket is still the hard ceiling: 10 DISTINCT
        // principals each with a fresh per-principal burst of 2 cannot
        // collectively exceed the global ScanControl burst (3) in one
        // instant.
        let limiter = RateLimiter::new();
        let mut accepted = 0;
        for i in 0..10 {
            let p = sid(&format!("S-1-5-21-1-2-3-{}", 2000 + i));
            if limiter.check(RateBucket::ScanControl, Some(&p)).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 3, "global burst (3) remains the ceiling");
    }

    #[test]
    fn unidentified_bucket_is_shared_and_conservative() {
        // Unresolved identities (fail-open, non-Windows) all land in ONE
        // shared bucket with the per-principal numbers — never an
        // unbudgeted bypass, never per-PID (see fairness.rs rationale).
        let limiter = RateLimiter::new();
        assert!(limiter.check(RateBucket::ScanControl, None).is_ok());
        assert!(limiter.check(RateBucket::ScanControl, None).is_ok());
        assert!(
            limiter.check(RateBucket::ScanControl, None).is_err(),
            "the shared unidentified bucket must be capped at the per-principal burst"
        );
        // Identified principals are unaffected by an exhausted
        // unidentified bucket.
        let alice = sid("S-1-5-21-1-2-3-1001");
        assert!(limiter.check(RateBucket::ScanControl, Some(&alice)).is_ok());
    }

    #[test]
    fn principal_state_bounded_with_lru_eviction() {
        // SID-spray bound: inserting more distinct principals than
        // MAX_PRINCIPAL_ENTRIES must not grow the map past the cap; the
        // least-recently-used entry is evicted (and simply starts fresh
        // if it ever returns — bounded memory beats exact accounting).
        let limiter = RateLimiter::new();
        for i in 0..(MAX_PRINCIPAL_ENTRIES + 20) {
            let p = sid(&format!("S-1-5-21-9-9-9-{}", i));
            assert!(limiter.check(RateBucket::ScanControl, Some(&p)).is_ok() || i >= 3);
            // ^ only the first 3 distinct principals get a token (global
            // burst); the rest are rejected but still tracked.
        }
        let len = limiter
            .principals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len();
        assert!(
            len <= MAX_PRINCIPAL_ENTRIES,
            "principal map must stay bounded: {len} > {MAX_PRINCIPAL_ENTRIES}"
        );
    }

    #[test]
    fn per_principal_does_not_tighten_other_buckets() {
        // A principal capped on ScanControl keeps full budgets elsewhere —
        // buckets are independent per (bucket, principal) pair.
        let limiter = RateLimiter::new();
        let p = sid("S-1-5-21-1-2-3-1001");
        while limiter.check(RateBucket::ScanControl, Some(&p)).is_ok() {}
        assert!(limiter.check(RateBucket::ScanControl, Some(&p)).is_err());
        for _ in 0..4 {
            assert!(limiter.check(RateBucket::QuarantineOps, Some(&p)).is_ok());
        }
    }

    #[test]
    fn status_per_principal_fits_dashboard_baseline() {
        // Sizing guard: the dashboard polls ~108 Status requests/min from
        // ONE user SID. The per-principal Status budget (150/min, burst
        // 40) must absorb that steady rate; simulate 108 requests after
        // backdating a full minute and require all to pass.
        let limiter = RateLimiter::new();
        let gui = sid("S-1-5-21-1-2-3-1001");
        while limiter.check(RateBucket::Status, Some(&gui)).is_ok() {}
        backdate_principal(&limiter, RateBucket::Status, Some(&gui), 60_000);
        backdate_global(&limiter, RateBucket::Status, 60_000);
        // Per-principal refill for 60s = 150 tokens (burst cap 40... the
        // burst cap is the ACCUMULATION ceiling, not the rate ceiling, so
        // backdating 60s only mints up to burst). Consume in waves with
        // intermediate backdates to model continuous traffic.
        let mut ok = 0;
        for wave in 0..3 {
            if wave > 0 {
                backdate_principal(&limiter, RateBucket::Status, Some(&gui), 20_000);
                backdate_global(&limiter, RateBucket::Status, 20_000);
            }
            for _ in 0..36 {
                if limiter.check(RateBucket::Status, Some(&gui)).is_ok() {
                    ok += 1;
                }
            }
        }
        assert_eq!(ok, 108, "dashboard's 108/min from one SID must fit");
    }
}

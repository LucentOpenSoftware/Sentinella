//! IPC Control Plane Policy — method registry, rate limiting, payload caps.
//!
//! Every IPC method has a declared class, auth requirements, payload limit,
//! and rate limit bucket. The dispatcher checks policy BEFORE dispatching.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

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
}

impl BucketConfig {
    const fn new(max_per_minute: u32, burst: u32) -> Self {
        Self {
            max_per_minute,
            burst,
        }
    }
}

fn bucket_config(bucket: RateBucket) -> BucketConfig {
    match bucket {
        // v0.1.8: bumped 120/20 -> 300/40 to absorb v0.1.8 Settings page
        // bursts (3 extra reads on every Settings open: settings.get_full,
        // settings.get_defaults, settings.restart_requirements). The
        // dashboard already polls 9 status endpoints every 5s (~108/min
        // steady), so the old 120/min cap with 2/sec refill gave only a
        // 12/min cushion for everything else. New 300/min cushion is
        // 192/min above dashboard baseline, plenty for Settings + ad-hoc
        // user-driven status queries from other pages.
        RateBucket::Status => BucketConfig::new(300, 40),
        RateBucket::ScanControl => BucketConfig::new(10, 3),
        RateBucket::QuarantineOps => BucketConfig::new(30, 5),
        RateBucket::ConfigMutation => BucketConfig::new(10, 2),
        RateBucket::DiagnosticsExport => BucketConfig::new(6, 2),
        RateBucket::SourcesMutation => BucketConfig::new(5, 2),
        RateBucket::MemoryScan => BucketConfig::new(10, 2),
        RateBucket::Unlimited => BucketConfig::new(u32::MAX, u32::MAX),
    }
}

/// Per-bucket token-bucket rate limiter.
pub struct RateLimiter {
    buckets: HashMap<RateBucket, BucketState>,
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
        Self { buckets }
    }

    /// Try to consume one token. Returns Ok(()) or Err with retry_after_secs.
    pub fn check(&self, bucket: RateBucket) -> Result<(), u32> {
        if bucket == RateBucket::Unlimited {
            return Ok(());
        }
        let state = match self.buckets.get(&bucket) {
            Some(s) => s,
            None => return Ok(()),
        };

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
    m.insert(
        "memory.scan_process",
        auth_action(1024, RateBucket::MemoryScan, true),
    );
    m.insert(
        "quarantine.add",
        auth_action(4096, RateBucket::QuarantineOps, true),
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
        for _ in 0..5 {
            assert!(limiter.check(RateBucket::QuarantineOps).is_ok());
        }
    }

    #[test]
    fn rate_limiter_blocks_excess() {
        let limiter = RateLimiter::new();
        // Exhaust SourcesMutation bucket (burst=2).
        assert!(limiter.check(RateBucket::SourcesMutation).is_ok());
        assert!(limiter.check(RateBucket::SourcesMutation).is_ok());
        assert!(limiter.check(RateBucket::SourcesMutation).is_err());
    }

    #[test]
    fn rate_limiter_never_underflows() {
        let limiter = RateLimiter::new();
        assert!(limiter.check(RateBucket::SourcesMutation).is_ok());
        assert!(limiter.check(RateBucket::SourcesMutation).is_ok());
        for _ in 0..10 {
            assert!(limiter.check(RateBucket::SourcesMutation).is_err());
        }
        let bucket = limiter.buckets.get(&RateBucket::SourcesMutation).unwrap();
        assert_eq!(bucket.tokens.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rate_limiter_unlimited_never_blocks() {
        let limiter = RateLimiter::new();
        for _ in 0..100 {
            assert!(limiter.check(RateBucket::Unlimited).is_ok());
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
            let _ = limiter.check(RateBucket::ConfigMutation);
        }
        // Set last_refill to 6.5s ago via the only mutable backdoor:
        // the lock guard.
        {
            let mut last = bucket.last_refill.lock().unwrap();
            *last = std::time::Instant::now() - std::time::Duration::from_millis(6_500);
        }
        // Trigger a refill check.
        let _ = limiter.check(RateBucket::ConfigMutation);
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
}

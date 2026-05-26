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
        RateBucket::Status => BucketConfig::new(120, 20),
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
        {
            let mut last = state.last_refill.lock().unwrap_or_else(|e| e.into_inner());
            let elapsed = last.elapsed();
            let refill = (elapsed.as_secs_f64() * state.config.max_per_minute as f64 / 60.0) as u64;
            if refill > 0 {
                let current = state.tokens.load(Ordering::Relaxed);
                let new_val = current
                    .saturating_add(refill)
                    .min(state.config.burst as u64);
                state.tokens.store(new_val, Ordering::Relaxed);
                *last = Instant::now();
            }
        }

        // Try to consume one token without underflowing under concurrent callers.
        loop {
            let current = state.tokens.load(Ordering::Relaxed);
            if current == 0 {
                let retry_secs = 60 / state.config.max_per_minute.max(1);
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
    m.insert("watcher.status", pub_status(512));
    m.insert("idle_scanner.status", pub_status(512));
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

    // ── Authenticated actions ──────────────────────────
    m.insert(
        "scan.start",
        auth_action(4096, RateBucket::ScanControl, true),
    );
    m.insert(
        "scan.cancel",
        auth_action(512, RateBucket::ScanControl, true),
    );
    m.insert(
        "update.start",
        auth_action(1024, RateBucket::ScanControl, true),
    );
    m.insert(
        "activity.log",
        auth_action(4096, RateBucket::Unlimited, false),
    );
    m.insert(
        "argus.analyze",
        auth_action(8192, RateBucket::ScanControl, false),
    );
    m.insert(
        "argus.reload",
        auth_action(1024, RateBucket::ScanControl, true),
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

    // ── Privileged mutations (challenge required) ──────
    m.insert(
        "settings.set",
        priv_mutation(16384, RateBucket::ConfigMutation),
    );
    m.insert(
        "protection.set_critical",
        priv_mutation(4096, RateBucket::ConfigMutation),
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
    fn reloading_blocks_mutations() {
        let reg = method_registry();
        assert!(!reg["scan.start"].allowed_while_reloading);
        assert!(!reg["sources.set"].allowed_while_reloading);
        assert!(reg["health"].allowed_while_reloading);
        assert!(reg["scan.status"].allowed_while_reloading);
    }
}

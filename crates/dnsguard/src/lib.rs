//! # dnsguard
//!
//! Local filtering DNS proxy — the testable heart of Sentinella's web
//! protection feature (see `docs/WEB_PROTECTION_DESIGN.md`).
//!
//! Architecture: the Windows DNS Client is pointed at this proxy via an NRPT
//! catch-all rule; every query is parsed ([`wire`]), decided ([`filter`]),
//! and either answered locally (NXDOMAIN / zero-IP for blocked names) or
//! forwarded to the system-configured upstream resolvers with a
//! TTL-respecting cache ([`proxy`]).
//!
//! Design invariants enforced across the crate:
//! - no `unsafe`, no DNS-library dependency — the wire codec is hand-rolled
//!   and every function is total over arbitrary byte input;
//! - everything is bounded (blocklist line cap, in-flight semaphore, cache
//!   capacity, upstream timeouts);
//! - fail-safe: malformed input gets FORMERR, dead upstreams get SERVFAIL,
//!   never a hang and never a panic.

pub mod filter;
pub mod proxy;
pub mod wire;

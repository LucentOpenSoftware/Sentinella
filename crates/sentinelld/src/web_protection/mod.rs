//! Web protection: the sentinelld side of the `dnsguard` filtering DNS
//! proxy.
//!
//! # The invariant this module exists to keep
//!
//! An NRPT rule points the whole machine's DNS at our listener, lives in
//! the registry, and SURVIVES REBOOTS. So the dangerous state is not "the
//! proxy is broken" — it is "the rule is installed and the proxy is not
//! answering", which is a machine with no name resolution at all, across
//! every subsequent boot, for a user who cannot search for the fix because
//! search does not resolve.
//!
//! Therefore: **the rule may exist only while the daemon is PROVEN
//! healthy.** The daemon adds it after a passing self-test; a boot-time
//! reconciler, running out of process and independent of this service,
//! removes it whenever that precondition is not observably true. Under any
//! uncertainty the system degrades to "no filtering", never to "no DNS".
//!
//! # Two states that are not the same state
//!
//! - `config.web_protection.enabled` — USER INTENT. Persisted in TOML.
//! - `status.nrpt_installed` — A FACT ABOUT THE SYSTEM. Read from the
//!   registry, never inferred from intent.
//!
//! They come apart in normal operation: while the daemon starts, after a
//! failed self-test, after a crash, during an upgrade, during an MSI
//! rollback. Every surface that reports on web protection reports BOTH,
//! and nothing derives one from the other.
//!
//! # What is here, and what is deliberately not
//!
//! This commit is the daemon side ONLY. It contains no NRPT code, creates
//! no scheduled task, and writes no registry keys — so nothing it can do,
//! including failing completely, can cost the machine its DNS. Enabling it
//! starts a proxy on `127.0.0.1:53` that nothing points at; you reach it by
//! asking it directly (`nslookup name 127.0.0.1`).
//!
//! The rule itself cannot land until its remover exists. The sequence is:
//! (A) this commit; (B) the installer registers the reconciler task and
//! ships the reconciler binary; (C) the daemon installs and removes rules,
//! with the task's existence as a hard precondition. No intermediate state
//! of that sequence can leave a live rule with no remover.

pub mod config;
pub mod rule;
pub mod service;
pub mod status;
pub mod upstreams;

pub use config::WebProtectionConfig;
pub use service::{WebProtection, WebProtectionHandle};
#[allow(unused_imports)] // consumed by the IPC status surface later in this commit
pub use status::WebProtectionStatus;

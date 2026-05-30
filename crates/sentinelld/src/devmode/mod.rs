//! Developer mode (v0.1.6) — a local, per-machine aid for the author to assess
//! how Sentinella behaves on different hardware.
//!
//! **Local-only.** Nothing here talks to the network, aggregates across users,
//! or leaves the machine. The only artifact is a bounded text file in the AV
//! diagnostics dir. Developer mode is gated behind a password (see
//! `config::DeveloperConfig`) and is OFF by default.

pub mod telemetry;

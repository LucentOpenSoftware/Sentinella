# Sentinella Continuous Improvement Roadmap

**Date**: May 2026  
**Status**: Active — Wave 1 in progress

---

## Waves

| # | Name | Focus | Status |
|---|---|---|---|
| 1 | Performance Observability | Scan timing, strategy counts, diagnostics | **Done** |
| 2 | IPC Resilience | Backpressure, queue, health metrics | **Done** |
| 3 | FP Field Regression | Confidence calibration, installer tests | **Done** (validated) |
| 4 | Quarantine Safety | Vault integrity, restore safety | **Done** |
| 5 | Idle/Watcher Tuning | Resource awareness, startup scan | **Done** (prior waves) |
| 6 | Release Hardening | Installer, staging, metadata, beta prep | **Done** |
| 7 | Field Feedback Loop | Controlled deployment, issue triage | **Ready to begin** |
| 8 | Startup UX | True pre-UI splash window, tray-first prep | **Done** |
| 9 | Scan Performance | Multi-threaded validation, strategy enforcement | **Done** |
| 10 | Performance Benchmarks | Benchmark docs, target metrics | **Done** |

## Principles

- Stability > features
- Precision > detection quantity
- Explainability > fear
- Local-first, deterministic, auditable
- No telemetry, no cloud, no MITM, no kernel driver yet
- Every wave validates: `cargo check && cargo test && tsc && pnpm build`

## Hard Stop Conditions

- Build warnings appear
- Tests fail
- Daemon disconnect regression
- Mainstream installers quarantined
- Forbidden scope touched

## Success Definition

A user can install Sentinella, leave it running, understand what it does,
recover from quarantines, and trust it won't break normal software while
catching real threats.

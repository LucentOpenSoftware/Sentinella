# Sentinella Deep Audit — July 2026 (post-v0.1.11)

A full-tree audit of the Sentinella workspace followed by a verified fix
pass. Conducted after the "final" v0.1.11 release, which had itself
shipped a four-front internal audit; this pass went deeper and wider.

## Scope and method

- **Coverage:** all 11 workspace crates (~65k LOC of first-party Rust),
  the Tauri GUI (`gui/src-tauri` + `gui/src` frontend), and the vendored
  `clamav-main/` tree (determined to be an unmodified upstream ClamAV
  source snapshot used for building `libclamav`; stock upstream code was
  not re-audited, only Sentinella's integration glue).
- **Method:** 17 parallel read-only audit units, each instructed to read
  its files end-to-end and verify every finding against real callers
  before reporting. Every reported finding was then *re-verified* by the
  fixing agent against the live code before any change was applied —
  findings that could not be confirmed were left untouched.
- **Raw artifacts:** per-unit audit reports and per-unit fix reports are
  preserved in `.audit/` (untracked working directory).

## Totals

| Severity | Reported | Fixed | Refuted | Deferred / cross-cutting remainder |
|----------|----------|-------|---------|------------------------------------|
| High     | 13       | 13    | 0       | —                                  |
| Medium   | 40       | ~34   | 1       | remainder noted below              |
| Low      | 90       | ~60   | 1       | rest judged not-trivially-safe     |

All 13 high-severity findings were confirmed real and fixed. ~75 fixes
landed in total (including low-severity and enhancement items), plus a
9-item cross-cutting sweep into `sentinelld`'s IPC core.

## High-severity findings — all fixed

1. **`argus.analyze` UNC/device-path filter bypass.** The IPC handler
   checked only `path.exists()` before making the SYSTEM daemon stat and
   read attacker-controlled paths (`\\host\share`, `\\.\`,
   `\globalroot\`, …) — machine-account NTLM-relay material, since the
   IPC secret is world-readable by design. The `scan.start` R8-LETHAL
   filter was factored into a shared `validate_local_scan_path()` now
   applied by both handlers. Regression tests added.
2. **Fail-open pipe-identity resolution (dead-PID race) bypassed the
   v0.1.9 elevation gate.** `resolve_client` now distinguishes
   `Unresolved` (transient API quirk — still fail-open) from
   `ClientGone` (PID obtained but process/token unopenable — the exact
   signature of a short-lived helper + `DuplicateHandle` + exit), which
   now fails **closed**. Pure `decide_pipe_auth` + unit tests.
3. **Sandbox network containment covered only the sample's root exe.**
   Child processes spawned by the sample inherited no firewall block.
   `sandboxd` now sweeps the process tree every 500 ms during detonation
   and applies the containment rule to descendants.
4. **Sandbox fail-open to an unrestricted SYSTEM token** when
   restricted-token creation failed. All three fallback paths in
   `restricted.rs` now fail closed — a sample never runs with more
   privilege than intended because a hardening step errored.
5. **`clamavd` called `cl_scanfile` through a wrong 6-arg FFI signature
   with a NULL `scanoptions`.** Verified against the vendored
   `clamav.h`: corrected to the real 5-arg signature, added a
   `#[repr(C)] ClScanOptions`, and passed real options (heuristics +
   default parse flags, mirroring the in-process path). Also fixed
   `cl_load` dboptions (`0x1F` → `CL_DB_STDOPT 0x200A`) and the
   `scanned` out-param type (`c_ulong`, not `u64` — LLP64).
6. **CLI never attached `auth` to five subcommands** (`scan`,
   `quick-scan`, `quarantine-list`, `activity`, `config`) — all broken
   against the fail-closed daemon. Added `with_ipc_auth()` plus a
   fallback read of the world-readable secret file, matching the GUI.
7. **Scan-cache content fingerprint covered only the first 64 KB.** A
   same-size, same-mtime overwrite past 64 KB kept a stale "clean"
   verdict. The fingerprint now streams the full file through SHA-256.
8. **Fresh-database schema migration v4 always failed**, permanently
   wedging the migration chain (base `SCHEMA` already contained the
   columns v4 tried to `ALTER TABLE ... ADD`). Migration is now guarded
   by `column_exists()`; fresh installs reach the correct version.
9. **Leaked stuck worker's epilogue blinded the watchdog** to the
   replacement worker's next hang (orchestrator disarm writes).
10. **Idle scanner targeted the LocalSystem profile**, not real user
    directories — the feature was silently near-useless in the shipped
    service configuration. It now enumerates real user profiles.
11. **Profile budgets never reached the engine** — every production scan
    ran with the 60 s `manual()` budget; the budget-aware engine APIs
    were dead code. Wired end-to-end: watcher, idle scanner, folder
    worker (uses `scan_profile.budget`), startup scan, and the
    `argus.analyze` IPC path.
12. **Reputation trust discount from an unverified certificate
    subject** — forgeable with a self-signed cert. The discount now
    requires a successfully Authenticode-verified signer match.
13. **PDF layer unbounded reference-following recursion** in three
    helpers — cyclic PDF object graphs could overflow the scanner's
    stack. Bounded with `MAX_REF_FOLLOW_DEPTH = 8` and depth tracking.

## Cross-cutting sweep (post-swarm, sentinelld IPC core)

- **Central `MethodClass` enforcement** in `dispatch_sync`:
  `AuthenticatedRead`/`AuthenticatedAction` methods (`scan.history`,
  `stats.runtime`, `argus.packs`, `sources.status`, `sources.list`) are
  now auth-checked before dispatch. GUI and CLI call sites updated to
  attach auth; `quarantine.add` reclassified to `PrivilegedMutation` so
  the challenge-token flow is unaffected.
- **`sources.update` single-flight** + moved off the tokio worker
  (`spawn_blocking`); concurrent requests get a clean "busy" response.
- **Restore-suppression lifecycle**: suppression marks are removed when
  a restore fails, and mark/lookup keys are canonicalized identically
  (fixes the `restore_as` key mismatch).
- **Quarantine DB error propagation**: `insert_quarantine_item` /
  `get_quarantine_item` return `Result`; a DB failure during quarantine
  now removes the orphaned vault file and surfaces the error.
- **`memory.scan_process` hardened**: added to the elevation gate
  (cross-privilege ASLR-layout disclosure via `ModuleInfo.base_address`)
  and moved to `spawn_blocking`. **User-visible change: the GUI memory
  scan now requires an elevated GUI.**
- **Scan-cache signature fingerprint** synced at daemon startup so
  signature updates invalidate stale cache entries.
- **Read-failure verdicts no longer recorded as Clean** (sharing
  violations etc. produce an error outcome and are never cached).
- **Trust-graph signer observation** wired into the three clean-scan
  observation sites; drift events logged.

## Other notable fixes (medium/low, by area)

- **Engine/scan**: update-pipeline manifest soft-fail removed (hard fail
  on fetch/verify error); `set_var` race on the multithreaded reload
  path eliminated (cache path passed via FFI); name/path-based scan
  skips hardened against canonical-path spoofing; `.tmp`/recycle-bin
  skips scoped correctly.
- **Quarantine/DB**: FK constraint no longer defeats `scans` retention;
  quarantine-source vs restore-path blocklist reconciled.
- **Watcher/idle/memory**: watcher thread no longer blocks ~30 s on
  memory scans; budget-partial quarantine TOCTOU revalidation restored;
  budget-partial results no longer cached as clean; idle scanner honors
  restore suppression and survives thread-spawn failure.
- **argus engine**: timeout evidence now reported in `ScanTiming`;
  `analyze_buffer` performs the IOC lookup; cancellation flag consulted
  at budget gates; `apply_cap` no longer rounds above the cap.
- **argus layers**: LZW expansion bounded; cumulative PDF decompression
  budget added; Authenticode tampered-signature classification fixed;
  trusted-publisher substring matching replaced with word-boundary
  matching; script layer decodes UTF-16; Zone.Identifier ADS read
  capped; `&CMSG_SIGNER_INFO` misalignment UB fixed; YARA rule-dir
  recursion depth-capped.
- **sandboxd/etw_probe**: `netsh program=` quoting; low-integrity
  samples can write their sandbox dir; job-object process-count limit;
  `EVENT_TRACE_PROPERTIES` alignment UB fixed; SHA-256 computed on the
  actually-detonated bytes.
- **PLM/WeedHack**: filter dedup slot no longer consumed before the
  signer check; stale callback-context pointers on `OpenTraceW` failure;
  snapshot mode refreshes tracked PIDs (PID-reuse guard).
- **Runtime integrity / trust**: binary-integrity TOFU reset via
  manifest delete fixed; corrupt `integrity.json` no longer silently
  resets the gate; zero-key trust-integrity fail-open replaced with a
  per-boot random secret; `DefaultHasher` MAC replaced with truncated
  HMAC-SHA256.
- **GUI**: shared blocking runtime instead of per-call tokio runtimes;
  dead updater "Restart" button removed; `--elevated-restart`
  single-instance bypass now requires elevation; ShellExecuteW arg
  quoting hardened.
- **Enhancements applied**: CLI reads the secret file directly; argusd
  error JSON emits `"verdict": "error"`; symlink-safe, capped file
  collection in `sentinella-argus`; exe-dir-first rules/IOC resolution;
  dev-console prefers the installed `argusd.exe` when elevated.

## Deferred (deliberately not done)

- Shared libclamav-bindings crate for `sentinelld`/`clamavd`
  (architectural).
- ~~`clamavd self-test` subcommand~~ — **no longer deferred: delivered in
  round 2** as `clamavd --self-test` (EICAR round-trip). See below.
- Update-manifest signing (trust anchor is currently hard-fail verify;
  signing is a release-infrastructure decision).
- `check_chain_drift` wiring (needs PLM chain-key plumbing that doesn't
  exist at scan sites).
- `EventCorrelator` consumer wiring (record-only today; burst detection
  is a feature, not a bug).
- Authenticode revocation checking (documented as a deliberate policy;
  comment added).
- ~205 pre-existing clippy *style* lints (150 collapsible-`if`, etc.) —
  cosmetic; left to avoid churn. Zero clippy errors.

## Verification

- `cargo check --workspace`: clean (0 errors, 0 warnings after the pass;
  three pre-existing warnings were also cleaned up).
- `cargo clippy --workspace --all-targets`: no errors; style lints only.
- `cargo test --workspace`: all suites green (sentinelld 476 + 198 +
  10 + 8, argus and remaining crates included; see session log). New
  regression tests were added for the UNC filter, pipe-auth fail-closed
  decision, cancel transitions, PDF recursion bound, and migration
  guard, among others.
- `cargo check --manifest-path gui/src-tauri/Cargo.toml`: clean.
- Frontend: `tsc --noEmit` clean (per GUI fix agent).

## Round 2 — residual sweep (same day)

A second, smaller pass (3 agents) re-reviewed the round-1 diff itself for
introduced regressions and mined the round-1 reports for unverified
suspicions and skipped items.

**Regressions introduced by round 1, found and fixed:**

- `config::validate()` clamped the idle-delay floor to ≥1 ms *before* the
  min/max swap, so a `(0, 0)` pair ended at `min=0` — defeating the
  tight-loop floor. Reordered (swap → clamp → raise); regression test.
- `is_known_installer`: dropping the caller's `is_pe &&` gate widened
  pure-substring installer heuristics (NSIS/Inno/Go/Rust markers) to
  **all** file types — a false-negative discount vector and ~20 wasted
  full-buffer scans per non-PE file. Gate moved inside the helper; OLE2
  restricted to the MSI branch; tests corrected and extended.

**Residual findings fixed:**

- `ipc_secret` creation race: the losing daemon could read the winner's
  not-yet-written empty file and truncate-write its own secret, locking
  the GUI out. Read now retries before falling back.
- `quarantine.list` response could exceed the clients' 1 MiB frame cap —
  capped at the 1000 newest rows (retention sweep still uses the full
  DB-side list).
- `vault_ok` heuristic replaced with `vault_blob_plausible()` magic +
  per-format minimum-length check.
- Idle scanner re-checks `is_reparse_point` at scan time (closes a
  symlink-swap read oracle running as SYSTEM).
- `clamavd --self-test` added (EICAR round-trip) — first end-to-end
  coverage for subprocess mode's FFI contract.
- dev-console password fields scrubbed on clear; stale `Settings` docs
  in ipc-proto corrected.

Everything else investigated was refuted with evidence or remains
deferred with a recorded reason (see `.audit/` round-2 reports in the
session log). Re-verification after round 2: workspace check clean,
full test suite green.

## Known residual risks (honest limitations)

- The IPC secret remains world-readable by design (R3); local
  unprivileged processes can issue authenticated-but-not-elevated
  requests. Elevation-gated methods are protected; read endpoints
  intentionally serve local users.
- Pipe-identity resolution still fails open on *transient* API errors
  (documented trade-off so an API quirk can't brick a legitimate GUI).
- Subprocess `clamavd` mode's coverage is the round-2 `--self-test`
  (EICAR round-trip over the real FFI contract) — that closes the
  "no end-to-end coverage" gap round 1 recorded, but it is a single
  happy-path probe, not a suite.
- `clamav-main/` upstream code was not re-audited.

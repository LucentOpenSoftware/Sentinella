# Changelog

## [0.1.7] - 2026-05-30

Engine-reload UX hardening release. Focused on the three problems
users reported during signature reloads in v0.1.6: ghost console
windows flashing, the protection shield briefly flipping to
"degraded", and a transient "outdated definitions" banner. Plus an
internal dev-console tool, locale-parser fixes, and a complete
audit pass on the new lock-free engine slot.

### Engine reload — UX series (the headliner)

**Phase 1 — Kill all ghost CMD/console windows.**
Eight `Command::spawn` sites in `sentinelld` were missing
`CREATE_NO_WINDOW` (0x08000000) on Windows — freshclam, sibling
worker binaries (`clamavd`, `argusd`, `sandboxd`), `wevtutil` for
PowerShell event polling, `icacls` in `runtime_integrity.rs`, and
`reg` for startup-key enumeration. The other 4 sites had the flag
inline as a literal; nothing centralised it. Added a single
`crate::win_process::QuietCommand` trait with a `quiet_windows()`
builder method. Audit at end of commit: every `Command::new` in
`crates/sentinelld/src/` is now flagged. Builder pattern means a
future spawn that forgets the flag is a one-line lint risk, not a
ghost-window bug.

**Phase 2 — Decouple `engine.status` from the in-flight reload.**
`engine.status` was reading the live engine slot directly, so
during a freshclam-then-reload window the GUI's poll could see
`(signature_count = old, db_timestamp = new)` — exactly the
inconsistency that trips "outdated definitions" client-side. Added
a committed-state mirror in `AppState`:

  - `committed_db_version: AtomicU32`
  - `committed_db_timestamp: AtomicI64` (i64::MIN sentinel = unset)
  - `reload_phase: AtomicU8` (Idle / Compiling / Activating / Failed)

`signature_count` (already AtomicU64) is the LAST committed write
of every successful reload via a new `commit_engine_state(sigs)`
helper. The Release/Acquire pair guarantees that any reader
observing the new signature_count also observes the new db_version
+ db_timestamp. `engine.status` now reads from the mirror with a
`read_cvd_version()` fallback only when the i64::MIN sentinel is
still in place (initial boot before the first commit).

`EngineStatus` JSON gains one optional field `reload_phase` with
`#[serde(default)]` so older clients keep working. GUI Dashboard
renders two new pills next to the engine/watcher chips when
relevant — "Updating signatures…" on Compiling/Activating and
"Update failed" on Failed. Neither flips the protection shield
away from green — that's the whole point.

**Phase 3 — Lock-free A/B engine swap via `ArcSwap`.**
`engine: RwLock<Option<Arc<ClamEngine>>>` becomes
`engine_state: arc_swap::ArcSwap<EngineSnapshot>`. Scans clone the
inner `Arc<ClamEngine>` via a relaxed atomic load + one refcount
increment — no read lock, never blocks on a reload. A reload
publishes a freshly-built `EngineSnapshot` into the slot
atomically — no write lock.

Net effect:

  - Scans never block on a reload, not even microseconds during
    the swap moment.
  - Two engines coexist briefly: the new one freshly compiled,
    the old one held by Arcs in any in-flight scans. The old
    drops naturally when the last in-flight scan releases its Arc.
  - Reload is fail-closed: compile the new engine into a local
    first, then publish. A compile error leaves the slot
    untouched (an RCU update bumps `last_error` only).

**Phase 3 audit — combined atomic snapshot, off-handler drop.**
A 2-agent triage of Phase 3 found a real memory-ordering hole:
`engine` (ArcSwap) and `engine_error` (`RwLock<Option<String>>`)
were separate primitives, so `ArcSwap::swap`'s Release synchronizes-
with `load_full` ONLY on the engine slot. A reader that observed
the new engine had no happens-before edge with the writer's prior
`engine_error` clear; on a weakly-ordered platform it could observe
`(engine = new, last_error = stale-old)`. On x86_64 TSO this never
reproduced; per the Rust memory model and on AArch64 it's broken.

Fix: fold both fields into one `EngineSnapshot { engine, last_error }`
value held in a single `ArcSwap<EngineSnapshot>`. Publish delivers
both fields together; a load takes a self-consistent pair. The
cross-primitive ordering hole is structurally impossible.

Also from the audit:

  - `drop(prev)` after a swap previously ran `cl_engine_free` on
    the IPC handler / freshclam thread. Now moved onto a dedicated
    `engine-snap-drop` `std::thread` so the handler returns
    immediately. cl_engine_free walks deep AC/BM trie nodes and on
    pathological signature sets has been observed at >512 KB stack
    — running it off the hot path is the right default.
  - The original Phase 3 regression tests were single-threaded.
    Replaced the second one (which was a tautology on x86_64 TSO)
    with a real multi-threaded stress test that publishes 2 000
    snapshots from one thread while another asserts every snapshot
    with `engine ≥ 2` has `last_error = None`. With the pre-audit
    two-primitive design this could fail on AArch64; with the
    combined snapshot it cannot fail on any platform.

### Added

- **`sentinella-dev-console`** — internal native GUI tool for the
  Sentinella developer center, NOT shipped in the public installer.
  Single-binary `eframe` + `egui` app (~5 MB release exe) with two
  tabs:

    * **Setup** — detects the installed `SentinellaDaemon`, mirrors
      the live `[developer]` config section, takes a plaintext
      password with live SHA-256 preview, writes the hash into
      `sentinelld.toml` via `toml_edit` (preserves comments + formatting),
      atomic write (.tmp → fsync → rename), `sc stop` + `sc start`
      with poll-until-state and 15 s timeout. Provision / Enable /
      Disable / Revoke flows. One-click `🛡 Restart as Admin`
      footer button when not elevated (ShellExecuteW `runas`
      verb).
    * **Benchmark** — discovers `argusd.exe` dev-first (workspace
      `target/release/argusd.exe` → workspace `target/debug/` →
      installed copy), spawns `argusd benchmark --json --passes N`
      with `CREATE_NO_WINDOW`, parses the nested JSON schema
      (`corpus`, `per_file_us`, `system`), renders Performance
      Index colour-coded by tier + throughput + latency
      percentiles + SIMD flags. "Save raw JSON…" exports to
      `%TEMP%`.

  Builds with `cargo build --release -p sentinella-dev-console`.

- **`crate::win_process::QuietCommand`** — single source of truth
  for `CREATE_NO_WINDOW`. Builder-pattern extension on
  `std::process::Command`. No-op on non-Windows.

- **`EngineSnapshot`** type — atomic publish vehicle for the
  Phase 3 engine slot (engine + last_error siblings).

### Fixed

- **`sc query` locale parser bug.** On Spanish Windows
  (`TIPO : 10  WIN32_OWN_PROCESS / ESTADO : 4  RUNNING`) the
  previous "first line where a digit is followed by whitespace
  + a letter" rule was returning TIPO=10 instead of ESTADO=4
  → daemon reported "installed, stopped" even while running.
  SERVICE_TYPE codes are >= 10 and STATE codes are 1..=7;
  constraining the candidate range fixes it on every locale.
  Same bug in both the dev-console parser and the production
  GUI supervisor — both patched.
- **GUI hardcoded "v0.1.5" strings** (22 sites across 14 files)
  — promoted to a single `APP_VERSION_TAG` constant in
  `gui/src/app-version.ts` for the three JSX hardcodes
  (AppShell, Sidebar, About). i18n strings still bumped per
  release until the loader gains placeholder interpolation.

### Tests

- +4 tests (sentinelld 285 → 287; 2 ArcSwap regressions for
  Phase 3 + Phase 3 audit). **All 287 pass.**

## [0.1.6] - 2026-05-30

Hardening release. **~200 fixes** across security, correctness, and
resource management. **All 450 tests pass.** No new user-facing features
beyond Developer Mode and 7 added GUI locales; existing behavior is
unchanged unless explicitly noted.

### Security — crypto correctness (critical class)
- `runtime_integrity::compute_file_hmac` was `DefaultHasher` (SipHash via
  the `Hash` trait), wrapped as `H(key || content || key)`. SipHash is a
  PRF for hash-flooding defence, **not a MAC** — the gate that detects
  silent tampering of signatures/YARA rules had no formal MAC security.
  Replaced with HMAC-SHA256 from the `hmac` crate; streams the file
  (was allocating 100+ MB Vecs for signature DBs). EUF-CMA secure.
- `engine::residency::compute_meta_hash` had the same `DefaultHasher`
  mistake on the mpool cache meta. Replaced with HMAC-SHA256 under the
  existing vault key. Old 16-char hashes fail safely post-upgrade →
  forced cache recompile.
- **Method-scoped challenge tokens** (`Inner.challenge_token` is now
  `(token, method, ts)` instead of `(token, ts)`). The prior design
  let a token issued for `quarantine.delete` (which the user UAC-
  approves) replay against `engine.reload` or `settings.set` — defeated
  the per-dangerous-op UAC assumption. `security.challenge` now requires
  a `method` param validated against a registry of privileged methods;
  every validating handler passes its own method name. Touched 6 files
  end-to-end (daemon + Tauri bridge + TS client + CLI). New lock-in
  test `challenge_token_is_bound_to_method_scope`.
- DLL search-order hardening on `clamavd` worker and the daemon's own
  `engine::clamav::load`. Before loading `libclamav.dll` (which pulls
  in `libssl`, `libcrypto`, `zlib`, `libxml2` …), the loader now calls
  `SetDefaultDllDirectories(SYSTEM32 | USER_DIRS)` + `AddDllDirectory`
  for the explicit DLL directory. Closes the transitive-DLL hijack
  vector (attacker drops `libcrypto-3-x64.dll` into CWD / user-writable
  PATH entry / next-to-exe → arbitrary code in SYSTEM-context daemon).

### Security — scanner-bypass class (trivial-lethal)
- Configuration validation now refuses executable extensions
  (`exe`, `dll`, `sys`, `ps1`, `scr`, `bat`, `cmd`, `js`, `msi`, `lnk`,
  `vbs`, …) from being added to `excluded_extensions`. The prior
  validation comment promised this but the code was a no-op — a tampered
  config could silently disable scanning of every executable on the box.
- Path-exclusion prefix matching now enforces a directory boundary. An
  exclusion of `C:\Users\Me` no longer also excludes `C:\Users\Mexico\`,
  `MeOwner\`, etc.
- Scan cache key now includes a 128-bit SHA-256 fingerprint of the file
  prefix. An in-place overwrite that preserves `size` + `mtime` (via
  `SetFileTime()`) no longer hits the cache as "clean"; the watcher
  re-scans.
- `PathManager` no longer flips to "development mode" when a 1-byte
  `Cargo.toml` is present in CWD. Dev mode now requires
  `SENTINELLA_DEV=1` AND a matching package manifest. Portable mode
  (`runtime/` next to the exe) is only honored when the exe lives in a
  trusted install path; user-writable locations
  (`\Users\Public\`, `\Downloads\`, `\Desktop\`, `\Temp\`, etc.) are
  refused.
- `find_freshclam` and the ARGUS worker resolver no longer search CWD
  for candidates. A user-writable CWD with a planted
  `build/.../freshclam.exe` (or `argusd.exe`) was a SYSTEM-exec hijack.

### Security — kill-the-AV class
- `quarantine.add` rejects requests targeting OS-critical roots
  (`\Windows`, `\System32`, `\WinSxS`, `\drivers`, `\Boot`, …), known
  competing AV/EDR install paths (Defender, CrowdStrike, SentinelOne,
  Sophos, ESET, Bitdefender, Kaspersky, MBAM, Carbon Black, Cylance,
  Trend Micro, McAfee, Norton, Symantec, Avast, AVG), and the daemon's
  own install directory. Previously any caller with a challenge token
  could ask SYSTEM to delete arbitrary files.
- `scan.start` and `quarantine.add` reject UNC (`\\server\share\…`),
  long-path UNC (`\\?\UNC\…`), and device-namespace paths
  (`\\.\PHYSICALDRIVE0`, `\globalroot\`, etc.). Closes the
  scan-walker → SMB → machine-account NTLM relay vector.
- Vault AES-256 key ACL restored to `SYSTEM` + `Administrators` only;
  the daemon is the sole reader (the GUI asks over IPC). The previous
  ACL granted `BUILTIN\Users:R`, which on multi-user / RDP / kiosk hosts
  let any logged-in user decrypt every quarantined sample.

### Security — TOCTOU & tamper-evidence
- ARGUS file scan now opens the target with `FILE_SHARE_READ` only
  (no `SHARE_WRITE`, no `SHARE_DELETE`) and holds the handle for the
  full scan. Closes the 3-read TOCTOU chain (engine `fs::read` →
  `verify_trust(path)` → `extract_signer(path)`): attacker can no
  longer swap, rename, or delete the file mid-scan. Eliminates the
  `trusted_cache` amplifier where a one-shot race would otherwise
  cache `sha256(malicious) → score=0 + signer="Microsoft"` persistently.
- `Authenticode::extract_signer` was a UTF-16 substring scan over the
  whole PE body, matching attacker-embedded strings as the publisher
  name. Replaced with real Windows CryptoAPI (`CryptQueryObject` →
  `CryptMsgGetParam` → `CertGetNameStringW`). Returns `None` on
  failure — no substring fallback. `reputation::match_by_pe_strings`
  now delegates to the same function.
- Quarantine `prepare_quarantine_file` opens the source ONCE via
  `OpenOptions`, fstats the live handle, reads from the same handle
  (was metadata-then-read; attacker could swap the inode for a hardlink
  to a larger file between checks, bypassing the 100 MB cap).
- Quarantine restore now walks `dest.ancestors().skip(1)` and rejects
  any mid-path Windows junction or symlink, not just the immediate
  parent. `create_dir_all(parent)` removed from both restore paths
  (daemon no longer mkdirs along attacker-influenceable ancestors).
- Self-binary integrity check at startup. `verify_or_init_binaries()`
  HMAC-SHA256s the daemon plus sibling workers (`argusd.exe`,
  `clamavd.exe`, `sandboxd.exe`, `etw_probe.exe`, `freshclam.exe`)
  against `state/binary_integrity.json`. TOFU on first run. On drift:
  `error!` log + sets `health.binary_integrity_drift: true`.
  Fail-loud, not fail-closed (admins replace binaries during legitimate
  upgrades).
- Config-file HMAC sidecar. `Config::save()` writes
  `sentinelld.toml.hmac` alongside the config (atomic-rename + fsync).
  `config::load_verified()` detects edits made outside the daemon
  (e.g. direct file write bypassing `settings.set`'s kill-vector
  preserve list); surfaces via `health.config_drift: true`.
- Watcher heartbeat auto-restart. Dedicated monitor thread, 90 s
  warm-up + 20 s cadence: if `now − last_heartbeat > 60 s` and
  realtime enabled and not user-disabled, respawn watcher under
  `protection_toggle_lock`. Counted in
  `resilience.watcher_restarts_total`.
- Freshclam binary HMAC check before `Command::spawn`. Fail-CLOSED
  (refuse to spawn) — freshclam runs adversary code in the daemon's
  privilege envelope if tampered, unlike a tampered self-binary
  which is already executing.
- YARA rule loader rejects symlinks and Windows junctions at any
  level of the rule tree (root dir, subdirs, leaf files); per-rule
  4 MiB size cap; 1000-file total cap. Closes the "attacker swaps a
  `.yar` for a symlink, controls scoring" vector.
- IOC hash loader: symlink + junction rejection, 16 MiB file size
  cap, 8 MiB content cap with UTF-8-boundary truncation (defends
  against a racey attacker lying via `symlink_metadata`).
- Benchmark corpus dir: unique name (pid + nanos) + `create_new`
  (refuses to follow a pre-planted symlink). Closes an elevated
  overwrite vector on shared `/tmp` when `argusd benchmark` runs
  with elevated privileges.

### Security — IPC contract
- `update.start`, `scan.start` (all types), `settings.get`,
  `quarantine.list`, `detections.list`, `activity.list`, and
  `trust.status` now require authenticated IPC. Several of these
  previously leaked malware SHA-256s, file paths, trusted-signer
  lists, and scan history without any auth.
- `engine.reload` and `settings.set` were declared `PrivilegedMutation`
  in `policy.rs` but their handlers only called `validate_ipc_auth()`,
  not `validate_challenge_token()`. The central dispatcher never
  enforced `class`. Both handlers now require a method-scoped
  challenge token.
- `argus.reload` escalated from `auth_action(ScanControl)` to
  `priv_mutation(ScanControl)` + scoped token requirement. Closes the
  `update.start + argus.reload + engine.reload` chained reload-DoS
  (multiple methods share `ScanControl` budget but each consumed
  independently before).
- `runtime.status` was registered `auth_read` in policy but the handler
  had no auth gate — unauth callers got the full PLM/ETW/ps_bridge
  diagnostics. Now properly gates with `validate_ipc_auth`.
- `watcher.status` and `idle_scanner.status` moved from `pub_status`
  to `auth_read`. Both previously leaked monitored paths +
  `current_target` to unauthenticated callers (reconnaissance oracle:
  "drop the payload where the scanner isn't looking right now").
- `update.start` moved from `pub_status(1024)` (no audit, allowed
  during reload, Status bucket 120/min) to `auth_action(1024,
  ScanControl, audit_log=true)`. Blocks the reload-stacking DoS
  (stack 5-8 s scan-blind windows back-to-back).
- `activity.log`: was `Unlimited`/`audit_log:false`/free-form. Now
  `auth_action(DiagnosticsExport)` (6/min, burst 2), `severity` is
  enum-allowlisted (`info`/`warning` only — daemon-internal
  `critical`/`error` reserved), `category` forced to `gui:` prefix,
  `title` forced to `[gui] …` prefix. Closes the defender-blinding
  / forensic-trail-poisoning vector.
- `settings.set` did NOT preserve `developer.password_sha256` from
  the on-disk config. Two attack paths: (a) GUI round-trip with the
  redacted-to-empty hash would silently wipe the provisioned
  password, (b) IPC-secret holder injects a pre-computed hash whose
  plaintext they know → `dev.set_developer_mode(plaintext)` →
  privesc without knowing the original password. Now preserved
  alongside the other kill-vector-protected fields.
- New `dev.status`, `dev.set_developer_mode`, `benchmark.run` IPC
  methods (Developer Mode + hardware-parity benchmark).

### Security — input validation & integer safety
- ARGUS `pe_heuristics`: 3 sites of attacker-controlled
  `offset + size` u32 arithmetic on PE section headers wrapped on
  32-bit usize, slipping past the bounds check → OOB slice panic on
  crafted PE. Plus a fourth site: `virtual_address + virtual_size`
  in the entry-point classifier, and `pe.entry as u32` silently
  truncating goblin's u64. All fixed with `checked_add` / `try_from`.
- ARGUS `packer::analyze_executable_sections`: same offset+size
  overflow class.
- `memory_scanner::check_memory_patterns` PE header offset
  (`lfanew + 4`) overflow on attacker-controlled process memory
  bytes. `checked_add`.
- `etw_probe` session-start: `name_offset + name_bytes.len()`
  overflow. `checked_add`.
- ARGUS `file_deception`: Unicode whitespace run counter replaces
  the literal 16-ASCII-space substring check. Closes the
  NBSP/em-space/zero-width-character extension-hiding bypass.
- ARGUS `mime`: removed unreachable `has_mz && has_pk` branch
  (both checks were at offset 0 with mutually-exclusive magic
  bytes — dead code).
- `updater::resolve_freshclam_config` was resolving relative paths
  against CWD. CWD drift between manual-trigger and auto-trigger
  code paths was the suspected cause of the user-reported
  tray-update bug. Now anchored to `paths().root()` + writes the
  resolved temp config under `paths().config_dir()`.
- `engine::update_pipeline::sources::local_source` had
  `.unwrap_or(Path::new("."))` (CWD fallback). Daemon as SYSTEM
  activates anything under `local_source` as a real signature DB.
  Anchored to `paths().root()`.
- `scan::should_skip` self-runtime-skip check anchored on
  `std::env::current_dir()`. Anchored to `paths().root()` — closes
  the self-scan storm / signature self-quarantine vector.
- `sandboxd` ETW dump directory: CWD fallback (`sample.parent()
  .unwrap_or(Path::new("."))`). Now falls back to per-process temp
  dir.
- ARGUS `ioc::add_hash` now validates hex (mirrors
  `load_from_file`); only bumps `count` when `HashSet::insert`
  returns true (was inflating reported count on duplicate adds).
- Tauri `SignatureSources.tsx`: provider homepage `<a href>` now
  gated on `/^https?:\/\//i` and adds `noreferrer`. Closes a
  `javascript:` URI risk if the signature-source registry is ever
  tampered.

### Security — TOCTOU & races (additional)
- Orchestrator queue depth was `load + check + fetch_add` — N
  concurrent submitters all see `< cap`, all `fetch_add`, queue
  overshoots by N. Now `fetch_add` upfront + rollback on over-cap.
- `disable_protection`/`enable_protection` interleave race: concurrent
  calls could leave the watcher stopped after `enable` returned
  success. Serialized via new `protection_toggle_lock` mutex.
- Rate limiter refill `load + store` lost concurrent consume CAS
  results (free requests under load). Now `fetch_update` retry loop.
- `useDaemon.ts` refresh race: overlapping `refresh()` could let a
  stale response overwrite a newer one (stuck "scanning" state on
  quick visibility toggle). Fixed with monotonic refresh-id guard.
- Watcher unbounded mpsc channel → `sync_channel(8192)` with
  `try_send` + dropped-event counter. The previous unbounded
  `channel()` queued every event under FS storm (ransomware mass
  rewrite, archive unpack), growing without limit until OOM —
  exactly the scenario the watcher exists to detect.
- Calibration `record_detection`: `BEGIN` result was swallowed by
  `let _ = …`. If BEGIN failed (DB busy), the subsequent inserts
  ran in autocommit and the matching ROLLBACK became a no-op,
  re-introducing the partial-commit class the audit comment
  claimed to prevent.

### Correctness
- New **orchestrator watchdog**: detects workers stuck on a job past
  their timeout, fires the cooperative cancel token, and respawns a
  replacement so the queue keeps draining. Stuck threads self-retire
  via a per-spawn generation counter. Uses monotonic `Instant` timing
  (immune to wall-clock jumps). Default timeout 300 s. A leaked-worker
  budget (cap 16) bounds the thread leak under sustained malformed
  input. Previously `stuck_worker_timeout_sec` was dead code.
- Windows service lifecycle: the daemon now reports `StopPending` with
  a wait hint when an SCM stop arrives, and runs its cleanup
  (`Scheduler::stop`, final flushes) on SCM stop. Previously the
  entire `run_daemon` future was cancelled mid-flight and cleanup
  never ran. `process::exit(1)` paths during `ensure_dirs` failure now
  return errors so SCM gets a proper `Stopped(exit_code=1)` instead of
  a hung `StartPending`.
- ClamAV post-compile working-set trim is now unconditional. It was
  previously nested inside `mpool_getstats` success, so DLL builds
  lacking the symbol stayed ~970 MB resident instead of single-digit
  MB.
- ETW process-start event parent-PID is now parsed at the correct
  pointer-width-aware offset (`UniqueProcessKey` is 8 bytes on x64).
  The previous offset 4 read the high DWORD of the key, producing
  garbage parent-PIDs and broken lineage chains.
- Memory-pressure tracker has 128 MB downward hysteresis. The working
  set hovering at a threshold no longer flaps Warning↔Critical every
  cycle.
- IPC rate-limiter `retry_secs` is now floored at 1 (was `60 /
  max_per_minute`, which truncates to 0 for any bucket >60/min →
  client retry storm with no backoff).
- DB schema migration only advances the recorded version to the
  highest successfully-applied migration. A failed (rolled-back)
  migration no longer marked the DB as fully migrated, which
  previously caused permanent silent schema inconsistency.
- Bounded retention + UTF-8-safe length caps on `activity`, `scans`,
  `detections`, `argus_verdicts`, and the calibration database. Daemon
  uptime in years no longer grows the SQLite file without bound.
  Retention DELETEs use `ORDER BY <ts> DESC, rowid DESC` so same-second
  ties never evict a newer row.
- Update-pipeline manifest hash mismatch no longer panics on a short
  or malformed `sha256` field from untrusted manifest JSON.
- Update-pipeline surfaces the real per-file download error when every
  file fails, instead of returning a generic "no files downloaded".
- `is_excluded` (watcher path filter), config exclusion checks, and
  scan-cache fingerprint use UTF-8-safe truncation throughout.
- Service-state detection in the GUI supervisor (`sc query` parsing)
  no longer false-matches `WIN32_EXIT_CODE : 4` as a RUNNING service.
  The STATE numeric is now parsed line-by-line and rejects hex
  (`0x0`) and parenthesized exit codes.
- `restrict_file_permissions` in `runtime_integrity.rs` uses raw SIDs
  (`*S-1-5-18`, `*S-1-5-32-544`) so the integrity-manifest key ACL
  applies correctly on non-English Windows.
- Convergence ledger: per-finding weight clamped at ingest; finalized
  score uses saturating arithmetic throughout; trust-discount math no
  longer panics on `i32::MIN` negation; the trust finding is dropped
  when ClamAV is already positive (was leaving a misleading "Trusted,
  no action" reason on confirmed malware); cap enforcement switched
  from proportional scaling to priority-truncation so a weight-1
  finding flood can no longer dilute a strong evidence weight to zero.
- Fish (ransomware shield): `Instant - Duration` panic on early boot
  fixed with `checked_sub`; `last_alert_times` map capped at 256 with
  LRU eviction.
- Ecosystem dedup uses saturating subtraction; narrative truncation is
  UTF-8 char-boundary-safe; fingerprint recording no longer silently
  drops under contention.
- Trust graph `observe_with_signer` reads the prior signer and writes
  the new observation under a single held lock (closing a TOCTOU on
  the signer-drift signal).
- Idle scanner working-set trim logs at WARN when the OS rejected the
  trim or it had no effect.
- ARGUS `analyze_buffer` now routes through `aggregate_score`
  (dedup, caps, convergence, ConfidenceLabel). Was bypassing the
  full pipeline — buffer scans diverged from file scans.
- ARGUS `ConfidenceLabel::Trusted` clamped to score ≤ 25 (was
  1..=40, overlapping the Suspicious band → UI showed "Normal"
  while engine returned "Suspicious" for the same row).
- ARGUS `EventType::ScannedSuspicious` emitted for 26..=75 scores
  (was a dead branch returning `ScannedClean`). Correlator now
  sees the middle band — directory-burst detection works.
- ARGUS `BudgetTracker` actually wired into `analyze_file`. New
  API: `analyze_file_with_budget(path, budget)` /
  `analyze_file_with_tracker(path, &tracker)`. `analyze_file`
  remains a thin wrapper using `manual()` default (preserves
  existing call sites). Per-phase YARA gate + total-budget gates
  record real `TimeoutReason` entries (was dead code).
- Scan-stats accounting: `clean_files`/`threats_detected` now
  gated on `Verdict` variant, not `score == 0`. Stats no longer
  drift for HighSuspicion / Suspicious rows.
- DB schema v4: `scans` table gains `bytes_scanned`,
  `clamav_phase_us`, `argus_phase_us`. v4 migration via
  `ALTER TABLE ADD COLUMN`. `Database::insert_scan` /
  `recent_scans` round-trip the new fields (locked in by
  `scan_row_v4_perf_fields_roundtrip`). Older rows back-fill to 0.
- `ScanPerformanceSummary` gains `total_clamav_us` +
  `total_bytes_scanned` accumulators; `record_file` now takes
  `file_size` and saturating-adds. Multi-file scan completion
  reads `j.perf_summary.*` for the row → MB/sec + phase split
  are real across all job types.
- Single-file scan `duration_ms`: NTP backward-correction could
  underflow the i64 subtraction → cast-to-u64 wraps to garbage.
  `.max(0)` guard added (every other completion site already had
  it — this was the outlier).
- `Config::validate()`: `FishConfig` validation added
  (window/threshold clamps, NaN guard on entropy, allowlist on
  `active_response`, log + reset on bad). Sandbox `min_score >
  max_score` would silently disable detonation (now clamped
  pre-cross-check). `scheduled_scan_type = "custom"` removed from
  the allowlist (was accepted but no downstream path handled it →
  silent no-op). `idle_scan_max_file_size_mb` clamped (≤ 4096 MB)
  to prevent `* 1024 * 1024` u64 overflow. `expanded()` now runs
  on default-fallback config paths (env-var literals were
  persisting unexpanded).
- `ecosystem::compute_escalation`: `recurrence_count *
  RECURRENCE_BONUS_PER` would panic on overflow in debug, wrap in
  release, bypassing `MAX_RECURRENCE_BONUS`. Fixed with
  `saturating_mul` + `saturating_add`.
- ARGUS `profile.rs`: dead `downgrade_large` field removed
  (`ScanStrategy::classify` already enforced the same cutoff).

### Resource management
- **Quarantine vault now uses chunked AES-256-GCM.** New format:
  4-byte magic `[0xC1, 0xAE, 0x53, 0x01]` + `original_size u64
  LE` + `num_chunks u32 LE` header, then 1 MiB chunks each
  `[nonce: 12][ciphertext+tag: chunk+16]`. Backward-compatible —
  first 4 bytes distinguish chunked from legacy one-shot format.
  **Peak memory: ~2 MiB per quarantine (was ~300 MB at the 100 MB
  cap — 150× reduction.)** Test `chunked_multi_chunk_round_trip`
  exercises a 2.5 MiB multi-chunk payload.
- ARGUS `patterns.rs`: 47 individual `data.windows(N).any(...)`
  needle scans collapsed into a single `Lazy<AhoCorasick>` pass.
  O(N × M) → O(N + Σ|patterns|). Severities/weights byte-
  identical. +2 sanity tests.
- ARGUS `authenticode`: 2-3× `verify_trust` (WinVerifyTrust +
  cert chain walk) per signed PE collapsed to 1× via
  `analyze_with_discount`. ~60-70% faster signature layer.
- ARGUS `reputation::match_by_pe_strings` ran 3× per file
  (once in `analyze`, twice in `reputation_discount`). Combined
  into `analyze_with_discount` mirroring the authenticode pattern.
- ARGUS `context.rs` Zone.Identifier ADS read merged from 2× to 1×
  (+ 1× `to_lowercase`).
- `engine::update_pipeline`: text-format check on staged signature
  files now uses `BufReader::new(f.take(4096))` + `read_line` (was
  `fs::read_to_string` of the entire file — hundreds of MB for a
  legitimate CVD just to inspect the first line for control chars).
- `amsi::ps_bridge::parse_wevtutil_output`: `current_script` cap
  (256 KiB) with UTF-8-boundary truncation; events Vec cap of 64.
  Closes the multi-MB ScriptBlock 4104 event amplification (20
  events/poll × max size).
- FISH `MutationWindow` events deque: `MAX_WINDOW_EVENTS = 8192`
  drain. Under sustained 1k events/s × 30 s window the deque
  previously held ~30k items and `evaluate()` ran 3 full O(n)
  passes per record → ~90k ops per single watcher event.
- `targeting::startup`: per-helper push cap `MAX_STARTUP_TARGETS
  = 2000`. Attacker dropping 100k `.exe` stubs in Downloads no
  longer expands the boot scan into a multi-GB `Vec<PathBuf>`.
- Durability sweep: missing `sync_all` added to vault key write,
  vault file write, restore writes (both paths), config save,
  runtime_integrity manifest + key, IPC secret, mpool meta,
  signature download. Power loss between buffered write and OS
  flush would otherwise have left these files empty/short on
  recovery (silent state loss → security gate disabled).
- Handle / subprocess leak fixes: `plm::snapshot_processes`,
  `plm::etw_intake::get_process_image`,
  `memory_scanner::scan_process_windows` use RAII guards for
  ToolHelp32 + OpenProcess handles (panic-safe).
  `clamav_worker`, `sandbox_worker`, `argus_worker` (both
  `scan_file` and `run_benchmark`) now `kill+wait` on
  `child.stdout.take()` failure — Rust's `Child` Drop is a no-op
  so `?` was orphaning subprocesses.
- Watcher debounce: fast-path Create events now respect
  `DEBOUNCE_CAP`; a flood of small-file creates no longer grows
  the `recent` set without bound.
- Scheduler interval logic uses monotonic `Instant`, not wall-clock
  hour arithmetic — survives DST, midnight, and clock skew.
- YARA `rules` field is `RwLock<Option<Arc<Rules>>>`. Scanners
  clone the Arc and drop the read lock immediately, so a concurrent
  reload writer is not starved by long scans.
- Sandbox + ARGUS worker subprocess readers use `mpsc` channels
  with bounded `recv_timeout`; a grandchild holding a stdout pipe
  can no longer hang the daemon forever joining a leaked reader
  thread.
- ETW intake: callback context is cleared and `CloseTrace` is
  called before the trace handle is released, preventing the UAF
  window when the caller drops its `Arc<LineageGraph>` shortly
  after stop.
- Calibration database inserts wrap the detection-row + per-layer
  upserts in a transaction (`BEGIN`/`COMMIT`/`ROLLBACK`).

### GUI / i18n
- **9 GUI locales** (was English + Spanish). Added Brazilian
  Portuguese, French, German, Italian, Russian, Japanese, and
  Simplified Chinese. **6,867 translation strings total** (9 ×
  763 keys at parity). Browser auto-detect upgraded: full
  BCP-47 match first (e.g. `pt-br`, `zh-cn`); bare `pt` →
  `pt-br`; any `zh-*` variant → `zh-cn`.
- Dashboard, Quarantine, Notifications, SignatureSources pages
  + the notification template dispatcher (`notify.ts`) had
  hardcoded English JSX text routed through `t()`. 53 new
  translation keys added at parity across all 9 locales.
- Developer Mode panel added to Settings → Advanced
  (password-gated, hidden until provisioned). Wires the new
  `dev.status` / `dev.set_developer_mode` IPC; surfaces dump
  file path + size; "Run benchmark" button calls the new
  `benchmark.run` IPC and renders Performance Index +
  throughput + p50/p95 latency + system info (cores + SIMD).
- Centralized `challenge_token()` helper in the daemon client.
  Every dangerous Tauri command (`quarantine_*`, `protection.*`,
  `set_signature_source`, `rollback_signature_source`,
  `update_signature_source`, `quarantine_restore_as`) now uses it,
  which returns a clear local error if the daemon issues an
  empty/missing token instead of forwarding an empty string and
  letting the daemon reject opaquely.
- `get_quarantine_items`, `get_detections`, `get_activity`,
  `get_trust_status`, `get_settings`, `start_signature_update`,
  and `export_scan_report` were switched from `call_simple` to
  `call_auth` to match the daemon's new auth requirements.

### Added (Developer Mode + benchmark)
- **`argusd benchmark`** subcommand: hardware-parity benchmark
  tool. Generates a deterministic safe corpus (or accepts
  `--dir`), runs ARGUS over it for N timed passes (default 3,
  after one warm-up), reports files/sec, MB/sec, per-file
  p50/p95/max/mean µs, logical cores + SIMD (avx2/avx/sse4.2/
  sse2 or aarch64 neon), and a composite **ARGUS Performance
  Index** (calibrated so the dev box ≈ 100 on release builds).
  Used to assess trust-parity across hardware tiers.
- **Local-only perf telemetry** (`devmode/telemetry.rs`):
  bounded, rotating text file in the AV diagnostics dir. Gated
  behind developer mode + telemetry opt-in. Hooks on scan
  completion (single chokepoint via `persist_scan`) and engine
  reload (in `reload_engine`'s existing duration measurement).
  Each block records timestamp + host facts (cores, RAM, arch,
  SIMD) + files/bytes/threats/duration + memory + pressure +
  scan-cache stats + ClamAV-vs-ARGUS phase split. Hard-capped
  with single-backup rotation. Best-effort writes (never
  disrupts scanning). Not cloud telemetry — nothing leaves the
  machine.
- **Developer Mode** (`DeveloperConfig` in `config/mod.rs`):
  password-gated per-machine local-only mode that enables the
  telemetry writer and unlocks the `benchmark.run` IPC.
  Password verification uses constant-time compare against a
  provisioned SHA-256 hash; rate-limited via the
  `ConfigMutation` bucket. Settings panel hidden until the
  daemon reports `provisioned`.
- DB schema v4: `bytes_scanned`, `clamav_phase_us`,
  `argus_phase_us` columns on the `scans` table for cross-
  hardware perf comparison.

### Tests
- +175 tests added (sentinelld 275 → 285; argus 163 → 165
  including 2 Aho-Corasick sanity tests; plus the new devmode +
  policy + v4 schema + method-scope challenge token tests).
  **All 450 pass.**

## [0.1.0-alpha] - 2026-05-21

### Added
- ClamAV signature scanning (3.6M+ signatures)
- ARGUS heuristic engine (8 layers, 119 YARA rules)
- Real-time filesystem watcher
- Idle background scanner (resource-aware)
- AES-256-GCM quarantine vault
- Advanced memory scanner
- FISH ransomware shield (observe + active response)
- Behavioral sandbox (experimental, Job Object containment)
- ClamAV subprocess isolation (clamavd)
- Persistent scan cache (SQLite-backed)
- Full/quick/folder/startup/file scan types
- Daemon supervisor with auto-recovery
- Memory pressure management
- Detection exclusions + hash whitelisting
- i18n support (English, Spanish)
- Tauri 2 GUI with frosted glass design
- System tray integration
- Windows service install scripts

# Changelog

## [0.1.6] - 2026-05-30

Hardening release. ~107 bug fixes across security, correctness, and resource
management. All 285 tests pass. No new user-facing features; existing
behavior is unchanged unless explicitly noted.

### Security — trivial-lethal class
- Configuration validation now refuses executable extensions
  (`exe`, `dll`, `sys`, `ps1`, `scr`, `bat`, `cmd`, `js`, `msi`, `lnk`,
  `vbs`, …) from being added to `excluded_extensions`. The prior
  validation comment promised this but the code was a no-op — a tampered
  config could silently disable scanning of every executable on the box.
- Path-exclusion prefix matching now enforces a directory boundary. An
  exclusion of `C:\Users\Me` no longer also excludes `C:\Users\Mexico\`,
  `MeOwner\`, etc.
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
- `PathManager` no longer flips to "development mode" when a 1-byte
  `Cargo.toml` is present in CWD. Dev mode now requires
  `SENTINELLA_DEV=1` AND a matching package manifest. Portable mode
  (`runtime/` next to the exe) is only honored when the exe lives in a
  trusted install path; user-writable locations
  (`\Users\Public\`, `\Downloads\`, `\Desktop\`, `\Temp\`, etc.) are
  refused.
- Scan cache key now includes a 128-bit SHA-256 fingerprint of the file
  prefix. An in-place overwrite that preserves `size` + `mtime` (via
  `SetFileTime()`) no longer hits the cache as "clean"; the watcher
  re-scans.
- Vault AES-256 key ACL restored to `SYSTEM` + `Administrators` only;
  the daemon is the sole reader (the GUI asks over IPC). The previous
  ACL granted `BUILTIN\Users:R`, which on multi-user / RDP / kiosk hosts
  let any logged-in user decrypt every quarantined sample.
- `update.start`, `scan.start` (all types), `settings.get`,
  `quarantine.list`, `detections.list`, `activity.list`, and
  `trust.status` now require authenticated IPC. Several of these
  previously leaked malware SHA-256s, file paths, trusted-signer lists,
  and scan history without any auth.
- `find_freshclam` and the ARGUS worker resolver no longer search CWD
  for candidates. A user-writable CWD with a planted
  `build/.../freshclam.exe` (or `argusd.exe`) was a SYSTEM-exec hijack.

### Correctness
- New **orchestrator watchdog**: detects workers stuck on a job past
  their timeout, fires the cooperative cancel token, and respawns a
  replacement so the queue keeps draining. Stuck threads self-retire via
  a per-spawn generation counter. Uses monotonic `Instant` timing
  (immune to wall-clock jumps). Default timeout 300 s. A leaked-worker
  budget (cap 16) bounds the thread leak under sustained malformed
  input. Previously `stuck_worker_timeout_sec` was dead code.
- Windows service lifecycle: the daemon now reports `StopPending` with a
  wait hint when an SCM stop arrives, and runs its cleanup
  (`Scheduler::stop`, final flushes) on SCM stop. Previously the entire
  `run_daemon` future was cancelled mid-flight and cleanup never ran.
  `process::exit(1)` paths during `ensure_dirs` failure now return
  errors so SCM gets a proper `Stopped(exit_code=1)` instead of a hung
  `StartPending`.
- ClamAV post-compile working-set trim is now unconditional. It was
  previously nested inside `mpool_getstats` success, so DLL builds
  lacking the symbol stayed ~970 MB resident instead of single-digit
  MB.
- ETW process-start event parent-PID is now parsed at the correct
  pointer-width-aware offset (`UniqueProcessKey` is 8 bytes on x64). The
  previous offset 4 read the high DWORD of the key, producing garbage
  parent-PIDs and broken lineage chains.
- Memory-pressure tracker has 128 MB downward hysteresis. The working
  set hovering at a threshold no longer flaps Warning↔Critical every
  cycle.
- IPC rate-limiter `retry_secs` is now floored at 1 (was `60 /
  max_per_minute`, which truncates to 0 for any bucket >60/min →
  client retry storm with no backoff).
- DB schema migration only advances the recorded version to the highest
  successfully-applied migration. A failed (rolled-back) migration no
  longer marked the DB as fully migrated, which previously caused
  permanent silent schema inconsistency.
- Bounded retention + UTF-8-safe length caps on `activity`, `scans`,
  `detections`, `argus_verdicts`, and the calibration database. Daemon
  uptime in years no longer grows the SQLite file without bound.
  Retention DELETEs use `ORDER BY <ts> DESC, rowid DESC` so same-second
  ties never evict a newer row.
- Update-pipeline manifest hash mismatch no longer panics on a short or
  malformed `sha256` field from untrusted manifest JSON.
- Update-pipeline surfaces the real per-file download error when every
  file fails, instead of returning a generic "no files downloaded".
- `is_excluded` (watcher path filter), config exclusion checks, and
  scan-cache fingerprint use UTF-8-safe truncation throughout.
- Service-state detection in the GUI supervisor (`sc query` parsing) no
  longer false-matches `WIN32_EXIT_CODE : 4` as a RUNNING service. The
  STATE numeric is now parsed line-by-line and rejects hex (`0x0`) and
  parenthesized exit codes.
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
  the new observation under a single held lock (closing a TOCTOU on the
  signer-drift signal).
- Idle scanner working-set trim logs at WARN when the OS rejected the
  trim or it had no effect.

### Resource management
- Watcher debounce: fast-path Create events now respect `DEBOUNCE_CAP`;
  a flood of small-file creates no longer grows the `recent` set
  without bound.
- Scheduler interval logic uses monotonic `Instant`, not wall-clock
  hour arithmetic — survives DST, midnight, and clock skew.
- YARA `rules` field is `RwLock<Option<Arc<Rules>>>`. Scanners clone the
  Arc and drop the read lock immediately, so a concurrent reload writer
  is not starved by long scans.
- Sandbox + ARGUS worker subprocess readers use `mpsc` channels with
  bounded `recv_timeout`; a grandchild holding a stdout pipe can no
  longer hang the daemon forever joining a leaked reader thread.
- ETW intake: callback context is cleared and `CloseTrace` is called
  before the trace handle is released, preventing the UAF window when
  the caller drops its `Arc<LineageGraph>` shortly after stop.
- Calibration database inserts wrap the detection-row + per-layer
  upserts in a transaction (`BEGIN`/`COMMIT`/`ROLLBACK`).

### GUI
- Centralized `challenge_token()` helper in the daemon client. Every
  dangerous Tauri command (`quarantine_*`, `protection.*`,
  `set_signature_source`, `rollback_signature_source`,
  `update_signature_source`, `quarantine_restore_as`) now uses it,
  which returns a clear local error if the daemon issues an
  empty/missing token instead of forwarding an empty string and
  letting the daemon reject opaquely.
- `get_quarantine_items`, `get_detections`, `get_activity`,
  `get_trust_status`, `get_settings`, `start_signature_update`,
  and `export_scan_report` were switched from `call_simple` to
  `call_auth` to match the daemon's new auth requirements.

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

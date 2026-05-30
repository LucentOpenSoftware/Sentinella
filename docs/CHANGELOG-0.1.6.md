# Sentinella — v0.1.6 Bug-Fix Campaign (Definitive Changelog)

> **Status: PRE-RELEASE / IN PROGRESS.** v0.1.6 has **not** been tagged.
> Reconstructed from the Claude Code session transcript
> `~/.claude/projects/C--Users-Nicolas-Desktop-clamav-main/70d5c946-917b-4db4-be90-7a4c9cdfd9db.jsonl`
> (the originating session is permanently blocked by an API `thinking`-block error).
>
> **Goal bar:** "v0.1.6 cannot ship with fewer than 200 bugs fixed" — treated as a rough
> *meets-expectations* line, not a ceiling. **More is encouraged.**
>
> **Where it stands now:**
> - **≈101 distinct fixes** landed in the pre-0.1.6 audit campaign (agent's running tally, 2026-05-28 13:42).
> - Test suite was **247/247 green** at peak.
> - **⚠️ One regression introduced afterward:** `ecosystem::tests::cooling_transition` is now **FAILING**
>   (246 passed / 1 failed / 2 ignored, 2026-05-28 14:07) in `crates/sentinelld/src/ecosystem/mod.rs`. **Fix this first.**
> - ~99 fixes still needed to *comfortably* clear the 200 bar; untouched modules are listed at the bottom.

**Counting note:** numbers below are the agent's own running estimates ("≈"). The enumerated list
that follows is the *deduplicated, concrete* set of fixes that can be traced to a specific bug + fix in
the transcript. Some early IDs (e.g. R3-1..R3-6) were fixed in batches summarized only in aggregate;
they're marked as such. Treat the enumerated entries as the authoritative work log.

---

## Part A — Shipped patch releases (v0.1.1 → v0.1.5)

These were tagged and released *before* the v0.1.6 audit campaign. Listed for continuity.

### v0.1.1 — Critical hotfix bundle (commit `84a72d0`)
1. **Realtime watcher watched non-existent dirs.** Under `LocalSystem`, `%USERPROFILE%` → `C:\Windows\system32\config\systemprofile`, so zero real user dirs were watched. → Enumerate `C:\Users\*` for each real profile (skip Default/Public/defaultuser0/WDAGUtilityAccount).
2. **GUI generated its own IPC secret on cold-boot race.** GUI started before daemon wrote the secret, invented its own, cached in `OnceLock` → auth desync all session. → GUI never generates; retries reading daemon's file every 500 ms for 5 s, else clear `-32099` error.
3. **IPC secret file ACL blocked unelevated GUI.** Daemon wrote secret SYSTEM+Admin-only; autostart GUI runs unelevated → can't read. → Grant `BUILTIN\Users:R` via icacls (raw SIDs, non-English safe); re-apply on every daemon start to repair upgrades.
4. **Case-different watcher paths double-registered.** `notify` failed second registration → `os error 5`. → Canonicalize + lowercase `HashSet` dedup.

### v0.1.2 — Stability hotfix (commit `6d62ccb`)
5. **mpool cache file doubled on every engine reload** (`engine/residency.rs`). freshclam reload every 4 h → cache grew 977 MB → 1.9 → 2.9 GB… → memory pressure, ARGUS timeouts, "disconnecting". → `MpoolResidencyManager::prepare()` deletes the prior cache file + meta sidecar before each compile so `CREATE_ALWAYS` opens truly fresh. Bounded at ~977 MB.

### v0.1.3 — Supervisor/service race (commit `5d4ad70`)
6. **Supervisor spawned its own daemon in installed (service) mode** (`gui/src-tauri/src/supervisor.rs`). Orphan grabbed the named pipe; SCM's service daemon then failed to bind → STOPPED, dual-daemon, "Protection degraded". → Added `is_service_registered()`; when service-managed, supervisor only monitors, never spawns.
7. **`ipc/mod.rs run_named_pipe` first `create_pipe_server` propagated errors with `?`** → daemon crashed on transient boot pipe contention. → Retry 20× with 3 s backoff (60 s window).
8. *(chore)* Hardcoded `v0.1.0` version strings in `Sidebar.tsx`, `About.tsx`, `AppShell.tsx`, `en.ts`, `es.ts` → bumped.

### v0.1.4 — Detection latency (commit `89c5641`)
9. **`DEBOUNCE_MS = 800`** added 800 ms latency to every realtime scan. → Reduced to **150 ms** (each new event still extends the window).
10. **No fast path for small files.** → Added `FAST_PATH_MAX_SIZE = 2 MB`; small `Create(File)` events force immediate flush (~20 ms vs 820 ms). Large files keep debounce.

### v0.1.5 — Restore pre-0.1.0 detection speed (commit `724fb37`)
11. **Build-artifact cooldown (`f9f7a43`, 500 ms skip) applied to ALL folders**, including Downloads — stacked with debounce for ~1,300–1,800 ms total latency; Defender always won. → Cooldown now skipped for user-visible folders (Downloads/Desktop/Documents/OneDrive); still applies elsewhere to protect `cargo build` churn.

---

## Part B — Pre-0.1.6 audit campaign (the "200 bugs" push)

Multiple audit/fix rounds run 2026-05-27 23:00 → 2026-05-28 13:42. Rounds were labelled
inconsistently (R1/R2/R3, then C#/CV#, then R4–R9 "LETHAL", then module sweeps) — normalized here.

### Round 1 — 10 fixes (424 tests pass)
- **R1-1** `watcher/mod.rs:215` fast-path `checked_sub` returned None on low uptime → file stuck in `recent`. → bool flag / saturating.
- **R1-2** `nsis-hooks.nsh:26` `StrCpy $SENTI_DATA` line 1 dead-overwritten → hardcoded `C:\ProgramData`, wrong-drive installs broke. → `ReadEnvStr "ProgramData"`.
- **R1-3** `nsis-hooks.nsh:87` `--db-dir "$SENTI_DATA\\signatures"` literal `\\`. → single `\`.
- **R1-4** `nsis-hooks.nsh:70` bootstrap idempotency only checked `main.cvd` → stale `.cvd` next to newer `.cld` after freshclam. → also check `.cld`.
- **R1-5** `daemon_client.rs:70` `std::thread::sleep` inside async blocked tokio 200 ms/call during pipe storms. → `tokio::time::sleep().await`.
- **R1-6** `state.rs:2778` `reload_engine_inner` panic skipped `ENGINE_RELOAD_IN_PROGRESS=false` reset → flag stuck → all mutating IPC blocked forever. → RAII guard with `Drop`.
- **R1-7** `state.rs:1471` `start_orchestrated_*` overwrote `active_scan`/`scan_live` without checking prior → orphaned uncancellable worker. → reject/queue if a job is Running (all 4 entrypoints).
- **R1-8** `supervisor.rs:247` `is_service_registered` returned true for STOPPED → user `sc stop` = permanent dead. → parse STATE, only RUNNING/START_PENDING.
- **R1-9** `state.rs:2858` `start_watcher` ignored `config.realtime_roots` → custom paths dead. → read config, fallback to hardcoded if empty.
- **R1-10** `quarantine/mod.rs:301/284` `restore_file*` TOCTOU between `is_symlink()` and open → symlink escape from vault. → `FILE_FLAG_OPEN_REPARSE_POINT` (open fails on symlink).

### Round 2 — 8 new fixes (16 cumulative; 424 tests pass)
- **R2-1** `watcher/mod.rs:330` cooldown substring match broke on localized OneDrive (German `Persönlich`). → `path.components()` exact case-insensitive match.
- **R2-2** `ipc/mod.rs:138` pipe retry always `first_instance=true` → permanent fail if orphan holds pipe. → after 10 tries retry with `first_instance=false`.
- **R2-3** `ipc/mod.rs:181` IPC main loop double-`?` killed the whole server on transient fail. → loop with backoff.
- **R2-4** `state.rs:75` env-var secret overwrote disk → GPO injection poisoning. → validate env matches disk; mismatch → keep disk.
- **R2-5** `ipc_auth.rs:27` `Box::leak` per retry + cache-invalidate per call (~64 B/cycle leak). → `OnceLock<Result>`, dedup on cache miss.
- **R2-6** `nsis-hooks.nsh:16` 3 s blind sleep after `sc stop` → delete-pending race broke next install. → poll `sc query` until clean (30 s cap) + sc-delete poll (15 s).
- **R2-7** `lib.rs:612` GUI had no single-instance guard → double-launch = 2 supervisors/runtimes. → `tauri-plugin-single-instance` wired.
- **R2-8** `db/mod.rs:35` schema_version bumped but only `CREATE TABLE IF NOT EXISTS` → upgrades never added columns; "no such column" swallowed. → real per-version `ALTER TABLE` migration framework.

*False alarms cleared in R2:* main.rs StartPending→Stopped (valid SCM transition), tray scan.start (already 6 s timeout), splash timeout (React shows banner), sandbox_dedup eviction (already done), file_identity canonicalize (micro).

### Round 3 — 23 fixes (R3-1..R3-22 + R3-25; R3-9 & R3-17 skipped)
> R3-1..R3-6 fixed in an earlier batch (summarized in aggregate in transcript). R3-7+ detailed:
- **R3-7** orchestrator `longest_duration_ms` racy read-modify-write → `fetch_max`.
- **R3-8** sandbox + ARGUS reader threads hung on `reader.join()` (grandchild-held pipes) → `mpsc` + `recv_timeout`.
- **R3-9** *(skipped — gate already correct for MAX=1)*.
- **R3-10** ETW callback context use-after-free + handle leak → null context before `CloseTrace`, release `trace_handle`.
- **R3-11** scheduler used wall-clock `hour + interval` (broke across midnight/DST/skew) → `Instant::elapsed`.
- **R3-12** YARA `rule_dirs` unreachable via Arc → `RwLock`, `set_rule_dirs(&self)`, auto-cached.
- **R3-13** YARA scan starved reload writer → clone `Arc<Rules>` + drop read-lock immediately.
- **R3-14** FISH `Instant - Duration` panic on early boot → `checked_sub`.
- **R3-15** `last_alert_times` unbounded growth → cap 256 + LRU evict.
- **R3-16** ecosystem fingerprint `try_lock` silently dropped → blocking `lock()`.
- **R3-17** *(skipped — minor `Config::load` I/O per cycle)*.
- **R3-18** update_pipeline tautological local SHA-256 self-verify removed; manifest is sole authority.
- **R3-19** trust_graph `observe_with_signer` TOCTOU on signer drift → single-lock `observe_locked`.
- **R3-20** idle_scanner trim → warn if `trim_ok=false` or working set didn't drop.
- **R3-21** DB migrations wrapped in `BEGIN/COMMIT/ROLLBACK`.
- **R3-22** watcher roots capped at 128.
- **R3-25** IPC secret `create_new` + read-loser path (TOCTOU between two racing daemons).

### Round 4 — Config validation (C1..C23, ~18 concrete)
`Config::validate()` hardening — many were silent security defeats:
- **C1 (CRIT)** `Config::load` now calls `validate()` itself; direct callers previously bypassed kill-switch filtering (e.g. `excluded_detections=[""]` suppressed ALL detections).
- **C3** `scheduled_scan_hour > 23` silently disabled scan → clamped.
- **C4** `idle_scan_cpu_pause_threshold` 0 or >100 → clamped.
- **C5** `idle_scan_disk_latency_pause_ms=0` → permanent pause; min 50 ms.
- **C6** idle scan delay `min > max` → `rand::gen_range` panic; swapped.
- **C7** `idle_scan_max_files_per_session=0` wedge guard.
- **C8** `quarantine_retention_days=0` → instant vault wipe; min 1 day.
- **C9** `realtime_roots` capped at 64 in validate.
- **C10** `update_mirror` strips scheme/paths, length-checked.
- **C11** `log_level` allowlisted.
- **C12** `memory_warning_mb >= memory_critical_mb` reset.
- **C14** `enhanced_signature_provider` allowlisted.
- **C15** `clamav_worker_timeout_sec < 5` reset (1 s timeout failed every scan).
- **C16** refuses drive roots (`C:\`) + system roots (`C:\Windows`, `C:\Users`) in `excluded_paths`.
- **C17** bad-config backup uses timestamp suffix (no overwrite loop).
- **C18** `save()` atomic write via `.tmp` + rename.
- **C20** `powershell_poll_seconds` clamped [5..3600].
- **C23** `expand_vars` word-boundary check (`$USERPROFILEEXT` no longer partial-matches `$USERPROFILE`).

### Round 4 — Convergence engine (CV1, CV4–CV14)
- **CV1** `apply_trust_discount` uses `.max()` so a late zero-discount can't erase an earlier strong discount.
- **CV4 (CRIT)** cap enforcement → **priority truncation** (sort desc, keep strongest until cap, zero rest). Old proportional scaling let weight-1 noise floods dilute a weight-30 ADS finding to ~0.
- **CV5** `add_evidence` clamps per-finding weight at `MAX_SINGLE_POST_WEIGHT=40` (stops `u32::MAX` overflow).
- **CV6** `finalize` uses `saturating_add` fold (was `.sum()` → debug panic / release wrap → cap bypass).
- **CV7** `patch_explanation` raw_post sum → saturating fold.
- **CV8** `attribution` trust_adjustment via i64 intermediate + clamp (was `-(u32 as i32)` → `i32::MIN` negation panic).
- **CV9** `ConvergenceLedger::new` clamps `base_score` to 100.
- **CV11** `apply_trust_discount` drops trust finding entirely when ClamAV positive (no "Trusted, no action" on confirmed malware).
- **CV14** ledger marker upgraded from bare U+200B to `ZWSP+ZWJ+"LDG"+ZWJ+ZWSP` — single ZWSP was trivially injectable via YARA descriptions/persistence names to forge "ledger-sourced" evidence.

### Round 4 — LETHAL class (security)
- **R4-LETHAL-1 (TOTAL AV BYPASS)** `Config::validate()` `excluded_extensions` retain closure ended in `true` — a **no-op** despite the comment. Config with `excluded_extensions=["exe","dll",...]` silently stopped scanning every executable format. → hard-deny list of 30+ exe/script extensions, stripped + loud warn; rejects `*`/`?` globs.
- **R4-LETHAL-2** `is_excluded()` raw `starts_with` with no dir boundary → `C:\Users\Me` also excluded `C:\Users\Mexico\evil.exe`. → require next char to be `\`,`/`, or EOF.
- **R4-LETHAL-3 (THE BIG ONE)** `quarantine.add` had **zero source-path validation**; daemon (SYSTEM) deletes the original → any authed caller could quarantine/delete Defender/EDR binaries, `lsass.exe`, drivers, or sentinelld itself. → `validate_quarantine_source()` rejects OS roots, 17 named security vendors, and own install dir.
- **R4-LETHAL-4** `update.start` no auth → on-demand 5–8 s scan-blind window. → `validate_ipc_auth`.
- **R4-LETHAL-5** `scan.start` (quick) no auth → CPU/disk DoS + cover for payload drops. → auth-gated.
- **R4-LETHAL-6** `settings.get` no auth → leaked `excluded_*`, `trusted_hashes`, `realtime_roots` (blind-drop intel). → auth-gated.

### Round 5 — LETHAL (243/243 green)
- **R5-LETHAL (1-byte file = full AV root hijack)** `detect_root()` switched the entire data root to `CWD/runtime/` if `Cargo.toml`/`crates/` existed in CWD → drop a 1-byte `Cargo.toml` to relocate config, IPC secret, vault key, YARA rules, quarantine. → (1) dev mode requires `SENTINELLA_DEV=1`; (2) `Cargo.toml` must contain `name="sentinelld"`; (3) portable mode requires `is_trusted_install_dir()` (refuses Public/Downloads/Desktop/Temp/profile paths; trusts Program Files / ProgramData\Sentinella / /opt / /usr/local …).

### Round 6 — LETHAL (245/245 green)
- **R6-LETHAL (scan-cache bypass)** `check_with_metadata` cache key was `(path,size,mtime,sig_generation)` — all attacker-controlled. Overwrite a cached-clean file with malware, pad to same size, `SetFileTime()` → cache HIT → ARGUS + ClamAV skipped. → add 128-bit truncated SHA-256 of first 64 KB to the key (verified only on HIT, ~0.1 ms); folded into R3 integrity hash; pre-fingerprint rows rejected. Schema: `ALTER TABLE scan_cache ADD COLUMN content_fp BLOB`.

### Round 7 — LETHAL (245/245 green)
- **R7-LETHAL-1** `quarantine.list` + `detections.list` + `activity.list` + `trust.status` returned attack-staging intel (every caught malware's SHA-256/path/family; scan timing; trusted-signer list) with **no auth**. → all four gated on `validate_ipc_auth`; GUI commands updated accordingly.
- **R7-LETHAL-2** Vault **AES-256 key world-readable** (`Users:R`, mistakenly extended by R3). The key is only ever read by the daemon (SYSTEM); GUI decrypts via IPC. Any logged-in user could decrypt every quarantined sample. → ACL = SYSTEM + Administrators only.

### Round 8 — LETHAL (246/246 green)
- **R8-LETHAL-1** `scan.start` `target` had only length/empty checks → UNC `\\attacker.com\share\` makes SYSTEM daemon emit machine-account NTLM hash → responder → relay → **AD compromise**; also `\\.\PHYSICALDRIVE0` raw-disk DoS, `\\?\GLOBALROOT\…` namespace bypass. → IPC-layer reject bare UNC, long-path UNC, device namespaces, NUL bytes; allow `\\?\C:\…`. Mirror fix on `validate_quarantine_source`.
- **R8-LETHAL-2** `insert_activity` had no length cap / no retention → multi-GB SQLite over months → minutes-long startup / disk OOM. → UTF-8-safe truncation (title ≤256, message ≤2048, category ≤48, severity ≤24, event_id ≤64) + last-10K-row retention.

### Round 9 — LETHAL + DB retention (246/246 green)
- **R9-LETHAL-1** `find_freshclam` checked CWD-relative candidates **first** → SYSTEM exec hijack via dropped `build\...\freshclam.exe`. → anchor all candidates to `current_exe().parent()`.
- **R9-LETHAL-2** `argus_worker::resolve_worker_path` same CWD-fallback exec hijack. → removed all CWD candidates.
- **R9-LETHAL-3** `runtime_integrity` icacls used localized `BUILTIN\Administrators` → silently failed on non-English Windows → world-readable signing key. → raw SIDs `*S-1-5-18` + `*S-1-5-32-544`.
- **R9 DB retention** applied R8-LETHAL-2 pattern to `scans` (last 5K), `detections` (path ≤4096/virus_name ≤256/action ≤64, last 20K), `argus_verdicts` (path ≤4096, findings_json ≤64 KB, last 20K).

### Final module sweeps (247/247 green) — ~9 fixes
- **HIGH** watcher fast-path bypassed `DEBOUNCE_CAP` (small-file `Create` inserted unconditionally) → respect cap, demote to directory-rescan over cap.
- **MED** ecosystem `now_ts - e.timestamp` i64 overflow panic → `saturating_sub`.
- **MED** ecosystem narrative `String::truncate` UTF-8 panic on multibyte boundary → step back to char boundary.
- **MED** calibration DB unbounded + non-transactional `record_detection` → `BEGIN/COMMIT/ROLLBACK` + 50K retention.
- **HIGH** `policy.rs` rate-limit `retry_secs = 60/max_per_minute` truncated to 0 for >60/min buckets → retry storm → floor at 1 s.
- **MED** DB migration version bump persisted even on a **rolled-back** migration → permanent silent schema inconsistency → track highest *contiguously-applied* version, halt on first failure.
- **MED** `etw_intake` ParentId read from wrong offset (`data[4..8]` = high DWORD on x64) → garbage PPIDs, broken lineage → pointer-width-aware offset (`ptr_size+4`).
- **MED** DB/calibration retention tie-break: `ORDER BY ts DESC LIMIT N` dropped arbitrary same-second rows → added secondary `rowid DESC` to all 5 retention DELETEs.
- **LOW** `etw_intake` drive-letter scan `ch >= b'C'` dropped `A:`/`B:` → `is_ascii_uppercase()`.

---

## Part C — Current status & what's next

### ⚠️ Immediate regression to fix (release blocker)
- **`ecosystem::tests::cooling_transition` FAILS** — `crates/sentinelld/src/ecosystem/mod.rs`, **aging** group.
  Last run 246/247. Likely related to the R3-14 / ecosystem `saturating_sub` aging-timestamp work or the
  narrative/aging refactors above. Diagnose whether the test's expectation or the cooling state machine is
  wrong; prefer fixing the logic over weakening the test. Then confirm full suite back to 247/247.

### Biggest systemic hole still open (highest ROI)
- **IPC secret is world-readable** (`ipc_secret` ACL grants `Users:R`, from the R3 GUI-compat fix) — this is
  what makes ~6 of the LETHAL fixes "only as strong as *are you logged in*." **Real fix:** a token broker that
  authenticates the GUI process by parent/session SID instead of a shared file secret. Touches daemon + GUI.
- **IPC pipe ACL grants Authenticated Users (GRGW)** — same root cause. Drop AU → admin-only pipe + GUI UAC
  self-elevate, or per-connection client-SID check.

### Security not yet done
- Updater pubkey rotation / backup key (ship 2 ed25519 keys; no app-signature on enhanced-provider files beyond manifest SHA).
- `runtime/` dir ACL on first-create (if user-mode GUI creates the ProgramData tree before SYSTEM daemon, CREATOR OWNER = user). R5 hardened root *detection*, not dir *creation*.

### Correctness (deferred)
- plm PID-reuse overwrite (`map.insert(pid,node)` keyed on PID only → false lineage on recycled PID; needs start-time/generation disambiguation).
- plm O(n) `min_by_key` eviction per insert under load.
- scans/detections insert error swallow (FK failure loses forensic record; currently by-design fire-and-forget).
- calibration `GROUP BY file_hash` bare columns → nondeterministic FP-candidate metadata.
- fish hardcoded `>=5` ext-mutation threshold (unconfigurable, inconsistent with rename/rewrite thresholds).

### Low / cosmetic
- file_identity second-resolution mtime (content tamper already caught by R6 fingerprint), fish `<` vs `<=`
  one-tick-stale boundary, watcher `Config::load().unwrap_or_default()` silent-corruption fallback (add warn),
  ecosystem recurrence_count==0 under-count + escalation_count inflation (diagnostics-only),
  token-bucket fractional-refill precision loss, orchestrator snapshot non-atomic avg-duration read,
  `StagingMeta.provider_id` always empty.

### Untouched modules (not yet audited — mine these for the remaining ~99 toward the 200 bar)
- `footprint/*` (residency, pressure)
- `convergence.rs` (got R4 pass, not a full 3-way audit)
- `runtime_integrity.rs` (only ACL fix, not full logic)
- `targeting/startup.rs`
- `main.rs` service dispatcher / SCM lifecycle
- `gui/src-tauri/*` beyond the IPC commands already touched
- `nsis-hooks.nsh` full review
- `amsi/ps_bridge.rs` (only `Command` args checked so far)
- `engine/clamav.rs` FFI lifetimes + `cl_engine_free` paths
- `scan/*` full pipeline (ADS, archive limits, recursion bombs)
- All `unwrap()` / `expect()` outside tests

---

## Tally summary

| Bucket | Fixes |
|---|---|
| Shipped v0.1.1–v0.1.5 | ~11 |
| Round 1 | 10 |
| Round 2 (new) | 8 |
| Round 3 | 23 |
| Round 4 — Config (C#) | ~18 |
| Round 4 — Convergence (CV#) | 9 |
| Round 4 — LETHAL | 6 |
| Round 5–9 LETHAL + DB retention | ~10 |
| Final module sweeps | ~9 |
| **Pre-0.1.6 campaign total (agent tally)** | **≈101** |

**Goal: ≥200 (meets-expectations). Remaining: ~99+. Higher is encouraged.**
First action for the next agent: **fix `cooling_transition`, restore 247/247, then resume auditing the untouched modules above** — starting with the IPC auth broker (closes the world-readable-secret class).

# Sentinella v0.1.12 — Implementation Round Matrix (workstream A: MATRIX)

Audit spine for the gated implementation round on
`docs/EXTERNAL_REVIEW_v0.1.12.md`. Every row below was re-verified against
**current code** (file opened, line read) — the review's claims were treated
as claims, not facts.

**Tree state caveat (material):** line numbers refer to the working tree on
2026-07-30. Since commit `5a32ee7` the working tree carries **uncommitted,
in-flight work from parallel agents**: a shared
`sentinella_common::etw_props::EventTracePropsStorage` helper now used by
`sentinelld/src/plm/etw_intake.rs` and `sandboxd/src/etw.rs` (alignment-UB
fix only — **not** the F-1 system-logger fix), and a new untracked
`crates/argus/src/layers/framework/` directory (F-7 structural installer
anchors, in progress). Rows distinguish **landed** (committed) from
**in-flight** (uncommitted) state.

Landed since `b387776` (do not redo):
- `e9f980d` — F-9 watch root (`%LOCALAPPDATA%\Programs`)
- `8a18ed6` — F-8 threshold docs/comments + `scripts/check-threshold-docs.ps1`
- `5a32ee7` — F-10 per-principal IPC connection fairness (`ipc/fairness.rs`)

---

## 1. Verification matrix

Status legend: **confirmed** (claim holds in current code) · **strengthened**
(worse than claimed) · **narrowed** (real but smaller than claimed) ·
**stale** (already fixed — landed) · **in-flight** (fix exists but
uncommitted) · **refuted** · **still unverified**.

| # | Finding | Original claim | Current code path (verified) | Status | Severity | Implementation decision | Required test | Fix commit |
|---|---------|----------------|------------------------------|--------|----------|-------------------------|---------------|------------|
| F-1 | ETW kernel session delivers zero events; silent-zero invisible | `SentinellaPLM` not a system logger → `EnableFlags` inert → 3 ETW-fed detectors dead; watchdog can't fire | `plm/etw_intake.rs:170` (`LogFileMode = 0x100` REAL_TIME only), `:179` (EnableFlags PROCESS\|IMAGE_LOAD\|FILE_IO_INIT), `Wnode.Guid` never assigned anywhere in the file; give-up only on error 5 (`:111-124`); watchdog only boosts snapshot on `etw_gave_up` (`plm/mod.rs:597-616`); snapshot 6× interval in ETW mode (`plm/mod.rs:568`); no zero-event alarm exists anywhere | **confirmed** — also in sandboxd + etw_probe (C-1). NOTE: module comment (`etw_intake.rs:7-18`, uncommitted) now *describes* the fixed architecture (SYSTEM_LOGGER_MODE + private GUID) while the code still doesn't implement it — comment/code mismatch | HIGH | Apply review §4.4: `EVENT_TRACE_SYSTEM_LOGGER_MODE` + fresh private session GUID + 1450 give-up + any-persistent-failure give-up + zero-event alarm (~2 min) + fix misleading "kernel trace session started" log (`:219`). Keep snapshot path untouched | Live elevated box per review §4.5: 5 spawned processes → `etw_events ≥ 5`; zero-event alarm fires when stream is empty; 8-logger slot exhaustion → clean give-up. Unit: none possible (FFI) — harness is `scripts/collect-weedhack-runtime-diagnostics.ps1` before/after | TBD |
| F-2 | Uncapped MimeValidation (45) + Deception (35) convicts at 76 with 2 cheap signals | cap table omits Mime | `argus/src/engine.rs:982-988` caps (no CAP_MIME), `:1010-1016` apply_cap calls (MimeValidation absent); `layers/mime.rs:51,67,82` weight 45 Critical | **confirmed** | HIGH | Cap/fold MimeValidation: re-weight 45→25–35 or add `CAP_MIME` and/or fold into Deception cap. Re-calibrate against the 85 bar, not 76 (F-8) | Harness probes (`crates/argus/examples/eval.rs`): p2 (MZ+`%PDF-` renamed `.pdf`) must land < 76 post-change; p4-style script attack must still convict ≥ 85 ARGUS-only; clean-corpus run must not regress | TBD |
| F-3 | Unsigned-system-path −20 discount is a laundering primitive + separator-fragile | admin malware drops unsigned binary in System32 → −20, no sig check; forward slashes lose discount | `argus/src/layers/authenticode.rs:316` (`if is_windows_system_path(path) { 20 } else { 0 }`); `:354-382` prefix table — lowercase compare against backslash prefixes with `rest.starts_with('\\')` → a `C:/Windows/System32/...` (forward-slash) path fails the prefix match and silently loses the discount; discount applied as `max(reputation, authenticode)` post-cap (`engine.rs:1020-1021`) | **confirmed** (both the primitive and the separator inconsistency) | HIGH | Reduce −20→−10 and/or gate on catalog-signature verification eligibility; normalize `/`→`\` before prefix match; pair with tuning the noisy structural rules the discount currently masks | Harness: same unsigned binary under System32 (backslash vs forward slash) must score identically; clean System32 corpus FP rate re-measured after discount shrink | TBD |
| F-4 | Unreadable/blocked files verdict "Clean" (fail-open) | EICAR on disk (os error 225) → score 0, Clean | `argus/src/engine.rs:777-805` `error_verdict` still stamps `Verdict::Clean` score 0 with weight-0 Info "Analysis incomplete: …" finding; daemon side: `argus_analysis_error` (`ipc/state.rs:6470-6474`) detects the marker; startup-scan cache guard (`state.rs:5403-5409`) and DEEP_AUDIT's "read-failure verdicts never recorded as Clean" | **narrowed** — engine *label* still says Clean (user-visible in `argus.analyze`/harness), but daemon scan paths no longer cache or record error verdicts as clean | MEDIUM | Introduce distinct `Unknown/Error` verdict in `argus::verdict` (keep the marker string for back-compat during transition); surface "could not be scanned" in GUI instead of green-clean | Harness: read-denied fixture → verdict `Unknown`, never `Clean`; daemon test: `argus_analysis_error` still matches during transition; GUI file-scan of unreadable file shows non-clean state | TBD |
| F-5 | Orphaned ETW session leak on every shutdown | "previous session is never stopped on shutdown" (80/80 boots show stale cleanup) | Stop path **exists**: stop thread in `run_etw_session` polls `running` every 500 ms and calls `ControlTraceW(STOP)` (`etw_intake.rs:276-295`). But `PlmMonitor::Drop` only sets the flag — **no join** (`plm/mod.rs:841-845`), so a fast service-stop/process-exit beats the 500 ms poll → session orphaned → next boot's error-183 cleanup (`:195-211`) fires. sandboxd (`etw.rs:122-149`) and etw_probe (`main.rs:43-93`) have proper synchronous `SessionGuard` Drop | **narrowed / overstated** (canonical #13): "never stopped" is false — it's an unsynchronized shutdown race, not a missing stop. Unclean exits still always leak; with F-1's system-logger fix each leak consumes one of 8 system-logger slots | MEDIUM | Join (or bound-wait for) the ETW thread in `PlmMonitor::Drop`/daemon shutdown so the stop thread's `ControlTraceW(STOP)` lands before exit; keep error-183 stale cleanup as defense-in-depth | Hard to unit-test (FFI). Live: clean service stop → `logman query -ets` shows no `SentinellaPLM`; kill -9 → next boot reclaims via 183 path (existing behavior, keep) | TBD |
| F-6 | YARA FP on stock `wmi.dll` | "WMIC process creation" rule fires on DLL content, w22 | `runtime/argus/rules/yara/sentinella_lolbins.yar:45-59` — condition `$wmic and $proc and $call and $create` over raw file content; no filetype/MZ/script gate | **confirmed** | LOW | Restrict rule to script/text filetypes or require PE-executable characteristics + extension gate; add stock `wmi.dll` to the FP regression corpus | Harness clean-corpus run: `wmi.dll` scores 0 from YARA; a `.ps1`/`.bat` containing `wmic process call create` still fires | TBD |
| F-7 | Installer-marker forgery + 1-byte mutation = total evasion | bare ASCII markers anywhere in a PE earn Structural/Packer ÷3 + installer-YARA ÷2; discount runs before dedup/caps | `argus/src/engine.rs:1183-1253` — `contains = data.windows(n).any(...)`; `has_nsis` (`"Nullsoft Inst"`), Inno, WiX, InstallShield, Advanced Installer all bare full-buffer substrings for PEs; discount applied at `:497-528`, aggregation at `:560` (discount first — confirmed). OLE2/MSI branch already extension-only (`:1204-1216`, landed in deep-audit round 2). 85-bar interaction: F-8 | **confirmed** (PE branch exactly as claimed; OLE2 branch fixed earlier). **In-flight:** untracked `crates/argus/src/layers/framework/` = parallel agent building structural anchors | CRITICAL | Structural framework detection: NSIS overlay/CRC anchor, Inno signature at known offset; bare ASCII markers demoted to weak hint. Coordinate with the in-flight `layers/framework/` work — do not duplicate | Harness: nsis-probe (notepad.exe + `Nullsoft Inst` + pad) must NOT earn installer flag; real NSIS/Inno installers must keep it; post-mutation heuristic-only score of a real sample ≥ 85 must survive marker stripping | TBD |
| F-8 | Documented quarantine threshold wrong: ARGUS-only needs 85 | 76–84 ARGUS-only silently dropped: no detection row, no quarantine, scan reported clean; only forensic ARGUS verdict persisted | `ipc/state.rs:6517-6521` (`clamav_infected ? argus.is_threat() : argus.score >= 85`); comment block `:6508-6516` (landed `8a18ed6`); forensic persist at `:2133`, `:2443`, `:5910`, `:5924`. **Strengthening found this round:** 76–84 ARGUS-only is also affirmatively **cached as clean** (`state.rs:5406-5409` — `is_threat=false` + not error → `record(clean=true)`), making the suppression sticky until sig-generation bump or content change | **strengthened** (sticky via scan cache) + docs landed (`8a18ed6`; guard script passes — C-8) | HIGH | Docs done. Behavior decision (orchestrator gate): alert-but-don't-quarantine 76–84 ARGUS-only (detection row, no quarantine), and/or exclude sub-85 ARGUS-only results from the clean cache. Recommend: detection row with `action=notify` + no clean-cache write below 85 | Unit: `unify_detection_filtered` 84→`(false,None)`, 85→threat (exists, `state.rs:6808+`); new: cache test asserting 76–84 ARGUS-only is NOT recorded clean; scan-path test that a notify row is created if that decision lands | TBD |
| F-9 | Realtime watch gap: `%LOCALAPPDATA%\Programs` not watched | verified live absent from `watcher.status` roots | `ipc/state.rs:3872-3923` — `start_watcher` enumerates `C:\Users\<u>\AppData\Local\Programs` via `user_profile_subdirs` (skips Default/Public, missing dirs, case-insensitive dedup); config env-expansion `%LOCALAPPDATA%\Programs` (`config/mod.rs:848`, test `:1809-1817`); tests at `state.rs:7385-7410` | **stale — FIXED, landed `e9f980d`** | HIGH | Done. Remaining nit: verify live `watcher.status` on the production box now lists the per-user Programs roots | Live `watcher.status` shows per-user `AppData\Local\Programs`; drop a file there → realtime scan fires | e9f980d |
| F-10 | Management-plane starvation via 64-connection parking | one principal parks all 64 permits, shed rejects victim not flooder | `ipc/fairness.rs` (landed `5a32ee7`): per-SID cap 8, shared capped `Unidentified` bucket 16 (no PID fallback — correct), global 64 unchanged (`ipc/mod.rs:190`); wired at `mod.rs:199,333-350`; invariant test `2×8+16 ≤ 64` (`fairness.rs:272-279`) | **stale — FIXED, landed `5a32ee7`** | MEDIUM | Done. Distinct residual: the **global rate limiter** is still identity-blind (C-5) — do not conflate | Live soak: 8 parked connections from user A → GUI (same SID, 9th conn) shed — expected; user B / elevated GUI still served. GUI connection-pattern regression pass | 5a32ee7 |
| F-11 | World-readable-secret tier leaks the blind-spot map | `settings.get`/`watcher.status`/config readable by any local user → recon package | `ipc/state.rs:243-252` (`ipc_secret` deliberately `*S-1-5-32-545:(R)`); policy unchanged: `watcher.status` auth_read (`policy.rs:251`), `detections.list` auth_read (`:263`), `settings.get` (`:276`), `settings.get_full` (`:285`), `diagnostics.export` auth_action (`:362-365`). `client_auth::decide` allows the console user unelevated by design | **confirmed** — unchanged | MEDIUM | Orchestrator decision (GUI-compat risk — GUI reads settings unelevated): redact `watched_roots`/exclusions/update-cadence from unelevated responses vs full elevation gate. Recommend redaction over gating | GUI regression: Settings page renders with redacted fields; IPC probe: unelevated `watcher.status` no longer enumerates roots; elevated still does | TBD |
| F-12 | `update.start` churn: rolling cache invalidation + compile spikes | exit-0 (even "up-to-date") → unconditional engine reload → full scan-cache + trusted-cache wipe + ~2× compile RAM; ScanControl 10/min shared | `ipc/state.rs:4268-4284` — `if success { … reload_engine() }` unconditional; `reload_engine_inner` does `scan_cache.invalidate_all()` (`:3789`) + `argus.trusted_cache.invalidate()` (`:3793`) + fail-closed 2× compile (`:3775-3794`); policy: `update.start` = auth_action ScanControl 10/min burst 3 (`policy.rs:302-310`) | **confirmed** — unchanged | MEDIUM | Parse freshclam's "up-to-date"/no-change result and skip `reload_engine()` on no-change; optionally re-gate `update.start` (challenge or separate tighter bucket) | Unit: freshclam-output parser no-change → reload skipped, changed → reload runs; live: 10/min `update.start` loop no longer wipes caches when DB unchanged | TBD |
| F-13 | Named-pipe squatting / orphan-attach | squatter pre-creates `\\.\pipe\sentinelld` during downtime; service attaches after 10 failed first-instance creates; no client-side server authentication | `ipc/mod.rs:147-182` — attach fallback present verbatim ("attached to existing pipe (orphan owner)", `:162`); `GetNamedPipeServerProcessId` appears nowhere in the tree (grep-verified) | **confirmed** — unchanged | MEDIUM | Never attach to a pipe whose owner SID isn't SYSTEM/this-service (fail loudly → service error instead); clients verify server PID/image signer. Note: orphan-GUI flows rely on attach — needs a migration path (kill orphan, don't join it) | Live: plant a medium-IL pipe pre-service-start → service must refuse + log, not attach; legit orphan-GUI recovery path still works | TBD |
| F-14 | `argus.analyze` / `runtime.scan_buffer`: oracles as SYSTEM | guided-evasion oracle + SYSTEM file-read oracle; per-layer weights returned unelevated | `runtime.scan_buffer` handler returns per-finding `layer`/`weight`/`description` (`ipc/mod.rs:1305-1311`), auth = world-readable secret (`:1226`); policy auth_action MemoryScan (`policy.rs:334-337`). `argus.analyze` auth_action ScanControl (`policy.rs:320-323`), **not** elevation-gated. Deep audit already closed the UNC/device-path branch (shared `validate_local_scan_path`) — local-file stat/read-as-SYSTEM oracle remains | **confirmed**, narrowed only on the UNC sub-claim | MEDIUM | Elevation-gate `argus.analyze`; coarsen `runtime.scan_buffer` for unelevated callers (verdict + score, no per-layer weights); keep full detail elevated | IPC probe: unelevated `scan_buffer` response has no `weight` fields; unelevated `argus.analyze` → `-32005`; GUI/dev-console regression pass | TBD |
| F-15 | First-run-as-user ACL residue collapses file protections | MSI sets no ACLs; daemon ACLs specific files, never the data root; installing user can rewrite cache/config/DBs and read vault key | `installer/windows/Product.wxs` — zero `Permission` elements (grep-verified); data root created by bare `create_dir_all` (`paths.rs:201`, root at `:275-276`); per-file icacls only: `ipc_secret` (`state.rs:243`), `.vault_key` (`quarantine/mod.rs:156`), integrity key (`runtime_integrity.rs:632`) — nothing ACLs `C:\ProgramData\Sentinella` itself or `...\state` | **confirmed** (see also C-3, C-4) | HIGH | Set explicit DACL on the data root at install (MSI `Permission`) AND re-assert/repair at service start when drifted (SYSTEM+Admins only); re-ACL vault key on read, not only on create (C-4) | Clean-VM MSI install → `icacls C:\ProgramData\Sentinella` shows SYSTEM/Admins only; tamper ACLs → service start repairs; GUI still functions | TBD |
| C-1 | ETW inert in **multiple** components (canonical) | review covered sentinelld only | **sandboxd**: same inert config — `LogFileMode = 0x100` REAL_TIME only (`sandboxd/src/etw.rs:207`), no `Wnode.Guid`, EnableFlags PROCESS\|IMAGE\|REGISTRY\|NETWORK (`:204-206`); StartTraceW succeeds → `backend_used = "etw_kernel_session"` (`:160`) with zero events; polling fallback only on start *error* (`:74-86`), never on silent-zero → **every sandbox detonation's ETW telemetry is silently empty**. **etw_probe**: same config (`etw_probe/src/main.rs:216-220`); prints `StartTraceW: SUCCESS` (`:259`) then `Events received: 0` (`:427`) — a diagnostic that cannot detect the bug it exists to probe | **confirmed** | HIGH (sandboxd) / LOW (probe) | Same system-logger fix, shared via the in-flight `sentinella_common::etw_props` helper (extend it to carry session-GUID + mode flags so the three call sites can't drift again); sandboxd should treat `events==0 at timeout` as backend failure → fall back to polling; etw_probe should print a loud zero-event warning | Live: detonate a spawning sample → `processes_spawned` non-empty from `etw_kernel_process` source; probe run under activity prints events > 0 or a loud warning | TBD |
| C-2 | Aligned-storage UB in `etw_intake.rs` (canonical) | `Vec<u8>` (align 1) cast to `*mut EVENT_TRACE_PROPERTIES` (align 8) = misaligned-reference UB | **At HEAD**: confirmed — `vec![0u8; props_size]` cast at four sites. **In working tree (uncommitted): FIXED** — `sentinella_common::etw_props::EventTracePropsStorage` (`crates/sentinella-common/src/etw_props.rs`, new) used in `etw_intake.rs` and `sandboxd/src/etw.rs`; etw_probe already had its own `aligned_props_storage` (`etw_probe/src/main.rs:39-41`, landed in deep audit) | **in-flight fix (uncommitted)** — was confirmed at HEAD | MEDIUM | Land the working-tree helper (belongs to the parallel ETW agent — flag to orchestrator, do not duplicate); then build the F-1 fix on top of it | Compile + existing suites; miri-style review of the helper's SAFETY comment; live session start still works | TBD |
| C-3 | Data-root DACL missing (canonical) | no ACL on `C:\ProgramData\Sentinella` at install or first run | Verified: no DACL write targets the root anywhere (`Grep BUILTIN|icacls|SDDL` over sentinelld → only per-file); MSI has no `Permission` elements; root created at `paths.rs:201` | **confirmed** (same root cause as F-15; tracked separately per canonical list) | HIGH | Same as F-15 — one fix covers both rows | Same as F-15 | TBD |
| C-4 | Vault-key DACL creation-only (canonical) | `.vault_key` ACL applied only when the key file is first created | `quarantine/mod.rs:83-89` — existing-key fast path returns **without** `restrict_file_permissions`; ACL applied only at `:109` (create path). If the file was created by a user-context process (F-15 history) or ACLs drift, nothing repairs them | **confirmed** | MEDIUM | Call `restrict_file_permissions` (or a cheaper verify-then-fix) on the existing-key path too — idempotent, cheap relative to quarantine I/O | Test: pre-create `.vault_key` with permissive ACL → `get_vault_key_in` → ACL now restricted (assert via icacls or ACL read API) | TBD |
| C-5 | IPC **global rate limiter** identity-blind — DISTINCT from F-10's connection cap (canonical) | rate buckets are global; one caller can drain ScanControl (10/min) starving every other client's `scan.start`/`update.start`/`argus.analyze` | `ipc/policy.rs:86-126` — `RateLimiter { buckets: HashMap<RateBucket, BucketState> }`, one token bucket per class for the whole daemon, no principal key; checked centrally at `ipc/mod.rs:723`. F-10's fix keyed *connections* by SID; *requests* are still identity-blind | **confirmed** — separate, unfixed issue | MEDIUM | Per-principal (SID-keyed, reuse accept-time identity from `client_auth`) sub-buckets for ScanControl/MemoryScan, or a global+per-principal dual check mirroring the connection model; keep bucket sizes from `bucket_config` (`policy.rs:65-84`) | Unit: two principals — A drains ScanControl to 429, B still served; burst semantics unchanged within a principal | TBD |
| C-6 | `ProcessNode.command_line` is `None` at **all** production construction sites (canonical) | command-line-based chain detection never fires in production | Production sites, all `command_line: None`: `plm/etw_intake.rs:437`, `plm/etw_file_io.rs:527,541`, `plm/etw_image_load.rs:677`, snapshot `plm/mod.rs:954` ("ToolHelp32 doesn't provide cmdline"), `plm/weedhack_http_intake.rs:650`, `plm/weedhack_image_load.rs:684,695,706`, `plm/weedhack_etw_adapters.rs:185`. Only *test* constructors set `Some` (`weedhack_runtime.rs:315-337`). Consumer `weedhack_runtime.rs:185` (`node.command_line.as_deref().unwrap_or("")`) therefore always matches empty | **confirmed** | MEDIUM | Populate cmdline: WMI `Win32_Process.CommandLine`, `NtQueryInformationProcess` PEB read, or (post-F-1) kernel process-start event v3+ CommandLine field; cheapest correct first step is the snapshot path via WMI | Unit: `evaluate_chain` with populated cmdline fires the Pjibf/cmdline signals (tests exist with synthetic nodes); live: snapshot path records non-empty cmdline for a spawned process | TBD |
| C-7 | Session-leak claim overstated (canonical #13) | review F-5 said "never stopped on shutdown" | See F-5 row: stop thread exists (`etw_intake.rs:276-295`); real defect is the no-join `Drop` (`plm/mod.rs:841-845`) + unclean-exit leak | **narrowed** — folded into F-5 decision | MEDIUM | As F-5 | As F-5 | TBD |
| C-8 | "76 docs" claim corrected (canonical #15) | no shipped doc may tie quarantine to 76 without naming the 85 ARGUS-only bar | `scripts/check-threshold-docs.ps1` executed this round: **PASS — "no doc presents 76 as the universal quarantine threshold (29 files checked)"**; invariant comment corrections landed in `verdict.rs:437-447`, `profile.rs`, `state.rs:6508-6516` (commit `8a18ed6`, "NO behavioral change") | **verified corrected** (guard green) | — | Keep guard in CI/pre-commit; any future threshold doc edit must run it | Re-run `scripts/check-threshold-docs.ps1` after every threshold-touching commit in this round | 8a18ed6 |
| C-9 | ≥ 85 ARGUS-only bar is intentional (canonical) | state.rs comment documents the split as deliberate FP protection | `ipc/state.rs:6508-6516` — comment states 76–84 ARGUS-only "labeled Malicious … but NOT a detection here … prevents quarantining legitimate installers"; `8a18ed6` commit message: "NO behavioral change: the intentional [split]" | **verified intentional** — but see F-8 strengthening: the *silent+sticky* aspect (cached clean) is a behavior decision still owed | — | Orchestrator: ratify 85 bar as-is, or adopt F-8's alert-76–84 decision. Calibration workstream must target 85 | — | TBD |

### Refuted / defense-held items (from review §"Attacks refuted" — spot-checked)

- ETW stop/flush from medium IL — requires admin (review VERIFIED err 5); code requires the session-control privilege. Holds.
- Cache poisoning — `scan/cache.rs` per-entry keyed hash + `sig_generation` + fail-to-rescan (`:600-664`); holds.
- Vault read/plant — production ACL SYSTEM/Admins (`quarantine/mod.rs:151-168`), blobs AES-256-GCM; holds, modulo C-4 (creation-only) + F-15 (residue).
- Service stop / process kill from medium IL — SDDL + SYSTEM process DACL; not re-verified this round (accepted from review).

---

## 2. ETW architecture map — current vs intended

All three components share the same broken edge: **provider enablement is
inert** — `EnableFlags` is documented by Microsoft as valid *only for system
loggers*, and no component sets `EVENT_TRACE_SYSTEM_LOGGER_MODE` or a session
GUID. Sessions start, consumers block on an empty stream, nothing alarms.

### sentinelld (daemon, `SentinellaPLM` session)

| Stage | Current (file:line) | Intended | Edge |
|---|---|---|---|
| Spawn | `plm/mod.rs:547` `start_etw_intake` → thread `plm-etw`; mode = `Etw` if the *thread* spawns (`:552-554`) | same | OK |
| Session creation | `etw_intake.rs:144` `run_etw_session`; props via aligned storage (in-flight, `:165-169`); `LogFileMode = 0x100` REAL_TIME only (`:170`); `EnableFlags = PROCESS\|IMAGE_LOAD\|FILE_IO_INIT` (`:179`); **`Wnode.Guid` never set**; `StartTraceW` (`:187-193`) | `REAL_TIME \| EVENT_TRACE_SYSTEM_LOGGER_MODE` + fresh private session GUID in `Wnode.Guid` | **BROKEN** — kernel delivers nothing; `EnableFlags` inert |
| Provider enablement | none (deliberately no `EnableTraceEx2` — correct for kernel MOF flags, see module comment `:13-18`) | via `EnableFlags` — valid only once the session is a system logger | **BROKEN** (same edge as above) |
| Consumer | `OpenTraceW` (`:236`) + `ProcessTrace` blocking (`:297`) + `etw_event_callback` (`:330`) | same | works but starved — blocks on empty stream forever |
| Processing | dispatch: ImageLoad → `etw_image_load` (`:344-349`), FileIo → `etw_file_io` (`:356-361`), process-start → parse + `record_process` (`:363-442`) | same | dead in production (BrowserInjection, WalletHarvest, signer verify unreachable — `plm/mod.rs:500-517` caller chain) |
| Health/watchdog | `etw_gave_up` only on error 5 ×5 (`:111-124`); watchdog boosts snapshot only on `gave_up` (`plm/mod.rs:597-616`); snapshot 6× interval in ETW mode (`:568`); **no zero-event alarm** | give-up on any persistent failure (incl. 1450 slot exhaustion) + `running && events==0` for ~2 min → alarm + snapshot boost | **BROKEN** — silent-zero is invisible; snapshot stuck at 30 s cadence |
| Shutdown | stop thread polls `running` 500 ms → `ControlTraceW(STOP)` (`etw_intake.rs:276-295`); `PlmMonitor::Drop` sets flag, **no join** (`plm/mod.rs:841-845`) | join the ETW thread during daemon shutdown so STOP lands before exit | **PARTIAL** — stop exists but racy → orphan on fast/unclean exit (F-5) |
| Restart | outer loop retries with backoff 1→30 s (`:92-138`); error 183 → stop stale + retry (`:195-211`) | same + 1450 treated as give-up | OK for errors; blind to silent-zero |

### sandboxd (`SentinellaSandbox` session, per detonation)

| Stage | Current (file:line) | Intended | Edge |
|---|---|---|---|
| Spawn | `sandboxd/src/main.rs:647-648` thread → `etw::monitor_process_until` (`etw.rs:68`) | same | OK |
| Session creation | `etw.rs:151` `etw_kernel_monitor`; `LogFileMode = 0x100` REAL_TIME only (`:207`); EnableFlags PROCESS\|IMAGE\|REGISTRY\|NETWORK (`:204-206`); no `Wnode.Guid`; `StartTraceW` (`:218-224`); 183 → stop+retry once (`:226-273`) | system-logger mode + private GUID (shared helper) | **BROKEN** — zero kernel events per detonation |
| Consumer | `OpenTraceW` (`:294`) + `ProcessTrace` on thread (`:300-305`) | same | starved |
| Processing | callback `:421`: process-spawn (`:460`), TCP (`:536`), image load (`:568`), registry persistence (`:602`) → `EtwReport` | same | dead — report empty but labeled `backend_used = "etw_kernel_session"` (`:160`) |
| Fallback | polling only when `StartTraceW`/`OpenTraceW` **errors** (`:74-86`) | also fall back on `events == 0` at timeout (silent-zero detection) | **BROKEN** — silent success masks inertness |
| Shutdown | `SessionGuard` synchronous stop, panic-safe Drop (`:122-149`, `:313`) | same | **OK** (model for sentinelld's F-5 fix) |
| Restart | none within a detonation; fresh session next detonation (fixed name → 183 reclaim) | same | OK |

### etw_probe (diagnostic, `SentinellaProbe_<pid>`)

| Stage | Current (file:line) | Edge |
|---|---|---|
| Session creation | `main.rs:197-255`: REAL_TIME only (`:216`), EnableFlags PROCESS (`:220`), no GUID; 183 retry (`:274-322`); aligned storage (`:39-41`) | **BROKEN** — same inert config |
| Consumer | `try_open_trace` (`:374`) + callback counter (`:357-372`) + `ProcessTrace` thread (`:414-418`) | starved |
| Verdict | prints `StartTraceW: SUCCESS` (`:259`) then `Events received: 0` (`:427`) | **BROKEN** — reports success for the exact failure it exists to detect; needs a zero-event loud warning |
| Shutdown | `SessionGuard` Drop (`:43-93`) | OK |

**Summary of broken edges (all three):** (1) session config — not a system
logger, EnableFlags inert; (2) no silent-zero detection anywhere (watchdog,
fallback, and probe all key on hard errors only); (3) sentinelld-only: shutdown
stop is unsynchronized (no join). The intended post-fix topology is one shared
`sentinella_common::etw_props` builder (already in flight, uncommitted) +
`EVENT_TRACE_SYSTEM_LOGGER_MODE` + per-component private session GUIDs + a
zero-event alarm that triggers the existing snapshot/polling fallbacks.

---

## 3. 76/85 decision table (workstream V input) — every cell from code

Sources: `argus/src/verdict.rs:516-522` (`from_score`: 0 Clean · 1–25
LowSuspicion · 26–50 Suspicious · 51–75 HighSuspicion · 76+ Malicious),
`verdict.rs:449-450` (`is_threat` = Malicious label, i.e. 76+),
`ipc/state.rs:6502-6526` (`unify_detection_filtered`: ClamAV hit → threat
always; ARGUS-only → `score >= 85`), name synthesis `state.rs:6528-6560+`
(ClamAV name + `[ARGUS: n/100]` suffix iff `score > 50`, `:6531-6533`),
clean-cache write `state.rs:5406-5409`, forensic persist `state.rs:2133, 2443,
5910, 5924`, auto-quarantine e.g. `state.rs:5420-5425` (startup) and the
watcher unify site `watcher/mod.rs:798`, GUI `Scan.tsx:474-480, 579-592,
626-642`, GUI detection/verdict feeds `gui/src/api/sentinella.ts:85, 244`.

Note: the 76–77 vs 78–84 split has **no code-level distinction** — verified by
reading `unify_detection_filtered` and `from_score` end to end; both bands
behave identically. The split exists only in the review's probe data (p4 = 78).

### ARGUS-only (no ClamAV hit)

| Score | Engine label | Detection row | Quarantine | Scan verdict / cache | UI visibility |
|---|---|---|---|---|---|
| < 76 | Clean / LowSuspicion / Suspicious / HighSuspicion per band | No | No | Reported clean; **cached clean** (`state.rs:5408`) | Green "file clean" card; ARGUS card shows score + band label (amber border if score > 25, `Scan.tsx:581`); forensic record via `get_argus_verdicts` |
| 76–77 | **Malicious** | **No** | **No** | Reported clean; **cached clean** | Green "file clean" main card **+ red "Malicious" ARGUS badge + score/100** (`Scan.tsx:592` vs `:634-642`) — contradictory UI; forensic record only |
| 78–84 | **Malicious** | **No** | **No** | Reported clean; **cached clean** | Identical to 76–77 (no code distinction) |
| 85+ | Malicious | **Yes** — ARGUS-only synthesized name (`Stealer.*`/`Suspicious.<Layer>` etc., `state.rs:6537+`) | **Yes** — auto-quarantine at all unify call sites | Threat; not cached clean | Red threat card + virus name + quarantine affordance; appears in `get_detections` |

### ClamAV hit (any ARGUS score)

| Score | Engine label | Detection row | Quarantine | Scan verdict / cache | UI visibility |
|---|---|---|---|---|---|
| < 76 | per band | **Yes** — ClamAV name, no ARGUS suffix if score ≤ 50 (`state.rs:6531-6533`) | **Yes** | Threat | Red threat card with ClamAV name |
| 76–77 | Malicious | Yes — ClamAV name + `[ARGUS: n/100]` | Yes | Threat | Same |
| 78–84 | Malicious | Yes — ClamAV name + suffix | Yes | Threat | Same |
| 85+ | Malicious | Yes — ClamAV name + suffix | Yes | Threat | Same |

### Installer-classified (`is_known_installer` true)

Not a separate unify input — acts **only through score reduction** before
dedup/caps: Structural/Packer ÷3, installer-class YARA ÷2
(`engine.rs:497-528`, marker set `:1183-1253`). Read the ARGUS-only table at
the **post-discount** score. Consequences: an installer-classified file needs
a pre-discount heuristic score well above 85 to be quarantined (the review's
evasion math: 90 → ≈36); a real installer scoring 76–84 post-discount gets
the same silent-drop + clean-cache treatment (intended FP protection per
`state.rs:6508-6516`). ClamAV hits are unaffected — signature detection
bypasses the discount entirely.

### System-path-discounted (unsigned binary under `C:\Windows\…` etc.)

Also score-only: −20 as `max(reputation, authenticode)` discount after caps
(`authenticode.rs:316`, applied `engine.rs:1020-1021`; path table
`authenticode.rs:354-382`, backslash-prefix only — forward-slash paths lose
it, F-3). Read the ARGUS-only table at the post-discount score: an 85+ raw
score drops to 65–84 → Malicious-labeled but silently dropped + cached clean.
ClamAV hits unaffected.

### The one-line summary for workstream V

Engine *labels* at 76 (`verdict.rs:521-522`); the daemon *acts* at 85 for
ARGUS-only (`state.rs:6520`); 76–84 ARGUS-only is dropped **and affirmatively
cached as clean** (`state.rs:5408`), while the GUI still renders the red
"Malicious" ARGUS badge next to a green "file clean" card (`Scan.tsx:592,
634-642`). Any re-calibration, alert-76–84 feature, or threshold-doc change
must target 85 and keep `scripts/check-threshold-docs.ps1` green.

---

## Verification method (what was actually done)

- Read end-to-end: `EXTERNAL_REVIEW_v0.1.12.md`, `HANDOFF.md`,
  `PROJECT_SUMMARY.md`, `DEEP_AUDIT_2026-07.md`.
- Opened and read every cited code path at its current line: `etw_intake.rs`
  (full), `sandboxd/src/etw.rs` (full), `etw_probe/src/main.rs` (full),
  `state.rs` (unify, update/reload, cache-write, ACL, watcher-roots, persist
  sites), `policy.rs` (buckets + method table), `fairness.rs` (full),
  `mod.rs` (pipe create/attach, scan_buffer, fairness wiring), `engine.rs`
  (caps, installer detection + discount, error_verdict), `mime.rs`,
  `authenticode.rs` (discount + path table), `verdict.rs` (from_score,
  is_threat), `quarantine/mod.rs` (vault key + ACL), `paths.rs` (data root),
  `Scan.tsx` (verdict display), `sentinella_lolbins.yar`.
- Grep-verified absences: `EnableTraceEx2` (none in crates), `Wnode.Guid`
  assignment (none), `GetNamedPipeServerProcessId` (none tree-wide),
  `Permission` elements in `Product.wxs` (none), zero-event alarm (none).
- Executed `scripts/check-threshold-docs.ps1` → PASS (29 files).
- `git log`/`git diff`/`git status` to separate landed (`e9f980d`, `8a18ed6`,
  `5a32ee7`) from uncommitted in-flight work (`etw_props` helper,
  `layers/framework/`).
- Not re-verified live (no elevated box used this round): the literal
  `events_seen == 0` counter, live `watcher.status` root list, service SDDL.
  These remain as stated by the review with code-side corroboration.

---

## Fix-commit map (round close)

Filled at round close; the authoritative VERIFIED RECORD with per-finding commits and statuses now lives in `docs/IMPLEMENTATION_ROUND_HANDOFF.md` (19 commits, `e9f980d`..`e56e3f9`).

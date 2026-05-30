# Sentinella — Session Handoff

**Workspace:** `C:\Users\Nicolas\Desktop\sentinella` (Rust workspace · `sentinelld` daemon · Tauri 2 + React/Vite GUI in `/gui` · ClamAV vendored unchanged in `third_party/clamav`).
**Companion docs:** `docs/PROJECT_SUMMARY.md` (background), `docs/CHANGELOG-0.1.6.md` (the ~101-fix pre-0.1.6 audit log).

---

## ✅ Completed this session (verified)

### 1. `cooling_transition` fixed at root cause — release blocker cleared
- Added an `expire_at(now: Instant)` testability seam in `crates/sentinelld/src/ecosystem/mod.rs`; tests now pass explicit future instants instead of the underflow-prone `checked_sub` path.
- Removed both `#[ignore]` attributes.
- **Full workspace: 447 tests green** — argus 158, etw_probe 40, sentinelld 249 — **0 failed, 0 ignored.**

### 2. `checked_sub` class sweep
- Audited every `checked_sub` site. Only the ecosystem tests + watcher had the broken silent-no-op pattern. The 3 live production sites are correct (intentional fail-safe fallbacks). No further change needed.

### 3. Watcher live-reload (decision #1) — DONE
- The watcher config snapshot now refreshes on an **mtime gate** every 5 s: GUI edits to exclusions / heuristics / sandbox settings apply **without a daemon restart**.
- mtime-gating was chosen deliberately: it avoids both (a) the per-flush (~150 ms) disk read the original load-once change was avoiding, and (b) re-triggering `Config::load`'s parse-error side effects (timestamped `.bad` backup + save-defaults) on a stable file — a stable config is never re-read.
- Compiles clean; daemon suite still 249 green.

### 4. GUI build validation (decision #2) — DONE
- Tauri Rust crate `cargo check` ✓
- `tsc + vite build` ✓ — no TypeScript errors, `dist` emitted.

### Guardrails honored
- No edits under `third_party/clamav`.
- No rewinding/editing of prior assistant turns (the earlier session died on the `thinking`-block API deadlock — do not reintroduce that).
- Tool output kept to tails/summaries to keep context lean.

### 5. `scan.start` overlap TOCTOU — FIXED (verified)
- Replaced `check_no_overlapping_scan()` (check-then-release-then-set) with `try_reserve_scan(job)`, which performs the overlap check **and** the `active_scan` reservation in a SINGLE `inner` critical section. The reservation core was split into a free fn `reserve_active_scan(&mut Inner, job)` so the invariant is unit-testable without building a full `AppState` (which panics without `paths::init`).
- Applied to all four orchestrated entrypoints: file / folder / quick / full. Each now does fail-fast validation BEFORE reserving, reserves the **fully-built** `ScanJob` (real `cancel_flag` + `live`, so a concurrent `scan.cancel` in the window can't be lost to a placeholder), then installs `scan_live`.
- `active_scan.status` remains the single source of truth (no parallel `AtomicBool` gate). Reused the existing `ScanStartResponse` rejection → GUI unaffected.
- Regression test `reserve_active_scan_serializes_and_recovers_on_terminal_state`: reserve once → second reserve rejected (names the in-flight job, doesn't overwrite) → after Completed/Cancelled/Failed a fresh reserve succeeds.
- **Full workspace: 448 green** (argus 158, etw_probe 40, sentinelld 250), 0 failed, 0 ignored.
- NOTE (out of scope, follow-up candidate): the **legacy non-orchestrated** scan paths still set `active_scan = Some(..)` directly (state.rs ~2216/2273/2336/2501) without `try_reserve_scan`. They aren't reachable via the orchestrated entrypoints, but if ever invoked concurrently they'd have the same overlap gap — consider routing them through `reserve_active_scan` too.

---

## ✅ Round 6 — deferred-correctness cluster (verified, full workspace 455 green: argus 158 / etw 40 / sentinelld 257)

- **🔑 runtime_integrity predictable vault key on Windows (SECURITY):** `generate_key()` tried `/dev/urandom` (fails on Win) then `"NUL"` (opens but reads EOF) → key stayed all-zero → fell back to `timestamp ^ pid ^ const` = PREDICTABLE. That key authenticates the integrity manifest, so a predictable key lets an attacker forge valid hashes after tampering signatures/rules → defeats the anti-"silent-lobotomy" design. Replaced with `rand::thread_rng().fill_bytes` (OS CSPRNG, same primitive as the quarantine vault key). Tests `generate_key_is_random_not_zero`, `hmac_detects_content_tamper`.
- **🔎 PS-bridge dropped all-but-newest script block per poll (detection coverage):** `wevtutil /rd:true` returns events newest-first; `ps_bridge_loop` set `last_record_id` to the first (highest) id then treated every later lower-id event as a duplicate → a burst of PowerShell scripts between polls had all-but-one silently skipped. Fixed via `unprocessed_ascending` (de-dup vs poll baseline, process oldest-first, advance to batch max). Tests: `descending_batch_processes_all_new_events`, `already_seen_events_are_dropped`, `empty_batch_keeps_baseline`.
- **🔢 YARA untrusted `weight` metadata overflow:** `translate_match` did `n as u32` on yara-x's signed `weight` → a negative/huge value in a (3rd-party) rule pack became ~u32::MAX and overflowed the engine's `findings…sum::<u32>()` (panic in debug / wrap → under-detection in release). Clamp at source via `sane_weight(i64)->u32` = `n.clamp(0,100)`. Test `sane_weight_clamps_untrusted_metadata`.
- **🔄 Signature-update freshness + diagnosability (updater thread):**
  - **Bug #2 (false "out of date"):** `db_stale` derived from in-memory `last_update_timestamp` (None on every daemon boot → `(true,0)` = stale, 24h threshold) → a freshly-updated DB showed "out of date" after any service/daemon restart. Fixed: freshness = max(in-memory ts, newest signature FILE mtime via `newest_signature_db_mtime_secs`) — persists across restarts — via pure `compute_db_stale`. Threshold now **configurable** `config.signature_stale_days` (default 3, clamp [1,30], cached `AppState.signature_stale_hours`). Tests `db_stale_uses_3_day_threshold_and_handles_restart`.
  - **Updater diagnosability:** `start_update` failure branch logged the first 200 chars (freshclam banner/noise) → real reason truncated. Now `freshclam_error_detail` surfaces the actionable TAIL (last non-empty stderr line: DNS/mirror/permission) to the activity log → a tray/scheduled failure is now visible in the GUI. Test `freshclam_error_detail_surfaces_tail_not_banner`.
  - This likely also explains the perceived "fails in tray, works when UI opened": the scheduled update was succeeding but the card lied (bug #2); now it won't. If a REAL tray freshclam failure remains, the activity log will now name the reason.
  - [DONE] GUI Settings control for `signature_stale_days` (Updates tab, 3/5/7/14-day select, EN/ES `settings.sig_stale*`). Takes effect on daemon restart (cached at AppState init like perf settings).
- **🔐 trust_graph: signer not bound into integrity hash (manufactured trust):** node integrity hash covered `(key, observation_count, stable_days)` but NOT `signer`. `query()` recomputes trust level from the DB `signer` (`has_signer` drives Established→Trusted, +3 discount). So `UPDATE trust_nodes SET signer='Microsoft'` on a legit Established node flipped it to Trusted while the hash still validated — defeating the integrity design's intent (count/days ARE hash-protected, so only already-established nodes were liftable; modest but real). Fixed: `trust_node_hash` now binds `signer`; updated observe-write (reads effective post-COALESCE signer), query-verify, and `reset_trust` (now clears signer + hashes None). Test `signer_tamper_revokes_trust_via_integrity`. NOTE one-time effect: existing nodes' old-formula hashes mismatch on next query → trust revoked (no discount, fail-safe) until re-observed re-hashes them.
- **🎭 Installer-trust deception — bare OLE2 → "installer" discount:** `is_known_installer` treated any file with OLE2 compound-file magic (`D0CF11E0`) as an installer → structural findings cut /3 + YARA dropper/persistence /2. But legacy Office `.doc/.xls/.ppt` are ALSO OLE2 → every macro-laden Office document got a detection discount (false-negative vector for macro droppers). Now requires `.msi` extension or an MSI-specific marker (`Windows Installer` / `Installation Database`); real MSIs still recognized. Test `ole2_office_doc_is_not_treated_as_installer`. Follow-up [FIXED]: the name+size path now requires a generic installer body hint (uninstaller/CAB/SFX), closing the "rename malware to setup.exe + pad to 2 MB" bypass (test `name_only_installer_requires_content_hint`). RESIDUAL (documented, lower priority): single substring markers (`"Windows Installer"`, `"InstallShiel"`) matched anywhere in a PE still grant the discount — partial (/3,/2), not an exemption. Also: About-page topic cards now i18n (EN/ES, `about.topic.*`); CVP approved → full security audit unblocked.
- **🧠 ARGUS trusted-cache never expired in production (false-negative after update):** `TrustedCache` caches per-hash clean verdicts for signed/reputable files and expires them via `invalidate()` (bumps `sig_generation`). But `invalidate()` was only ever called in a TEST — no production path called it → `sig_generation` stayed 1 forever → a signed/reputable file cached clean shortcut ARGUS analysis permanently, even after a new YARA rule/IOC that now matches it. Wired `trusted_cache.invalidate()` into both `argus.reload` (rule/IOC reload) and `reload_engine_inner` (signature reload). Tests `hit_then_expire_on_invalidate`, `unsigned_or_high_score_not_cached`.
- **🐟 FISH slow-burn detector (ransomware "slow-and-low" evasion):** all FISH detection lived in one 30 s window with high bars (rename 50 / rewrite 200), so encryption kept under those rates (e.g. 40 files/30 s sustained) evaded everything. Added a long **tumbling-window cumulative counter** (`slow_burn_window_secs`=600, `slow_burn_threshold`=250, both configurable, 0→default) → `FishDecision::SlowBurn`, wired into `fish_feed_event`, surfaced in diagnostics. Observe-only (no auto-kill — "aware, not paranoid"). Test `slow_burn_catches_low_rate_mutation_under_burst_thresholds`. Residual (documented, not bug): tumbling window can be straddled across the boundary.
- **🌐 i18n (Spanish) — COMPLETE:** every UI surface is bilingual EN/ES — StartupScreen, TopBar, Dashboard, Scan, Quarantine, History, Notifications, Intelligence, Settings, Update, and About (overview chrome + the full help-topic essays). About essays were lifted into `gui/src/pages/aboutContent.ts` (`en`/`es` records via `topicContentFor(locale)`), removing the 330-line inline `topicContent` from the component. en/es key parity maintained; every `pnpm build` green. Intentional English kept: acronyms (SBL, ARGUS) and proper nouns (ClamAV, Rust, AES-256-GCM, JSON-RPC, Tauri). Earlier detail:
- **🌐 i18n (Spanish):** `StartupScreen` (every-launch screen, was 100% hardcoded EN) fully wired to `t()` + EN/ES keys (`startup.*`, 16 strings); `TopBar` tooltips (`topbar.*`). `es.ts` is genuine Spanish (not EN copies). **Remaining hardcoded EN to translate** (counts of `label/title/...="Cap…"`): `Diagnostics.tsx` ~48, `Intelligence.tsx` ~32, `Dashboard.tsx` 7, `About.tsx` 6 — Diagnostics/Intelligence are mostly technical telemetry jargon (lower priority).

### Ransomware-evasion awareness (NOT yet fixed — future FISH hardening, keep "aware not paranoid")
- **Entropy-delta signal unused:** `entropy_delta_threshold` is configured but `evaluate()` never checks entropy → in-place same-name encryption (overwrite `file.docx` with ciphertext, keep name+ext) below the 200-rewrite bar is invisible. Needs watcher to compute per-file entropy delta.
- **Watched-dir scope:** FISH/watcher cover user profile dirs; encryption on other volumes / non-watched paths is unseen.
- **LOLBin trust discount:** mass-mutation from a trusted-signed process (powershell/certutil) still gets the signer trust discount in convergence — consider suppressing the discount when a process is implicated in a FISH burst.

- **🛠️ Developer Mode + Benchmark (v0.1.6 feature, partial):** `DeveloperConfig` landed in config — per-machine, password-gated, LOCAL-ONLY perf telemetry (no cloud). Fields `enabled`/`password_sha256`/`telemetry_enabled`/`telemetry_max_kb`; `validate()` scrubs malformed hash + forces `enabled=false` without a provisioned password + clamps cap. Helpers `hash_developer_password` / `verify_developer_password` (constant-time, locked-if-unprovisioned). `settings.get` redacts the hash over IPC. 2 tests. Architecture for the telemetry writer + `argusd benchmark` tool (ARGUS-scan-based hardware perf index, v0.1.6-sunset) in `docs/DEVELOPER_MODE_AND_BENCHMARK_v0.1.6.md`. TODO: `dev.set_developer_mode`/`dev.status` IPC, `devmode/telemetry.rs` writer, GUI Advanced→Developer section, benchmark B0–B2.
- **📄 v2 design doc:** `docs/ENGINE_HOTSWAP_V2_DESIGN.md` — blue-green in-process engine hot-swap to kill the "protection degraded" reload window + make failed reloads non-destructive (atomic rollback). Rejects the A/B-process approach (pipe/DB/watcher split-brain). Prereqs: per-instance mpool cache path + pressure gate. Phasing P0/P1/P2.
- **🔗 Cross-codebase junction/reparse hardening:** `Path::is_symlink()` misses NTFS junctions (mount-point reparse tag), so dir walkers guarding with it could still traverse a junction into an unintended tree. Added shared `scan::is_reparse_point` (checks `FILE_ATTRIBUTE_REPARSE_POINT` via `symlink_metadata` → catches symlinks AND junctions) and applied it to all four walker guards: `idle_scanner` walk_recursive (dir + file) and `state.rs` `collect_files` + `collect_files_streaming`. (Watcher already detected all reparse points via file_id.revalidate.) Test `is_reparse_point_negatives` (positives need privileged junction setup → manual/field). Resolves the junction residual flagged in the idle_scanner + watcher items below.
- **🚶 idle_scanner walk: dir-symlinks not skipped (scope-creep):** `walk_recursive` skipped symlinks for FILES but not DIRECTORIES → a dir-symlink got recursed, allowing traversal loops + scope-creep into unintended trees (e.g. a symlink into another user's profile under SYSTEM). Bounded by depth(8)+count caps, but inconsistent with the files branch + realtime walker. Added `is_symlink()` skip for dirs. (NTFS junctions still a known cross-codebase residual — `is_symlink` doesn't flag mount-points; same caps bound them.) Rest of idle_scanner audited sound (pause gates, cancel, `random_sleep` min≥max guard, bounded recursion).
- **🔔 Phantom "freshly caught" tray toast during engine reload:** `useDaemon` fires `notifyQuarantined` for any quarantine id not in the previous poll's `quarantineIds`. During a reload the set got wiped two ways → old items re-fired on recovery: (1) a disconnected/fallback poll (engine=error, sig=0) still overwrote `prevRef`; (2) `getQuarantineItems().catch(()=>[])` blipping to empty while engine read ok. Fixed in `gui/src/hooks/useDaemon.ts`: only snapshot `prev` from a connected poll, AND treat a sudden N>0→empty quarantine list as an unreliable blip (skip notify + preserve prior set/count). GUI tsc+build clean.
- **🧨 sandboxd ETW parse: unbounded `extract_wide_string` (attacker-controlled input):** parses ETW events emitted BY the detonating malware. `extract_wide_string(data, offset, max_len)` had NO length param and never validated `offset`/bounds — its doc even claimed "returns None if offset out of range" but didn't. A bad `offset`/`max_len` → `data.add(offset)` past the ETW buffer + raw u16 reads = UB / access violation, which is a hardware exception NOT caught by the callback's `catch_unwind` → uncatchable crash (or adjacent-memory leak into a "finding"). Current callers happened to bound `max_len`, but it was a landmine. Fixed: added `data_len` param, enforce `offset < data_len` + clamp `max_len` to remaining bytes INSIDE the fn; updated all 3 prod callers + 5 tests to pass `UserDataLength`. New test `extract_wide_string_is_bounds_safe` (offset-past-end now → None instead of OOB read).
- **Audited — sandbox restricted token (`sandboxd/restricted.rs`):** code correct (handles closed, suspended launch, low-IL SID S-1-16-4096 valid, well-tested). KNOWN LIMITATION documented at `launch_restricted`: the "restricted" token is `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` derived from sandboxd's own token = SYSTEM (spawned by LocalSystem daemon) with no restricting/deny SIDs → it's "SYSTEM, privileges disabled + low IL", NOT identity-isolated. Token-setup failure FAILS OPEN to `launch_unrestricted` (full token), job-contained + flagged. **v1.0 hardening:** run sandboxd under a dedicated low-priv account OR add restricting SIDs so samples are identity-isolated. Job Object remains the real containment net.
- **Audited sound — sandbox containment (`sandboxd`):** verified the detonation containment chain is fail-closed: `CreateJobObject`/`SetInformationJobObject` failure → abort (no detonation); `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + no `BREAKAWAY` + 512MB cap; launch `CREATE_SUSPENDED` → `AssignProcessToJobObject` (assign-fail → kill+abort) → resume only after job + network block; force-killing sandboxd closes the job handle → kills malware + grandchildren. No exploitable gap. Removed a dangerous stale comment ("fall through without containment — still useful for monitoring") that was dead code contradicting the fail-closed `return` and could mislead a future edit into an uncontained-detonation path.
- **Audited clean (no bug; well-guarded):** `scan/ads.rs` (16-stream/10MB caps + `take()`), `scan/mod.rs` (H1/H2/H3/R4 domain-constrained skips), `engine/clamav.rs` (MAXSCANSIZE 400MB / MAXFILESIZE 100MB / MAXRECURSION 10 / MAXFILES 5000; Drop frees safely; concurrent-scan-on-compiled-engine is libclamav-safe), `plm/etw_intake.rs` (bounds-checked binary parse + `catch_unwind` around the FFI callback). IPC/engine/quarantine non-test `unwrap()` surface = clean.

- **startup-scan REG_EXPAND_SZ env-var gap (persistence-detection):** `parse_reg_output` never expanded `%VAR%`, so a Run-key autostart entry like `%APPDATA%\evil.exe` (REG_EXPAND_SZ) resolved to a literal non-existent path and was SILENTLY skipped → malware persisting that way escaped the startup scan. Added `expand_env_vars` (unknown vars kept literal, `%%`→`%`, unterminated `%` verbatim), applied to REG_EXPAND_SZ values. Tests `expand_env_vars_resolves_known_and_preserves_unknown`, `parse_reg_output_expands_reg_expand_sz_paths`.

- **scan.start legacy paths unified:** the 4 legacy (non-orchestrated) entrypoints (folder/quick/full/startup) routed through `reserve_active_scan`. They were already single-lock (no TOCTOU) but only rejected on `Running` — now also reject `Pending`/`Draining`, so a legacy scan can't clobber an in-flight orchestrated Pending job (config-flag-flip-mid-flight gap). Dedups the rejection logic.
- **PLM PID-reuse false lineage:** `get_chain` walked `parent_pid` with the map keyed on PID only; a recycled PID attributed a victim to the wrong ancestor → bogus convergence escalation. Fix: reject any hop where the candidate parent's `created_at` is newer than its child. Test `pid_reuse_does_not_produce_false_lineage`.
- **PLM eviction O(n)/insert → amortized:** at capacity it did a fresh `min_by_key` scan + single removal on every insert. Now batch-evicts oldest down to 90% in one pass.
- **calibration FP-candidate nondeterminism:** `GROUP BY r.file_hash` with bare columns relied on SQLite's single-`max()` rule; timestamp ties → arbitrary metadata row. Rewrote with window functions (`ROW_NUMBER … ORDER BY timestamp DESC, rowid DESC`). Test `fp_candidates_tiebreak_is_deterministic`.
- **FISH ext-mutation threshold configurable:** was hardcoded `>= 5` while rename/rewrite are config-driven. Added `FishConfig.ext_mutation_threshold` (default 5; 0 → falls back to 5). `#[serde(default)]` keeps old TOML compatible. Test `extension_mutation_threshold_is_configurable`.

## ✅ Signature freshness + updater reliability (workspace 474 green)

- **"Out of date" card lied after a successful update (bug):** `db_stale`/`db_stale_hours` (state.rs `runtime_stats`) derived ONLY from `inner.last_update_timestamp` — an in-memory value that resets to `None` on every daemon boot → `(true,0)` = stale, with a 24h threshold. So after any daemon/service restart a freshly-updated DB showed "out of date" until an in-session update ran ("updated DB but still shows out of date"). This also explains the **"updater fails when minimized to tray" perception**: the scheduled tray update (scheduler/mod.rs runs `start_update` every `update_interval_hours`) actually succeeds, but the card falsely showed stale → user opens UI, clicks update, card refreshes → "works manually."
  - Fix: freshness now = max(in-memory ts, **newest signature FILE mtime** via `newest_signature_db_mtime_secs` — persists across restarts) with a **3-day** threshold (`STALE_THRESHOLD_HOURS=72`). Pure `compute_db_stale()` + test `db_stale_uses_3_day_threshold_and_handles_restart`. GUI `App.tsx` already gates the card on `db_stale` → now only shows at ≥3 days.
- **Updater panic-wedge (latent reliability):** `start_update` sets `update_running=true` and the spawned thread clears it at the end — but a panic in `reload_engine`/YARA-reload would leave it stuck true → the re-entry guard rejected EVERY future update (scheduled + manual) until daemon restart. Added an `UpdateGuard` RAII (clears `update_running`/phase on drop, panic-safe).
- ⚠️ If genuine *scheduled-freshclam* failures persist after this (distinct from the card lying), need a daemon log line from a failing tray run (freshclam stderr/exit code) — can't diagnose blind. Note: `resolve_freshclam_config` resolves relative paths against CWD (system32 for the service) — only matters if the installed `freshclam.conf` uses relative `DatabaseDirectory` (installed config should be absolute).

## ✅ IPC auth-broker — per-connection client-SID check (IMPLEMENTED, workspace 460 green)

Closes the world-readable-secret class: the daemon now authenticates the *connecting process* independent of the shared secret. New module `crates/sentinelld/src/ipc/client_auth.rs`:
- Pure `decide(ClientIdentity, active_console) -> Allow/Deny` (5 unit tests): deny anonymous/null SID; allow SYSTEM + elevated (incl. RDP admins); allow interactive console-session user; deny unprivileged non-console/cross-user/session-0 callers; fail-open if console session unknown.
- Thin unsafe `resolve_client(pipe_handle)`: `GetNamedPipeClientProcessId` → `OpenProcess(QUERY_LIMITED)` → token `User` SID / `SessionId` / `Elevation`. Returns `None` on ANY error → caller **fails open** (allow + warn) so an API quirk never bricks a legit GUI.
- Hooked in `run_named_pipe` AFTER the next listener is ready (reject can't starve the pipe). Env kill-switch `SENTINELLA_DISABLE_CLIENT_SID_CHECK=1`.
- Cargo: added `Win32_System_Pipes` + `Win32_System_RemoteDesktop` features.

⚠️ **NEEDS LIVE VERIFICATION** (could not integration-test the FFI — needs a real pipe + tokens): after install, confirm the normal-user GUI still connects (daemon log shows no "rejected pipe client") and that a second non-admin user is rejected. The shared secret is now an anti-CSRF nonce; it was NOT removed (defense-in-depth). Pipe ACL still grants AU — could tighten later, but the per-connection check is the real gate now.

### Remaining from this class (optional follow-ups)
- Tighten pipe SDDL (drop `(A;;GRGW;;;AU)`) now that per-connection SID is enforced — verify GUI still connects first.
- Demote/skip the secret check entirely once SID check is field-proven.

## ✅ DONE — `scan.start` overlap TOCTOU (confirmed REAL bug)

### Why it's real (not theoretical)
The IPC server **`tokio::spawn`s one task per connection** (`crates/sentinelld/src/ipc/mod.rs:220` for named pipe, `:242` for unix socket). `dispatch_sync` is synchronous *within* a connection, but separate pipe connections run **concurrently**. So two clients can each fire `scan.start` at the same time and both reach the scan-start path in parallel.

### The race
In `crates/sentinelld/src/ipc/state.rs`:
1. `check_no_overlapping_scan()` (**line 1494**) acquires `lock_inner()`, inspects `active_scan`, then **releases the lock** and returns `None`.
2. `start_orchestrated_file_scan()` (**line 1519**) calls that check at **1524**, then does unrelated work (uuid, target validation, building `ScanLiveState`), and only **re-acquires** `lock_inner()` at **1557** to set `active_scan = Some(ScanJob{ status: Pending, .. })`.
3. Between the release in step 1 and the set in step 3, a second concurrent `scan.start` also passes the check. Both set `active_scan`; the first job is now orphaned — uncancellable, and its completion handler no-ops because `active.id != job.id` (exactly the failure mode the comment at 1490–1493 describes; this is the residual gap left by the R1-7 fix).

### All four entrypoints share the pattern (fix all of them)
- `start_orchestrated_file_scan`   — state.rs:1519 (check at 1524)
- `start_orchestrated_folder_scan` — state.rs:1939 (check at 1944)
- `start_orchestrated_quick_scan`  — state.rs:2053 (check at 2057)
- `start_orchestrated_full_scan`   — state.rs:2363 (check at 2367)

### Recommended fix — atomic check-and-reserve under a single lock (lowest risk)
Make the overlap check and the `active_scan` reservation **one critical section** so no second caller can interleave. Concretely:

1. Do cheap, fail-fast validation (e.g. empty-target check) **before** locking — no point reserving for a request that's about to error.
2. Add a helper, e.g.
   ```rust
   /// Atomically: reject if a scan is Running/Pending/Draining, else reserve
   /// `active_scan` as a Pending placeholder for `id`. Single critical section.
   fn try_reserve_scan(&self, id: Uuid, kind: &str, path: &str, now: i64) -> Result<(), ScanStartResponse>
   ```
   Inside, hold `lock_inner()` across **both** the `matches!(job.status, Running|Pending|Draining)` check **and** the `inner.active_scan = Some(ScanJob{ status: Pending, .. })` assignment. Return the existing rejection `ScanStartResponse` on conflict.
3. Each of the 4 entrypoints calls `try_reserve_scan(...)` instead of `check_no_overlapping_scan()`, then fills in `scan_live` / spawns the orchestrated job. Keep the single-source-of-truth in `active_scan`.
4. **`scan_live` caveat:** it lives in a *separate* `Mutex` (`ipc/state.rs:267`) from `inner`. After reserving `active_scan`, set `scan_live` immediately; readers tolerate the brief window, but don't add a second authority for "is a scan active?" — keep `active_scan.status` canonical so the existing Completed/Cancelled/Failed transitions still reset everything.

**Avoid** a separate `AtomicBool scan_active` CAS gate: it's a second source of truth that must be kept in sync with every `active_scan` status transition (completion, cancel, failure, drain) and will desync. The single-lock reserve reuses the existing state machine.

### Verification checklist
- `cargo test -p sentinelld` → expect **249 green, 0 failed, 0 ignored**.
- Add a regression test that simulates two concurrent reservations: reserve once → second `try_reserve_scan` returns the rejection `ScanStartResponse`; after the first job transitions to Completed/Cancelled/Failed, a new reserve succeeds.
- Full workspace: `cargo test` → expect **447 green**.
- `cargo check` on the GUI Tauri crate if any IPC response shape changed (it shouldn't — reuse the existing `ScanStartResponse`).

### Guardrails for the next agent
- Do **not** touch `third_party/clamav`.
- Do **not** edit/rewind earlier assistant turns (API `thinking`-block deadlock risk).
- Keep tool output lean (tails/summaries) — this project's transcripts have ballooned before.
- Prefer fixing logic over weakening tests.

### After the TOCTOU
Resume the pre-0.1.6 audit toward the 200-fix *meets-expectations* bar (≈101 done; higher encouraged). Highest-ROI target per `CHANGELOG-0.1.6.md`: the **IPC auth-broker** refactor that closes the world-readable-secret class (authenticate the GUI by parent/session SID instead of a shared file secret). Untouched modules are listed at the bottom of that changelog.

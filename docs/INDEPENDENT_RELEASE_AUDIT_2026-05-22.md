# Independent Release Audit - 2026-05-22

## Verdict

Independent verdict: **not ready for public alpha before runtime verification**.

Static BLOCKER items were confirmed. Several were fixed in this pass, but the named-pipe DACL, installer cleanup, UAC behavior, and MSI contents still need Windows runtime/installer validation before public alpha.

## Commands Run

- `cargo check --workspace`
- `cargo test -p sentinelld validate_restore_path_rejects_unc_paths`
- `cargo test -p sentinelld expands_programdata_path`

Full final validation is recorded in the assistant final report.

## Verification Table

| ID | Prior | Status | Final | Evidence | Fix status |
|---|---:|---|---:|---|---|
| B1 | BLOCKER | CONFIRMED | BLOCKER | `crates/sentinelld/src/ipc/mod.rs` previously used `ServerOptions::create()` with null security attributes. | Fixed statically with SDDL DACL `SY + BA`; needs runtime ACL test. |
| B2 | BLOCKER | CONFIRMED | BLOCKER | `gui/src-tauri/tauri.conf.json` had `"csp": null`; `gui/public/splash.html` used inline script and inline event handler. | Fixed non-null CSP; public splash script externalized. |
| B3 | BLOCKER | CONFIRMED | BLOCKER | `runtime/config/sentinelld.toml`, `crates/sentinelld/runtime/config/sentinelld.toml`, and `gui/src-tauri/runtime/config/sentinelld.toml` contained `C:\Users\Nicolas\...`; `runtime/config/freshclam.conf` contained developer-local paths. | Fixed templates and added env-var expansion. |
| H1 | HIGH | CONFIRMED | HIGH | `installer/windows/Product.wxs` creates ProgramData dirs but has no uninstall cleanup for state/quarantine/signatures. | Open; needs explicit product policy and installer test. |
| H2 | HIGH | PARTIALLY CONFIRMED | MEDIUM | `Product.wxs` documents heat for YARA/certs but does not include harvested component groups. `scripts/stage-windows-package.bat` copies YARA/certs. | MSI direct path still open; staging path partially mitigates. |
| H3 | HIGH | CONFIRMED | HIGH | `reload_engine()` swapped engine before cache invalidation. | Fixed; cache invalidates before swap. |
| H4 | HIGH | CONFIRMED | HIGH | `validate_restore_path()` did not explicitly reject `\\server\share` or `//server/share`. | Fixed with UNC block and test. |
| H5 | HIGH | CONFIRMED | HIGH | GUI uses IPC auth/challenge, but no `runas`/elevation path was found in `gui/src-tauri/src`. | Open; needs UAC design/runtime test. |
| H6 | HIGH | PARTIALLY CONFIRMED | MEDIUM | `Config::default()` disables orchestrator and ARGUS worker; runtime configs varied. ARGUS worker disabled is intentional fallback safety. | File-scan pilot enabled in bundled configs; worker remains opt-in. |
| H7 | HIGH | CONFIRMED | HIGH | Daemon IPC secret used `runtime/state/ipc_secret` relative to CWD. | Fixed to ProgramData data dir. |
| M1 | MEDIUM | CONFIRMED | MEDIUM | `folder_scan_worker_inner()` collects all files into `Vec<PathBuf>` before scan. | Open; streaming producer/consumer needed. |
| M2 | MEDIUM | FALSE POSITIVE | LOW | `FirstRun.tsx` allows optional scan later; `StartupScreen.tsx` has limited-mode path. | No fix. |
| M3 | MEDIUM | CONFIRMED | MEDIUM | `delete_vault_file()` uses normal delete only. | Open; secure delete policy needed. |
| M4 | MEDIUM | CONFIRMED | MEDIUM | `challenge_token: Option<(String, Instant)>` is single-use but not operation-bound. | Open. |
| M5 | MEDIUM | PARTIALLY CONFIRMED | MEDIUM | Restore validates path then creates file. `create_new(true)` prevents overwrite, but reparse swaps still need runtime hardening. | Partially mitigated with UNC and symlink-parent checks. |
| M6 | MEDIUM | NEEDS RUNTIME TEST | MEDIUM | Many logs include user paths through tracing fields. Need newline/control-character log test. | Open. |
| M7 | MEDIUM | CONFIRMED | MEDIUM | Config exposes one `update_mirror`; `freshclam.conf` uses one `DatabaseMirror`. | Open. |
| M8 | MEDIUM | PARTIALLY CONFIRMED | MEDIUM | YARA load preserves rules on hard failure, but compile errors still swap a partial ruleset. | Open. |
| M9 | MEDIUM | CONFIRMED | MEDIUM | `scheduler_loop()` triggers updates on interval boundaries; no jitter. | Open. |
| M10 | MEDIUM | CONFIRMED | MEDIUM | `supervisor_loop()` backs off forever; no max restart cap. | Open. |
| M11 | MEDIUM | CONFIRMED | MEDIUM | Retention cleanup calls delete per item without transaction boundary. | Open. |
| M12 | MEDIUM | PARTIALLY CONFIRMED | LOW | Watcher skips `path.is_symlink()`; full/idle traversal still merits reparse-point audit. | Open. |
| L1 | LOW | CONFIRMED | LOW | `sentinella-common::IPC_PIPE_NAME` is fixed `\\.\pipe\sentinelld`. | Accepted for single-instance alpha. |
| L2 | LOW | CONFIRMED | LOW | No explicit `CL_ENGINE_MAXRECLEVEL` setting found in Rust ClamAV wrapper. | Open. |
| L3 | LOW | CONFIRMED | LOW | Restore hash compare was normal string compare. | Fixed with constant-time compare. |
| L4 | LOW | CONFIRMED | LOW | Audit mode exit uses `AUDIT_STABLE_MINUTES`, not richer stability metrics. | Open. |
| L5 | LOW | CONFIRMED | LOW | Update messages truncate to 200 chars in `state.rs`. | Open. |
| L6 | LOW | FALSE POSITIVE | LOW | Cleanup cutoff uses UTC timestamps; only schedule trigger uses local hour. | No fix. |
| L7 | LOW | CONFIRMED | LOW | `pnpm build` reports static+dynamic import warning for `sentinella.ts`. | Open. |
| L8 | LOW | CONFIRMED | MEDIUM | `.github` has issue templates but no workflow files. | Open; release engineering gap. |

## Fixes Applied

### BLOCKER

- Added explicit Windows named-pipe DACL using SDDL: SYSTEM and built-in Administrators.
- Set non-null Tauri CSP.
- Removed inline public splash script and inline image error handler.
- Replaced developer-local runtime config paths with `%USERPROFILE%`, `%TEMP%`, and ProgramData paths.
- Added config variable expansion for `%USERPROFILE%`, `%TEMP%`, `%PROGRAMDATA%`, `$USERPROFILE`, `$TEMP`, `$PROGRAMDATA`.

### HIGH

- Moved scan-cache invalidation before ClamAV engine swap.
- Blocked UNC/network quarantine restore paths.
- Moved daemon IPC secret path to ProgramData data directory.

### MEDIUM / LOW

- Blocked symlink parent directories during restore.
- Added constant-time restore hash comparison.

## New Tests Added

- `config::tests::expands_programdata_path`
- `quarantine::tests::validate_restore_path_rejects_unc_paths`

## Runtime Tests Required

### Named Pipe DACL

Run daemon as LocalSystem/admin, then:

1. `Get-Acl \\.\pipe\sentinelld` or Sysinternals access check equivalent.
2. Verify only SYSTEM and Administrators have access.
3. Verify standard non-admin GUI behavior is either blocked intentionally or uses elevation.

### Installer Cleanup

1. Install MSI on clean VM.
2. Create quarantine item and signatures/state.
3. Uninstall.
4. Verify policy: either ProgramData retained with warning, or removed by explicit user-approved cleanup.

### UAC

1. Launch GUI as standard user.
2. Attempt protected operations.
3. Verify expected elevation prompt or controlled denial.

### Log Injection

1. Scan/quarantine a filename containing newline/control characters.
2. Verify logs remain single-entry structured records.

## Remaining Unfixed Risks

- Installer uninstall policy unresolved.
- GUI critical-operation elevation unresolved.
- Full scan still pre-collects all file paths.
- YARA partial compile can replace previous complete ruleset.
- Supervisor can respawn indefinitely.
- No CI workflow.
- No code signing/timestamping configured.

## Next 3 Milestones

1. **Ship-safe alpha gate**: runtime-test pipe DACL, UAC behavior, installer contents, uninstall policy.
2. **Hardened alpha**: streaming full scan, YARA rollback, supervisor restart cap, update jitter/mirror fallback.
3. **Beta gate**: CI, signing, MSI integration tests, reparse-point restore hardening, secure deletion policy.

## Do Not Ship Until

- Pipe DACL passes runtime test.
- Standard-user GUI behavior is deliberately handled.
- Installer package includes intended rules/certs.
- Uninstall retention policy is explicit.
- No developer-local paths remain in staged package.
- Full validation passes.

## Safe Public Alpha If

- Runtime DACL test passes.
- CSP remains non-null.
- Configs are portable.
- Quarantine UNC restore test passes.
- Cache invalidation is before engine swap.
- Remaining HIGH items are documented in release notes.

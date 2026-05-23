# Independent SEV Audit - Sentinella / ARGUS

## Executive summary

Audit date: 2026-05-17

Tested state: no valid `HEAD` was available (`git rev-parse HEAD` reported ambiguous `HEAD`). The working tree was dirty, with many staged, modified, and untracked files. Findings below are based on the current workspace state, not a stable committed revision.

Result: no SEV-1 issue was proven in this pass. The highest release blockers are Windows packaging scripts misexecuting under `cmd.exe`, release configs shipping developer-local `freshclam` paths, missing IPC client timeouts, unused/misreported scan cache, watcher event drops under storms, and quarantine restore/locking safety gaps.

Finding counts:

- SEV-1: 0
- SEV-2: 7
- SEV-3: 5
- SEV-4: 0

## Commands run

```bat
cargo check --workspace
cargo test -p argus
cd gui
pnpm exec tsc --noEmit
pnpm build
cmd /c scripts\release-sanity-windows.bat nopause
cmd /c scripts\stage-windows-package.bat nopause
```

Build/test status:

- `cargo check --workspace`: passed.
- `cargo test -p argus`: passed, 119 tests passed, 0 failed. Warning remains for unused import `ChainStrength` in `crates\argus\src\engine.rs`.
- `pnpm exec tsc --noEmit`: passed.
- `pnpm build`: passed.
- `scripts\release-sanity-windows.bat`: failed under `cmd.exe` due batch parsing errors.
- `scripts\stage-windows-package.bat`: emitted batch parsing errors under `cmd.exe`; tool process returned 0, but script behavior was not reliable.

## SEV-1 findings

None proven in this pass.

## SEV-2 findings

### ID: SEV2-IPC-001

Severity: SEV-2

Area: Tauri IPC client / daemon reachability

Evidence: `gui\src-tauri\src\daemon_client.rs:89-97` writes and reads the named-pipe frame with no timeout. `resp_len` is read from the pipe and used directly for `vec![0u8; resp_len]` with no client-side maximum.

Why it matters: a half-open pipe, stalled daemon, or corrupted local pipe peer can hang GUI commands indefinitely or force excessive allocation. This makes control-plane UI state unreliable during daemon failure.

Reproduction / code path: call any Tauri command that uses `daemon_client::call`, then stall the pipe after response length or return an excessive frame length.

Recommended fix: wrap connect/write/read operations in `tokio::time::timeout`, add a client-side `MAX_FRAME_SIZE` matching the protocol, and reject zero/oversized responses before allocation.

Risk of fix: low.

Status: open.

### ID: SEV2-SCAN-001

Severity: SEV-2

Area: Scan strategy / performance

Evidence: `AppState` owns `scan_cache` in `crates\sentinelld\src\ipc\state.rs:55`, reports cache stats at `state.rs:1401-1403`, but quick/folder workers scan every file at `state.rs:1543-1544` without `scan_cache.check()` or `scan_cache.record()`. The watcher has a separate local cache at `crates\sentinelld\src\watcher\mod.rs:219` and `watcher\mod.rs:245`.

Why it matters: repeated quick/folder scans rescan unchanged files, cache metrics are misleading, and large vendor folders can dominate CPU/I/O despite a cache being present.

Reproduction / code path: run the same folder scan twice and inspect `runtime.stats`; manual scan cache hit/miss counters do not represent the scan work.

Recommended fix: wire the shared `AppState.scan_cache` into manual scan workers, record clean results only after both ClamAV and ARGUS agree, and invalidate on signature/database update as already intended.

Risk of fix: medium, because cache semantics affect detection freshness.

Status: open.

### ID: SEV2-PKG-001

Severity: SEV-2

Area: Packaging / release scripts

Evidence: `scripts\release-sanity-windows.bat` and `scripts\stage-windows-package.bat` have LF-only line endings. Running `cmd /c scripts\release-sanity-windows.bat nopause` produced misparsed command errors such as `"entinella" no se reconoce...`, `"Verifies" no se reconoce...`, and `"No se esperaba should en este momento."`

Why it matters: Windows release validation cannot be trusted if the batch scripts do not execute correctly under `cmd.exe`. This can hide bad release artifacts.

Reproduction / code path: run `cmd /c scripts\release-sanity-windows.bat nopause` on Windows in this workspace.

Recommended fix: normalize all `.bat` files to CRLF and rerun release staging/sanity from a clean shell.

Risk of fix: low.

Status: open.

### ID: SEV2-PKG-002

Severity: SEV-2

Area: Signature updater / release config

Evidence: `runtime\config\freshclam.conf:5` points to `C:\Users\Nicolas\Desktop\sentinella\runtime\signatures`; `runtime\config\freshclam.conf:8` points to a developer-local log path. `scripts\stage-windows-package.bat:91-92` copies that file into staging. `scripts\build-release.bat:72` also copies `runtime\config\freshclam.conf`. A proper installed-mode template exists at `installer\windows\freshclam.conf.template:6` and `installer\windows\freshclam.conf.template:9`.

Why it matters: shipped builds can try to update signatures into a developer-only path or fail to update on user machines, leaving protection stale.

Reproduction / code path: stage or build a Windows package, then inspect staged `runtime\config\freshclam.conf`.

Recommended fix: generate packaged `freshclam.conf` from the installed-mode template or write ProgramData paths during install/staging. Keep developer-local runtime config out of release artifacts.

Risk of fix: low.

Status: open.

### ID: SEV2-QUAR-001

Severity: SEV-2

Area: Quarantine / IPC responsiveness

Evidence: `crates\sentinelld\src\ipc\state.rs:953-960` locks the database mutex and calls `crate::quarantine::quarantine_file()`. The quarantine code reads, hashes, encrypts, writes, and removes the source file while operating through that call path (`crates\sentinelld\src\quarantine\mod.rs:101-127`). Restore/delete paths also operate with the DB lock held from `state.rs:975` and `state.rs:984`.

Why it matters: a large quarantine operation can block other DB-backed IPC such as quarantine list, scan history, diagnostics, and watcher auto-quarantine. Under multiple detections, the daemon control plane can appear stalled.

Reproduction / code path: quarantine a large file while polling quarantine/history/status endpoints.

Recommended fix: split DB read/write from file crypto. Hold the DB lock only for metadata lookup and final status update; perform file I/O outside the DB mutex.

Risk of fix: medium, because transaction ordering must preserve vault/database consistency.

Status: open.

### ID: SEV2-QUAR-002

Severity: SEV-2

Area: Quarantine restore safety

Evidence: `restore_file()` ignores its `_vault_dir` argument at `crates\sentinelld\src\quarantine\mod.rs:144-156` and trusts `item.vault_path` from the database. Restore path validation happens before write at `quarantine\mod.rs:161`, then creates parent directories and writes at `quarantine\mod.rs:193-196`, leaving a time-of-check/time-of-use window. The symlink check only checks the target path at `quarantine\mod.rs:249`, not every parent component at write time.

Why it matters: corrupted DB state or a local race can redirect vault reads or restore writes outside the intended safety model. The hash check prevents arbitrary plaintext restoration, but path safety is still not robust enough for malware-handling code.

Reproduction / code path: tamper a quarantine DB entry or race parent directory replacement between validation and `fs::write()`.

Recommended fix: require `vault_path` canonical containment under `vault_dir`, validate every parent component, use safe create-new semantics, and avoid following symlinks/junctions during final write.

Risk of fix: medium.

Status: open.

### ID: SEV2-WATCH-001

Severity: SEV-2

Area: Watcher / real-time protection

Evidence: watcher debounce stores events in `recent` and only inserts while `recent.len() < 10_000` at `crates\sentinelld\src\watcher\mod.rs:154-155`. Extra events are silently dropped. Batches are then scanned serially at `watcher\mod.rs:164-168`, with ClamAV and ARGUS per file at `watcher\mod.rs:231-234`.

Why it matters: a large file creation storm can drop real-time scan events before they are scanned. Manual or idle scans may catch files later, but real-time protection can miss newly created malware during the storm window.

Reproduction / code path: create more than 10,000 eligible files quickly under a watched directory and observe that events beyond the cap are not queued for later scan.

Recommended fix: replace silent drop with a bounded overflow signal that schedules a targeted folder rescan, or persist overflow directories for later scan.

Risk of fix: medium, because storm handling must not create notification or scan loops.

Status: open.

## SEV-3 findings

### ID: SEV3-SCAN-001

Severity: SEV-3

Area: GUI / Tauri contract

Evidence: `gui\src-tauri\src\lib.rs:41-42` exposes `start_full_scan()` and sends `{"type":"full"}`. Daemon `start_scan()` accepts only `"file"`, `"quick"`, and `"folder"` at `crates\sentinelld\src\ipc\state.rs:565-568`.

Why it matters: any UI/tray/menu path that calls `start_full_scan()` will always fail with `Unknown scan type: full`.

Reproduction / code path: invoke the registered Tauri command `start_full_scan`.

Recommended fix: either map full scan to the supported folder/full-disk strategy or remove the registered command until daemon support exists.

Risk of fix: low.

Status: open.

### ID: SEV3-SCAN-002

Severity: SEV-3

Area: GUI / scan status contract

Evidence: the scan status fast path returns `finished_at: None` for all live-state statuses at `crates\sentinelld\src\ipc\state.rs:837-839`. The worker marks live state completed/cancelled at `state.rs:1626` and updates inner job later at `state.rs:1666`. `scan_live` remains installed after completion.

Why it matters: polling clients can observe a completed/cancelled scan with no finish timestamp while the live state remains present. This can create inconsistent scan completion UX.

Reproduction / code path: poll `scan.status` immediately as a scan finishes or is cancelled.

Recommended fix: add `finished_at` to live scan state or clear `scan_live` after inner state is finalized.

Risk of fix: low.

Status: open.

### ID: SEV3-REL-001

Severity: SEV-3

Area: Release sanity

Evidence: `scripts\release-sanity-windows.bat:53` exits with `exit /b 0` even after `FAIL` is incremented and errors are printed.

Why it matters: after line endings are fixed, release sanity can still report failure text but return success to automation.

Reproduction / code path: stage a forbidden directory, run release sanity, and inspect process exit code.

Recommended fix: return `exit /b 1` when `FAIL GTR 0`.

Risk of fix: low.

Status: open.

### ID: SEV3-REL-002

Severity: SEV-3

Area: License / attribution packaging

Evidence: root has `NOTICE.md`, not `NOTICE`. `scripts\stage-windows-package.bat:111` copies only `%ROOT%\NOTICE`. The script then prints `LICENSE/NOTICE OK` at `stage-windows-package.bat:112`. Release sanity checks `LICENSE` but does not check NOTICE.

Why it matters: required ClamAV/Cisco and project attribution can be absent from staged release artifacts.

Reproduction / code path: run staging and inspect whether NOTICE content exists in `release\staging\Sentinella`.

Recommended fix: copy `NOTICE.md` or normalize the root notice filename, then enforce it in release sanity.

Risk of fix: low.

Status: open.

### ID: SEV3-REL-003

Severity: SEV-3

Area: Source packaging / malware sample hygiene

Evidence: `.gitignore` excludes only selected research sample extensions under `runtime/research_samples/`. `scripts\package-source-windows.bat:40-42` excludes only `*.exe`, `*.dll`, and `*.zip` from `runtime/research_samples`.

Why it matters: controlled samples with other extensions can be included in source packages. Current inspection did not prove such samples are present, so this is a release-readiness hygiene issue rather than a current sample leak.

Reproduction / code path: place a controlled `.ps1`, `.js`, `.docm`, `.bin`, or extensionless sample under `runtime\research_samples`, then run source packaging.

Recommended fix: exclude the whole `runtime/research_samples/` directory from source packages and keep only a README placeholder if needed.

Risk of fix: low.

Status: open.

## False positives risk

Risk: moderate.

ARGUS tests passed and no broad high-severity single-string YARA rule was found during this pass. ARGUS-only quarantine is gated at score >= 85 in `unify_detection`, which reduces accidental quarantine. Remaining FP risk is mainly around future YARA/category changes, signed installer edge cases, and watcher auto-quarantine operating without user context.

## Malware escape risk

Risk: moderate.

The strongest proven escape-adjacent issue is watcher storm handling: events beyond the 10,000 debounce cap are silently dropped. Manual and idle scans may still catch files later, but real-time protection can miss files during a storm. No scoring bug proving mainstream malware escape was found in this pass.

## Daemon stability risk

Risk: moderate.

The server has frame-size checks and panic containment, but the GUI client lacks timeouts and maximum response-frame validation. Quarantine operations can block DB-backed IPC while doing file crypto. Watcher storms can create delayed real-time processing.

## Quarantine safety risk

Risk: moderate.

AES-GCM with hash verification is present. The main safety gaps are DB/vault path trust, restore TOCTOU, parent symlink/junction handling, and long DB lock holds during file operations.

## Release readiness risk

Risk: high.

Windows release scripts misexecute under `cmd.exe`, sanity can exit success on failure, release staging copies developer-local `freshclam.conf`, and NOTICE packaging is incomplete. These should block beta packaging until fixed and rerun from a clean workspace.

## Recommended immediate fixes

1. Normalize Windows batch scripts to CRLF and rerun all release scripts under `cmd.exe`.
2. Make `release-sanity-windows.bat` return nonzero on failures.
3. Stop copying developer `runtime\config\freshclam.conf` into release artifacts; use installed ProgramData paths.
4. Add Tauri daemon-client timeouts and response-frame size validation.
5. Wire shared scan cache into quick/folder workers or remove misleading stats until implemented.
6. Harden quarantine restore containment and move file crypto outside DB mutexes.
7. Replace watcher silent event drop with overflow rescans.

## Recommended next audit pass

1. Run live daemon IPC stress with many parallel GUI calls during a scan.
2. Test scan cancellation during large archive/ClamAV/YARA work.
3. Run watcher storm tests with more than 10,000 eligible files.
4. Run mainstream installer FP corpus and known-malware regression corpus in an isolated VM.
5. Build a clean Windows beta package from a clean checkout and inspect staged artifacts byte-for-byte.

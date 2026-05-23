# Claude Handoff - ARGUS Worker Foundation

## What Codex implemented

Codex added first worker-isolation wave for ARGUS without removing existing in-process scanning.

New binary:

```text
argusd.exe
```

Cargo package:

```text
crates/argusd
```

Daemon integration:

```text
sentinelld optionally invokes argusd per file, parses JSON, falls back in-process on failure.
```

## Files changed

- `Cargo.toml`
- `crates/argusd/Cargo.toml`
- `crates/argusd/src/main.rs`
- `crates/sentinelld/src/main.rs`
- `crates/sentinelld/src/argus_worker.rs`
- `crates/sentinelld/src/config/mod.rs`
- `crates/sentinelld/src/ipc/mod.rs`
- `crates/sentinelld/src/ipc/state.rs`
- `crates/sentinelld/src/orchestrator/mod.rs`
- `scripts/test-argus-worker.ps1`
- `scripts/stage-windows-package.bat`
- `scripts/release-sanity-windows.bat`
- `scripts/build-release.bat`
- `installer/windows/Product.wxs`
- `docs/ARGUS_WORKER_ARCHITECTURE.md`
- `docs/CLAUDE_HANDOFF_ARGUS_WORKER.md`

## How argusd works

Commands:

```bat
argusd scan-file <path> --json
argusd self-test
argusd rules
```

`argusd` builds `ArgusEngine`, loads existing runtime YARA/IOC paths, scans one file, emits JSON, exits.

Exit codes:

- `0`: clean/normal
- `1`: suspicious/unusual
- `2`: high risk/malicious
- `3`: scan error
- `4`: rules/config error
- `5`: invalid args

Important: daemon treats `0`, `1`, and `2` as valid scan exits and uses JSON verdict.

## Daemon optional worker mode

Default remains in-process ARGUS.

Config:

```toml
[scan]
argus_worker_enabled = false
argus_worker_path = "argusd.exe"
argus_worker_timeout_sec = 15
orchestrator_file_scan_enabled = false
```

Flat legacy-compatible fields also work:

```toml
argus_worker_enabled = false
argus_worker_path = "argusd.exe"
argus_worker_timeout_sec = 15
```

Daemon reads worker config at startup.

Worker path resolution checks explicit config path, `sentinelld.exe` sibling folder, current working directory, `target\release`, `target\debug`, and project root inferred from target folders.

## Orchestrator routing pilot

Codex routed one safe path through the orchestrator:

```text
scan.start { type: "file" }
```

The pilot is disabled by default:

```toml
[scan]
orchestrator_file_scan_enabled = false
```

When enabled, manual single-file scans enqueue on the manual queue and return quickly with a job id. Existing `scan.status` remains the compatibility surface for progress and final status.

Still legacy:

- quick scans
- folder scans
- watcher scans
- idle scans

Cancellation:

- queued file job: cancel flag set, status becomes `cancelled`
- running file job: status becomes `cancelling`
- optional `argusd` worker receives same cancel flag and can be killed
- in-process ClamAV/ARGUS drains current file before final `cancelled`

Diagnostics added under `diagnostics.export.orchestrator`:

- `enabled_file_scan`
- `last_orchestrated_job`
- `manual_queue_depth`
- `worker_active_path`
- `cancelled_jobs`
- `failed_jobs`
- `average_manual_scan_duration_ms`
- nested queue/worker state under `state`

## Fallback behavior

Worker disabled:

```text
daemon -> in-process ARGUS
```

Worker enabled, success:

```text
daemon -> argusd -> JSON verdict
```

Worker missing, timeout, bad JSON, rules/config failure:

```text
daemon logs warning -> in-process ARGUS fallback
```

Malformed JSON, missing fields, invalid enum values, invalid score, invalid SHA-256, huge stdout, huge stderr, partial output, and non-UTF8 output all fail closed into fallback.

Worker cancellation:

```text
scan.cancel -> cancel flag -> kill worker -> controlled file error
```

Diagnostics:

```text
diagnostics.export.argus_worker.enabled
diagnostics.export.argus_worker.path
diagnostics.export.argus_worker.timeout_sec
diagnostics.export.argus_worker.fallback_count
diagnostics.export.argus_worker.timeout_count
diagnostics.export.argus_worker.last_error
diagnostics.export.argus_worker.last_timeout
```

Packaging:

```text
argusd.exe staged next to sentinelld.exe
release sanity checks argusd.exe
WiX installs argusd.exe to INSTALLFOLDER
worker remains disabled by default
```

## Validation commands

```bat
cargo check --workspace
cargo test -p argus
cargo run -p argusd -- self-test
cargo run -p argusd -- rules
cargo run -p argusd -- scan-file Cargo.toml --json
cd gui
pnpm exec tsc --noEmit
pnpm build
```

Script:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\test-argus-worker.ps1
```

## Known limitations

- No persistent worker pool.
- No OS sandbox/job object.
- No GUI worker settings.
- No ClamAV in worker.
- Orchestrator pilot disabled by default.
- Only manual single-file scan can use orchestrator.
- Quick/folder/watcher/idle remain legacy.
- Watcher/idle scanner still in-process.
- Daemon config changes require restart.
- Malformed worker/timeout tests still need automation.

## Next recommended waves

1. Add integration tests with stub worker: timeout worker, malformed JSON, huge JSON, non-UTF8 output.
2. Add Windows job object kill containment for worker subtree.
3. Add tests for orchestrated file enqueue/complete/cancel.
4. Route folder scans through manual queue after pilot stability.
5. Consider routing watcher/idle scanner only after pool stability.
6. Add optional GUI setting after worker pool stability.

## Copy-paste prompt for Claude

```text
Continue Sentinella ARGUS worker isolation from current state.

Do not remove in-process ARGUS fallback.
Do not change ARGUS scoring.
Do not touch GUI unless needed.

Review:
- docs/ARGUS_WORKER_ARCHITECTURE.md
- docs/CLAUDE_HANDOFF_ARGUS_WORKER.md
- crates/argusd
- crates/sentinelld/src/argus_worker.rs

Next goals:
1. Validate orchestrator_file_scan_enabled=true with one clean file and one cancellation.
2. Add integration tests for orchestrated file enqueue/complete/cancel.
3. Add integration tests using stub worker for timeout, malformed JSON, huge JSON, non-UTF8 output, and exit code 1/2 valid verdicts.
4. Add Windows job object/process tree kill safety.
5. Route folder scans through manual queue only after pilot stability.
6. Keep config default disabled and preserve fallback to in-process ARGUS.

Validation:
cargo check --workspace
cargo test -p argus
cargo run -p argusd -- self-test
cargo run -p argusd -- rules
cargo run -p argusd -- scan-file Cargo.toml --json
```

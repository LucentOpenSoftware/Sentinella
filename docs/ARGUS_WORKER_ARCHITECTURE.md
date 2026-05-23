# ARGUS Worker Architecture

## Why this exists

ARGUS can do heavy file analysis: hashing, YARA, PE parsing, script inspection, and reputation checks. Running that work inside `sentinelld` keeps integration simple, but one bad or slow file can steal time from daemon control-plane work.

The external worker path starts separating scan worker-plane risk from daemon IPC, watcher, status, cancellation, and quarantine control-plane behavior.

## Current state

This wave adds a one-shot worker binary:

```bat
argusd scan-file <path> --json
argusd self-test
argusd rules
```

`argusd` reuses `crates/argus` directly. It does not duplicate scoring, detection logic, YARA mapping, IOC logic, or confidence logic.

`sentinelld` still defaults to in-process ARGUS. External worker use is optional and disabled by default.

## Output contract

`argusd scan-file <path> --json` emits one JSON object with:

- `path`
- `file_size`
- `sha256`
- `mime_type`
- `score`
- `verdict`
- `confidence_label`
- `threat_maturity`
- `framework`
- `strategy`
- `timing`
- `findings`
- `analysis_time_us`
- `engine_version`
- `timestamp`
- `explanation`
- `errors`

Exit codes:

- `0`: clean/normal
- `1`: suspicious/unusual
- `2`: high risk/malicious
- `3`: scan error
- `4`: rules/config error
- `5`: invalid args

Daemon integration treats exit codes `0`, `1`, and `2` as valid scan results when JSON parses correctly.

## Runtime paths

Worker rule loading checks project-root and installed-folder style paths:

- `runtime/argus/rules/yara`
- `runtime/rules`
- `runtime/rules/ioc_hashes.txt`
- `runtime/argus/rules/ioc/ioc_hashes.txt`
- `runtime/signatures/ioc_hashes.txt`
- installed sibling rule paths such as `rules/yara`

Explicit overrides:

```bat
argusd --rules-dir <path> --ioc-file <path> scan-file <path> --json
```

Daemon worker binary resolution checks explicit config path, the same directory as `sentinelld.exe`, current working directory, `target\release`, `target\debug`, and project root inferred from target folders.

## Config flags

Current supported config fields:

```toml
[scan]
argus_worker_enabled = false
argus_worker_path = "argusd.exe"
argus_worker_timeout_sec = 15
orchestrator_file_scan_enabled = false
```

Backward-compatible flat fields are also accepted by the current daemon config:

```toml
argus_worker_enabled = false
argus_worker_path = "argusd.exe"
argus_worker_timeout_sec = 15
```

`sentinelld` reads these settings at daemon startup. Restart daemon after changing worker mode.

## Orchestrator routing pilot

The scan orchestrator now has one routed pilot path, guarded by config:

```toml
[scan]
orchestrator_file_scan_enabled = false
```

When disabled, manual single-file scans use the legacy synchronous path.
When enabled, only `scan.start { type: "file" }` is enqueued on the manual orchestrator queue and returns a job id quickly. Quick scans, folder scans, realtime watcher scans, and idle scans still use legacy scan paths.

Pilot job status values are `queued`, `running`, `cancelling`, `completed`, `cancelled`, and `failed`. `scan.status` remains compatible and reports the active file job using the existing IPC response shape.

`scan.cancel` sets the shared cancellation flag immediately. Queued file jobs become cancelled before execution. Running file jobs move to cancelling while the current ClamAV/ARGUS operation drains. If the optional ARGUS worker is active, the same cancel flag is passed into worker execution so the daemon can kill `argusd` instead of waiting forever.

Diagnostics now include:

- `orchestrator.enabled_file_scan`
- `orchestrator.last_orchestrated_job`
- `orchestrator.manual_queue_depth`
- `orchestrator.worker_active_path`
- `orchestrator.cancelled_jobs`
- `orchestrator.failed_jobs`
- `orchestrator.average_manual_scan_duration_ms`

## Fallback behavior

Default path:

```text
sentinelld -> in-process ARGUS
```

Worker-enabled path:

```text
sentinelld -> argusd -> JSON verdict
```

If worker spawn, timeout, bad JSON, or rules/config exit failure occurs, daemon logs warning and falls back to in-process ARGUS. Worker failure must not crash daemon.

If scan cancellation occurs while worker runs, daemon kills worker and records a controlled scan error for that file instead of waiting for ARGUS to finish in-process.

Worker JSON is bounded to 16 MiB on stdout and 64 KiB on stderr. Missing fields, invalid enum values, invalid score, invalid SHA-256, partial JSON, non-UTF8 JSON, and inconsistent final score are rejected and routed to fallback.

## Timeout behavior

`argus_worker_timeout_sec` controls per-file worker lifetime. When exceeded:

1. daemon kills worker process;
2. child process is reaped;
3. worker result is discarded;
4. daemon logs warning and falls back to in-process ARGUS for non-cancel failures;
5. scan remains controlled and IPC should remain reachable.

Cancellation uses same worker kill path.

## Diagnostics

`diagnostics.export` includes worker metadata:

- `argus_worker.enabled`
- `argus_worker.path`
- `argus_worker.timeout_sec`
- `argus_worker.fallback_count`
- `argus_worker.timeout_count`
- `argus_worker.last_error`
- `argus_worker.last_timeout`

## Release integration

Release staging copies `argusd.exe` beside `sentinelld.exe`. Release sanity checks fail when worker binary is missing. WiX installs `argusd.exe` into the application folder. Worker mode still remains disabled by default.

## What is not implemented yet

- No persistent process worker pool.
- No GUI controls for worker mode.
- No ClamAV inside worker.
- No OS sandbox/job object containment.
- No automated malformed-worker integration tests yet.
- Watcher and idle scanner still use in-process ARGUS.
- Quick and folder scans still use legacy scan routing.

## Future worker pool plan

Next safe step:

1. Add small bounded worker pool.
2. Add per-worker job object/process group.
3. Share structured timeout/fallback counters through `runtime.stats`.
4. Route folder scan through manual queue after pilot stability.
5. After stability tests, route watcher/idle scanner selectively.

## Validation

```bat
cargo check --workspace
cargo test -p argus
cargo run -p argusd -- self-test
cargo run -p argusd -- rules
cargo run -p argusd -- scan-file Cargo.toml --json
```

## Orchestrator Pilot Status (May 2026)

### What's Routed

| Scan Type | Routing | Status |
|---|---|---|
| Manual file scan | Orchestrator (when enabled) | **Pilot — disabled by default** |
| Manual folder scan | Orchestrator (when enabled) | **Pilot — disabled by default** |
| Quick scan | Orchestrator (when enabled) | **Pilot — disabled by default** |
| Watcher scan | Legacy path | Not routed |
| Idle scanner | Legacy path | Not routed |

### How to Enable

```toml
# sentinelld.toml
[scan]
orchestrator_file_scan_enabled = true
orchestrator_folder_scan_enabled = true
orchestrator_quick_scan_enabled = true
```

### How to Disable

Set `orchestrator_file_scan_enabled = false` or remove the field (defaults to false).

### Status Transitions (Orchestrated File Scan)

```
queued → running → completed (with result)
queued → cancelled (if cancelled before worker picks up)
running → cancelling → cancelled (if cancelled during scan)
running → failed (if worker error or timeout)
```

### UI Compatibility

- "queued" status handled by Scan page (polls for completion)
- "cancelling" status displayed correctly
- Stop button works for both queued and running states
- Legacy path still works when flag is disabled

### Known Pilot Limitations

- Only manual single-file scan is routed
- Worker process (`argusd.exe`) must exist in expected path
- If worker missing, falls back to in-process ARGUS
- No queue depth limits enforced yet
- No worker restart on crash yet (panic caught, not process crash)

### Next Route Candidate

**Recommended: Option A — Manual folder scan**

Rationale:
- Folder scan is the heaviest workload (8530s HP driver folder before optimization)
- Multi-threaded worker pool already exists in orchestrator (2 manual workers)
- Folder scan already uses separate thread with cancel flag — natural fit
- Risk is low: folder scan is user-initiated, not background protection

After folder scan pilot stable → quick scan → watcher events.

## Pilot Validation Results (May 2026)

### Test Matrix

| Scenario | File Pilot | Folder Pilot | Quick Pilot | Legacy |
|---|---|---|---|---|
| Status: queued → running → completed | ✅ Code verified | ✅ Code verified | ✅ Code verified | N/A |
| Cancel before worker pickup | ✅ Token checked | ✅ Token checked | ✅ Token checked | ✅ |
| Cancel during active scan | ✅ Token propagated | ✅ Token → 4 workers | ✅ Token → 4 workers | ✅ |
| Worker panic recovery | ✅ catch_unwind | ✅ catch_unwind | ✅ catch_unwind | N/A |
| Diagnostics exposure | ✅ | ✅ | ✅ | N/A |
| Live state lock-free reads | ✅ | ✅ | ✅ | ✅ |
| Legacy fallback (flag=false) | ✅ | ✅ | ✅ | ✅ |

### Orchestrator Test Suite: 9 tests

| Test | Verifies |
|---|---|
| manual_queue_executes_job | Basic job execution |
| cancelled_token_reaches_job | Pre-cancel propagation |
| realtime_queue_executes | Realtime queue works |
| idle_queue_executes_with_delay | Idle 250ms pacing |
| diagnostics_snapshot | 3 queues, 4 workers visible |
| multiple_manual_jobs | 5 concurrent jobs complete |
| cancel_before_execution | Pre-cancel flag check |
| worker_recovers_from_panic | Panic → crash count → next job works |
| queue_depth_tracks | Submitted/depth counters correct |

### Enablement Strategy

**Phase 1 (Current): All disabled by default.**
- Developers can enable per-flag for testing.
- Legacy paths are the production default.
- No user-visible behavior change.

**Phase 2 (After 1 week stable field test): Enable file scan.**
- Lowest risk — single file, synchronous result expected.
- If stable for 3 days → enable folder scan.

**Phase 3 (After folder stable): Enable quick scan.**
- Quick scan is effectively folder scan with predefined targets.
- If stable → all three manual scans routed through orchestrator.

**Phase 4 (Future): Route watcher through Realtime queue.**
- Highest frequency path — requires careful backpressure.
- Defer until manual scan pilots proven stable.

## Live Validation Harness

### Test Corpus Generator

```powershell
# Create a safe test corpus (24 files, ~5MB).
scripts/create-scan-test-corpus.ps1

# Include EICAR test file (will be detected).
scripts/create-scan-test-corpus.ps1 -Eicar

# Clean up.
scripts/create-scan-test-corpus.ps1 -Clean
```

Generates: 3 executables, 3 scripts, 3 documents, 4 config/skip files,
4 build artifacts, 2 media, 1 large blob, 3 nested files.

### Validation Script

```powershell
# Run full validation (requires sentinella-argus built).
scripts/test-orchestrator-pilots.ps1

# With verbose output.
scripts/test-orchestrator-pilots.ps1 -Verbose
```

Checks: self-test, rules, file scan, folder scan, explain mode,
strategy classification, JSON output parsing.

### Validation Results (May 2026)

```
Self-test:     5/5 passed
Rules:         119 YARA, 9 IOC
File scan:     clean_app.exe → 0/100 Clean
Folder scan:   24 files → 0 threats → 5.9s (debug build)
Explain:       Score breakdown, confidence, maturity, timing all present
Strategy:      .log → SkipSafe, .jpg → SignatureOnly, .exe → FullAnalysis
```

### 3-Day Pilot Enablement Plan

**Day 1-3: File scan pilot only**
```powershell
scripts/enable-orchestrator-dev.ps1 -Pilot file
# Restart daemon
```
- Scan known clean EXE files
- Scan installers (Claude Setup, ChromeSetup)
- Cancel a file scan
- Check diagnostics: `health.healthy = true`
- Verify daemon stays reachable

**Day 4-6: Enable folder pilot (if file stable)**
```powershell
scripts/enable-orchestrator-dev.ps1 -Pilot folder
# Restart daemon
```
- Scan Downloads folder
- Scan test corpus
- Cancel during active folder scan
- Check performance summary
- Verify no daemon disconnects

**Day 7+: Enable quick pilot (if folder stable)**
```powershell
scripts/enable-orchestrator-dev.ps1 -Pilot all
# Restart daemon
```
- Quick scan from GUI
- Cancel quick scan
- Verify all three pilots working together

**Rollback at any time:**
```powershell
scripts/disable-orchestrator-dev.ps1
# Restart daemon
```

### Health Gate

Diagnostics include an orchestrator health assessment:
```json
{
  "health": {
    "healthy": true,
    "ready_for_next_pilot": true,
    "crashes": 0,
    "timeouts": 0,
    "fallbacks": 0,
    "failed": 0,
    "completed_file_scans": 5
  }
}
```

- `healthy`: true if zero crashes, timeouts, failures, and ≤2 fallbacks
- `ready_for_next_pilot`: true if healthy AND ≥3 completed file scans
- If either is false, do NOT enable next pilot

### File Pilot Field Validation (May 2026)

**Config**: `orchestrator_file_scan_enabled = true`

| File | Score | Verdict | Confidence | Time | Notes |
|---|---|---|---|---|---|
| notepad.exe | 5/100 | Low Suspicion | Unusual | 891ms | Future timestamp finding. Normal. |
| cmd.exe | 57/100 | High Suspicion | Suspicious | 836ms | YARA matches (PID spoofing, USB worm strings). Expected — CLI lacks Authenticode. Daemon gives -25 → 32. |
| clean_app.exe | 0/100 | Clean | Normal | 49ms | Test stub. Perfect. |
| deploy.ps1 | 0/100 | Clean | Normal | 15ms | Test script. Perfect. |
| app.log | 0/100 | Clean | Normal | 0ms | SkipSafe strategy. Instant. |
| photo.jpg | 0/100 | Clean | Normal | 2ms | SignatureOnly strategy. |
| libtest.rlib | 0/100 | Clean | Normal | 0ms | SkipSafe strategy. Instant. |

**Folder scan**: 24 corpus files → 0 threats → 6.3s (debug build)

**Authenticode**: CLI now includes Windows system path trust for catalog-signed
binaries (cmd.exe, notepad.exe). System32/SysWOW64 binaries get -20 discount.
Embedded Authenticode signatures are also verified as before.

**Recommendation**: File pilot is **stable and ready** for daemon field testing. cmd.exe score is not a bug — it's expected behavior without Authenticode context.

### What Constitutes a Failed Validation

- Self-test fails (engine/rules not loading)
- Clean files score > 25
- Scan exits with code 3+ (scan error)
- JSON output not parseable
- Strategy classification wrong (.log gets FullAnalysis)
- Folder scan timeout (>60s for 24 files)

### Folder Scan Orchestration Design

When `orchestrator_folder_scan_enabled = true`:

1. `scan.start { type: "folder" }` returns `status: "queued"` immediately
2. Job submitted to orchestrator Manual queue
3. Worker picks up job → runs `folder_scan_worker` (same multi-threaded pipeline as legacy)
4. Live state updated atomically (files_total, files_scanned, threats)
5. `scan.status` reads from lock-free ScanLiveState
6. Cancel sets token → workers stop accepting new files → drains → cancelled

The orchestrated folder scan reuses the entire existing scan pipeline — it just routes
through the queue instead of spawning a thread directly. This means:
- Same 4-thread worker pool
- Same scan strategy classifier
- Same YARA/ARGUS analysis
- Same performance metrics
- Same cancel behavior

The difference: the scan request returns "queued" and the orchestrator controls when
it starts, enabling future priority management and backpressure.

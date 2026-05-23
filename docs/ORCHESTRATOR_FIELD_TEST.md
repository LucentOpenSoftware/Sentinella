# Orchestrator File Pilot — Field Test Procedure

**Date**: May 2026  
**Pilot**: `orchestrator_file_scan_enabled = true`  
**Prerequisites**: daemon built, GUI built, config enabled

---

## Setup

```powershell
# 1. Enable file pilot.
scripts/enable-orchestrator-dev.ps1 -Pilot file

# 2. Start daemon.
dev-run.bat
# OR: target\release\sentinelld.exe --foreground --log-level info --dll-dir target\release --db-dir runtime\signatures
```

## Test Matrix

### File Scans (6 files minimum)

| # | File | Expected Score | Expected Verdict |
|---|---|---|---|
| 1 | `C:\Windows\System32\notepad.exe` | 0 | Clean / Trusted |
| 2 | `C:\Windows\System32\cmd.exe` | <=40 | Suspicious / Normal |
| 3 | `test-corpus\executables\clean_app.exe` | 0 | Clean / Normal |
| 4 | `test-corpus\scripts\deploy.ps1` | 0 | Clean / Normal |
| 5 | Any `.exe` from Downloads | varies | Should not auto-quarantine |
| 6 | Any small text file | 0 | Clean |

### Status Transitions

For each file scan, observe in the Scan page:

```
Click "Scan Now" → UI shows "Scanning..." 
  (may briefly show "queued" if orchestrator is busy)
→ Progress spinner
→ Result appears with score + verdict
```

**Pass criteria:**
- No stuck "queued" state (should transition in <2s)
- No "Daemon not connected" during scan
- Result displays correctly
- Score matches expected range

### Cancellation Tests

| Test | Steps | Expected |
|---|---|---|
| Cancel immediately | Click Scan Now → immediately click Cancel | Status → "Cancelled" |
| Cancel during scan | Scan a file → click Cancel while scanning | Status → "Cancelling" → "Cancelled" |

**Pass criteria:**
- UI becomes usable immediately after cancel
- No error states
- No "Daemon unreachable"

### Diagnostics Check

After 3+ successful scans:

1. Export diagnostics (IPC: `diagnostics.export`)
2. Check orchestrator section:

```json
{
  "orchestrator": {
    "health": {
      "healthy": true,
      "ready_for_next_pilot": true,
      "crashes": 0,
      "timeouts": 0,
      "fallbacks": 0,
      "failed": 0,
      "completed_file_scans": 3
    }
  }
}
```

**Pass criteria:**
- `healthy = true`
- `ready_for_next_pilot = true`
- All error counters = 0

### Daemon Reachability

During scan activity:
- [ ] Dashboard shows "Connected" (green badge)
- [ ] Scan page does NOT show "Daemon not connected"
- [ ] Protection state does NOT show "degraded"
- [ ] Other pages remain navigable

## Rollback

If any test fails:

```powershell
scripts/disable-orchestrator-dev.ps1
# Restart daemon
```

## Decision Gate

**Keep file pilot enabled** if:
- All 6 scans completed successfully
- No crashes or stuck states
- Cancellation works
- Diagnostics health green
- Daemon remained reachable throughout

**Disable file pilot** if:
- Any scan hung or stuck in queued
- Daemon showed unreachable during scan
- Protection degraded appeared during scan
- Crashes > 0 in diagnostics
- Scores wildly wrong (notepad.exe > 25)

### Memory Pressure During Scans

After each scan, check diagnostics.export:

```json
{
  "memory_pressure": {
    "state": "normal",
    "working_set_mb": ...,
    "prefer_external_argus": false,
    "actions": []
  },
  "footprint": {
    "working_set_mb": ...,
    "delta_since_start_mb": ...,
    "warning_level": "normal"
  }
}
```

**Pass criteria:**
- Memory pressure stays `normal` or `elevated`
- Working set returns within ~50MB of baseline after scan
- No monotonic growth warning in footprint notes
- `delta_since_start_mb` < 200 after idle period

### Worker Lifecycle

Check orchestrator workers after scans:

```json
{
  "workers": [
    {
      "id": "Manual-0",
      "state": "ready",
      "completed_jobs": 3,
      "last_duration_ms": 1200,
      "crash_count": 0
    }
  ],
  "queues": [
    {
      "kind": "manual",
      "depth": 0,
      "pressure": "normal"
    }
  ]
}
```

**Pass criteria:**
- All workers `state: "ready"` after scans
- `crash_count = 0`
- Queue `pressure = "normal"` at rest
- `depth = 0` at rest

## Next Step

If file pilot stable for 3 days:
```powershell
scripts/enable-orchestrator-dev.ps1 -Pilot folder
```

---

## Quick Start

```bat
scripts\run-file-pilot-test.bat
```

This script enables the pilot, runs self-test, starts daemon, and guides you through testing.

## Pre-Validation Results (Automated, May 2026)

| File | Score | Confidence | Status |
|---|---|---|---|
| notepad.exe | 0/100 | Trusted | ✅ |
| cmd.exe | 37/100 | Normal | ✅ |
| clean_app.exe | 0/100 | Normal | ✅ |
| deploy.ps1 | 0/100 | Normal | ✅ |
| app.log | 0/100 | Normal | ✅ (SkipSafe) |
| photo.jpg | 0/100 | Normal | ✅ (SigOnly) |

All files within expected ranges before daemon test.

---

*This procedure should be run by the developer on a controlled machine.
Do not enable on secondary/shared machines until file pilot proven stable.*

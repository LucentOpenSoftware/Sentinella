# ASTRA Runtime Intelligence

## Overview

ASTRA runtime intelligence adds contextual awareness beyond static file analysis.
Three components work together:

1. **AMSI Runtime Scanning** — Analyzes deobfuscated script content
2. **Persistence Intelligence** — Contextual scoring for autorun locations
3. **PLM (Process Lineage Monitor)** — Tracks parent-child process chains

## Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| AMSI scan pipeline | Ready | Dev injection via CLI/IPC |
| AMSI provider | Not registered | Observe-only first |
| Persistence Intelligence | **LIVE** | Wired into scan workers |
| PLM graph | **LIVE** | 5-second process snapshots |
| PLM scan correlation | **LIVE** | File path matched to process tree |
| Runtime blocking | Disabled | Observe-only mode |

## How to Test

### Runtime Scan via CLI

```powershell
$env:SENTINELLA_IPC_SECRET = Get-Content runtime\state\ipc_secret
.\target\release\sentinella.exe runtime-scan test.ps1 --language powershell --json
```

### Validation Corpus

```powershell
.\scripts\test-runtime-intake.ps1
```

## Architecture

```
Script content (file or runtime buffer)
  |
  v
ARGUS analyze_buffer()  (YARA-heavy, no PE, 2s budget)
  |
  v
PLM query_by_image_path()  (lineage chain scoring)
  |
  v
Persistence check_persistence_context()  (autorun location boost)
  |
  v
Combined ASTRA verdict (score + findings + should_block)
```

## Scoring

- Runtime buffers are deobfuscated content = cleaner signals
- Convergence threshold: 20 (lower than file scanning)
- Blocking threshold: score >= 80
- PLM boost: up to +30 from suspicious process chains
- Persistence boost: +8 to +15 from autorun locations

## What Happens Next

1. PowerShell Script Block Logging / ETW intake (live buffer capture)
2. True AMSI provider registration (COM interface)
3. Runtime blocking for high-confidence detections
4. Full PLM-AMSI-Persistence convergence

## Safety Guarantees

- Runtime intake is **observe-only** — no blocking, no quarantine
- PLM uses process snapshots (ToolHelp32), not kernel hooks
- No scripts are executed during testing
- Blocking will only be enabled after field validation

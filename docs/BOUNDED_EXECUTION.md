# Bounded Execution Architecture

## Overview

Every file scan in Sentinella operates within an execution budget. Exceeding a budget is NOT failure -- it is evidence. Timeouts feed back into the ARGUS convergence model as suspicion signals.

## Scan Profiles

| Profile | max_duration | max_clamav | max_yara | max_structural | archive_depth | extracted_bytes | yara_matches |
|---------|-------------|------------|----------|----------------|---------------|-----------------|-------------|
| realtime | 10s | 5s | 3s | 2s | 5 | 100MB | 50 |
| manual | 60s | 30s | 15s | 10s | 10 | 500MB | 200 |
| idle | 120s | 60s | 30s | 20s | 10 | 500MB | 200 |
| startup | 15s | 8s | 5s | 3s | 3 | 50MB | 50 |

## Timeout Reasons

| Reason | Suspicion Weight | What it means |
|--------|-----------------|---------------|
| ClamAvTimeout | +3 | Parser complexity, mildly suspicious |
| YaraTimeout | +5 | Rule complexity or obfuscation |
| StructuralTimeout | +8 | Unusual PE/document structure |
| TotalTimeout | +5 | General complexity |
| ArchiveExplosion | +12 | Deliberate zip bomb or evasion |
| ExtractionOverflow | +10 | Decompression bomb |
| YaraFlood | +8 | Too many matches (noise or evasion) |
| SandboxOverrun | +6 | Process would not terminate |

## Budget Outcomes

| Outcome | Meaning |
|---------|---------|
| Clean | Completed within budget, no timeouts |
| Suspicious | Completed but high-weight timeouts occurred |
| Exhausted | Entire budget consumed |
| Aborted | Cancelled by user or system |
| Partial | Some phases timed out, evidence is partial but usable |

## Partial-Result Semantics

If a timeout occurs mid-scan:
- Evidence collected BEFORE the timeout is preserved
- ClamAV result is never discarded (even if ARGUS times out)
- Timeout suspicion weight is added to the ARGUS score
- The file is NOT marked as "scan failed" -- it is "partially analyzed"
- The scan continues to the next file (no abort)

## What is Wired Now

- Manual/folder/full/quick scan worker loop: per-file budget enforcement
- ClamAV phase timing checked against budget
- ARGUS/YARA phase timing checked against budget
- Total budget checked between ClamAV and ARGUS phases
- Timeout reasons recorded in ScanTiming
- Timeout suspicion contributes to ARGUS score
- Diagnostics counters (files_with_timeouts, clamav_timeouts, etc.)
- BudgetOutcome classification

## What is NOT Wired Yet

- Watcher inline scan (different code path, no thread pool)
- Idle scanner (single-threaded, different path)
- Archive depth/extracted byte tracking (requires ClamAV engine integration)
- Per-file timeout enforcement within ClamAV (ClamAV has internal limits)

## Expansion Plan

1. Wire budget into watcher scan path
2. Wire budget into idle scanner
3. Add archive depth/extraction byte tracking via CL_ENGINE settings
4. Expose budget outcome in GUI scan results
5. Feed budget evidence into calibration system

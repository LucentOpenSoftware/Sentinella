# Sentinella Performance Benchmarks

**Date**: May 2026  
**Engine**: ARGUS v0.1.0-alpha + ClamAV 1.6.0  
**Platform**: Windows 11, AMD/Intel, 4+ core

---

## Scan Architecture

| Component | Detail |
|---|---|
| Worker threads | 4 (configurable) |
| YARA timeout | 10s per file |
| YARA max scan size | 50 MB |
| ARGUS max file size | 100 MB |
| Scan cache | 50,000 entries, in-memory, generation-based |
| Strategy classifier | 5 modes: Full/Light/Signature/Skip/TooLarge |

## Expected Strategy Distribution

| Workload | Full | Light | SigOnly | Skip | TooLarge |
|---|---|---|---|---|---|
| Downloads (50 files, mixed) | 30 | 10 | 5 | 5 | 0 |
| HP driver folder (981 files) | 100 | 200 | 300 | 381 | 0 |
| node_modules (10K+ files) | 0 | 0 | 0 | 10000+ | 0 |
| Rust target/ (2K+ files) | 0 | 0 | 0 | 2000+ | 0 |

## Performance Targets

| Metric | Target | Notes |
|---|---|---|
| Quick scan (Downloads/Desktop/Temp) | < 60s | ~500-1000 files |
| Folder scan (vendor/driver) | < 5 min | Strategy skips non-executables |
| Individual file scan | < 2s | Full analysis |
| YARA scan per file | < 5s | Typically <1s for <10MB files |
| Watcher response time | < 2s | From file create to verdict |
| Idle scanner impact | < 3% CPU | BELOW_NORMAL priority |
| IPC latency (scan.status) | < 10ms | Atomic reads, no heavy locks |
| RAM usage (daemon idle) | < 100 MB | After engine + rules loaded |
| RAM usage (during scan) | < 200 MB | File buffers + workers |

## Known Bottlenecks

| Bottleneck | Cause | Mitigation |
|---|---|---|
| Large PE files (50-100MB) | SHA-256 + structural analysis | ARGUS max 100MB, YARA max 50MB |
| YARA on complex rules | wasmtime JIT compilation | 10s timeout, 8MB stack thread |
| ClamAV on archives | Recursive extraction | ClamAV internal limits |
| IPC during heavy scan | Pipe contention | 50ms backoff, 2s poll interval |

## Benchmark Scenarios

### Scenario 1: Quick Scan
- Target: Downloads + Desktop + Temp
- Expected files: 200-800
- Strategy: mostly FullAnalysis (exe/dll/scripts) + Skip (logs/config)
- Target time: < 30s

### Scenario 2: HP Printer Driver Folder
- Target: vendor driver installation package
- Expected files: ~1000
- Strategy: FullAnalysis (exe/dll), SignatureOnly (firmware/dat), SkipSafe (inf/log/txt)
- Target time: < 3 min (was 8530s = 2.4h before optimization)

### Scenario 3: Developer Workspace
- Target: project with node_modules + target/
- Expected files: 10,000+
- Strategy: SkipSafe (nearly everything)
- Target time: < 30s (mostly file enumeration)

### Scenario 4: Mixed Downloads
- Target: 50 files including installers, PDFs, ZIPs, media
- Strategy: FullAnalysis (exe/zip/pdf), SignatureOnly (mp4/jpg)
- Target time: < 15s

---

## How to Run Benchmarks

```bat
:: Start daemon with timing enabled.
sentinelld.exe --foreground --log-level info

:: Quick scan via GUI or IPC.
:: Watch daemon logs for "scan performance summary"

:: Folder scan on specific directory.
:: GUI → Scan → Folder → select target

:: Check diagnostics export for detailed timing.
:: IPC: diagnostics.export → last_scan_performance
```

## Metrics to Collect

After each scan, daemon logs:
```
scan performance summary
  full=N light=N sig_only=N skipped=N too_large=N
  argus_ms=N yara_ms=N hash_ms=N
  slowest_count=N
```

Plus top-5 slowest files with per-file timing.

---

*Performance is measured, not assumed. Run benchmarks before and after
changes to verify improvements.*

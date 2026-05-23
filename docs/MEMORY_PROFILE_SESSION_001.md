# Memory Profile Session 001

**Date:** 2026-05-17
**Build:** 0 warnings, 0 errors, 160 tests passing
**Methodology:** Static analysis + footprint telemetry architecture + pressure policy

## Live Measurement Template

Run daemon, record `diagnostics.export` at each stage:

| Stage | working_set_mb | private_bytes_mb | peak_ws_mb | pressure | cache_entries | workers | notes |
|-------|---------------|-----------------|-----------|----------|--------------|---------|-------|
| 1. Pre-startup | — | — | — | — | — | — | Process not yet running |
| 2. After ClamAV load | | | | | | | Sigs loaded |
| 3. After YARA load | | | | | | | JIT compiled |
| 4. Idle 60s | | | | | | | Baseline |
| 5. During quick scan | | | | | | | Peak activity |
| 6. After quick scan | | | | | | | Memory return? |
| 7. During folder scan | | | | | | | Large workload |
| 8. After folder scan | | | | | | | Memory return? |
| 9. 2nd folder scan | | | | | | | Growth check |
| 10. After 2nd scan | | | | | | | Monotonic? |
| 11. Watcher burst | | | | | | | 50+ file copies |
| 12. After burst | | | | | | | Return to baseline? |

**How to capture:** `echo '{"jsonrpc":"2.0","id":1,"method":"diagnostics.export","params":{}}' | sentinella-ipc` or use GUI diagnostics export.

## Measurement Infrastructure

Footprint capture now integrated at:
- `diagnostics.export` IPC endpoint (full snapshot)
- `stats.runtime` IPC endpoint (embedded in RuntimeStats)
- Lifecycle logging: startup baseline, post-scan baseline
- Delta tracking: `delta_since_start_mb`, `delta_since_last_scan_mb`
- Warning levels: normal (<800MB), elevated (800-1500MB), warning (1500-2500MB), critical (>2500MB)
- Monotonic growth detection over last 8 captures

## Expected Memory Consumers

### 1. ClamAV Signature Database

**Estimated footprint:** 200-400MB for ~3.6M signatures
**Behavior:** Loaded once at startup, retained permanently, reloaded on `freshclam` update.
**Memory pattern:** Step function. Jumps at load, stable thereafter.
**Note:** This is the single largest memory consumer. Cannot be reduced without reducing detection coverage. ~1MB per 10K signatures is the rough estimate.

### 2. YARA-X / Wasmtime JIT Runtime

**Estimated footprint:** 50-150MB for ~119 rules
**Behavior:** Compiled at startup via wasmtime JIT. Each rule becomes a WASM module.
**Memory pattern:** Step function. Large allocation at JIT compilation, stable after.
**Note:** wasmtime + cranelift contribute significant baseline. Suppressed at `warn` log level to avoid noise. Not reducible without moving to interpreted YARA mode (significant performance cost).

### 3. Scan Cache (DashMap)

**Estimated footprint:** ~1KB per entry, grows with scan activity
**Behavior:** Entries added per-file-scanned, keyed by path + metadata hash.
**Memory pattern:** Monotonic growth bounded by total unique files scanned.
**Warning threshold:** 40,000 entries flagged in diagnostics.
**Note:** Cache is not currently evicted. Growth is slow (only unique files). A large folder scan of 100K files would add ~100MB.

### 4. Active Scan Workers

**Baseline:** 4 workers (2 manual + 1 realtime + 1 idle)
**Per-worker footprint:** ~5-20MB (file I/O buffers, PE parsing, YARA matching context)
**Behavior:** Allocated on job start, freed on completion.
**Memory pattern:** Spike during scan, returns after.
**Note:** Workers use `catch_unwind` for panic recovery. Stack is standard Rust thread stack (~8MB reserved, ~few KB committed until used).

### 5. Orchestrator Queue Buffers

**Footprint:** Negligible (<1MB)
**Behavior:** mpsc channels with bounded depth tracking.
**Note:** Queue messages are closures, not file data.

### 6. FISH MutationWindow

**Footprint:** ~1MB max (1024-capacity VecDeque of FileMutationEvent)
**Behavior:** Sliding window, auto-expires events older than 30s.
**Note:** Negligible contributor. Self-bounding.

### 7. SQLite State Database

**Footprint:** ~2-10MB (connection + page cache)
**Behavior:** Persistent, grows with scan history and activity log.
**Note:** SQLite manages its own page cache. Not a significant contributor.

## Predicted Baseline (No Scan Active)

| Component | Estimated MB |
|-----------|-------------|
| ClamAV signatures | 200-400 |
| YARA-X / wasmtime | 50-150 |
| Rust runtime + daemon | 20-50 |
| SQLite + misc | 5-15 |
| **Total baseline** | **275-615** |

## Predicted Peak (During Folder Scan)

| Component | Additional MB |
|-----------|--------------|
| Scan buffers (4 workers) | 20-80 |
| Scan cache growth | 10-100 |
| ARGUS analysis context | 5-20 |
| **Peak total** | **310-815** |

## Key Questions for Live Measurement

### Does memory return after scans?
**Expected:** Yes for scan worker buffers. No for scan cache entries.
**Delta tracking:** `delta_since_last_scan_mb` will show positive if buffers retained.
**Measurement:** Compare footprint at idle vs 60s after folder scan completion.

### Is growth monotonic?
**Expected:** Slow monotonic growth from scan cache. Not pathological.
**Detection:** `FootprintBaselines::is_monotonic_growth(8)` checks last 8 captures.
**Threshold:** Growth >50MB over 8 captures without scan activity = investigate.

### Does ClamAV dominate RAM?
**Expected:** Yes. 50-70% of working set.
**Verification:** Compare `working_set_mb` with `signature_count / 10000` estimate.

### Does YARA runtime dominate RAM?
**Expected:** Second largest consumer at 50-150MB.
**Note:** wasmtime JIT is inherently memory-heavy. This is the cost of fast rule matching.

### Would subprocess isolation help?
**Expected:** Yes for peak reduction. ClamAV signatures would not need to be loaded in the main daemon process if scanning happens in a subprocess.
**Trade-off:** IPC overhead, startup latency per scan, process management complexity.
**Recommendation:** Defer until baseline is proven >1.5GB in practice.

## Diagnostics Export Fields

```json
{
  "footprint": {
    "working_set_mb": 450,
    "private_bytes_mb": 520,
    "peak_working_set_mb": 680,
    "clamav_loaded": true,
    "signature_count": 3600000,
    "yara_rules": 119,
    "scan_cache_entries": 12500,
    "active_workers": 0,
    "delta_since_start_mb": 15,
    "delta_since_last_scan_mb": -30,
    "warning_level": "normal",
    "notes": [
      "ClamAV: ~360MB estimated for 3600000 signatures",
      "YARA-X: 119 rules (wasmtime JIT contributes ~50-150MB)",
      "Memory returned after scan completion"
    ]
  }
}
```

## Lifecycle Logging Points

1. **Startup:** After engine + YARA load → baseline recorded
2. **Post-scan:** After every folder/quick scan completion → post-scan baseline updated
3. **On-demand:** Via `diagnostics.export` or `stats.runtime` IPC calls

## Memory Pressure Architecture (Wave 2)

### Pressure States

| State | Threshold | Actions |
|-------|-----------|---------|
| Normal | < 800 MB | No intervention |
| Elevated | 800–1500 MB | Monitor, log transitions |
| Warning | 1500–2500 MB | Route ARGUS to external worker, reduce in-process workers to 1 |
| Critical | > 2500 MB | All Warning actions + pause idle scanner, reject new full scans |

### Pressure-Driven Behavior

```toml
[performance]
memory_profile = "normal"
memory_warning_mb = 1500
memory_critical_mb = 2500
external_argus_under_pressure = true
max_resident_workers_on_pressure = 1
```

### External Worker Strategy

When pressure >= Warning AND `external_argus_under_pressure = true`:
1. `analyze_argus_file()` routes to `argusd.exe scan-file --json` subprocess
2. Subprocess loads its own ARGUS + YARA engine, scans one file, outputs JSON, exits
3. All worker memory (JIT, buffers, PE parser state) freed when process exits
4. If external worker fails → fallback to in-process (logged as pressure-fallback)

### Disposable Worker Mode

`sentinella-argus scan-file <path> --json --single-use`
- Process loads ARGUS, scans one file, outputs verdict JSON, exits immediately
- All heap + JIT + mmap state returned to OS on exit
- Key benefit: worker memory does NOT accumulate in daemon's working set

### Idle Scanner Pressure Awareness

- Critical pressure → idle scanner pauses with reason "memory_pressure"
- Pauses for 30s, rechecks pressure before resuming
- Inner scan loop also checks pressure before each file

### Diagnostics Export

```json
{
  "memory_pressure": {
    "state": "warning",
    "working_set_mb": 1800,
    "prefer_external_argus": true,
    "pause_idle_scanner": false,
    "reject_full_scans": false,
    "max_resident_workers": 1,
    "actions": [
      "route_argus_to_external_worker",
      "reduce_resident_workers_to_1"
    ]
  },
  "footprint": { ... }
}
```

### Health Endpoint

```json
{
  "status": "ok",
  "memory_pressure": "normal",
  "user_disabled": false
}
```

## Recommendations

### No Optimization Needed Yet
- Baseline is expected to be 300-600MB — acceptable for a security daemon
- ClamAV signature footprint is inherent and non-negotiable
- YARA-X/wasmtime is the cost of fast rule matching

### Active Mitigations (Implemented)
- Memory pressure policy classifies and drives adaptive behavior
- External ARGUS worker routing under pressure (config-gated)
- Idle scanner auto-pauses under critical pressure
- Disposable `--single-use` worker mode available for subprocess isolation

### Monitor For
- Working set >1.5GB sustained → pressure system auto-routes to external workers
- Monotonic growth over 8+ captures → possible slow leak
- Peak >2.5GB → critical pressure auto-pauses idle scanner
- `delta_since_last_scan_mb` consistently positive → scan buffers not freed

### Future Optimization Candidates (not yet justified)
1. Scan cache eviction (LRU with time-based expiry)
2. Full ClamAV subprocess isolation (moves ~300MB out of daemon)
3. Lazy YARA-X initialization (defer until first scan)
4. Bounded file I/O buffers per worker
5. Batch worker mode (`argusd scan-batch --max-files 50 --exit-after`)

## Session Status

**Phase:** Pressure architecture complete, awaiting live measurements
**Next:** Run daemon with pressure logging, measure in-process vs external worker footprint
**Blocking:** None — all pressure policy and telemetry is wired and shipping
**Test count:** 160 (119 ARGUS + 41 sentinelld, including 10 pressure tests)

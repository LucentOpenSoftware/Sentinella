# Developer Mode + ARGUS Benchmark Tool — v0.1.6

**Status:** B0 (`argusd benchmark`), B1 (telemetry writer + scan/reload hooks + real bytes-scanned + ClamAV/ARGUS phase split via v4 schema), and B2 (dev-mode IPC + GUI toggle + "Run benchmark" button via `benchmark.run`, with benchmark→telemetry routing) all IMPLEMENTED. Remaining polish: per-ARGUS-layer breakdown, mpool note, benchmark history compare.
**Scope:** v0.1.6 ONLY. A local, per-machine performance-assessment aid for the
author's own hardware. Future versions may keep only the perf-improvement
findings and drop the tool itself.

**Non-goals (hard):** no cloud, no aggregation, no network egress, no
per-user/cross-machine telemetry. Nothing leaves the machine. This is "dump
this box's performance to a txt file in the AV data dir," nothing more.

---

## 1. Developer Mode (config — IMPLEMENTED)

`DeveloperConfig` (in `crates/sentinelld/src/config/mod.rs`):

```toml
[developer]
enabled = false              # per-machine state; only honored after password check
password_sha256 = ""         # lowercase hex SHA-256 of the unlock password; empty = locked
telemetry_enabled = true     # when dev mode on, append perf telemetry to the dump file
telemetry_max_kb = 2048      # hard cap on the dump file (KiB), clamped to [64, 65536]
```

Rules enforced in `Config::validate()`:
- `password_sha256` must be empty or exactly 64 lowercase hex chars; malformed → scrubbed to empty.
- `enabled = true` with no/invalid password → forced back to `false`.
- `telemetry_max_kb` clamped to `[64, 65536]`.

Helpers (config/mod.rs): `hash_developer_password(pw) -> hex`, and
`verify_developer_password(input, stored_hex) -> bool` (constant-time, locked if
unprovisioned/malformed). Tested.

`settings.get` redacts `developer.password_sha256` before returning over IPC.

### Provisioning + enabling (flow)
1. Provision the hash once, out-of-band: edit `sentinelld.toml`
   `[developer] password_sha256 = <sha256 hex of chosen password>` (or via a
   future `dev.provision` IPC that accepts the plaintext on an elevated channel
   and stores only the hash). Empty hash keeps the feature locked.
2. Enable at runtime via a new authenticated IPC method (TODO, §3):
   `dev.set_developer_mode { password, enabled }`.
   - Daemon: `verify_developer_password(password, cfg.developer.password_sha256)`.
   - On match: set `cfg.developer.enabled = enabled`, save config, start/stop the
     telemetry writer.
   - On mismatch / unprovisioned: reject (rate-limited; reuse the existing
     `RateBucket` machinery to blunt guessing of the low-harm gate).

Security framing: this is a low-harm local convenience gate (enables a perf
dump), NOT an auth boundary. SHA-256 (no salt/KDF) + constant-time compare is
deliberately sufficient-not-strong; documented as such in code.

---

## 2. Perf telemetry writer (IMPLEMENTED — core)

Module `crates/sentinelld/src/devmode/telemetry.rs` (+ `devmode/mod.rs`).

- **Sink [DONE]:** `<data>/diagnostics/perf_telemetry.txt` via
  `paths().diagnostics_dir()`. Plain text, append.
- **Gate [DONE]:** `telemetry::enabled(cfg)` = `cfg.enabled && cfg.telemetry_enabled`.
  AppState caches the `DeveloperConfig` in a `Mutex` (`developer_config`),
  initialized in `AppState::new`, runtime-replaceable via `load_developer_config`
  (awaits the B2 `dev.set_developer_mode` IPC). The gate is checked BEFORE any
  footprint capture so it is a true no-op when off.
- **Triggers [DONE]:**
  - **Scan completion** — hooked at `persist_scan` (the single chokepoint every
    recorded scan flows through). Emits `kind="scan"`.
  - **Engine reload** — hooked at `reload_engine` (reuses the already-computed
    `reload_ms`). Emits `kind="reload"` with signature count / error.
- **Record (one human-readable block per event) [DONE]:**
  - timestamp (local, with tz), host cores + total RAM + arch + SIMD summary
    (avx2/avx/sse4.2/sse2 via `footprint::system_info_json`)
  - files, bytes, threats, wall duration, files/sec, MB/sec (zero-duration safe)
  - working set / private bytes / peak + pressure state at completion
  - free-form notes: scan status/id/errors + `scan_cache hits/misses/entries`;
    reload signature count
- **Bounded [DONE]:** before append, if `current + block > telemetry_max_kb`
  (clamped [64, 65536] KiB) and the file exists, rotate to `perf_telemetry.1.txt`
  (single backup) and start fresh. A single oversized block still writes once.
- **Best-effort [DONE]:** write failures are logged at debug and swallowed —
  telemetry can never disrupt scanning.
- **Tests [DONE]:** gate logic, zero-duration throughput, SIMD-summary ordering,
  block formatting, append/grow, and cap-triggered rotation (6 unit tests).

**B1 follow-ups landed (v4 schema, b1-perf-fields):**
- `ScanRow` gained `bytes_scanned`, `clamav_phase_us`, `argus_phase_us`. DB
  migrated via v4 (`ALTER TABLE scans ADD COLUMN ...`); base schema mirrors.
  `Database::insert_scan` / `recent_scans` round-trip the new fields (locked in
  by `scan_row_v4_perf_fields_roundtrip`). Older rows back-fill to 0.
- Single-file scan paths (`scan_file`, `complete_orchestrated_file_success`)
  populate from `result.scanned_bytes` and `verdict.timing.{clamav_us,
  argus_total_us}`.
- Multi-file legacy job path now aggregates via `ScanPerformanceSummary`
  (added `total_clamav_us` + `total_bytes_scanned`, accumulated in
  `record_file`) and `persist_scan` reads `j.perf_summary.*` for the row.
- `emit_scan_telemetry` now writes real `bytes` + a `phase: clamav=Xus
  argus=Yus` note — MB/sec in the dump is finally real for both single-file
  and multi-file jobs.

**Remaining (smaller B1 polish, not blocking v0.1.6 trust-parity testing):**
- per-ARGUS-layer breakdown (yara/structural/hash) in the telemetry note —
  already aggregated in `perf_summary` (`total_yara_us`, `total_hash_us`),
  just unsurfaced.
- mpool file-backed? + cache-MB note.
- **ACL:** file is created under the SYSTEM-owned data dir; readable by
  Administrators. No secrets in the dump (full paths are fine on a dev box).

---

## 3. IPC + GUI surface (IMPLEMENTED — dev toggle/status)

- **IPC methods [DONE]** (registered in `ipc/policy.rs`, handled in `ipc/mod.rs`):
  - `dev.set_developer_mode { password, enabled, telemetry_enabled? }` →
    `verify_developer_password` (constant-time) against the provisioned hash,
    then flips `developer.enabled` (+ optional telemetry sub-switch), runs
    `config.validate()`, refreshes the in-memory gate via
    `load_developer_config`, persists, and audit-logs. `AuthenticatedAction` +
    `ConfigMutation` rate bucket (blunts password guessing); rejects with a
    clear error when locked/unprovisioned/bad-password.
  - `dev.status` → `{ enabled, telemetry_enabled, provisioned, telemetry_max_kb,
    dump_path, dump_size_kb }`. `AuthenticatedRead`. Never returns the hash.
  - Policy unit test `dev_mode_methods_registered` asserts class/audit/bucket.
  - `benchmark.run { passes? }` [DONE] → gated behind developer mode in the
    handler; `AuthenticatedAction` on the `DiagnosticsExport` bucket (throttled),
    blocked while reloading. `AppState::run_benchmark` spawns the worker
    (`argus_worker::run_benchmark`, hardened spawn: no CWD search, bounded reads,
    120s timeout + cancel), parses the report, and — when telemetry is on —
    appends a `kind="benchmark"` record to the dump (closes benchmark→file
    routing). Tiny generated corpus ⇒ ~1-2s, safe to run synchronously.
- **Tauri bridge [DONE]** (`gui/src-tauri/src/lib.rs`): commands
  `get_developer_status` / `set_developer_mode` (registered in the invoke
  handler) call the daemon via `call_auth`. TS wrappers in
  `gui/src/api/sentinella.ts` (`getDeveloperStatus`, `setDeveloperMode`,
  `DeveloperStatus`).
- **GUI [DONE]:** Settings → Advanced → "Developer Mode" `DeveloperSection`
  (`gui/src/pages/Settings.tsx`). Hidden entirely until `dev.status` reports
  `provisioned`. Password field → enable/disable; when enabled, a telemetry
  toggle + dump path/size readout + a **"Run benchmark" button** that calls
  `benchmark.run` and renders Performance Index, throughput, p50/p95 latency,
  and system (cores + SIMD). Tauri command `run_benchmark` + TS
  `runBenchmark`/`BenchmarkReport`. All strings via `t()` (EN + ES added).
- **Live verification pending:** the `benchmark.run` round-trip is build-/unit-
  verified and the standalone `argusd benchmark` is confirmed working; a final
  click-test against a running daemon (dev mode unlocked) is still advisable.

### Security hardening applied while wiring (bug-identification pass)
- **Benchmark corpus symlink/TOCTOU:** the generated corpus dir is now uniquely
  named (pid + nanos), wiped before use, and each file is written with
  `create_new` (refuses to follow a pre-planted symlink). Closes an
  elevated-overwrite hole on shared `/tmp`.
- Residual (accepted): the telemetry file lives in the SYSTEM-owned diagnostics
  dir; a symlink-follow there would require pre-existing admin write access.

---

## 4. ARGUS Benchmark Tool (architecture)

**Purpose:** assess how ARGUS scanning performs on a given machine's hardware —
a repeatable, deterministic score so the author can compare boxes / regressions.

**Principle:** reuse the real ARGUS pipeline (no synthetic micro-bench that
drifts from production). Run ARGUS over a fixed, shipped **benchmark corpus** so
results are comparable across machines.

### Corpus
- A small, deterministic, SAFE set bundled with the tool (NOT live malware):
  reuse `scripts/create-scan-test-corpus.ps1` shape — N executables, scripts,
  documents, archives, one large blob, nested dirs. Fixed bytes → fixed work.
- Optional EICAR for a detection-path timing sample.
- Lives under `runtime/benchmark/corpus/` or generated to a temp dir at run.

### Harness (`argusd benchmark` subcommand — reuses the existing one-shot worker)
- Warm-up pass (prime caches / page-in mpool), then **M timed passes**.
- Per pass: total wall, files/sec, MB/sec, p50/p95 per-file latency, per-ARGUS-
  layer time breakdown (timing already exposed), ClamAV vs ARGUS split.
- Aggregate across passes: median + stddev (variance matters — flag noisy runs).
- Capture machine facts: CPU model/cores, RAM, disk type (SSD/HDD if derivable),
  whether file-backed mpool active.
- Output: a single `BenchmarkReport` → pretty txt into the perf telemetry dir
  AND a JSON for tooling. A single composite **"ARGUS Performance Index"**
  (e.g. normalized MB/sec at a reference profile) for quick cross-box compare.

### Determinism / fairness
- Pin the scan profile (e.g. `ScanProfile::manual()`), disable idle/watcher
  interference during the run, run at a fixed concurrency, fixed corpus.
- Report environmental caveats (on battery? pressure state? other load?) so a
  bad run is identifiable rather than silently skewing the index.

### Phasing
- **B0 [DONE]:** `argusd benchmark [--dir D] [--passes N] [--json]` in
  `crates/argusd/src/main.rs`. Implemented:
  - Corpus: caller `--dir` (bounded recursive collect, depth ≤ 12, ≤ 4096 files,
    skips symlinks/reparse) OR a generated deterministic SAFE corpus in a temp
    dir (xorshift bytes → identical across machines): pseudo-PE at 3 sizes,
    ps1/bat/js scripts, an OOXML-ish docx, and opaque blobs 1 KiB–1 MiB. Temp
    corpus auto-cleaned.
  - 1 untimed warm-up pass + N timed passes (default 3); median total wall for
    throughput, latency distribution from the middle pass.
  - Reports files/sec, MB/sec, per-file p50/p95/max/mean µs, logical cores +
    arch + SIMD (avx2/avx/sse4.2/sse2 or aarch64 neon), and a composite
    **Performance Index** (`files_per_sec * 2`, calibrated so the dev i5-1265U
    ≈ 100 on a RELEASE build — debug scores ~10× lower; index only comparable
    when run over the generated corpus).
  - Pretty text or `--json`. Exit `EXIT_CLEAN`; `EXIT_SCAN_ERROR` on empty corpus.
  - Verified on dev box: generated corpus 11 files / 1.86 MB → ~45 files/sec,
    ~7.6 MB/sec, index ~90 (release).
- **B1:** multi-pass + median/stddev + machine facts + txt/JSON report into the
  dev telemetry dir (gated by developer mode). NOTE: multi-pass + machine facts
  (cores/SIMD/arch) already landed in B0; B1 adds stddev/variance flagging,
  disk-type + on-battery + mpool facts, per-ARGUS-layer time breakdown
  (`argus::verdict::timing`), and routing the report into the telemetry dir.
- **B2 [DONE, minus history]:** dev-mode GUI (password unlock, enable/disable,
  telemetry toggle, dump path/size) + `dev.status`/`dev.set_developer_mode` IPC
  + the **"Run benchmark" button** wired to `benchmark.run` (shells out to
  `argusd`, routes the report into the telemetry file) + Performance Index shown
  in the UI. Remaining: benchmark **history compare** across runs.

### Trust-parity across hardware (the actual goal)

The point is NOT "how many MB/s." It is: **does Sentinella behave acceptably on
an i7-7200U / Core 2 Quad / Skylake / Ryzen the same way it does on the i5-1265U
dev box?** So the benchmark must assess SLO adherence per hardware tier, not a
raw number:

1. **Capture machine capability** (so results are comparable + caveats explicit):
   - logical/physical cores, base clock, **SIMD level** (AVX2 / AVX / SSE4.2 /
     SSE2). This matters: yara-x and hashing use SIMD; a Core 2 Quad (no AVX)
     takes the scalar path and is materially slower — a number that looks "bad"
     may just be "old CPU, working as designed."
   - total RAM, disk type (SSD/HDD), on-battery, file-backed mpool active.
2. **Measure the SLOs that define "trustable," not just throughput:**
   - **Real-time per-file latency p95** — the watcher must stay responsive even
     on a Core 2 Quad (a slow box must not make file saves feel laggy).
   - **Memory-budget adherence** — working set must stay under the
     (now RAM-relative) pressure thresholds; the `Critical` gate must actually
     fire *before* swap on a 4 GB box.
   - **Idle politeness** — idle scanner must yield under CPU/disk pressure on a
     weak box (the cpu_pause / disk_latency gates).
   - throughput (files/s, MB/s) reported but **normalized per logical core** so a
     2c/4t i7-7200U isn't unfairly compared to a 10-thread 1265U.
3. **Verdict per tier:** PASS/WARN/FAIL against tier-appropriate SLO targets
   (e.g. "p95 real-time latency < 250 ms on any tier"), so the answer is
   "trustable here?" not "fast here?".

### Cross-hardware trust gaps found while scoping this (status)

- **[FIXED]** Pressure thresholds were absolute (1500/2500 MB) → on 4 GB they
  fired after swap; on 32 GB they were needlessly low. Now derived from total
  RAM via `pressure::ram_relative_thresholds(total_ram_mb, profile)` +
  `detect_total_ram_mb()`, wired in `AppState::new`. Profiles low/normal/
  aggressive scale the percentages.
- **[FIXED]** `AppState::new` now loads the user's `[performance]` config
  (incl. `memory_profile`). Thresholds left at defaults → auto-derived from RAM
  using the configured profile; explicit user overrides respected as-is.
- **[FIXED]** Background folder/full scan pool was a fixed `SCAN_THREADS=4`
  regardless of cores → now `scan_threads()` = ~half logical CPUs clamped [2,8]
  (Core 2 Quad → 2, i7-7200U 4t → 2, 1265U 10t → 5, big Ryzen → 8). The
  orchestrator pilot pools (`MANUAL/REALTIME/IDLE_WORKERS`) remain fixed — they
  are mostly disabled and lower-traffic; revisit if the pilot is promoted.
- **[DONE]** SIMD/CPU-feature detection: `footprint::system_info_json()`
  (logical_cores, total_ram_mb, arch, SIMD avx2/avx/sse4.2/sse2 via the safe
  `is_x86_feature_detected!` macro) is now exposed under `system` in
  `diagnostics.export`. The benchmark report should embed this so a Core 2 Quad's
  no-AVX scalar-path result reads as "old CPU, working as designed."

### Explicit v0.1.6 sunset
This tool exists to gather hardware perf data during 0.1.6 hardening. Post-0.1.6,
keep the *learnings* (profile tuning, concurrency defaults) and consider removing
the benchmark surface, or demote it to a dev-only `argusd` subcommand with no GUI.

# Design: Zero-Downtime Engine Reload (Blue-Green Hot-Swap) — v2

**Status:** Proposed (post-0.1.x). Not scheduled for 0.1.6.
**Author:** audit session, 2026-05.
**Goal:** Eliminate the "daemon disconnected — protection degraded" UI state during signature updates / engine reloads, and make a failed reload non-destructive.

---

## 1. Problem

Today, `AppState::reload_engine_inner` (`crates/sentinelld/src/ipc/state.rs`) reloads the ClamAV engine **destructively and in place**:

```rust
// 1. Drop the OLD engine first (to avoid 2× mpool ≈ 2 GB).
{ let mut g = self.write_engine(); if let Some(old) = g.take() { drop(old); } }
// 2. ~5–8 s: build + compile the NEW engine.
match ClamEngine::load(dll_dir, db_dir) { Ok(new) => *self.write_engine() = Some(Arc::new(new)), ... }
```

Two consequences:

1. **Degraded window.** Between the `take()` and the new `Some(...)`, `self.engine == None` for ~5–8 s. Scans skip, `engine.status` reports no engine, and the GUI surfaces "protection degraded." This happens on every signature update that triggers a reload.
2. **Failed reload = protection fully down.** If `ClamEngine::load` fails (corrupt CVD, OOM, compile error), the old engine is already gone, so the daemon is left with **no engine at all** until a manual restart or a later successful reload. There is no fallback to the last-known-good engine.

The destructive order exists for one reason: avoid holding two ~970 MB mpools at once (the comment at state.rs:2898 is explicit).

## 2. Key enabler already in place

Scan paths do not hold the engine lock for the scan duration. They clone the `Arc` and release immediately:

```rust
let engine = match &*self.read_engine() { Some(e) => Arc::clone(e), None => return };
// ... scan using `engine` (an Arc<ClamEngine>), lock already released ...
```

So in-flight scans keep their engine alive by `Arc` refcount. A reload only needs a **brief write-lock to swap the pointer**; existing scans drain naturally on the old engine, new scans pick up the new one. This is the foundation for blue-green with no per-scan coordination.

## 3. Proposal: in-process blue-green swap

Double-buffer **only the engine**, not the process.

```
reload():
  1. new = ClamEngine::load(dll_dir, db_dir)   // on a blocking thread; does NOT touch self.engine
  2. if new.is_err(): log + KEEP old engine; return Err   // atomic rollback — never go to None
  3. { let mut g = self.write_engine(); let old = g.replace(Arc::new(new)); }  // brief lock
  4. drop(old) happens when its last in-flight scan finishes (Arc refcount → 0)
  5. invalidate scan cache, update signature_count, reap old mpool cache file
```

Properties:
- Daemon process never exits → IPC pipe stays connected → **no "disconnected"**.
- `self.engine` is `Some` at all times → **no "degraded"**.
- Failed load keeps the working engine → **no protection-down gap**.
- No new process, no state handoff.

## 4. Why NOT a separate "A/B" support daemon

An Android-style A/B *process* swap was considered and rejected. The engine is the only component worth double-buffering; everything else must remain single-owner, and a second process forces split-brain:

| Shared resource | Problem with two daemons |
|---|---|
| Named pipe `\\.\pipe\sentinelld` | Two servers → which owns active-scan / quarantine state? |
| SQLite DBs (scan_cache, trust_graph, sentinella, calibration) | Two writers → lock contention / corruption |
| Real-time watcher + ETW sessions | Single-owner; two = duplicate/conflicting events |
| SCM service lifecycle | SCM manages one `SentinellaDaemon`; a spawned helper has no crash recovery |
| In-memory state (active scans, FISH window, PLM graph, trust graph, ecosystem) | Must be serialized + handed off → large new race surface |

The only thing A/B-process would buy over blue-green is **isolation of a crashy compile**, which is already covered by the Windows service failure-recovery policy plus the `ENGINE_RELOAD_IN_PROGRESS` guard. Cost ≫ benefit.

The one idea worth importing from A/B is **atomic rollback** (verify-then-swap, keep old on failure) — and blue-green delivers exactly that in §3 step 2.

## 5. Prerequisites

### 5.1 Per-instance mpool cache file path (REQUIRED)
`ClamEngine::load` passes a file-backed mpool cache path to libclamav via the `SENTINELLA_MPOOL_CACHE_PATH` env var, derived from `residency.prepare()` (clamav.rs:130-138). If that path is fixed, two coexisting engines **clobber the same cache file** — which is precisely why the current code drops-before-loads.

Blue-green requires a **generation-suffixed** cache path, e.g. `mpool.<gen>.bin`, where `<gen>` is a monotonically increasing reload counter. The old generation's file is deleted after the swap completes and the old engine is dropped.

Touch points: `ClamEngine::load` signature (accept a cache path / generation), `ResidencyManager::prepare`, and reap-on-drop.

### 5.2 Memory-pressure gate (REQUIRED)
During overlap, two mpools coexist (~2× ≈ 2 GB peak working set during the compile). Most of it is file-backed / standby pages, but RSS spikes while compiling. Gate the strategy on the existing `PressureTracker`:

- `Normal` / `Elevated` / `Warning` → blue-green (build new, then swap).
- `Critical` → fall back to today's destructive drop-first reload (accept the degraded window to avoid OOM).

### 5.3 Reload serialization (ALREADY DONE)
`ENGINE_RELOAD_IN_PROGRESS` (with the RAII guard) already prevents concurrent reloads. Keep it.

## 6. Phasing

| Phase | Scope | Risk | Ships |
|---|---|---|---|
| **P0** | Reorder reload to **build-into-local-var, swap only on `Ok`, keep old on failure**. Closes the "failed reload → no engine" protection-down bug. Still has the degraded window (still drops old before building under the fixed cache path — so P0 keeps drop-first ordering but adds the keep-old-on-failure semantics by loading into a temp and only `take()`ing the old after the new is ready *iff* the cache-path constraint allows; if not, P0 is just "on load failure, do not leave None — reload old from db_dir or mark last-good"). | Low | Could backport to 0.1.x |
| **P1** | Generation-suffixed mpool cache path → true engine coexistence. | Medium | v2 |
| **P2** | Background-thread compile + `Arc` swap + pressure gate → zero degraded window. | Medium | v2 |

> Note on P0: full atomic rollback needs §5.1 (two engines must coexist to "keep old while building new"). Until then, the cheap P0 win is narrower: on `ClamEngine::load` failure, **do not leave `engine = None`** — either retain a handle to the old engine (requires not dropping it first → needs §5.1) or, as a stopgap, attempt an immediate reload from the last-known-good DB directory and log loudly. The clean fix is P1+P2.

## 7. Testing

- Unit: reload strategy selection by pressure state (pure function, like `pressure::decide`-style).
- Unit: generation counter + cache-path naming + reap.
- Integration (manual / harness): trigger reload under active scan → assert no IPC disconnect, `engine.status` stays `Some`, in-flight scan completes on old engine, new scan uses new sig count.
- Fault injection: feed a corrupt CVD → assert old engine retained, `engine.status` still healthy, error surfaced in diagnostics.
- Memory: measure peak working set during overlap on a 4 GB VM; confirm `Critical` gate falls back.

## 8. Open questions

- Does `ResidencyManager` support multiple live cache files, or assume a singleton? (Determines P1 effort.)
- libclamav: any global state in `cl_engine_new`/`cl_engine_compile` that makes two live engines in one process unsafe? (ClamAV supports multiple engines per process in principle; verify with the vendored version.)
- Should the GUI show a subtle "updating signatures…" affordance during a hot-swap, or stay fully silent? (UX call.)

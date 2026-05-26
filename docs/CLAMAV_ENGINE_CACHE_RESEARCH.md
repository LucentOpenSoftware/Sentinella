# ClamAV Engine Cache Research

Research branch for reducing Sentinella's memory footprint from ~974 MB private bytes
down to a single-digit megabytes effective RAM via file-backed memory mapping.

## Problem

ClamAV's `cl_engine_compile()` builds the signature matching engine in anonymous
memory (VirtualAlloc/mmap). With 3.6M signatures, this consumes ~900 MB of private
committed pages. The OS cannot efficiently page these out because they're anonymous
(not file-backed).

The goal is to back the engine pages with a file on disk so the OS can freely
discard and reload pages on demand. Effective RAM usage drops to just the working
set (pages currently accessed), typically a fraction of total mapped size.

## Architecture

ClamAV's memory allocator (`libclamav/mpool.c`) is already mmap-based:
- `mpool_create()` uses `VirtualAlloc` (Windows) or `mmap` (Linux) for large regions
- All engine data structures are pool-allocated via `MPOOL_MALLOC`, `MPOOL_CALLOC`
- The pool is a linked list of `MPMAP` regions

## Pointer Census (cl_engine struct)

| Category | Count | Relocatable? |
|---|---|---|
| Scalar fields | ~15 | Trivially |
| Pool-allocated matchers | ~8 | If pool maps to same base |
| Pool-allocated sub-structs | ~8 | Same |
| Heap strings (tmpdir etc.) | 3 | Rebuild on load |
| Function callbacks | 7 | Set after load |
| AC automaton cross-refs | Millions | The hard problem |

## The AC Automaton Pointer Problem

Each Aho-Corasick node contains raw pointers to other nodes:
```c
struct cli_ac_node {
    struct cli_ac_node *fail;     // failure link → other node
    struct cli_ac_node *trans[];  // transition table → other nodes
    struct cli_ac_patt *list;     // pattern list → other node
};
```

If the pool maps to a different virtual address, every pointer is invalid.

## Phased Approach

### Phase 0: Measure (DONE)
- Working set: 974 MB at startup
- Pool stats: available via `mpool_getstats()`
- Signature count: 3,627,866
- mpool diagnostics wired into clamav.rs (logs used/total/efficiency after compile)

### Phase 1: Introspect (DONE)
- Identified 30+ raw pointer fields in cl_engine
- Confirmed AC automaton has millions of internal cross-pointers
- Confirmed mpool is the primary allocator (~95% of engine memory)
- Identified mpool.c as the single modification point
- Two allocation sites: `mpool_create()` (initial) and `mpool_malloc()` (growth)
- Both use `VirtualAlloc(NULL, sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)` on Windows

### Phase 2A: File-Backed mpool (IMPLEMENTED — needs ClamAV rebuild)
- Modified `mpool.c` with `SENTINELLA_FILEBACKED_MPOOL` compile flag
- Added `sentinella_alloc_filebacked()` — uses `CreateFileMapping + MapViewOfFile`
- Added `sentinella_free_filebacked()` — proper unmap + handle cleanup
- Added `sentinella_mpool_cleanup()` — full resource release
- Added `sentinella_mpool_set_cache_path()` — configure cache file location
- Gated behind `#ifdef SENTINELLA_FILEBACKED_MPOOL` — zero risk to vanilla ClamAV
- Graceful fallback: if file operations fail → falls back to `VirtualAlloc`
- Region tracking: up to 256 mapped regions tracked for cleanup
- Both allocation sites (create + growth) use file-backed path when enabled

**To activate:** Add `target_compile_definitions(clamav PRIVATE SENTINELLA_FILEBACKED_MPOOL)`
in `libclamav/CMakeLists.txt`. The daemon sets `SENTINELLA_MPOOL_CACHE_PATH` env var
before `cl_engine_new()`.

**What changes:** Page backing behavior only.
**What doesn't change:** Allocation semantics, matcher logic, AC traversal, detection.

### Phase 2B: Multi-Region File-Backed (VALIDATED)
- Fixed MapViewOfFile offset alignment (64KB allocation granularity)
- All mpool growth regions now file-backed (not just initial)
- Single backing file with growing mapped regions at aligned offsets
- Graceful fallback: any Windows API failure → VirtualAlloc

**MEASURED RESULTS:**

| Metric | Vanilla (anonymous) | File-backed | Improvement |
|---|---|---|---|
| **Private Bytes** | 989 MB | **17 MB** | **-98.3%** |
| Working Set | 992 MB | 989 MB | Same (hot) |
| **Compile time** | 3,469 ms | **2,260 ms** | **-35%** |
| Cache file | N/A | 978 MB | Backing store |
| Detection | ✅ | ✅ | Identical |
| Tests | 389/389 | 389/389 | No regression |

**Key insight:** Private Bytes drop from 989 MB to 17 MB — a 58× reduction.
The engine is no longer "heavy" — it collaborates with the OS memory manager.
Pages on disk are loaded on demand; unused signature pages can be evicted under pressure.

### Phase 2P: Residency Lifecycle Manager (IMPLEMENTED)
- `MpoolResidencyManager` in `engine/residency.rs`
- Cache metadata (`clamav-engine-mpool.meta`) with:
  - Schema version, DB version, signature count
  - Compile timestamp, compile duration
  - Mapped bytes, region count
  - HMAC integrity hash (keyed by vault key)
- Stale detection: DB version mismatch → invalidate + rebuild
- Corruption detection: HMAC mismatch → invalidate + rebuild
- Safety invariant: cache corruption NEVER crashes or blocks startup

### Phase 2: File-Backed mpool (NEXT)
Modify `mpool_create()` on Windows to use `CreateFileMapping` instead of
`VirtualAlloc`. The pool becomes file-backed immediately during compile.

**Expected benefit:** OS can page out signature pages freely. Effective RAM
drops from 974 MB to ~200-400 MB under normal use (only accessed pages resident).

**No pointer fixup needed** — compile still runs normally, addresses are the
same. The only difference: pages are backed by a file instead of anonymous commit.

Implementation:
```c
// In mpool.c, replace:
VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

// With:
HANDLE hFile = CreateFileW(L"engine.cache", ...);
HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, ...);
MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, sz);
```

### Phase 3: Same-Address Reload (RESEARCH)
After Phase 2, test whether the engine cache file can be reloaded at the
same virtual address on next startup:
```c
MapViewOfFileEx(hMap, FILE_MAP_READ, 0, 0, sz, original_base_address);
```

If this succeeds (address not occupied):
- Engine loads in ~0.5 seconds instead of 6-8 seconds
- All internal pointers are valid (same base address)
- If address is taken: fall back to full recompile

### Phase 4: Relocatable Engine (LONG TERM)
Replace raw pointers with pool-relative offsets:
```c
typedef uint32_t pool_offset_t;
#define POOL_DEREF(pool, off, type) ((type*)((char*)(pool) + (off)))
```

This requires modifying every data structure that contains pointers into the pool.
Estimated scope: ~2-4 weeks of careful work on libclamav internals.

## Risks

- Phase 2 is low risk — mpool already uses mmap, just changing backing store
- Phase 3 is medium risk — ASLR and address space competition
- Phase 4 is high risk — deep libclamav surgery, easy to break matching

## Files to Modify

| File | Phase | Change |
|---|---|---|
| `libclamav/mpool.c` | 2 | File-backed VirtualAlloc → CreateFileMapping |
| `libclamav/mpool.h` | 2 | Add cache file path parameter |
| `sentinelld/engine/clamav.rs` | 2 | Pass cache path to ClamAV init |
| `libclamav/matcher-ac.h` | 4 | Pointer → offset conversion |
| `libclamav/matcher.h` | 4 | Same |
| `libclamav/others.h` | 4 | cl_engine pointer fields |

## Success Criteria

| Phase | Metric | Target |
|---|---|---|
| 2 | Effective RAM under idle | < 400 MB |
| 3 | Startup time (cached) | < 1 second |
| 4 | Effective RAM under idle | < 200 MB |
| 4 | Startup time (cached) | < 0.5 seconds |

## References

- `third_party/clamav/libclamav/mpool.c` — pool allocator source
- `third_party/clamav/libclamav/others.h:294` — cl_engine struct definition
- `third_party/clamav/libclamav/matcher-ac.c` — Aho-Corasick implementation
- `third_party/clamav/libclamav/readdb.c` — signature database loading
- `third_party/clamav/libclamav/default.h` — default engine limits

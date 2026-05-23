# ETW (Event Tracing for Windows) — Sentinella Exploration

**Status**: Research complete — implementation planned for v1.5+  
**Date**: May 2026  
**Decision**: High-value, low-overhead — implement after core stability  

---

## Why ETW Matters for ARGUS

ETW provides the **missing context** that transforms ARGUS from isolated file analysis into contextual intelligence — without packet capture, kernel drivers, or surveillance.

Two providers change everything:
1. **`Microsoft-Windows-Kernel-Process`**: WHO created a file, WHAT spawned it, WHAT command line
2. **`Microsoft-Windows-DNS-Client`**: WHAT domains a process resolved BEFORE writing files

Combined with the existing `notify` file watcher, this enables verdicts like:
> "File `payload.exe` appeared in Downloads (watcher). Written by `chrome.exe` (process tree). Executed, spawned PowerShell with `-enc` flag (process start). Resolved `c2-server.evil.com` (DNS). ARGUS verdict: HIGH RISK."

## Architecture — Minimal Configuration

```
Sentinella Daemon
  ├── File watcher thread (notify/ReadDirectoryChangesW)  ← KEEP
  ├── ETW consumer thread (NEW, ferrisetw crate)
  │     ├── Microsoft-Windows-Kernel-Process (process start/stop)
  │     └── Microsoft-Windows-DNS-Client (DNS resolutions)
  └── Ring buffers (memory-only, 5-15 min retention)
        ├── ProcessBuffer: last 500 process events
        └── DnsBuffer: last 1000 DNS events
```

## Overhead

| Configuration | CPU | RAM |
|---|---|---|
| Process start/stop only | < 0.1% | ~1-2 MB |
| Process + DNS client | **< 0.5%** | ~2-4 MB |
| + Image loads (optional) | 1-3% | ~4-8 MB |
| + Kernel file events | 5-10%+ | NOT recommended |

**Recommended: Process + DNS only = under 0.5% CPU.** Realistic for desktop AV.

## Key Events

### Process Start (Event ID 1)
- Process ID, parent PID, image path, **command line**
- Kernel-level — cannot be bypassed by usermode malware
- Enables: "unsigned exe from %TEMP% spawned PowerShell with encoded command"

### DNS Resolution (Event ID 3008/3020)  
- Domain name, query type, **process ID**
- No packet capture needed — Windows DNS client reports directly
- Enables: "process in %TEMP% resolved discord-webhook.com"

## Privacy Line

**Acceptable (local, ephemeral):**
- Process start metadata in memory-only ring buffer
- DNS resolutions in memory-only ring buffer
- 5-15 minute retention, never persisted to disk
- Never transmitted off-machine

**NOT acceptable:**
- ❌ Keystroke logging
- ❌ Browser URL history
- ❌ Screen content
- ❌ Clipboard monitoring
- ❌ Persistent telemetry database
- ❌ Cloud upload of any ETW data

**This is NOT an EDR.** EDRs collect, persist, and transmit. ARGUS uses ETW as transient, local-only context enrichment.

## Rust Integration

**Primary crate**: [`ferrisetw`](https://crates.io/crates/ferrisetw) — Rust-idiomatic ETW consumer.

```rust
// Conceptual example (not implemented yet)
let provider = Provider::kernel_process()
    .add_keyword(0x10); // WINEVENT_KEYWORD_PROCESS

let session = UserTrace::new()
    .enable(provider)
    .start()?;

// Events arrive on dedicated thread via callback
```

## Comparison: ETW vs `notify` Watcher

| | `notify` (current) | ETW (proposed) |
|---|---|---|
| Answers | WHEN + WHERE a file appeared | WHO created it + WHAT domains it contacted |
| Process info | ❌ | ✅ PID, parent, command line |
| Network context | ❌ | ✅ DNS resolutions per process |
| Implementation | Already done | Future v1.5+ |

**Complementary, not competitive.** `notify` triggers scans. ETW enriches verdicts.

## What NOT to Implement

- ❌ Kernel file events (too noisy — thousands/second)
- ❌ Image load events by default (high volume)
- ❌ Registry monitoring via ETW (crosses into EDR territory)
- ❌ Network packet events (use DNS-Client instead)
- ❌ Persistent ETW log files
- ❌ Any cloud upload of ETW data

## Implementation Plan (v1.5+)

1. Add `ferrisetw` dependency
2. Spawn dedicated ETW consumer thread on daemon start
3. Subscribe to Process + DNS providers
4. Write events to lock-free ring buffers
5. ARGUS queries ring buffers during file analysis for context
6. Context findings added to verdict explanation
7. No UI for raw ETW data — only ARGUS-interpreted context

**Prerequisite**: Core ARGUS engine must be fully stable first.

---

*ETW is the pragmatic path to contextual intelligence — 80% of the value of Zeek/Suricata at 1% of the complexity.*

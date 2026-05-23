# Sentinella Protection Modules Architecture

**Date**: May 2026  
**Codename**: Protection Modules  
**Status**: Architecture defined, Wave A in progress

---

## Naming Convention

Internal modules describe **capability**, not threat marketing.

| Internal Name | Public UI Name | Purpose |
|---|---|---|
| `FISH` | Ransomware Shield | File integrity + mutation detection |
| `runtime_inspection` | Runtime Script Inspection | Script buffer analysis |
| `PLM` | Process Lineage Monitor | Parent-child process tracking |
| `TRRX` | Full Scan / Startup Scan | Scan target collection + policies |

---

## Module Overview

### FISH — File Integrity Shield
Detects destructive file modification patterns (mass rename, entropy spikes,
extension mutations) in user directories. Uses existing watcher foundation.
No kernel driver. Observe-only initially.

### Runtime Inspection
Analyzes script buffers (PowerShell, JS, VBS) at file level. Prepares for
future AMSI provider integration. Uses existing ARGUS script analysis layer.

### PLM — Process Lineage Monitor
Tracks parent-child process relationships. Provides context to ARGUS
convergence model. Existing `ProcessLineageHint` model ready for live data.
ETW integration planned.

### TRRX — Targeting
Centralizes scan target collection for Full Disk Scan, Startup Scan,
and Quick Scan. Uses existing orchestrator + scan pipeline.

---

## Implementation Waves

| Wave | Module | Scope | Risk |
|---|---|---|---|
| **A** | TRRX | Full scan + startup scan targets | **Low** — uses existing scanner |
| B | FISH | File mutation telemetry (observe-only) | Medium |
| C | PLM | Structs + classifier + tests (no ETW) | Low |
| D | PLM | ETW process creation intake | Medium |
| E | Runtime Inspection | Script buffer scanner | Medium |
| F | Runtime Inspection | AMSI exploration | High |
| G | FISH | Active response (alert → contain) | High |

---

## Wave A — TRRX (Targeting)

### Components

```
crates/sentinelld/src/targeting/
  mod.rs          — TargetProvider trait + registry
  full_disk.rs    — Enumerate all fixed drives
  startup.rs      — Windows Run keys + Startup folder + recent exes
  quick.rs        — Downloads/Desktop/Temp (existing targets)
  dedup.rs        — Path deduplication
```

### TargetProvider Trait

```rust
pub trait TargetProvider {
    fn name(&self) -> &str;
    fn collect(&self, config: &TargetConfig) -> Vec<PathBuf>;
}
```

### Scan Types Enabled

| Type | Provider | Status |
|---|---|---|
| Quick Scan | QuickScanTargetProvider | Already exists (Downloads/Desktop/Temp) |
| Full Disk Scan | FullDiskTargetProvider | **New** — all fixed drives |
| Startup Scan | StartupTargetProvider | **New** — Run keys + Startup folder |

### Config

```toml
[targeting]
startup_scan_enabled = false
startup_scan_on_boot = false
startup_recent_days = 7
full_scan_fixed_drives = true
full_scan_max_depth = 15
```

---

## Wave B — FISH (File Integrity Shield)

### Architecture

```
crates/sentinelld/src/fish/
  mod.rs              — FShield orchestrator
  activity_window.rs  — Sliding time window of file events
  burst_tracker.rs    — Mutation burst detection
  entropy_delta.rs    — Entropy change monitoring
  rename_storm.rs     — Mass rename detection
  decision.rs         — Alert/observe decision engine
```

### Detection Signals

| Signal | Description | Threshold |
|---|---|---|
| Rename storm | >25 renames in 30s window | Configurable |
| Rewrite burst | >40 file rewrites in 30s | Configurable |
| Entropy delta | >0.20 average entropy increase | Per-file delta |
| Extension mutation | .docx → .encrypted pattern | Pattern match |
| Delete-after-rewrite | Write → delete sequence | Correlated |
| Ransom note drop | New .txt/.html with ransom keywords | YARA-assisted |

### Watched Directories

- Documents, Desktop, Pictures, Downloads
- OneDrive (if detected)
- Configurable additional paths

### Modes

1. **Observe-only** (default): Log events, expose in diagnostics
2. **Alert**: Show notification on burst detection
3. **Active** (future): Suspend offending process, prompt user

---

## Wave C-D — PLM (Process Lineage Monitor)

### Architecture

```
crates/sentinelld/src/plm/
  mod.rs          — PLMonitor lifecycle
  event.rs        — ProcessEvent struct
  store.rs        — Ring buffer with TTL
  classifier.rs   — Suspicious chain classifier
  provider.rs     — Hint provider for ARGUS
```

### Data Model

```rust
pub struct ProcessEvent {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_name: String,
    pub command_line: Option<String>,
    pub timestamp: i64,
    pub image_path: Option<String>,
}
```

### ETW Source (Wave D)

Provider: `Microsoft-Windows-Kernel-Process`
Event ID: 1 (ProcessStart), 2 (ProcessStop)

---

## Wave E-F — Runtime Inspection

### Architecture

```
crates/sentinelld/src/runtime_inspection/
  mod.rs          — Scanner lifecycle
  buffer.rs       — Script buffer scanner
  verdict.rs      — RuntimeScriptVerdict
  amsi.rs         — Future AMSI provider (Wave F)
```

### Script Analysis Flow

```
Script file detected (watcher/scan)
  → Read content
  → Language detection (PS1/JS/VBS/BAT)
  → ARGUS script analysis layer
  → YARA behavioral rules
  → RuntimeScriptVerdict
```

---

## Config Summary

```toml
[targeting]
startup_scan_enabled = false
startup_scan_on_boot = false
startup_recent_days = 7
full_scan_fixed_drives = true

[fish]
enabled = false
observe_only = true
watch_documents = true
watch_desktop = true
watch_pictures = true
watch_downloads = true
window_seconds = 30
rename_threshold = 25
rewrite_threshold = 40
entropy_delta_threshold = 0.20

[plm]
enabled = false
observe_only = true
retention_minutes = 15
max_events = 5000

[runtime_inspection]
enabled = false
observe_only = true
scan_powershell = true
scan_js = true
scan_vbs = true
max_buffer_kb = 512
```

---

*All modules default disabled. Enable one at a time for testing.
Each wave must pass `cargo test --workspace` before proceeding.*

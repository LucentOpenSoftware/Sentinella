# Engine v0.12 Readiness Assessment

**Date**: May 2026  
**Assessor**: Development team  
**Target**: v0.1.2-alpha (internal milestone, not public release)

---

## Readiness Definition

v0.12 means: **safe to run daily on a test machine without unexpected data loss,
quarantine of legitimate files, or daemon instability.** Not a public beta yet.

---

## Component Readiness

### Detection Engine

| Component | Status | Detail |
|---|---|---|
| ClamAV integration | **Ready** | 3.6M sigs, runtime DLL loading, reload on update |
| ARGUS heuristics | **Ready** | 11 layers, weighted scoring, explanation output |
| YARA-X rules | **Ready** | 119 rules, 23 packs, compile-clean, hot-reloadable |
| IOC hash DB | **Ready** | 9 hashes, hot-reloadable |
| Authenticode | **Ready** | WinVerifyTrust, 55+ trusted signers |
| Reputation DB | **Ready** | 290+ entries, 2-tier discount system |
| Context layer | **Ready** | Gate >=5 points, capped 15, Zone.Identifier + path heuristics |
| Installer detection | **Ready** | NSIS/Inno/WiX/MSI/Electron/NW.js/Tauri + name heuristic (>2MB) |

### Protection Systems

| Component | Status | Detail |
|---|---|---|
| Real-time watcher | **Ready** | ReadDirectoryChangesW, 800ms debounce, build/dev dir skip |
| Idle background scanner | **Ready** | Resource-aware, adaptive speed, BELOW_NORMAL priority |
| Scan cache | **Ready** | Path+size+mtime+generation, 50K entries, invalidated on reload |
| Auto-quarantine | **Ready** | AES-256-GCM, watcher + idle scanner both quarantine threats |
| Multi-threaded scan | **Ready** | 4 workers, mpsc channels |

### Security

| Component | Status | Detail |
|---|---|---|
| Quarantine restore | **Ready** | Challenge token required, path validation, symlink blocked |
| Quarantine delete | **Ready** | Challenge token required (fixed this wave) |
| IPC hardening | **Ready** | Frame size limits, method name limits, catch_unwind |
| Self-exclusion | **Ready** | OnceLock anchor, dev + installed mode, build dir skip |
| Config corruption | **Ready** | Backup bad config, restore defaults, log warning |

### Observability

| Component | Status | Detail |
|---|---|---|
| Protection state | **Ready** | fully_protected / degraded / minimal / unprotected |
| Diagnostics export | **Ready** | Version, subsystem states, cache stats, recent errors |
| Notification system | **Ready** | Dedupe, storm control, severity threshold, calm language |
| Idle scanner status | **Ready** | 11 states, IPC endpoint, Dashboard tile |
| Cache statistics | **Ready** | hits/misses/entries exposed in runtime stats |

### Packaging

| Component | Status | Detail |
|---|---|---|
| Release build | **Ready** | sentinelld 26.8 MB, CLI 1.2 MB |
| Staging pipeline | **Ready** | 42 files, 44 MB |
| MSI installer | **Ready** | Tauri WiX build, 4.4 MB |
| NSIS installer | **Ready** | Tauri NSIS build, 3.2 MB |
| Sanity check | **Ready** | 24/24 pass |
| GPL-2.0 LICENSE | **Ready** | Root file present |

### GUI

| Component | Status | Detail |
|---|---|---|
| Dashboard | **Ready** | 5 status tiles incl. idle scanner |
| Scan page | **Ready** | File/quick/folder, cancel, report, ARGUS analysis |
| Quarantine page | **Ready** | Confirmation dialogs, restore/delete, toast feedback |
| History page | **Ready** | Drill-down, ARGUS verdicts, export |
| Update page | **Ready** | Progress bar, ARGUS pack reload |
| Settings page | **Ready** | 6 tabs incl. Notifications with severity threshold |
| About page | **Ready** | Version info |
| Error boundary | **Ready** | React crash recovery |
| System tray | **Ready** | No quit, protection status, quick scan |

---

## SEV Findings This Wave

| SEV | Finding | Status |
|---|---|---|
| **SEV-2** | YARA/IOC not reloaded after signature update (Phase 4 was no-op) | **Fixed** |
| **SEV-2** | `quarantine.delete` lacked challenge token (permanent data destruction without auth) | **Fixed** |
| **SEV-3** | Scan cache never invalidated after engine reload (stale clean results) | **Fixed** |

---

## Blockers: None

All identified blockers have been resolved. No correctness bugs, no broken
flows, no unsafe operations remain.

---

## Deferred Beyond v0.12

| Item | Reason |
|---|---|
| Startup quick scan | Idle scanner first cycle covers within minutes |
| Settings UI for idle scanner | Config-only via TOML is sufficient for alpha |
| Kernel minifilter (pre-access blocking) | v2.0+ |
| ETW process monitoring | v1.5+ |
| Network/traffic monitoring | v1.5+ |
| Browser extension | v2.0+ |
| Code signing certificate | External procurement |
| Thread priority IDLE (vs BELOW_NORMAL) | Minor, current behavior acceptable |
| Persistent idle scanner position | Nice-to-have, cache prevents rescan |

---

## Validation Checklist

Before tagging v0.12:

- [x] `cargo check --workspace` — 0 warnings, 0 errors
- [x] `cargo test -p argus` — 35/35 pass
- [x] `tsc --noEmit` — clean
- [x] `pnpm build` — clean
- [x] EICAR test file detected + quarantined
- [x] Quarantine restore works (challenge token flow)
- [x] Quarantine delete works (challenge token flow)
- [x] ClamAV engine reload after update
- [x] YARA rules reloaded after update
- [x] Scan cache invalidated after reload
- [x] Idle scanner pauses under CPU load
- [x] Watcher skips build artifacts
- [x] Notifications deduplicated
- [x] Diagnostics export contains no secrets
- [ ] 3-day stable run on dev machine (Phase 1 field test)

---

## Release Notes Draft (v0.1.2-alpha)

### What's New

- **Idle background scanner**: Resource-aware crawler scans dormant files when
  your system has spare capacity. Pauses during games, builds, and battery mode.
- **Windows toast notifications**: Calm, meaningful alerts for threats, quarantine,
  and protection changes. Includes dedupe and storm control.
- **Notification settings**: Per-event toggles, severity threshold, quiet mode.
- **Diagnostics export**: Export subsystem state for bug reports (no secrets).
- **Expanded trust database**: 290+ software reputation entries, 55+ Authenticode
  trusted signers. Electron, NW.js, and Tauri framework detection.

### Security Fixes

- Quarantine delete now requires challenge token
- Scan cache invalidated after signature update
- YARA rules properly reloaded after signature update

### False Positive Improvements

- Context amplification requires minimum 5-point pre-existing suspicion
- Installer detection tightened (name-only requires >2MB file)
- Electron/NW.js/Tauri binaries get structural weight reduction
- Build artifact extensions (.rlib, .rmeta, .pdb) excluded from watcher
- Build/dev directories (target/, node_modules/, .git/) skipped

### Known Limitations

- Windows-only
- No pre-access blocking (user-mode, post-write detection)
- No HTTPS traffic inspection
- No network monitoring
- Unsigned installer triggers SmartScreen warnings
- PyInstaller binaries without signing may score 10-25 (not flagged as threats)

---

*This assessment reflects the state after the v0.12 stabilization wave.
Tag v0.1.2-alpha after completing Phase 1 field test (3-day stable run).*

# Sentinella Release Readiness

**Status**: Pre-beta — functional but not production-ready  
**Date**: May 2026

---

## What Is Ready

| Component | Status | Notes |
|---|---|---|
| **ClamAV engine** | ✅ Ready | 3.6M signatures, runtime DLL loading |
| **ARGUS heuristics** | ✅ Ready | 11 layers, 119 YARA rules, 247 reputation entries |
| **GUI (7 pages)** | ✅ Ready | Dashboard, Scan, Quarantine, History, Update, Settings, About |
| **IPC protocol** | ✅ Hardened | Mutex recovery, pipe pre-creation, challenge tokens |
| **Quarantine vault** | ✅ Ready | AES-256-GCM, hash verification, path traversal prevention |
| **Real-time watcher** | ✅ Ready | Smart extension filtering, self-exclusion, debounce |
| **Scan pipeline** | ✅ Ready | Multi-threaded (4 threads), ClamAV + ARGUS unified |
| **Verdict persistence** | ✅ Ready | SQLite argus_verdicts table |
| **First-run wizard** | ✅ Ready | Welcome → signatures → optional scan |
| **Error boundary** | ✅ Ready | Catches React crashes |
| **System tray** | ✅ Ready | No quit option, protection status |
| **Context menu** | ✅ Ready | "Scan with Sentinella" shell integration |
| **Drag-and-drop** | ✅ Ready | File → scan page |
| **Light/dark theme** | ✅ Ready | Persistent via localStorage |
| **Authenticode** | ✅ Ready | WinVerifyTrust, 34 trusted signers |
| **Protection state** | ✅ Ready | fully_protected / degraded / minimal / unprotected |
| **Idle background scanner** | ✅ Ready | Resource-aware, adaptive speed, CPU/battery/fullscreen pause |
| **Windows toast notifications** | ✅ Ready | Dedupe, storm control, severity threshold, calm language |
| **Notification settings** | ✅ Ready | Per-event toggles, quiet mode, severity threshold |

## What Blocks Beta Release

| Blocker | Severity | Description |
|---|---|---|
| **Code signing** | High | Unsigned installer triggers SmartScreen warnings |

## Recently Resolved

| Item | Resolution |
|---|---|
| **WiX installer** | ✅ MSI + NSIS installers build via `pnpm tauri build` |
| **ClamAV DLL distribution** | ✅ DLLs staged in release pipeline |
| **Signature DB bootstrapping** | ✅ freshclam.conf template + freshclam.exe bundled |
| **Service registration** | ✅ Scripts bundled; WiX `Product.wxs` includes service component |
| **Staging pipeline** | ✅ 42 files, 44 MB staged package |
| **Release sanity check** | ✅ 24/24 checks pass |
| **Tauri GUI bundle** | ✅ MSI (4.4 MB) + NSIS (3.2 MB) |
| **GPL-2.0 LICENSE** | ✅ Root LICENSE file created |

## What Is Experimental

- Authenticode signer extraction (heuristic, not 100% reliable)
- Context amplification (requires ≥5 pre-existing points, capped at 15)
- YARA rule weights (calibrated on limited sample set)
- Multi-threaded scan (tested but not stress-tested)
- Idle scanner adaptive pacing (first real-world deployment)
- Disk latency probe accuracy (metadata-based, not IO counters)

## Operational Maturity (May 2026)

| Area | Status | Detail |
|---|---|---|
| **False positive mitigation** | ✅ Hardened | 290+ reputation entries, 55+ trusted signers, framework detection, context gate ≥5 |
| **Notification control** | ✅ Hardened | Dedupe (5-min cooldown), storm control (3+→aggregate), severity threshold |
| **Scan cache** | ✅ Active | Path+size+mtime+sig generation, 50K entries, LRU eviction |
| **Watcher noise** | ✅ Hardened | 30+ skipped extensions, 18 build/dev dirs, self-exclusion |
| **Idle scanner** | ✅ Active | Resource-aware, BELOW_NORMAL priority, adaptive speed |
| **Quarantine UX** | ✅ Polished | Confirmation dialogs, toast feedback, vault integrity check |

## What Must Be Excluded from GitHub/Package

| Exclude | Reason |
|---|---|
| `runtime/signatures/` | ClamAV DB files — too large, must be downloaded |
| `runtime/state/sentinella.db` | Local scan history — user data |
| `runtime/logs/` | Local log files |
| `runtime/quarantine/` | Encrypted malware samples |
| `runtime/research_samples/` | Controlled malware samples |
| `target/` | Build artifacts |
| `gui/node_modules/` | npm dependencies |
| `build/clamav/` | ClamAV build output |
| `third_party/clamav/` | ClamAV source (submodule or separate) |
| `*.db-wal`, `*.db-shm` | SQLite WAL files |

## Required `.gitignore` Entries

```
target/
build/
gui/node_modules/
runtime/signatures/
runtime/state/
runtime/logs/
runtime/quarantine/
runtime/research_samples/*.exe
runtime/research_samples/*.dll
runtime/research_samples/*.zip
*.db-wal
*.db-shm
```

## Legal / Attribution Requirements

| Requirement | Status |
|---|---|
| **GPL-2.0 license** | ✅ Present in Cargo.toml |
| **ClamAV attribution** | Required — "Powered by ClamAV" |
| **Cisco trademark** | "ClamAV is a registered trademark of Cisco Systems, Inc." |
| **YARA-X license** | BSD-3-Clause — compatible, no attribution required |
| **yara-x in About page** | Should mention YARA-X |
| **windows crate** | MIT/Apache — compatible |

## Signature Database Handling

- ClamAV signatures NOT bundled — downloaded via freshclam
- ARGUS YARA rules bundled in `runtime/argus/rules/yara/`
- ARGUS IOC hashes bundled in `runtime/rules/ioc_hashes.txt`
- Reputation DB compiled into binary (no external files)
- Pack manifest bundled in `runtime/argus/manifests/`

## Runtime Directories (Created Automatically)

```
runtime/
├── signatures/          # ClamAV CVD files (freshclam)
├── config/              # sentinelld.toml, freshclam.conf
├── state/               # sentinella.db (SQLite)
├── logs/                # sentinelld.log
├── quarantine/          # Encrypted vault
├── rules/               # IOC hashes
└── argus/
    ├── rules/yara/      # YARA rule files
    ├── compiled/        # Future: cached compiled rules
    └── manifests/       # Pack metadata JSON
```

## Known Limitations

- Windows-only (PE analysis, Authenticode, named pipes)
- No HTTPS traffic inspection
- No network monitoring (planned v1.5+)
- No browser extension
- No kernel driver (usermode only, post-write detection)
- ClamAV scanned_bytes UINT32_MAX warning (harmless, ClamAV bug)
- Large scans may temporarily show "Disconnected" (mitigated, 3-failure threshold)
- Idle scanner does not scan C:\Windows or Program Files (by design — too broad for v1)
- No startup quick scan yet (idle scanner first cycle covers high-risk dirs within minutes)

## Expected False Positives

Files that may occasionally produce low scores (not flagged as threats):

- Heavily packed/obfuscated legitimate software (UPX-packed tools)
- Unsigned Python-bundled executables (PyInstaller without code signing)
- Custom game mods and community tools (unsigned, unusual imports)
- Niche developer tools from small publishers (not in reputation DB)
- Recently released software not yet in signature database

These produce "Low Suspicion" or "Suspicious" verdicts (0-75 score),
never "Malicious" (76+), unless they also trigger ClamAV signatures or
multiple high-severity YARA rules.

## Non-Goals for v1

- Full IDS/IPS (Suricata/Zeek integration)
- HTTPS/TLS interception
- Kernel-mode minifilter (pre-access blocking)
- Cloud reputation lookup
- Telemetry or usage tracking
- Browser extension
- Mobile platform support

## Packaging Infrastructure (May 2026)

| Component | Status |
|---|---|
| WiX installer skeleton | ✅ `installer/windows/Product.wxs` |
| Staging script | ✅ `scripts/stage-windows-package.bat` |
| Sanity check script | ✅ `scripts/release-sanity-windows.bat` |
| Source package script | ✅ `scripts/package-source-windows.bat` |
| Dependency manifest | ✅ `release/DEPENDENCIES.md` |
| Runtime self-bootstrap | ✅ Daemon creates all dirs at startup |
| Tauri MSI build | ✅ `Sentinella_0.1.0_x64_en-US.msi` (4.4 MB) |
| Tauri NSIS build | ✅ `Sentinella_0.1.0_x64-setup.exe` (3.2 MB) |
| Freshclam config template | ✅ `installer/windows/freshclam.conf.template` |
| GPL-2.0 LICENSE file | ✅ Root `LICENSE` |

---

## ARGUS Worker Release Integration

`argusd.exe` is now part of release staging. It is copied beside `sentinelld.exe`, checked by `scripts/release-sanity-windows.bat`, and included in the WiX install folder.

Worker mode remains disabled by default. The binary is bundled only as an optional isolation safety valve for future rollout.

*This document tracks release readiness. Update as blockers are resolved.*

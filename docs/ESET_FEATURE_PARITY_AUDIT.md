# Sentinella vs ESET — Antivirus/Antimalware Feature Parity Audit

**Date**: May 2026  
**Scope**: Detection + protection features only. No firewall, VPN, parental controls, anti-theft.

---

## Feature Comparison Matrix

### Detection Technologies

| Feature | ESET | Sentinella | Gap | Priority |
|---|---|---|---|---|
| **Signature-based detection** | Virus definitions (LiveGrid updates) | ClamAV 3.6M signatures | **Parity** | — |
| **Heuristic analysis** | ThreatSense engine | ARGUS 11-layer scoring | **Parity** (different approach) | — |
| **Behavioral rules** | DNA Detections | YARA-X 119 rules + pattern detection | **Parity** | — |
| **Machine learning** | Cloud-assisted ML models | None | **Gap** | Low (requires cloud) |
| **Advanced Memory Scanner** | Scans process memory for unpacked malware | Executable region scan + YARA + PE injection + shellcode + entropy + RWX + auto-trigger | **Parity** | — |
| **Exploit Blocker** | Monitors exploitation techniques (ROP, heap spray) | PE import heuristics: DEP bypass, ROP/stack pivot, direct syscalls, parent spoofing, heap spray | **Partial** | Medium |
| **Ransomware Shield** | Monitors file modifications by untrusted processes | FISH: burst detection + cooldown + active response (suspend/terminate) + process attribution | **Parity** | — |
| **UEFI Scanner** | Scans UEFI firmware for rootkits | None | **Gap** | Low (niche) |
| **Script-based Attack Protection (AMSI)** | Windows AMSI integration for PS/JS/VBS | Static script analysis only | **Gap** | High |
| **PUA Detection** | Classifies potentially unwanted apps | PotentiallyUnwanted verdict + BehaviorTag + auto-reclassification | **Parity** | — |
| **Archive scanning** | Unpacks ZIP/RAR/7z/CAB/ISO recursively | ClamAV handles (built-in UnRAR/ZIP) | **Parity** | — |

### Real-Time Protection

| Feature | ESET | Sentinella | Gap | Priority |
|---|---|---|---|---|
| **Kernel minifilter (pre-access)** | ekrn.sys intercepts file open/read/write/execute | None — user-mode only (post-write) | **Major gap** | v2.0+ |
| **File open interception** | Blocks access before file is read | No — detects after write completes | **Gap** | v2.0+ |
| **Process execution monitoring** | Monitors process launches | None (ETW planned) | **Gap** | High |
| **Extension-based filtering** | Scans all risk extensions on access | Scans create/modify events, extension filter | **Partial** | — |
| **Smart scanning cache** | Hash-based, persistent across restarts | SQLite-backed, path+size+mtime+generation, survives restarts | **Parity** | — |
| **Watched scope** | Entire filesystem | 8 dirs (Downloads/Desktop/Temp/Documents/AppData/LocalTemp/ProgramData/OneDrive) | **Partial** | — |

### On-Demand Scanning

| Feature | ESET | Sentinella | Gap | Priority |
|---|---|---|---|---|
| **Quick scan** | Critical paths, startup entries | Downloads/Desktop/Temp | **Partial** | Medium |
| **Full scan** | Entire disk | All fixed drives via TRRX FullDiskTargets | **Parity** | — |
| **Custom scan** | User-selected folders | Folder scan ✓ | **Parity** | — |
| **Scheduled scan** | Configurable time/day/type | Config exists, scheduler exists | **Parity** | — |
| **Startup scan** | Boot-time critical path check | TRRX StartupTargets: Run keys + Startup folder + recent executables | **Parity** | — |
| **Right-click scan** | Explorer context menu | Shell integration script exists | **Parity** | — |
| **Drag-and-drop scan** | Not standard in ESET | Supported ✓ | **Advantage** | — |
| **Scan exclusions** | Path/extension/hash exclusions | Path + extension exclusions | **Parity** | — |
| **Multi-threaded scanning** | Multi-threaded | 4-thread worker pool ✓ | **Parity** | — |

### Idle/Background Scanning

| Feature | ESET | Sentinella | Gap | Priority |
|---|---|---|---|---|
| **Idle-state scanner** | CPU/IO aware, THREAD_PRIORITY_IDLE | Resource-aware, BELOW_NORMAL priority | **Parity** | — |
| **Battery awareness** | Pauses on battery | Configurable battery pause ✓ | **Parity** | — |
| **Fullscreen detection** | Pauses during games | SHQueryUserNotificationState ✓ | **Parity** | — |
| **Adaptive speed** | Ramps up when idle deepens | Slow/Normal/Fast modes ✓ | **Parity** | — |

### Reputation & Trust

| Feature | ESET | Sentinella | Gap | Priority |
|---|---|---|---|---|
| **Cloud reputation (LiveGrid)** | File hash → cloud prevalence/reputation | None — fully local | **Gap** | Low (by design) |
| **Local reputation DB** | Part of LiveGrid cache | 290+ entries, 2-tier trust | **Partial** | — |
| **Authenticode verification** | Validates code signing | WinVerifyTrust, 55+ trusted signers | **Parity** | — |
| **Prevalence tracking** | How common a file is globally | None | **Gap** | Low (requires cloud) |
| **Trusted hash cache** | Persistent across restarts | In-memory, generation-based | **Partial** | Medium |

### Quarantine & Recovery

| Feature | ESET | Sentinella | Gap | Priority |
|---|---|---|---|---|
| **Encrypted quarantine** | Encrypted vault | AES-256-GCM vault ✓ | **Parity** | — |
| **Restore to original path** | With verification | SHA-256 verified + path validation ✓ | **Parity** | — |
| **Auto-quarantine** | On threat detection | Watcher + idle scanner auto-quarantine ✓ | **Parity** | — |
| **Quarantine retention** | Configurable | Config field exists | **Parity** | — |
| **Submit to lab** | Upload samples for analysis | Not implemented (local-first) | **Gap** | Low (by design) |

### False Positive Handling

| Feature | ESET | Sentinella | Gap | Priority |
|---|---|---|---|---|
| **LiveGrid reputation** | Cloud prevalence reduces FPs | None — local reputation only | **Gap** | — |
| **Detection exclusions** | Per-detection-name exclusions | Config + enforcement in all scan paths | **Parity** | — |
| **Hash whitelisting** | Exclude specific file hashes | Manual trusted_hashes in config + watcher enforcement | **Parity** | — |
| **Framework recognition** | Recognizes common frameworks | 10+ frameworks (NSIS, Electron, Go, Rust, etc.) | **Parity** | — |
| **Installer heuristic** | Reduces noise on installers | Structural weight /3, YARA /2 | **Parity** | — |

### Download Protection

| Feature | ESET | Sentinella | Gap | Priority |
|---|---|---|---|---|
| **Browser integration** | Scans downloads via browser plugin | Zone.Identifier context only | **Gap** | Medium |
| **URL reputation** | Blocks known malicious URLs | None | **Gap** | v1.5+ |
| **Download origin tracking** | HTTP referrer analysis | Zone.Identifier referrer ✓ | **Partial** | — |

---

## Gap Priority Summary

### Critical (should implement before v1.0)

| Feature | Why | Approach |
|---|---|---|
| **Ransomware Shield** | #1 user threat — file encryption detection | Monitor file modifications by untrusted processes. Detect mass rename/encrypt patterns. Use ETW or minifilter. |

### High Priority (v1.0-v1.5)

| Feature | Why | Approach |
|---|---|---|
| **AMSI Integration** | Catches obfuscated PowerShell/JS at runtime | Windows AMSI API — register as provider, scan deobfuscated scripts |
| **Process execution monitoring** | See what runs, parent-child chains | ETW process events (already architected) |
| **Advanced Memory Scanner** | Catches unpacked malware in memory | ReadProcessMemory on suspicious processes after ARGUS flags them |
| **Full disk scan** | Standard AV feature, users expect it | Extend folder scan to all fixed drives |
| **Startup scan** | Check critical paths on boot | Already architected — implement |
| **Detection-name exclusions** | FP management | Allow users to whitelist specific detection names |

### Medium Priority (v1.5-v2.0)

| Feature | Why | Approach |
|---|---|---|
| **Exploit Blocker** | Prevents exploitation techniques | ETW + hardware breakpoints — complex |
| **Persistent scan cache** | Avoid rescanning unchanged files after restart | SQLite-backed cache with hash+generation |
| **Broader watcher scope** | ~~Monitor more than 3 dirs~~ | ✅ DONE — 8 dirs including AppData, ProgramData, Documents |
| **PUA classification** | Separate PUA from malware | Add PUA severity level + user config |
| **URL/domain reputation** | Block known bad download sources | Local domain blocklist (no cloud needed) |
| **Browser download scanning** | Scan files as they arrive | Watcher already covers Downloads — mainly UX |

### Low Priority (v2.0+)

| Feature | Why | Approach |
|---|---|---|
| **Kernel minifilter** | Pre-access blocking | Windows driver — major effort |
| **UEFI Scanner** | Firmware rootkit detection | Niche, complex, low prevalence |
| **Cloud reputation** | Global prevalence data | Conflicts with local-first principle |
| **Machine learning** | Advanced detection | Requires training data + model infrastructure |

---

## Where Sentinella Already Exceeds ESET

| Feature | Detail |
|---|---|
| **Explainable verdicts** | Full score breakdown with behavior tags, convergence chains, progression scoring |
| **Attack chain detection** | 10 named chains (stealer, backdoor, ransomware, etc.) with strength levels |
| **Convergence confidence** | Labels based on evidence quality, not just score |
| **Open source** | Fully auditable GPLv2 |
| **No telemetry** | Zero data collection |
| **YARA-X integration** | Modern YARA engine with 119 custom behavioral rules |
| **Drag-and-drop scanning** | Drop file → instant scan |
| **Frosted glass UI** | Modern Windows 11 aesthetic |

---

## Recommended Next Development Phases

### Phase 1: Ransomware Shield — ✅ DONE
- ✅ Observe-only: burst detection, cooldown, watcher integration
- ✅ Active response: suspend or terminate offending process
- ✅ Process attribution: enumerate processes in affected directory + suspicious name heuristics
- ✅ Safety: protected process list (system processes + Sentinella's own)
- ✅ Config: `active_response = "observe" | "suspend" | "terminate"`
- ✅ Diagnostics: processes_suspended, processes_terminated counters
- ⬜ ETW-based attribution (precise PID → file write correlation) — future
- ⬜ Rollback via shadow copy — future

### Phase 2: AMSI + Process Monitoring (High)
- Register as AMSI provider for PowerShell/JS/VBS/Office macros
- ETW process creation events for parent-child chain tracking
- Feed into existing ARGUS convergence model

### Phase 3: Full Scan + Startup Scan — ✅ DONE
- ✅ Full disk scan: all fixed drives via TRRX FullDiskTargets + IPC
- ✅ Startup scan: Run keys + Startup folder + recent executables via TRRX StartupTargets + IPC
- ✅ GUI scan cards for both
- ✅ Broader watcher scope: 8 directories (was 3)

### Phase 4: Memory Scanner — ✅ DONE
- ✅ VirtualQueryEx → executable region enumeration
- ✅ ReadProcessMemory → ARGUS analyze_buffer (YARA + patterns)
- ✅ PE header injection detection
- ✅ Reflective DLL loader detection
- ✅ Shellcode indicators: NOP sled, API resolution strings
- ✅ Process hollowing API detection (NtUnmapViewOfSection)
- ✅ RWX region flagging
- ✅ High entropy detection in executable memory
- ✅ Auto-trigger on HighRisk/Malicious watcher detection
- ✅ IPC: memory.list_processes, memory.scan_process
- ✅ 9 tests (PE header, NOP sled, reflective loader, API resolution, hollowing, entropy)

---

*This audit compares feature-for-feature with ESET Internet Security v17.x
as of 2025-2026. ESET has 30+ years of development. Sentinella is 2 months old.
The gaps are expected — the priority ordering guides where to invest next.*

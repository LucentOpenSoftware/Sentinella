# ARGUS Common AV Detection Baseline

**Date**: May 2026  
**Engine**: ARGUS v0.1.0-alpha  
**Status**: 119 YARA rules across 23 packs + native heuristic layers

---

## Coverage Summary

| Category | YARA Rules | Native Heuristics | Status |
|---|---|---|---|
| **Stealers (Discord/Browser/Crypto)** | 9 | Discord, credential, crypto patterns | ✅ Strong |
| **Ransomware** | 7 | — | ✅ Good |
| **Script Malware (PS/JS/VBS/BAT)** | 13 | PowerShell, JS, VBS, batch, .reg analysis | ✅ Strong |
| **LOLBin Abuse** | 6 | — | ✅ Good |
| **Document Malware (PDF/Office/LNK)** | 7 | MIME validation, polyglot detection | ✅ Good |
| **.NET Malware** | 6 | — | ✅ Good |
| **Droppers/Loaders** | 7 | Installer detection | ✅ Good |
| **Persistence/Evasion** | 12 | Persistence pattern detection | ✅ Strong |
| **Credential Tools** | 5 | — | ✅ Good |
| **Fake Updaters** | 4 | Installer framework detection | ✅ Good |
| **Browser Hijacking** | 4 | — | ✅ Good |
| **C2 Communication** | 5 | Download origin context | ✅ Good |
| **Stealer Exfiltration** | 5 | — | ✅ Good |
| **Evasion Techniques** | 6 | — | ✅ Good |
| **Cryptocurrency Threats** | 4 | Crypto pattern detection | ✅ Good |
| **GitHub-Distributed Stealers** | 5 | Fake game mod detection | ✅ Strong |
| **Backdoors/RATs** | 3 | — | ✅ Basic |
| **Worms/Propagation** | 3 | — | ✅ Basic |
| **Generic Trojans** | 6 | — | ✅ Good |
| **Packed/Obfuscated** | 4 | PyInstaller, Node SEA, section analysis | ✅ Good |
| **Spyware** | 3 | — | ✅ Basic |

## Non-YARA Detection Layers

| Layer | Description |
|---|---|
| **MIME/Magic Validation** | Extension mismatch, RTLO, double extensions, polyglots |
| **PE Structural Analysis** | Entropy, imports, sections, overlay, W^X, timestamps |
| **Packer Detection** | UPX, Themida, VMProtect, ASPack, MPRESS, Enigma, ConfuserEx |
| **Script Analysis** | PowerShell, JavaScript, VBScript, batch, .reg file analysis |
| **Pattern Detection** | Discord stealers, webhooks, credentials, crypto, persistence, fake game mods |
| **IOC Hash Matching** | 9 known-malicious hashes (Linua Updater variants) |
| **Software Reputation** | 247 recognized publishers, 2-tier trust system |
| **Authenticode Verification** | Windows signature validation, 34 trusted signers |
| **File Origin Context** | Zone.Identifier, directory location, download source, timing |
| **Event Correlation** | Rolling 100-event / 5-minute window for cross-file context |

## Sources Consulted

All rules are original or adapted from public behavior descriptions:

- **MITRE ATT&CK**: T1055 (Process Injection), T1036 (Masquerading), T1497 (Virtualization Evasion), T1091 (Removable Media), T1056 (Input Capture), T1113 (Screen Capture), T1571 (Non-Standard Port), T1095 (Non-Application Layer Protocol), T1573 (Encrypted Channel)
- **Public malware analysis**: Hybrid Analysis, ANY.RUN, Joe Sandbox (public reports)
- **Public vendor research**: F-Secure, Unit42, Check Point, ReversingLabs (published articles)
- **Public YARA examples**: YARA documentation, community rule format examples

## Legal Note

No proprietary signatures were copied. All rules are:
- Original heuristics written from public behavior descriptions
- Clearly marked with `source_type` metadata (`original_heuristic` or `public_behavior`)
- Multi-signal conditions (no single-string pattern matching)
- Licensed under GPL-2.0 (matching Sentinella's license)

## Remaining Baseline Gaps

| Category | Gap | Priority |
|---|---|---|
| Rootkit detection | Requires kernel-level visibility | Low (v2.0+) |
| Fileless malware | Requires ETW process monitoring | Medium (v1.5+) |
| Mobile malware | Out of scope for desktop AV | N/A |
| Mac/Linux malware | Windows-only currently | Future |
| Advanced APT tooling | Requires behavioral telemetry | Low |
| Supply chain attacks | Requires package manager integration | Future |
| Browser extension malware | Requires extension manifest parsing | Medium |

---

## Quality Audit Status (May 2026)

- **119/119 rules compile cleanly** — zero unused patterns
- **All rules have complete metadata**: description, severity, weight, category, author
- **No broad single-string high-severity rules** — all require 2+ combined conditions
- **Tightened rules**: webhook_exfiltration now requires data collection indicators alongside webhook URLs; ransomware ransom note requires 2+ strong phrases or strong+supporting combination
- **Pack attribution**: Every YARA finding includes pack name in technical detail
- **FP regression**: Trusted signed binaries suppress context amplification; files <5 score get zero context
- **Context gate**: Requires ≥5 pre-existing suspicion points before context amplification activates
- **Installer detection**: NSIS/Inno/WiX/MSI/Electron/NW.js/Tauri framework detection; name-only requires >2MB
- **Reputation DB**: 290+ entries across 20+ categories, 2-tier (Trusted=25, Recognized=15)
- **Authenticode**: 55+ trusted signers including game studios, AV vendors, communication apps

---

*ARGUS does not claim parity with commercial AV products. It provides explainable, layered detection focused on modern desktop threats.*

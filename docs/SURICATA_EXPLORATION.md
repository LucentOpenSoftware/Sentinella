# Suricata IDS/IPS — Sentinella Integration Exploration

**Status**: Research only — NOT integrated, NOT planned for v1.x  
**Date**: May 2026  
**Decision**: Do NOT implement yet

---

## What is Suricata?

Suricata is a high-performance network IDS/IPS/NSM engine maintained by OISF (Open Information Security Foundation). It inspects network traffic in real-time against rule sets (ET Open, ET Pro) to detect malware communication, exploits, and policy violations.

- **Language**: Hybrid C + Rust (protocol parsers migrating to Rust)
- **License**: GPL v2
- **Current version**: 8.0.x (July 2025)
- **Rules**: ET Open (~30,000 free), ET Pro (commercial)

## Architecture Summary

- Multi-threaded pipeline: Capture → Decode → Stream Reassembly → App Layer → Detection → Output
- Capture via libpcap/Npcap (passive IDS) or WinDivert (inline IPS)
- Output via EVE JSON (structured JSONL — one event per line)
- Fully local, zero cloud dependency

## Windows Feasibility

| Aspect | Assessment |
|---|---|
| **Builds on Windows** | Yes — MSI installers available |
| **Capture** | Npcap (passive) or WinDivert (inline) |
| **Service mode** | Yes, but startup ordering issues reported |
| **Privileges** | Administrator/SYSTEM required |
| **Memory** | 300MB–1.5GB with ET Open rules |
| **CPU** | ~1 core per 50 Mbps HTTP traffic |
| **Desktop overhead** | 5-15% CPU during active browsing, spikes on downloads |

## Possible Adapter Design

If ever integrated, Suricata would run as a **sidecar service** (completely separate process):

```
sentinelld (daemon)
    ├── ClamAV engine
    ├── ARGUS heuristics
    └── [reads] ← eve.json ← suricata.exe (separate service)
```

1. Suricata runs as Windows service, captures traffic
2. Writes EVE JSON alerts to a log file
3. Sentinella daemon tails the log file
4. Parses alerts, correlates with ARGUS file detections
5. Shows network alerts in a dedicated (optional) UI section

## Pros

- World-class network detection engine
- Fully local, no cloud
- EVE JSON is clean and parseable
- ARGUS + Suricata correlation is compelling ("this file came from a known-malicious IP")
- ET Open rules are free and regularly updated
- Rust components align with Sentinella's stack

## Cons

- **Massive dependency surface**: Npcap kernel driver, WinDivert driver, full Suricata engine
- **Npcap licensing**: Redistribution requires commercial OEM license from Insecure.Com LLC
- **Kernel attack surface**: Both Npcap and WinDivert install kernel drivers — vulnerabilities = kernel-level exploits
- **Suricata CVEs**: Regular parser vulnerabilities (DoS, memory exhaustion, detection bypass)
- **Performance on desktop**: Not designed for endpoint use, CPU/memory overhead non-trivial
- **False positive management**: ET Open generates noise on desktops without extensive tuning
- **Maintenance burden**: Tracking Suricata security patches, rule updates, driver compatibility
- **Desktop users don't need perimeter IDS**: Most are behind NAT routers already
- **Support burden**: Every Suricata bug becomes a Sentinella bug in users' minds

## Required Dependencies

- **Npcap**: Free for personal/5-system use, OEM license for redistribution ($$$)
- **WinDivert**: LGPL/GPL, free (alternative to Npcap for inline mode)
- MSYS2 for building from source
- libjansson, libpcre2, libyaml, libz

## Security Risks

- Kernel driver (Npcap/WinDivert) = kernel-level exploit target
- Suricata runs as SYSTEM = full system compromise on vulnerability
- Parser bugs in protocol decoders (documented CVEs in HTTP2, MIME, fragmentation)
- Npcap driver conflicts with other packet capture tools (Wireshark, etc.)
- Irony: security tool becomes an attack vector

## Why It Should Remain Optional

1. Sentinella's core value is file + heuristic analysis — that works without network monitoring
2. Adding a mandatory kernel driver dramatically increases attack surface
3. Not all users want/need network inspection
4. Licensing cost for Npcap redistribution
5. Desktop users behind NAT have limited exposure to network-level attacks
6. The maintenance burden of two detection domains is substantial

## What NOT to Implement Yet

- ❌ No sidebar "Traffic" or "Network" page
- ❌ No Suricata process management from Sentinella
- ❌ No rule management UI for Suricata
- ❌ No Npcap/WinDivert bundling
- ❌ No protection state changes based on Suricata
- ❌ No network alerts in the dashboard
- ❌ No EVE JSON parsing code in the daemon

## Future Integration Plan (v3+)

If Sentinella matures enough to warrant network detection:

1. **Phase 1**: Ship Suricata as optional separate installer (not bundled)
2. **Phase 2**: Add EVE JSON tail adapter in daemon (read-only, file-based)
3. **Phase 3**: Correlate network alerts with ARGUS file detections
4. **Phase 4**: Optional "Network Intelligence" page in GUI
5. **Phase 5**: Rule management integration

**Prerequisite**: Sentinella must first have a mature installer, signed binaries, stable service operation, and a team capable of tracking Suricata security updates.

---

*This document is a research note, not a commitment. Suricata integration should only be considered when Sentinella's core capabilities are fully mature.*

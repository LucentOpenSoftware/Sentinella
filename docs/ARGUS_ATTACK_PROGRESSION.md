# ARGUS Attack Progression Model

**Version**: 0.1.2-alpha  
**Date**: May 2026

---

## Core Concept

ARGUS now models malware as a *progression through attack stages*, not just
a bag of suspicious indicators. A coherent forward progression through stages
is more dangerous than random unordered tags at the same score.

## Attack Stages (MITRE-inspired)

| # | Stage | BehaviorTags | Example |
|---|---|---|---|
| 0 | **Initial Access** | Downloader, FakeInstaller, ArchiveStaging | File downloaded from Discord CDN |
| 1 | **Execution** | ScriptAbuse | PowerShell download cradle runs |
| 2 | **Persistence** | Persistence | Registry Run key created |
| 3 | **Defense Evasion** | Evasion, Packing, Entropy | Anti-debug checks, UPX packing |
| 4 | **Credential Access** | CredentialTheft, WalletTheft | Browser Login Data accessed |
| 5 | **Collection** | Injection | Process injection to intercept data |
| 6 | **Exfiltration** | Exfiltration | Data sent to Discord webhook |
| 7 | **Command & Control** | C2Communication | Beacon to remote server |
| 8 | **Impact** | Ransomware | Files encrypted, ransom note dropped |

## Progression Scoring

The `attack_progression_score()` counts meaningful forward transitions:

```
Stages:    0 → 1 → 4 → 6
Transitions: 0→1(gap 1) ✓, 1→4(gap 3) ✓, 4→6(gap 2) ✓
Score: 3 (maximum)
```

Only gaps of 1-4 count as "meaningful transitions." A jump from
InitialAccess directly to Impact (gap 8) is too incoherent to count.

```
Stages:    3 → 3 → 3 (all DefenseEvasion)
Score: 0 (no transitions)
```

## Process Lineage Model

Structures exist for scoring parent-child process relationships.
Not runtime-tracked yet — designed for future ETW integration.

| Parent | Child | Score | Reason |
|---|---|---|---|
| winword.exe | powershell.exe | 15 | Macro exploitation |
| excel.exe | cmd.exe | 15 | Macro exploitation |
| chrome.exe | %TEMP%\*.exe | 10 | Browser-dropped executable |
| explorer.exe | setup.exe | 0 | Normal user action |
| steam.exe | game.exe | 0 | Normal launcher |
| python.exe | powershell.exe | 5 | Script spawning shell |

## Threat Maturity Classification

Separate from Verdict (which measures score threshold), ThreatMaturity
describes what the malware *is*:

| Level | Meaning | Requirements |
|---|---|---|
| **Benign** | Not a threat | Score 0 |
| **SuspiciousUtility** | Has capability but no chain | Score ≥20, no chain |
| **Loader** | Fetches/stages payloads | Moderate chain |
| **ActiveMalware** | Active attack chain | Strong chain |
| **DestructiveMalware** | Data destruction potential | Ransomware chain |

## Signed Abuse Handling

Trust (Authenticode + reputation) reduces structural noise and lowers
confidence labels for clean/unusual files. However:

**Trust does NOT neutralize coherent attack chains.**

| Scenario | Trust | Chain | Result |
|---|---|---|---|
| Signed installer, no chain | Strong | None | Trusted |
| Signed binary, strong chain | Strong | Strong | **HighRisk** |
| Unsigned binary, weak chain | None | Weak | Suspicious |
| Unsigned binary, strong chain | None | Strong | **Malicious** |

This prevents LOLBin-style abuse where signed system tools are chained
for malicious purposes.

## Why Convergence != Progression

**Convergence** measures how many independent layers agree.
**Progression** measures whether the behaviors form a coherent attack narrative.

A file can have high convergence (many layers detect packing) but no
progression (all findings are in the same stage). Conversely, a file can
show clear progression (download → execute → persist → exfil) with
findings from just 2 layers.

Both contribute to confidence. Together they distinguish:
- Structural noise (high convergence, no progression) → FP risk
- Real malware (moderate convergence, clear progression) → true positive

---

*Progression awareness transforms ARGUS from "counting suspicious indicators"
into "recognizing attack narratives."*

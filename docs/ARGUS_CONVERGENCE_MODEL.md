# ARGUS Convergence Model

**Version**: 0.1.2-alpha  
**Date**: May 2026

---

## Why Score Alone Is Insufficient

A numeric score measures *how much* suspicion accumulated. It does not measure
*whether the evidence tells a coherent story*.

- Score 80 from one structural layer repeating the same entropy finding =
  likely false positive (single perspective, no corroboration).
- Score 50 from credential theft + exfiltration + Discord CDN context =
  likely real stealer (three independent signals forming a chain).

ARGUS uses **convergence** — the coherence of evidence across independent
layers and behavior categories — to distinguish genuine threats from
noise accumulation.

## Behavior Tags (15 categories)

Every finding is tagged with a semantic behavior:

| Tag | Meaning | Common Sources |
|---|---|---|
| DownloaderCapability | Has download APIs | Structural, YARA |
| DownloadOriginContext | File came from internet | Context (never deduped) |
| Packing | Binary is packed/compressed | PackerDetection, Structural, YARA |
| Entropy | High entropy sections | Structural |
| Persistence | Registry Run, scheduled tasks | Pattern, YARA |
| CredentialTheft | Browser data, DPAPI, passwords | Pattern, YARA |
| Exfiltration | Webhook, Telegram bot, upload | Pattern, YARA |
| Ransomware | Encryption, shadow copies | YARA |
| Injection | Process injection/hollowing | Structural, YARA |
| Evasion | Anti-debug, sandbox detection | Structural, YARA |
| ScriptAbuse | PowerShell, VBS, LOLBin abuse | YARA |
| C2Communication | C2 beacon patterns | YARA |
| WalletTheft | Crypto wallet theft | YARA |
| ArchiveStaging | SFX/dropper extraction | YARA |
| FakeInstaller | Masquerades as updater | YARA |

## Attack Chains

Chains represent coherent combinations of behaviors that form known attack patterns.

### Strong Chains (high-confidence malicious)

| Chain | Components | Example |
|---|---|---|
| **Stealer** | CredentialTheft + Exfiltration | Discord token stealer → webhook upload |
| **Backdoor** | Persistence + C2Communication | Registry Run key + beacon to C2 server |
| **Ransomware** | Ransomware + (Injection OR Persistence) | File encryption + shadow copy deletion |
| **Crypto Stealer** | WalletTheft + (Exfiltration OR CredentialTheft) | Wallet files + browser cookies |

### Moderate Chains (suspicious, need more evidence)

| Chain | Components | Example |
|---|---|---|
| **Fake Installer** | FakeInstaller + (Persistence OR Downloader) | Fake update + downloads payload |
| **Script Malware** | ScriptAbuse + (Downloader OR C2) | PowerShell cradle + HTTP fetch |
| **Loader** | Downloader + ArchiveStaging + Evasion | Download → extract → anti-debug |
| **Persistent Downloader** | Persistence + Downloader | Run key + HTTP download |

### Weak Chains (often benign)

| Chain | Components | Note |
|---|---|---|
| **Downloader Only** | DownloaderCapability alone | Normal for any internet-connected app |
| **Packed Only** | Packing + Entropy | Normal for installers, Go binaries |

## Confidence Labels

Labels reflect evidence quality, not just score magnitude:

| Label | Meaning | Requirements |
|---|---|---|
| **Trusted** | Signed + recognized, no concern | Score ≤40, strong trust signals |
| **Normal** | No suspicious indicators | Score ≤40 with trust, or score 0 |
| **Unusual** | Minor anomalies, likely benign | Score 1-40 unsigned, or installer at 41-60 |
| **Suspicious** | Multiple indicators, warrants attention | Score 41-75 OR high score with weak convergence |
| **High Risk** | Coherent attack chain detected | Strong chain, or score 76-90 with convergence |
| **Malicious** | Confirmed multi-layer threat | Score 91+ with strong convergence |

### Key Rules

1. **Single-category saturation → max Suspicious**. Score 80 from entropy
   findings alone = Suspicious, not HighRisk. One perspective repeating
   itself is not convergence.

2. **Strong chain promotes**. Score 55 with stealer chain = HighRisk.
   Coherent attack evidence matters more than raw score.

3. **Weak diverse tags ≠ danger**. 5 unrelated weak tags at score 50 =
   Suspicious. Random tag diversity without chain coherence is not meaningful.

4. **Malicious requires convergence**. Score 95 with one behavior tag =
   HighRisk, not Malicious label. Only strong chains or 3+ layers with
   moderate+ chain unlock Malicious label.

5. **Trust always considered**. Signed + recognized installer with
   residual structural noise = Trusted, regardless of raw score up to 40.

## Deduplication

Same behavior tag + same layer = redundant (only highest-weight counts).
Same behavior tag + different layers = convergence (both count).
Context findings are never deduplicated with capability findings.

## False-Positive Safety Rules

- Context amplification requires ≥5 pre-existing suspicion points
- Context layer max contribution capped at 15 points
- Installer framework detected → structural weights /3, installer-YARA /2
- Category caps: Structural≤30, YARA≤40, Context≤15, Packer≤20, Pattern≤25
- ARGUS-only auto-quarantine requires score ≥85 (ClamAV agreement uses ≥76)

---

*Convergence is the difference between "looks statistically suspicious"
and "behaves like known malware." ARGUS measures both.*

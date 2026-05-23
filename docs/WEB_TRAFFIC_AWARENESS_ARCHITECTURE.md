# Web & Traffic Awareness Architecture

**Status**: Architecture only — NOT implemented  
**Date**: May 2026  
**Target**: Sentinella v1.5-v2.0  

---

## 1. Goals

Give ARGUS **network context** for file verdicts without becoming IDS/firewall/proxy.

Target answers:
- "Which process downloaded this file?"
- "What domains did this process contact?"
- "Is this process expected to be online?"
- "Did this executable connect out immediately after extraction?"
- "Is this a known link-monetizer download chain?"

## 2. Non-Goals

- ❌ Full packet inspection
- ❌ HTTPS/TLS interception (MITM proxy)
- ❌ Deep URL content scanning
- ❌ Browser history collection
- ❌ Full firewall replacement
- ❌ VPN/proxy functionality
- ❌ IDS signature matching on traffic
- ❌ Personal message content scanning

## 3. ESET-Inspired Behavioral Baseline

ESET Internet Security provides (behavioral reference only):

| Feature | ESET Behavior | Sentinella Equivalent |
|---|---|---|
| **Web Access Protection** | Scans HTTP/HTTPS via proxy, blocks known-bad URLs | DNS domain reputation + download origin context |
| **Network Traffic Scanning** | Deep protocol parsing, SSL interception | NOT v1 — too heavy, privacy-invasive |
| **Application Firewall** | Per-app allow/block rules, connection visibility | App reputation model + ETW connection context |
| **SSL/TLS Filtering** | MITM certificate injection (ESET SSL Filter CA), decrypts HTTPS | NOT planned — privacy/compatibility concerns |
| **Reputation Blocking** | Cloud-checked URL/file reputation | Local domain reputation pack + IOC matching |
| **Protocol Detection** | Identifies protocols regardless of port | ETW DNS + process correlation (simpler) |
| **Interactive Firewall** | Per-app allow/deny prompts with "remember" option | Future WFP integration (v2.0+) |
| **App Modification Detection** | Alerts when ruled app binary changes | Authenticode + hash tracking (future) |

**Key ESET insight**: Interactive firewall mode = user explicitly grants network access per app. This builds trust because user controls what goes online. Sentinella can replicate this via WFP without MITM.

**Sentinella's approach**: Metadata + correlation, NOT inspection. 80% of ESET's value at 10% of complexity.

## 4. Lightweight Windows Data Sources

### Tier 1: Implement First (v1.5)

#### ETW DNS Events (`Microsoft-Windows-DNS-Client`)
```
Process PID → Domain resolved → Timestamp
```
- **Overhead**: < 0.1% CPU
- **Value**: Process→domain correlation without packet capture
- **Privacy**: DNS queries only, no content
- **Key events**: 3008 (query complete), 3020 (non-cached)
- **Rust crate**: `ferrisetw`

#### ETW Process Events (`Microsoft-Windows-Kernel-Process`)
```
Process start → PID, PPID, image path, command line
```
- **Overhead**: < 0.1% CPU
- **Value**: Parent-child chains (browser → download → exe → PowerShell)
- **Privacy**: Process metadata only
- **Key events**: Event 1 (ProcessStart)
- **Rust crate**: `ferrisetw`

### Tier 2: Add Later (v2.0)

#### GetExtendedTcpTable / GetExtendedUdpTable
```
PID → Remote IP:Port → State → Timestamp
```
- **Overhead**: Low (polling, ~1/sec)
- **Value**: Active connection snapshot per process
- **Privacy**: IP/port metadata only
- **Rust**: `windows-rs` raw API call
- **Simpler** than WFP, good fallback

#### Windows Filtering Platform (WFP)
```
Per-app connection control → Allow/Block decisions
```
- **Overhead**: Minimal (OS-native, designed for always-on firewall use)
- **Value**: Future blocking capability — what Windows Firewall itself uses
- **Privacy**: Connection metadata + blocking power
- **Rust crates**: `wfp`, `windows-wfp` (both on crates.io)
- **Privileges**: Admin for user-mode filters, kernel driver for deep inspection
- **Key difference from ETW**: WFP = active filtering (can block). ETW = passive observation (read-only)
- **Risk**: Wrong rules → break connectivity
- **ESET uses WFP**: Their per-app firewall is built on WFP + interactive mode prompts
- **Defer until**: Blocking UI + user trust established

### Already Implemented
- Zone.Identifier ADS (Mark-of-the-Web) → download origin
- Context layer → directory + filename + recency
- Event correlator → rolling 100-event / 5-min window

## 5. Privacy Model

### Collect (local-only, ephemeral)
| Data | Retention | Storage |
|---|---|---|
| DNS queries (domain + PID) | 5-15 min | Memory ring buffer |
| Process starts (path + PPID + cmdline hash) | 5-15 min | Memory ring buffer |
| Active connections (PID + remote IP:port) | Snapshot only | No storage |

### Never Collect
- Full URLs / HTTP paths
- Request/response bodies
- Cookies / auth tokens
- Browser history / bookmarks
- Message contents (Discord/Telegram/etc.)
- Keystroke data
- Screen content

### Privacy Rules
1. All data stays local — never transmitted
2. Ring buffer only — auto-expires, never persisted to disk
3. No UI exposure of raw DNS/process telemetry
4. User sees ARGUS verdicts, not surveillance logs
5. Opt-out toggle in Settings (degrades detection, clearly explained)

## 6. Performance Model

| Component | CPU | RAM | I/O |
|---|---|---|---|
| ETW DNS consumer | < 0.1% | ~1 MB buffer | None |
| ETW Process consumer | < 0.1% | ~1 MB buffer | None |
| GetExtendedTcpTable poll (1/sec) | < 0.1% | ~100 KB | None |
| Total v1 overhead | **< 0.5%** | **~3 MB** | **None** |

Compare: Suricata = 1+ core, 300MB+. Zeek = 1 core, 230MB+.

## 7. Event Schema

```rust
/// Network-aware event for ARGUS correlation.
struct NetworkEvent {
    timestamp: Instant,
    pid: u32,
    process_path: String,
    process_signed: bool,        // Authenticode check
    process_trusted: bool,       // Reputation DB match
    parent_pid: Option<u32>,
    parent_path: Option<String>,
    event_type: NetworkEventType,
}

enum NetworkEventType {
    DnsQuery {
        domain: String,
        success: bool,
    },
    ProcessStart {
        command_line_hash: u64,   // Hash, not full cmdline (privacy)
        has_encoded_args: bool,   // -enc / base64 detected
    },
    OutboundConnection {
        remote_ip: String,
        remote_port: u16,
        protocol: Protocol,       // TCP/UDP
    },
}
```

Ring buffer: 500 DNS events + 200 process events + 100 connection snapshots.

## 8. ARGUS Correlation Model

### Score Amplification Signals

| Signal | Weight | Condition |
|---|---|---|
| Unsigned exe in Downloads connects out | +8 | DNS/connection within 60s of file creation |
| PyInstaller binary → Discord webhook domain | +12 | DNS to discord.com/api/webhooks |
| Browser → download → exe → PowerShell chain | +10 | Process chain within 120s |
| Office → cmd/powershell child connects out | +12 | Process parent = WINWORD/EXCEL |
| Temp executable contacts internet | +8 | Process in %TEMP% + any DNS/connection |
| Unknown app → pastebin/raw GitHub | +10 | DNS to pastebin.com, raw.githubusercontent |
| Repeated failed DNS to random domains | +8 | DGA-like domains (high entropy, no resolution) |
| App normally offline goes online | +6 | Not in expected-online list |

### Correlation Rules
1. Context amplifies existing ARGUS suspicion — never standalone threat
2. Trusted signed apps get suppressed context (already implemented)
3. Known-online apps (browsers, Discord, Steam) → zero amplification
4. Maximum network context weight: **15 points** (matches current cap)

## 9. App Network Reputation Model

### Expected Online (no amplification)
```
browsers: chrome, firefox, edge, brave, opera, vivaldi
communication: discord, telegram, slack, teams, zoom, signal
cloud: onedrive, dropbox, googledrive, icloud, nextcloud, syncthing
gaming: steam, epicgames, gog, battlenet, ea
updates: windows update, microsoft store, adobe updater
dev tools: git, npm, cargo, pip, docker, vscode
```

### Suspicious If Online (amplify if other signals present)
```
unsigned exe in Downloads/Temp
recently extracted from archive
Office child processes (cmd, powershell, wscript)
scripts (.bat, .ps1, .vbs, .js)
fake updater/mod/cheat naming patterns
renamed system tool copies
executables from Discord/Telegram cache
```

### Model Storage
Static list compiled into binary (like reputation DB). No cloud lookup.

## 10. Link Monetizer / Fake Download Model

### Known Monetizer Domains (future intelligence pack)
```
linkvertise.com, adf.ly, ouo.io, ouo.press, shrink.pe,
shrinkme.me, shorte.st, bc.vc, exe.io, sub2unlock.com,
direct-link.net, link-to.net, link-center.net,
lootlabs.gg, work.ink, paster.so, lockr.so, luarmor.net,
adfoc.us
```

### Public Blocklist Sources
- **HaGeZi DNS Blocklists** (github.com/hagezi/dns-blocklists) — URL Shortener + Badware Hoster lists
- **uBlock Origin Badware risks** — deceptive download domains
- **URLhaus Filter** (abuse.ch) — malicious URL blocklist
- **FilterLists.com** — aggregator of public filter lists

### Detection Approach (future)
1. **DNS correlation**: Process resolves monetizer domain → flag downloads from that session
2. **Redirect chain heuristic**: Multiple DNS resolutions in rapid succession → likely redirect chain
3. **Download origin**: Zone.Identifier referrer contains monetizer domain → amplify suspicion
4. **Domain reputation pack**: Curated from HaGeZi + uBlock sources (public, compatible licenses)
5. **Browser extension (future)**: Optional extension reports download URLs to daemon for local reputation check

### NOT v1 — Defer Until
- Domain reputation pack curated from public sources
- ETW DNS integration operational
- User trust in Sentinella established

## 11. What to Implement First

### Phase 1 (v1.5): ETW DNS + Process
- `ferrisetw` crate integration
- DNS query ring buffer (500 events, 15 min)
- Process start ring buffer (200 events, 15 min)
- ARGUS queries buffers during file analysis
- Context findings in verdict explanation
- Settings toggle for network awareness

### Phase 2 (v1.7): Connection Snapshot
- `GetExtendedTcpTable` polling (1/sec)
- PID→connection mapping
- "This process has active connections to X" in verdicts

### Phase 3 (v2.0): App Reputation + Blocking
- WFP integration for per-app allow/block
- Network awareness UI page
- App connection history (short-term)
- User-configurable app network rules

### Phase 4 (v2.5): Domain Intelligence
- Monetizer domain pack
- DGA detection heuristic
- Download origin reputation
- Optional browser extension

## 12. What to Explicitly Avoid

| Avoid | Why |
|---|---|
| HTTPS interception | Privacy-invasive, breaks apps, requires root CA |
| Full packet capture | Heavy, privacy risk, Npcap licensing |
| Browser history access | Surveillance territory |
| Persistent network logs | Privacy risk, disk I/O |
| Cloud URL reputation | Leaks browsing activity |
| Blocking without UI | Breaks user apps silently |
| Suricata/Zeek integration | Too heavy for desktop (see research docs) |

## 13. Future Roadmap

```
v1.5  ETW DNS + Process context (< 0.5% CPU, 3 MB RAM)
        ↓
v1.7  Connection snapshot + app reputation
        ↓
v2.0  WFP blocking + Network Awareness UI
        ↓
v2.5  Domain intelligence pack + browser extension
        ↓
v3.0  Full application firewall with ARGUS correlation
```

Each phase validates before the next. No phase requires the next.
User can stay on v1.5 forever and still get value.

---

## Current ARGUS Context Layer → Future ETW Bridge

The existing `correlation.rs` module is designed for seamless ETW integration:

```
Current (v1.0):
  File watcher → EventCorrelator.record() → ContextHints { source_hint }
  Context layer queries correlator during ARGUS analysis

Future (v1.5+):
  ETW DNS thread → EventCorrelator.record_with_hints() → ContextHints { domain_hint, process_hint }
  ETW Process thread → EventCorrelator.record_with_hints() → ContextHints { process_hint, parent_process_hint }
  Context layer queries correlator → richer amplification signals
```

No ARGUS engine changes needed when ETW is added. The `ContextHints` struct
already has `domain_hint`, `process_hint`, `parent_process_hint`, and
`origin_confidence` fields. The `EventCorrelator` already has `domain_hints_for()`
and `process_chain_for()` query methods. ETW just populates them.

---

*This document is architecture. Implementation requires ETW research completion and core ARGUS stability. See also: `docs/ETW_EXPLORATION.md`, `docs/SURICATA_EXPLORATION.md`, `docs/ZEEK_EXPLORATION.md`.*

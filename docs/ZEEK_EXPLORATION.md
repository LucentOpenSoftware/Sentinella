# Zeek Network Intelligence — Sentinella Integration Exploration

**Status**: Research only — NOT integrated, NOT planned for v1.x  
**Date**: May 2026  
**Decision**: Do NOT implement yet

---

## What is Zeek?

Zeek (formerly Bro) is a network intelligence platform that transforms raw traffic into structured, semantic events. Unlike Suricata (signature IDS), Zeek *understands* protocols and describes what happened rather than matching patterns.

- **Language**: C++ core + Rust components + Zeek scripting language
- **License**: BSD
- **Philosophy**: "What is happening on this network?" vs Suricata's "Does this match a bad pattern?"

## Architecture

Two-layer design:
1. **Event Engine (C++)**: Processes packets, reassembles streams, generates semantic events
2. **Script Interpreter**: User-written Zeek scripts react to events — arbitrary detection logic

Key difference from Suricata: Zeek is Turing-complete for detection. Suricata is declarative pattern matching.

## Event Model — Why It's Interesting

Zeek generates per-protocol structured logs:
- `conn.log` — every TCP/UDP/ICMP flow
- `dns.log` — every DNS query+response
- `http.log` — full URL, User-Agent, MIME type
- `ssl.log` — TLS certificates, JA3 fingerprints, SNI
- `files.log` — files extracted from traffic with SHA-256 hashes
- `x509.log` — certificate chain details

All linked by `uid` for cross-log correlation. This is richer than Suricata's EVE JSON.

## ARGUS Correlation Potential (The Compelling Case)

**This is why Zeek matters for Sentinella's future:**

Example scenario: ARGUS flags `update.exe` as a stealer.

With Zeek data, Sentinella could explain:
- "Downloaded from `cdn-update[.]xyz` (registered 3 days ago)"
- "Over TLS with self-signed certificate"
- "HTTP User-Agent was `python-requests/2.28` (not a browser)"
- "After execution, endpoint began beaconing to `185.x.x.x:443` every 60s"

This transforms a file verdict into a **complete threat narrative** — exactly what ARGUS's explainability philosophy demands.

## Zeek vs Suricata — Head-to-Head

| Dimension | Suricata | Zeek |
|---|---|---|
| Philosophy | Signature IDS | Network intelligence |
| Detection model | Pattern matching | Event-driven scripting |
| Output quality | Alerts + metadata | Rich structured logs |
| Windows live capture | **Works** (experimental) | **Does NOT work** |
| Resource usage | Lighter | Heavier |
| Correlation quality | Good | **Excellent** |
| Desktop suitability | Poor but possible | **Worse — no live capture** |
| Alignment with ARGUS | Moderate | **Strong** |

**Verdict**: Zeek is architecturally superior for ARGUS correlation. Suricata is practically the only option on Windows today.

## Windows Reality Check

**Critical blocker**: Zeek cannot do live packet capture on Windows.

- Official status: "Experimental"
- PCAP file processing works
- Live capture via Npcap: not supported
- Spicy analyzers: not supported on Windows
- Package manager (zkg): not supported
- Plugins: not supported

Suricata has functional (if experimental) live capture on Windows. Zeek does not.

## Privacy Concerns

Zeek logs by default:
- Every DNS query (every website lookup)
- Every HTTP URL (full path)
- TLS SNI (which HTTPS sites visited)
- Connection metadata for every flow

For a desktop AV, this is essentially surveillance. Mitigation:
- Only log events correlated with flagged files (reactive mode)
- Aggressive data retention limits (minutes, not days)
- User-visible toggle with clear explanation
- Never log HTTP body or cookies

## Why NOT to Integrate Yet

1. **No live capture on Windows** — fundamental blocker
2. **Resource overhead** — 230MB+ RAM, one CPU core
3. **Privacy implications** — logging all network activity
4. **Complexity** — Zeek is a full platform, not a lightweight tool
5. **Npcap licensing** — redistribution requires commercial license
6. **Maintenance burden** — two detection domains to maintain
7. **Core focus** — ARGUS file analysis is not mature enough to split engineering attention

## Future Integration Plan (v3+, IF Zeek Windows matures)

1. Monitor Zeek Windows live capture progress
2. If viable: ship as optional separate installer
3. Minimal adapter: read JSON logs, index by uid
4. ARGUS query API: "network context for file hash X"
5. Enrich detection explanations with network context
6. Privacy controls: reactive mode, retention limits

**Prerequisite**: Zeek must gain stable live capture on Windows AND Sentinella's core must be fully mature.

## Recommendation

**Watch Zeek's Windows progress. If it gains live capture, it's the better choice over Suricata for Sentinella's explainability philosophy. Until then, neither should be integrated.**

The most pragmatic near-term alternative: lightweight DNS monitoring via Windows ETW (Event Tracing for Windows) — no kernel driver, no Npcap, no Zeek/Suricata. Just DNS resolution events correlated with file downloads. This would provide 80% of the correlation value at 1% of the complexity.

---

*This document is a research note, not a commitment.*

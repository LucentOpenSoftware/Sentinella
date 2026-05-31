<img width="1716" height="561" alt="about1" src="https://github.com/user-attachments/assets/eeb6c7ed-a3c4-4668-b1a1-8fe1c81a9555" />

# Sentinella

A modern, open-source antivirus suite built on the [ClamAV](https://www.clamav.net) scanning engine and the ARGUS heuristic engine.

**Status: alpha (0.1.9-alpha).** Core scanning, real-time protection, and quarantine are functional on Windows.

## What is this?

Sentinella wraps the battle-tested ClamAV engine in a modern, beginner-friendly interface and supplements it with ARGUS, an 8-layer heuristic engine. The ClamAV engine itself is kept **unmodified** so upstream security fixes merge cleanly.

## What is ARGUS?

ARGUS is Sentinella’s native heuristic and behavioral analysis engine, designed to complement traditional signature-based detection.

While ClamAV provides fast and reliable signature matching against known malware families, ARGUS focuses on identifying suspicious behavior patterns, anomalous execution characteristics, and threat convergence signals that may indicate previously unseen or modified malware.

The engine is built in Rust and operates as a layered analysis pipeline integrated directly into the Sentinella daemon.

### Current ARGUS components

* **Multi-layer heuristic pipeline** — combines static, behavioral, and contextual analysis
* **YARA-powered detection** — currently ships with 119 heuristic and malware classification rules
* **PE structure inspection** — detects malformed or suspicious Windows executables
* **Behavioral convergence scoring** — correlates weak indicators into higher-confidence detections
* **Memory analysis integration** — assists the memory scanner in identifying in-memory threats
* **Ransomware heuristics** — powers parts of the FISH ransomware shield
* **Cache-aware scanning** — avoids redundant analysis of unchanged files

ARGUS is intentionally designed as a companion engine rather than a replacement for ClamAV. The ClamAV engine remains upstream-compatible and unmodified, while ARGUS adds modern heuristic capabilities around it.

### Design philosophy

The long-term goal of ARGUS is to provide:

* modern heuristic detection,
* behavioral analysis,
* lightweight anomaly detection,
* and layered threat correlation,

without sacrificing transparency, performance, or upstream compatibility.

Unlike cloud-dependent security products, ARGUS is designed to operate locally and remain functional in offline environments.

## Current capabilities

- **ClamAV signature scanning** — 3.6M+ signatures via subprocess isolation (`clamavd`)
- **ARGUS heuristic engine** — 8-layer analysis pipeline with 119 YARA rules
- **Real-time filesystem watcher** — monitors 8 user directories for new/modified files
- **Idle background scanner** — resource-aware scanning during system idle
- **AES-256-GCM quarantine vault** — encrypted storage for detected threats
- **Memory scanner** — scans process memory for in-memory threats
- **FISH ransomware shield** — observe mode + active response
- **Behavioral sandbox** — experimental, Job Object containment on Windows
- **ClamAV subprocess isolation** — `clamavd` process boundary
- **Persistent scan cache** — SQLite-backed, avoids re-scanning unchanged files
- **Scan types** — full, quick, folder, startup, and single-file scans
- **Daemon supervisor** — auto-recovery on crash
- **Memory pressure management** — adapts to available system resources
- **Detection exclusions + hash whitelisting**
- **i18n** — English and Spanish
- **Tauri 2 GUI** — frosted glass design with system tray integration
- **Windows service install scripts**

### Architecture

```
GUI (Tauri + React)       Separate process, runs as current user
  |  JSON-RPC / IPC
Daemon (Rust)             Runs as a system service, holds the engine
  |  FFI bridge
libclamav (C, unchanged)  The ClamAV scanning engine
```

See `ARCHITECTURE.md` in the ClamAV source tree for the full design document.

## Building

### Prerequisites

- **Rust** 1.85+ (MSVC toolchain on Windows)
- **Node.js** 18+ and **pnpm**
- **CMake** 3.20+ (for building libclamav, when ready)

### Rust workspace (daemon + CLI)

```bash
cargo build --release
```

### GUI (Tauri app)

```bash
cd gui
pnpm install
pnpm tauri dev    # development mode with hot reload
pnpm tauri build  # production build
```

## Project structure

```
sentinella/
  crates/
    sentinella-ipc-proto/   # Shared JSON-RPC types
    sentinella-common/      # Paths, constants, version info
    argus/                  # ARGUS heuristic engine
    sentinelld/             # The daemon binary
    sentinella-cli/         # Command-line client
  gui/                      # Tauri + React frontend
  third_party/              # Will contain ClamAV upstream source
  installer/                # Per-platform packaging
  scripts/                  # Build and dev helper scripts
  tests/                    # Integration tests and test corpus
```

## License

GPLv2. See [COPYING.txt](COPYING.txt).

Scanning engine powered by ClamAV. ClamAV is a registered trademark of Cisco Systems, Inc. See [NOTICE.md](NOTICE.md).

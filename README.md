# Sentinella

A modern, open-source antivirus suite built on the [ClamAV](https://www.clamav.net) scanning engine.

**Status: early development scaffold.** The project compiles and the GUI renders, but no actual scanning is functional yet.

## What is this?

Sentinella wraps the battle-tested ClamAV engine in a modern, beginner-friendly interface. The ClamAV engine itself is kept **unmodified** so upstream security fixes merge cleanly.

### Goals

- Cross-platform (Windows first, then Linux, macOS)
- Modern GUI (Tauri + React) that non-technical users can understand
- Real-time file monitoring (user-mode in v1, kernel minifilter planned for v2)
- On-demand and scheduled scanning
- Quarantine vault with encrypted storage
- Automatic signature updates via freshclam
- No cloud dependencies, no telemetry, no AI buzzwords

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

# ARCHITECTURE.md — `<brand>` (ClamAV-based security suite)

> **Status:** design draft. Nothing is built yet. This document is the blueprint
> a contributor should be able to start implementing from. It is opinionated;
> every decision has a named alternative and a reason.

> **Placeholder naming.** Throughout this document `<brand>` is used for the
> product name, `<brandd>` for the daemon, and `<brand>-cli` for the command
> client. Replace once legal/trademark check is done (see §2).

---

## 1. Mission and non-goals

### Mission (v1)

Build a cross-platform, free, beginner-friendly antivirus suite on top of the
ClamAV scanning engine. Windows first, Linux and macOS to follow. Replace the
aging clamdtop/clamdscan CLI surface with a modern GUI. Add real-time scanning
on Windows via a user-mode watcher (pre-kernel-driver). Keep the ClamAV engine
itself unmodified so that upstream security fixes merge cleanly.

### Non-goals (v1)

- **Not a full Defender replacement.** No kernel driver in v1, so no pre-access
  blocking on Windows. Detection is post-facto and clearly labelled as such.
- **No behavioral / ML engine.** Signature + heuristic scanning only. The
  existing libclamav engine does what it does.
- **No cloud telemetry.** Everything runs locally. This is a privacy stance and
  a scope-control stance — cloud telemetry is hard to get right.
- **No enterprise management console.** No central policy server, no group
  policy, no remote quarantine browsing. Focus on the single-machine user.
- **No mail scanning (`clamav-milter`).** Dropped for v1. Can come back as a
  plugin.

### Non-goals (ever)

- Active-tampering detection, rootkit hunting, or memory forensics beyond what
  libclamav already does.
- Anti-analysis / anti-debugging features that exist purely to obstruct
  reverse-engineering of our own code. Open source does not paper over itself.

---

## 2. Legal / licensing / naming

### Upstream license — GPLv2

`libclamav` and all ClamAV tools are **GNU GPL v2**, confirmed by the file
headers in `libclamav/*.c` and `README.md:105–106`. `COPYING.txt` at the repo
root is a verbatim copy of GPLv2.

The `COPYING/` directory contains third-party component licenses. Of note:

| Component | License | Note for a fork |
|---|---|---|
| libmspack | LGPL | Fine under GPLv2 combination. |
| UnRAR (`libclamunrar`) | Non-free "RARLAB" license | **Incompatible with GPLv2** per upstream `README.md:131-139`. Cisco ships it despite this; the legal position is unclear. **For a new fork, ship without UnRAR by default.** Users who want RAR scanning can opt in at build time and carry the same risk Cisco carries. Document the decision in your NOTICE. |
| bzip2, zlib, pcre2, regex, getopt, file, png, curl | BSD/MIT-ish | Compatible. |
| YARA | Apache 2.0 | Compatible with GPLv2 under the GPLv3 linking rule? No — YARA is Apache 2 and GPLv2 is the consumer. Apache-2.0 → GPLv2 is **not** universally considered compatible (the Apache patent clause is the sticking point). Upstream ships it anyway, under GPLv2 + "additional terms". We inherit their story. Keep using it; document the same caveat. |
| LLVM bytecode runtime | Apache/LLVM | Same Apache story. |

### Our license

**License the entire `<brand>` fork as GPLv2.** All new code (daemon, GUI,
watcher, installer glue, docs) is GPLv2. This:

- Matches upstream, so we can cherry-pick their fixes without license
  conversion.
- Removes ambiguity about "is the GUI a derivative work of libclamav" — yes it
  is, and the whole thing is GPLv2, end of discussion.
- Is compatible with MIT / BSD / Apache-2.0 Rust crates we pull in (permissive
  → GPLv2 works; the combined binary is GPLv2).
- Means we cannot accept contributions under incompatible licenses. Document
  this in CONTRIBUTING.md.

Tauri itself is MIT/Apache-2.0 dual-licensed. Using it in a GPLv2 project is
fine. The GPLv2 obligation flows *out* to any downstream redistributor of
`<brand>`, not back into Tauri.

### Attribution (required and encouraged)

Required by GPLv2 §1:

- Preserve ClamAV copyright headers on any unmodified file.
- Preserve or re-state the GPLv2 notice on every source file we derive from
  ClamAV.
- Ship `COPYING.txt` and `COPYING/` verbatim.

Encouraged by good manners and Cisco trademark policy:

- Top-level `NOTICE.md` crediting Cisco Talos and the ClamAV community, with a
  link to https://www.clamav.net.
- In-app "About" dialog showing "Scanning engine powered by ClamAV®. ClamAV is
  a registered trademark of Cisco Systems, Inc.".
- Do **not** use the ClamAV logo or name in our branding, icon, installer
  name, window title, product metadata, or domain name.

### Trademark

Per Cisco's trademark guidelines for ClamAV: you can say "uses the ClamAV
engine" or "built on ClamAV" descriptively. You cannot name the product
"ClamAV-Something", "Clam-Something", or use the eyeball/clam logo. Pick a
new name and a new mark.

### Signature database (CVDs)

Freshclam fetches signed `.cvd` / `.cld` files from `database.clamav.net`
(and optionally a private mirror). These files are free to use but the
ClamAV database is **separately governed**: see the ClamAV Signature
Database EULA published on the ClamAV site. The short version: fine for
personal, educational, and commercial anti-malware use; you cannot resell
the signatures as a standalone data product.

**v1 default:** use the official ClamAV database. Expose the DNS database
URL as a configurable setting so users can point at a private mirror.

### Open naming question

Pick a name that is **not** in the USPTO trademark database for
"computer software, namely, anti-virus" (International Class 9) and whose
`.com` / `.org` / `.dev` domains are free. Run a name through:

- USPTO TESS: https://tmsearch.uspto.gov
- EUIPO eSearch
- Domain availability
- GitHub organization availability

Deferred decision; see §13.

---

## 3. System overview

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  GUI process  (<brand>)                                              │
  │  ─────────────────────────────────────────────────────────────────   │
  │  Tauri 2.x shell                                                    │
  │    Rust backend (tauri::Builder) ──┐                                │
  │    React + TypeScript frontend  ───┘  WebView2 / WebKitGTK / WKWebView
  │                                                                     │
  │  Talks to daemon via JSON-RPC over                                  │
  │    - Windows:  named pipe  \\.\pipe\<brand>d                        │
  │    - Linux:    UDS         /run/<brand>/<brand>d.sock               │
  │    - macOS:    UDS         /Library/Application Support/.../sock    │
  └────────────────────────────┬────────────────────────────────────────┘
                               │  JSON-RPC 2.0, length-prefixed framing
  ┌────────────────────────────▼────────────────────────────────────────┐
  │  Daemon process  (<brandd>)                                          │
  │  ─────────────────────────────────────────────────────────────────   │
  │  Rust binary. Holds exactly one libclamav engine.                    │
  │                                                                     │
  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
  │  │  IPC server      │  │  Scan queue      │  │  Watcher (opt.)  │   │
  │  │  (tokio, async)  │◄─│  (bounded mpsc)  │◄─│  (per-OS shim)   │   │
  │  └────────┬─────────┘  └────────┬─────────┘  └──────────────────┘   │
  │           │                     │                                   │
  │           │           ┌─────────▼──────────┐                        │
  │           └──────────►│  libclamav bridge  │                        │
  │                       │  (safe Rust FFI)   │                        │
  │                       └─────────┬──────────┘                        │
  │                                 │                                   │
  │                       ┌─────────▼──────────┐                        │
  │                       │  libclamav.{dll,so}│   ← unchanged          │
  │                       └────────────────────┘                        │
  │                                                                     │
  │  Side services:                                                     │
  │  - Quarantine vault  (see §7)                                       │
  │  - Scheduler         (scheduled scans, DB updates)                  │
  │  - Updater           (wraps freshclam, or reimplements HTTP)        │
  │  - Logger            (rotated file + OS log sink)                   │
  └─────────────────────────────────────────────────────────────────────┘

  Unmodified upstream binaries still shipped:
    - libclamav  (DLL / .so / .dylib)
    - freshclam  (updater — called as child process in v1)
    - sigtool    (CLI for power users, bundled but not GUI-exposed)
```

### Why a separate daemon process

1. **Engine load is expensive** (200+ MB of signatures, several seconds on
   cold start). Keep it loaded across GUI sessions.
2. **Privilege separation.** The daemon runs as a service (`LocalSystem` on
   Windows, a dedicated system user on Linux/macOS) so it can scan files the
   current user cannot read. The GUI runs as the logged-in user.
3. **GUI crashes don't lose scan state.** User can restart the GUI without
   aborting a scan or losing the quarantine DB lock.
4. **License hygiene.** Even though we're one big GPLv2 codebase, the split
   makes the "linking" boundary explicit. Matches upstream `clamd` +
   `clamdscan` topology.
5. **Cross-platform symmetry.** Same daemon code on all three OSes; only the
   watcher shim differs.

### Why not just reuse `clamd`?

Because `clamd`'s protocol is primitive (newline-terminated text, limited
commands) and its threading model predates async Rust. We can reimplement a
better daemon in a few weeks and reuse libclamav unchanged.

We **will** keep `clamd` working in the tree as an unused-but-compiling
component, so we don't fork the engine away from upstream and can still `diff`
against Cisco's releases for merging.

---

## 4. Repository layout

```
<brand>/
├── AUDIT_FINDINGS.md          ← the audit we already did
├── ARCHITECTURE.md            ← this file
├── CONTRIBUTING.md            ← GPLv2 only, DCO sign-off, ...
├── NOTICE.md                  ← upstream attribution
├── README.md
├── COPYING.txt                ← GPLv2 (inherited from upstream)
├── COPYING/                   ← third-party licenses (inherited)
│
├── upstream/                  ← git subtree or submodule of clamav-main
│   ├── libclamav/             ← UNCHANGED. Cherry-pick fixes only.
│   ├── libclamav_rust/        ← UNCHANGED.
│   ├── freshclam/             ← UNCHANGED.
│   ├── libfreshclam/          ← UNCHANGED.
│   ├── sigtool/               ← UNCHANGED.
│   ├── libclammspack/         ← UNCHANGED.
│   ├── libclamunrar/          ← REMOVED (license issue, see §2).
│   ├── libclamunrar_iface/    ← REMOVED.
│   ├── clamd/                 ← kept buildable for reference, not shipped.
│   ├── clamdscan/             ← kept buildable for reference, not shipped.
│   ├── clamav-milter/         ← REMOVED.
│   ├── clamonacc/             ← kept; we use it directly on Linux.
│   ├── clamdtop/              ← REMOVED (replaced by our GUI).
│   ├── clamsubmit/            ← REMOVED.
│   └── ...                    ← CMakeLists, Cargo.toml, platform.h.in, etc.
│
├── crates/                    ← OUR Rust code
│   ├── brandd/                ← the daemon binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── ipc/           ← JSON-RPC server (tokio + serde)
│   │       │   ├── mod.rs
│   │       │   ├── transport_pipe.rs        ← Windows named pipe
│   │       │   ├── transport_uds.rs         ← Unix domain socket
│   │       │   ├── framing.rs               ← length-prefixed
│   │       │   └── schema.rs                ← typed request/response
│   │       ├── scan/          ← scan queue + workers
│   │       │   ├── mod.rs
│   │       │   ├── queue.rs
│   │       │   ├── worker.rs
│   │       │   └── result.rs
│   │       ├── engine/        ← libclamav FFI wrapper
│   │       │   ├── mod.rs
│   │       │   ├── ffi.rs                   ← raw bindgen output
│   │       │   ├── engine.rs                ← safe Engine type
│   │       │   ├── context.rs               ← per-scan cl_scan_options
│   │       │   └── callbacks.rs             ← cl_engine_set_clcb_*
│   │       ├── watcher/       ← watcher abstraction (see §6)
│   │       │   ├── mod.rs                   ← trait Watcher
│   │       │   ├── none.rs                  ← no-op (for on-demand-only mode)
│   │       │   ├── windows_usn.rs           ← user-mode v1 (Windows)
│   │       │   ├── windows_readdir.rs       ← user-mode v1 (Windows)
│   │       │   ├── linux_fanotify.rs        ← wraps clamonacc, v1
│   │       │   └── macos_fsevents.rs        ← v1 mac (deferred to phase 2)
│   │       ├── quarantine/    ← see §7
│   │       │   ├── mod.rs
│   │       │   ├── vault.rs                 ← encrypted storage
│   │       │   └── db.rs                    ← sqlite metadata
│   │       ├── updater/       ← DB updates
│   │       │   ├── mod.rs
│   │       │   └── freshclam.rs             ← wraps freshclam as child
│   │       ├── scheduler/     ← scheduled scans & DB updates
│   │       │   └── mod.rs
│   │       ├── config/        ← on-disk settings
│   │       │   ├── mod.rs
│   │       │   └── schema.rs
│   │       ├── logging.rs
│   │       └── service/       ← OS service integration
│   │           ├── windows.rs               ← Windows service (SCM)
│   │           ├── linux.rs                 ← systemd unit
│   │           └── macos.rs                 ← launchd plist
│   │
│   ├── brand-cli/             ← command-line client (replaces clamdscan)
│   │   └── src/main.rs                      ← talks to <brandd> over IPC
│   │
│   ├── brand-ipc-proto/       ← shared JSON-RPC types (used by brandd, brand-cli, brand GUI backend)
│   │   └── src/lib.rs
│   │
│   └── brand-common/          ← paths, constants, version
│       └── src/lib.rs
│
├── gui/                       ← Tauri app
│   ├── Cargo.toml                            ← Rust backend
│   ├── tauri.conf.json
│   ├── src/                                  ← Rust glue (tauri commands)
│   │   ├── main.rs
│   │   └── ipc_client.rs                     ← speaks brand-ipc-proto to daemon
│   ├── src-ui/                               ← React + TS frontend
│   │   ├── package.json
│   │   ├── vite.config.ts
│   │   └── src/
│   │       ├── App.tsx
│   │       ├── pages/
│   │       │   ├── Dashboard.tsx
│   │       │   ├── Scan.tsx
│   │       │   ├── Quarantine.tsx
│   │       │   ├── History.tsx
│   │       │   ├── Settings.tsx
│   │       │   └── About.tsx
│   │       ├── components/
│   │       ├── hooks/
│   │       │   └── useDaemon.ts              ← reactive IPC bindings
│   │       └── i18n/
│   └── icons/
│
├── installer/
│   ├── windows/               ← WiX 4 project
│   │   ├── Product.wxs
│   │   └── scripts/
│   ├── linux/
│   │   ├── debian/            ← .deb
│   │   ├── rpm/               ← .rpm
│   │   └── appimage/
│   └── macos/
│       └── pkg/               ← signed .pkg (phase 2+)
│
├── scripts/
│   ├── build-windows.ps1
│   ├── build-linux.sh
│   ├── bootstrap-vcpkg.ps1    ← fetches pcre2, openssl, json-c, zlib, ...
│   └── run-daemon-dev.ps1
│
├── docs/
│   ├── architecture/          ← diagrams, ADRs
│   ├── ipc-protocol.md        ← the JSON-RPC contract
│   ├── security-model.md      ← threat model, trust boundaries
│   └── development-setup.md
│
└── tests/
    ├── integration/           ← spawns brandd, drives via IPC
    ├── corpus/                ← benign + eicar test files
    └── fuzz/                  ← reuse upstream fuzz/
```

### Rationale for keeping upstream as a subtree

- **Upstream merges**: `git subtree pull` lets us pick up ClamAV 1.6.1, 1.7,
  etc. with conflict resolution confined to the subtree directory.
- **No code duplication**: we never copy libclamav source into `crates/`; we
  only link against it.
- **Auditable diff**: anyone reviewing the fork can `diff upstream/ <pristine
  ClamAV release tarball>` and see exactly what we did (should be close to
  nothing — all changes live in `crates/` and `gui/`).

---

## 5. IPC protocol

### Transport

- **Windows:** named pipe `\\.\pipe\<brand>d`, ACL'd to
  `BUILTIN\Users` (read/write). Daemon creates the pipe in overlapped mode,
  uses `tokio::net::windows::named_pipe`.
- **Linux:** Unix domain socket at `/run/<brand>/<brand>d.sock`, mode 0660,
  group `<brand>`. Users must be in group `<brand>` to use the GUI, or the
  GUI runs setgid. (Decision deferred; probably group-based.)
- **macOS:** UDS under `/var/run/<brand>d.sock` or a sandbox-approved
  location.

### Framing

Each frame is a 4-byte big-endian length prefix followed by a UTF-8 JSON
object. No streaming JSON. Max frame size **16 MiB** (much larger than any
real request; guards against OOM). Connections are long-lived; the GUI opens
one at startup and holds it.

### Protocol

**JSON-RPC 2.0** with typed extensions:

- `request`: `{jsonrpc: "2.0", id: <u64>, method: <string>, params: {...}}`
- `response`: `{jsonrpc: "2.0", id: <u64>, result: {...}}` or `{..., error: {code, message, data}}`
- `notification` (server → client, no id): `{jsonrpc: "2.0", method: <string>, params: {...}}`

Notifications are how the daemon streams progress/events to the GUI.

### Methods (v1)

All types declared in `crates/brand-ipc-proto/src/lib.rs` with `serde`.

#### Engine

| Method | Params | Returns |
|---|---|---|
| `engine.status` | `{}` | `{state: "idle"\|"loading"\|"ready"\|"updating"\|"error", db_version: u32, db_timestamp: i64, signature_count: u64, last_update: i64}` |
| `engine.reload` | `{}` | `{ok: true}` — async; emits `engine.state_changed` notifications |

#### Scan

| Method | Params | Returns |
|---|---|---|
| `scan.start` | `{targets: [Path], options: ScanOptions}` | `{job_id: Uuid}` |
| `scan.cancel` | `{job_id: Uuid}` | `{ok: bool}` |
| `scan.status` | `{job_id: Uuid}` | `ScanStatus` |
| `scan.list` | `{}` | `[ScanStatus]` — all jobs (running + recently completed) |

`ScanOptions`:
```rust
struct ScanOptions {
    recursive: bool,
    follow_symlinks: bool,
    scan_archives: bool,
    scan_mail: bool,
    scan_pe: bool,
    scan_elf: bool,
    scan_ole2: bool,
    scan_pdf: bool,
    scan_html: bool,
    scan_scripts: bool,
    heuristic_alerts: bool,
    max_filesize_mb: u64,
    max_scansize_mb: u64,
    max_recursion: u32,
    max_files: u32,
}
```

`ScanStatus`:
```rust
struct ScanStatus {
    job_id: Uuid,
    state: "queued" | "running" | "completed" | "cancelled" | "error",
    started_at: i64,
    ended_at: Option<i64>,
    files_scanned: u64,
    files_total_estimate: Option<u64>,
    bytes_scanned: u64,
    threats_found: u64,
    current_path: Option<String>,
    errors: Vec<ScanError>,
}
```

#### Notifications emitted during a scan

- `scan.progress` — every N files or every 250 ms, whichever first.
- `scan.threat_found` — per finding, immediately.
- `scan.finished` — once, terminal.

```json
{"jsonrpc":"2.0","method":"scan.threat_found","params":{
  "job_id":"…","path":"C:/Users/X/Downloads/eicar.com",
  "signature":"Win.Test.EICAR_HDB-1","action_taken":"quarantined",
  "quarantine_id":"a1b2c3"}}
```

#### Quarantine

| Method | Params | Returns |
|---|---|---|
| `quarantine.list` | `{}` | `[QuarantineEntry]` |
| `quarantine.restore` | `{id: String}` | `{ok, restored_to: Path}` |
| `quarantine.delete` | `{id: String}` | `{ok}` |
| `quarantine.get_metadata` | `{id: String}` | `QuarantineEntry` |

#### Updates

| Method | Params | Returns |
|---|---|---|
| `update.start` | `{}` | `{ok}` — async; emits `update.progress` |
| `update.status` | `{}` | `{state, percent, bytes_downloaded, bytes_total}` |
| `update.history` | `{}` | `[{timestamp, result, new_version}]` |

#### Scheduler

| Method | Params | Returns |
|---|---|---|
| `schedule.list` | `{}` | `[ScheduledJob]` |
| `schedule.upsert` | `ScheduledJob` | `{ok}` |
| `schedule.delete` | `{id: String}` | `{ok}` |

#### Watcher

| Method | Params | Returns |
|---|---|---|
| `watcher.status` | `{}` | `{enabled, mode: "user-mode"\|"minifilter", watched_roots: [Path], events_per_sec: f64, last_event: i64}` |
| `watcher.enable` | `{roots: [Path]}` | `{ok}` |
| `watcher.disable` | `{}` | `{ok}` |

Emits:
- `watcher.file_event` (rate-limited) — diagnostic, for the GUI's "live"
  view.
- `scan.threat_found` — reuses the scan event channel when the watcher
  auto-scans a changed file.

#### Settings

| Method | Params | Returns |
|---|---|---|
| `settings.get` | `{}` | `Settings` |
| `settings.set` | `Settings` | `{ok, reload_required: bool}` |

#### Errors (RPC error codes)

| Code | Meaning |
|---|---|
| -32600..-32603 | Standard JSON-RPC errors |
| -32000 | Engine not ready |
| -32001 | Invalid path / permission denied |
| -32002 | Job not found |
| -32003 | Quarantine entry not found |
| -32004 | Update already running |
| -32005 | Insufficient privilege (e.g. restore outside user's home) |
| -32010 | Signature database corrupted |
| -32011 | Engine OOM |

### Backpressure

A scan of `C:\` can emit thousands of events per second. The daemon throttles:

- `scan.progress` to at most 4 Hz per job.
- `watcher.file_event` to at most 50 Hz total, with a ring buffer and
  "dropped N events" counter.
- `scan.threat_found` is **never** throttled (every finding must reach the
  GUI).

The IPC writer keeps a bounded async channel per client; if the client is
slow, notifications are coalesced (progress) or dropped (file_event), and
`scan.threat_found` blocks briefly. If the channel is full for more than a
timeout, the client connection is closed.

---

## 6. Daemon design

### State machine

```
          ┌─────────────┐
          │   Starting  │
          └──────┬──────┘
                 │ signatures loaded
          ┌──────▼──────┐
          │    Ready    │◄──────────┐
          └──────┬──────┘           │
      scan start │                  │ scan finished
          ┌──────▼──────┐           │
          │   Scanning  │───────────┤
          └──────┬──────┘           │
   update button │                  │ update finished
          ┌──────▼──────┐           │
          │  Updating   │───────────┘
          └─────────────┘
```

Multiple `Scanning` jobs run concurrently up to `max_parallel_scans`
(default = number of CPU cores). Updates are serialized.

### Threading (tokio)

- **1 tokio runtime**, multi-threaded, worker count = num_cpus.
- **IPC task** per connected client (typically 1: the GUI).
- **Scan workers**: a bounded work-stealing pool. Each worker owns its own
  `ScanContext` (cl_scan_options + per-thread state) but shares the single
  `cl_engine`. libclamav is thread-safe for scanning as long as the engine
  is loaded read-only, which it is post-`cl_engine_compile`.
- **Watcher task** (one per OS-appropriate source): reads events, debounces,
  emits into the scan queue.
- **Scheduler task**: time-based, owns a tokio `Instant`-priority heap.
- **Logging task**: async writer to file + OS log (no blocking).

### libclamav bridge (unsafe Rust → safe Rust)

```rust
// crates/brandd/src/engine/engine.rs

pub struct Engine {
    inner: NonNull<cl_engine>,
    db_dir: PathBuf,
    signature_count: AtomicU64,
}

impl Engine {
    pub fn load(db_dir: &Path) -> Result<Arc<Self>> {
        // 1. cl_init(CL_INIT_DEFAULT)
        // 2. cl_engine_new()
        // 3. cl_load(db_dir, engine, &sigs, CL_DB_STDOPT)
        // 4. cl_engine_compile(engine)
    }

    pub fn scan_file(
        self: &Arc<Self>,
        path: &Path,
        options: &ScanOptions,
        cb: impl Fn(ScanEvent) + Send + Sync + 'static,
    ) -> Result<ScanVerdict> {
        // 1. Build cl_scan_options from our ScanOptions
        // 2. Open file via fmap
        // 3. cl_scanfile_callback with pre-cache / post-scan callbacks
        //    that forward to `cb`
        // 4. Translate CL_* return codes into ScanVerdict::{Clean, Infected,
        //    Suspicious, Error}
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: inner is valid because we created it.
        unsafe { cl_engine_free(self.inner.as_ptr()); }
    }
}

unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}   // only after compile(); enforced by builder.
```

The Rust wrapper lives in `crates/brandd/src/engine/`. Raw FFI
(`extern "C"` declarations) goes in `ffi.rs`, generated by
[`bindgen`](https://rust-lang.github.io/rust-bindgen/) from
`upstream/libclamav/clamav.h` at build time. Safe wrappers are hand-written.

### Config file

Single TOML file. Location:

- Windows: `%ProgramData%\<brand>\config.toml`
- Linux: `/etc/<brand>/config.toml`
- macOS: `/Library/Application Support/<brand>/config.toml`

Hot-reloaded on `settings.set`; some keys (database directory, engine
options that require recompile) trigger a `engine.reload` automatically.

### Privilege model

- Daemon runs as `LocalSystem` (Windows) / `root` (Linux/macOS).
- Daemon drops to a dedicated unprivileged user after opening its sockets
  and loading the engine, on Linux/macOS. Not possible on Windows
  (`LocalSystem` is the norm for AV services).
- Scans requested by the user are executed by the daemon's privileges (so
  we can scan files the user can't), but quarantine *restore* requires the
  destination path to be writable by the requesting user's SID / UID. The
  IPC layer checks the peer credentials (SO_PEERCRED on Linux,
  `GetNamedPipeClientProcessId` on Windows, LOCAL_PEERCRED on macOS).

### Graceful shutdown

On `SIGTERM` (Linux/macOS) / `SERVICE_CONTROL_STOP` (Windows):

1. Stop accepting new connections.
2. Cancel all running scans.
3. Flush quarantine DB.
4. Drop engine (`cl_engine_free`).
5. Close the IPC server.
6. Exit.

Hard limit: 30 s. After that, exit(1) and let the service manager restart.

---

## 7. Watcher abstraction

### Trait

```rust
// crates/brandd/src/watcher/mod.rs

pub trait Watcher: Send + Sync {
    /// Start watching. May block until the backend is ready.
    fn start(&mut self, roots: &[PathBuf]) -> Result<()>;

    /// Stop watching and release OS resources.
    fn stop(&mut self) -> Result<()>;

    /// Pull a batch of debounced events.
    async fn next_events(&mut self) -> Vec<FileEvent>;

    /// What kind of watcher is this?
    fn mode(&self) -> WatcherMode;
}

pub enum WatcherMode {
    /// Post-facto: we see the file after it was written/closed.
    /// Cannot block access. Used in v1.
    UserModePostFacto,

    /// Pre-open blocking: we can deny IRP_MJ_CREATE. Used in v2+.
    KernelPreAccess,
}

pub struct FileEvent {
    pub path: PathBuf,
    pub kind: FileEventKind,
    pub timestamp: SystemTime,
    pub reason_tag: &'static str,   // for diagnostics
}

pub enum FileEventKind {
    Created,
    Modified,
    Renamed { from: PathBuf },
    /// Only emitted by kernel backends.
    OpenedForExec,
}
```

### v1 implementations

#### `windows_readdir.rs` — foreground watcher

- Uses `ReadDirectoryChangesW` on a fixed list of high-value directories:
  - `%USERPROFILE%\Downloads`
  - `%USERPROFILE%\Desktop`
  - `%USERPROFILE%\Documents`
  - `%TEMP%`
  - `C:\Windows\Temp`
  - `C:\ProgramData`
- Recursive watch with buffer size tuned (64 KiB; on overflow, re-scan the
  tree and drop events).
- One IOCP thread for all handles.

#### `windows_usn.rs` — background volume watcher

- Reads the NTFS USN Journal on every fixed drive using
  `DeviceIoControl(FSCTL_ENUM_USN_DATA / FSCTL_READ_USN_JOURNAL)`.
- Catches changes the foreground watcher misses (anywhere outside the
  high-value directories).
- Runs at low priority; its output is debounced hard (a file rewritten 10
  times in a second is one event).
- Persists the last read USN across daemon restarts so we don't re-scan the
  entire disk on every boot.

#### `linux_fanotify.rs` — wrap clamonacc

- v1: spawn `clamonacc` as a child and parse its output. `clamonacc` already
  handles fanotify setup, privilege drops, and can talk to `clamd`. We
  point it at our daemon via a shim (or bypass its clamd client and read
  events ourselves).
- v2: reimplement fanotify directly in Rust (there's a mature crate,
  `fanotify-rs`). Optional cleanup; v1 just reuses what upstream ships.

#### `macos_fsevents.rs` — deferred to phase 2

Phase 1 ships mac without real-time.

### v2 minifilter plan (write it down now, build later)

The `Watcher` trait already has `mode: KernelPreAccess`, so the daemon API
does not change. We just add a new implementation:

- `windows_minifilter.rs` — talks to a signed minifilter driver via a
  communication port (`FltCreateCommunicationPort`).
- The driver is a separate project under `installer/windows/driver/` (C,
  WDK, signed separately). The daemon queries the driver, blocks on
  scan verdicts for pre-create, and returns allow/deny.
- Requires: EV cert, WHQL/attestation signing, optional ELAM enrolment.
- Daemon needs a new method `watcher.set_mode` to let the user pick
  between user-mode and kernel-mode watching.

Code structured so the minifilter driver is an **optional component** that
the installer offers only if the driver is signed and installed. On a fresh
install without the driver, the user-mode watcher remains the default.

---

## 8. Quarantine vault

### Goals

1. A file placed in quarantine must not be openable, executable, or
   crawlable by other processes (including as SYSTEM, so ACLs are not
   enough — encrypt at rest).
2. Metadata is enough to restore the file to its original location with
   original ACLs.
3. Quarantine is per-daemon-installation, not per-user.
4. Atomic operations: restore either succeeds and the quarantine entry
   disappears, or fails and the entry remains untouched.

### On-disk layout

```
<ProgramData>\<brand>\quarantine\
├── vault.sqlite                 ← metadata, WAL mode, integrity check at startup
├── blobs/
│   ├── a1/
│   │   └── a1b2c3d4e5f6....bin  ← encrypted blob, first 2 hex chars as prefix
│   └── ...
└── key/
    └── vault.key                ← 32-byte random key, mode 0600 / NTFS ACL SYSTEM-only
```

### Encryption

AES-256-GCM. Per-file random 12-byte nonce prepended to the blob. AAD =
`quarantine_id || original_path_bytes`. Authenticated — tampering detected
on restore.

The vault key itself is stored in plaintext mode-0600 under the daemon's
protected directory. It is **not** user-secret; it exists only to prevent
file-system-crawling malware from identifying or extracting quarantined
samples without talking to the daemon. On Windows, the key file gets an ACL
granting access only to `NT AUTHORITY\SYSTEM`.

v2 can move the key into the Windows DPAPI machine store / Linux keyring,
but v1 uses the plain-file approach for simplicity.

### Metadata schema

```sql
CREATE TABLE entries (
  id                TEXT PRIMARY KEY,       -- uuid v4
  original_path     TEXT NOT NULL,
  original_size     INTEGER NOT NULL,
  original_mtime    INTEGER NOT NULL,
  original_mode     INTEGER,                -- unix mode or NULL
  original_owner    TEXT,                   -- "SID" on Windows, "uid:gid" elsewhere
  signature         TEXT NOT NULL,          -- clam sig name, e.g. "Win.Test.EICAR_HDB-1"
  sha256            BLOB NOT NULL,          -- of the original (plaintext)
  scan_job_id       TEXT,
  quarantined_at    INTEGER NOT NULL,       -- unix epoch millis
  blob_path         TEXT NOT NULL,          -- relative under blobs/
  blob_nonce        BLOB NOT NULL,
  blob_tag          BLOB NOT NULL,
  restorable        INTEGER NOT NULL,       -- 1 iff we could re-acquire the ACLs
  notes             TEXT
);
CREATE INDEX idx_entries_sig      ON entries(signature);
CREATE INDEX idx_entries_time     ON entries(quarantined_at);
```

### Operations

- **Quarantine**: read file → compute sha256 → write encrypted blob →
  `chmod 000` or deny-all ACL the original → record DB entry → delete
  original. On any failure, leave the system unchanged (the original file
  is only deleted as the last step, after the blob is fsync'd and the DB
  row committed).
- **Restore**: open blob → decrypt → verify tag → write decrypted file
  to `original_path` with `original_mode` / `original_owner` → delete
  blob → delete DB row. If the destination is unreachable (removable
  drive unmounted, etc.), fail and keep the quarantine entry.
- **Delete**: remove blob → remove DB row. Not recoverable.

### Retention

Default: quarantine entries older than 90 days are auto-purged by the
scheduler (configurable). Users are warned in the UI on approach.

---

## 9. GUI (Tauri)

### Stack

- **Tauri 2.x**: Rust backend, WebView2/WebKitGTK/WKWebView frontend.
- **Frontend**: React 18 + TypeScript + Vite + Tailwind CSS + shadcn/ui.
- **State management**: React Query for server state (IPC calls) +
  Zustand for local UI state.
- **Routing**: React Router, hash-based (no dev server in production).

### Pages

1. **Dashboard** — the "Is my PC safe?" landing page.
   - Big green/yellow/red status card.
   - "Last scan: X hours ago, clean" or "3 threats quarantined, click to
     review".
   - "Real-time protection: ON / OFF" toggle with an info tooltip that
     explains the v1 limitation honestly ("detects threats shortly after
     they appear; does not block access").
   - Signature database age, with "Update now" button.
   - "Run quick scan" / "Run full scan" / "Scan a folder..." buttons.

2. **Scan** — runs and results.
   - Current scan progress, cancel button, current file, speed, ETA.
   - Completed scans list with timestamps and verdicts.
   - Click a finding to see: path, signature, action taken, raw scan
     context (collapsible "advanced" section). Plain-language explainer
     for common signature prefixes (`Win.Test.*`, `Html.Trojan.*`, etc.).

3. **Quarantine** — browse, restore, delete.
   - Table view with filters (by date, signature, original location).
   - Entry detail pane: thumbnail if it's a known image type,
     original metadata, sha256, signature. "Restore" (with warning),
     "Delete permanently", "Submit as false positive" (phase 2,
     opens upstream ClamAV FP form in browser).

4. **History / Reports** — scan logs, per-month statistics.

5. **Settings** — all daemon config, grouped:
   - Scanning (file size limits, archive depth, what file types to scan)
   - Real-time protection (which folders, rate limits)
   - Updates (interval, proxy, custom mirror)
   - Scheduled scans (CRUD)
   - Exclusions (paths, signatures, hashes)
   - Advanced (raw config.toml editor for power users, with save-and-
     reload)

6. **About** — version, engine version, signature version, credits.
   The required ClamAV attribution lives here.

### Reactive IPC

```ts
// src-ui/src/hooks/useDaemon.ts
export function useEngineStatus() {
  return useQuery({
    queryKey: ['engine.status'],
    queryFn: () => invoke('ipc_call', { method: 'engine.status' }),
    refetchInterval: 2000,  // cheap poll
  });
}

// Notifications arrive via Tauri event bus:
useEffect(() => {
  const unlisten = listen<ScanProgress>('scan.progress', (e) => {
    queryClient.setQueryData(['scan.status', e.payload.job_id], e.payload);
  });
  return () => { unlisten.then(f => f()); };
}, []);
```

The Tauri Rust backend (`gui/src/ipc_client.rs`) keeps a single long-lived
connection to the daemon, demultiplexes responses and notifications, and
forwards notifications to the frontend via `app_handle.emit_all()`.

### Accessibility and i18n

- All text strings in `src-ui/src/i18n/<locale>.json`. English is
  canonical, community contributes the rest.
- Keyboard navigation throughout.
- Respects system dark mode.
- Screen-reader roles on all interactive components (shadcn/ui provides
  most of this via Radix).

### First-run experience

On first launch, a 3-step wizard:
1. Welcome + honest explainer of what real-time v1 can and cannot do.
2. Pick folders to auto-protect (pre-selected sensible defaults).
3. Run a quick scan now? (Y/N)

Then the dashboard.

---

## 10. Updater

### v1: wrap freshclam

- Daemon spawns `freshclam` as a child process (or uses `libfreshclam` via
  FFI, depending on stability).
- Parses freshclam's stdout for progress; forwards as `update.progress`
  notifications.
- Moves new CVDs into place atomically (`rename` on Linux, `MoveFileEx
  MOVEFILE_REPLACE_EXISTING` on Windows).
- After success, calls `engine.reload` internally to pick up new
  signatures.

### v2: reimplement in Rust

Optional. A few hundred lines of reqwest + sha256 verification. Lets us
skip the last C code in the update path and support alternate mirrors
more cleanly.

### Signature verification

CVD files are signed by Cisco. `libclamav` verifies them during load via
`cl_cvdverify` — we rely on this. We do **not** disable signature
verification even for testing mirrors; the mirror must serve properly
signed files.

---

## 11. Build system

### Bootstrap

`scripts/bootstrap-vcpkg.ps1` installs vcpkg and the manifest-mode
dependencies:

```json
// vcpkg.json (at repo root)
{
  "name": "brand",
  "version-string": "0.1.0",
  "dependencies": [
    "openssl",
    "pcre2",
    "zlib",
    "bzip2",
    "libxml2",
    "json-c",
    "curl",
    "libiconv"
  ]
}
```

`scripts/build-windows.ps1`:

1. Run vcpkg install.
2. Configure CMake for `upstream/` with
   `-DENABLE_LIBCLAMAV_ONLY=ON -DENABLE_UNRAR=OFF` (see §2).
3. Build `libclamav.dll` + `freshclam.exe` + `sigtool.exe`.
4. Build Rust workspace: `cargo build --release -p brandd -p brand-cli`.
5. Build Tauri app: `cd gui && pnpm install && pnpm tauri build`.
6. Run WiX against `installer/windows/Product.wxs` to produce the MSI.

### Linux

`scripts/build-linux.sh`:

1. Use distro packages for OpenSSL / pcre2 / zlib / etc.
2. CMake upstream with same options as Windows.
3. `cargo build --release`.
4. `pnpm tauri build` → produces .deb, .rpm, AppImage.

### CI

GitHub Actions matrix:

| OS | What runs |
|---|---|
| `windows-2022` | Full build + unit tests + integration tests (daemon + CLI, no GUI interaction) |
| `ubuntu-latest` | Full build + tests + ASAN run + clippy `-D warnings` |
| `macos-latest` | Build only (v1) |

Every PR runs the audit-script smoke tests: run EICAR and a small corpus
through the daemon, check IPC contract, no regressions in scan results.

---

## 12. Security model

### Trust boundaries

```
 [user] ──► GUI ──── IPC ────► Daemon ──── FFI ───► libclamav
                                │
                                └──── child process ──► freshclam
```

- **GUI ↔ Daemon**: mutually un-trusted across the pipe. The daemon
  validates every message against the typed schema. The GUI treats daemon
  replies as trusted only after schema validation. Peer credentials are
  checked on accept.

- **Daemon ↔ libclamav**: libclamav is trusted code but parses untrusted
  input (files). A libclamav crash is a daemon crash → service restart.
  We harden this with:
  - Per-scan resource limits (already exist in libclamav, we expose them).
  - Run scans in a work-stealing pool so one hung scan cannot pin the
    engine forever (kill + reload after a configurable per-file timeout).
  - v2: run each scan in a sandboxed subprocess
    (`PROCESS_MITIGATION_POLICY` / `seccomp-bpf`).

- **Daemon ↔ freshclam**: child process. freshclam fetches from a trusted
  HTTPS endpoint with cert verification and CVD signature verification.
  We pass through the user's configured proxy/mirror.

### Threat model in scope

- **Malicious files** scanned by the engine. This is the entire point;
  libclamav is the defence.
- **Malicious signature mirror** serving forged CVDs. Defence:
  `cl_cvdverify` signature check.
- **Local unprivileged user** trying to pivot via the IPC. Defence:
  message validation, peer credential check, principle-of-least-
  privilege on restore targets.
- **Malware already running as user** trying to disable real-time
  protection. Defence: v1 relies on the OS to protect the daemon from
  non-admin users; v2 adds tamper protection.

### Explicitly out of scope (for v1, documented)

- **Malware running as SYSTEM/root.** Such an attacker can remove or
  uninstall the daemon. There is no defence at this level without PPL /
  ELAM on Windows, which is v3 territory.
- **Physical attackers.** Not an AV problem.
- **Kernel exploits.** libclamav runs in user mode; kernel compromise is
  outside our threat model.

---

## 13. Phase milestones (no time estimates)

### Phase 0 — bootstrap
- [ ] Pick name. Verify trademark + domains.
- [ ] Create org + repo. Apply GPLv2, add NOTICE.md.
- [ ] Decide: include UnRAR or not (default: no).
- [ ] Set up Windows build toolchain and produce a working `clamscan.exe`
      from upstream, unmodified.
- [ ] Write CONTRIBUTING.md and security policy.

### Phase 1 — daemon MVP
- [ ] `crates/brand-ipc-proto` with full schema.
- [ ] `crates/brandd` skeleton: IPC server, engine load, `scan.start` on a
      single file, progress notifications, `engine.status`.
- [ ] `crates/brand-cli` that does `brand-cli scan <path>` end-to-end.
- [ ] Quarantine vault (v1 simple AES-256-GCM + sqlite).
- [ ] Updater wrapping freshclam.
- [ ] Scheduler (at least: "scan every Sunday 03:00").

### Phase 2 — GUI MVP
- [ ] Tauri scaffold, dashboard, scan, quarantine, settings, about.
- [ ] First-run wizard.
- [ ] WiX installer producing a signed MSI (if cert available; otherwise
      unsigned but documented).
- [ ] User testing: find five non-technical people, watch them install
      and run a scan. Fix everything that confuses them.

### Phase 3 — real-time v1 (user-mode, Windows)
- [ ] `windows_readdir.rs` foreground watcher.
- [ ] `windows_usn.rs` background watcher.
- [ ] Event debounce + scan queue integration.
- [ ] UI controls for enable/disable + watched-folder picker.

### Phase 4 — Linux port
- [ ] `linux_fanotify.rs` (wrap clamonacc).
- [ ] .deb + .rpm + AppImage.
- [ ] systemd unit.

### Phase 5 — macOS port
- [ ] `macos_fsevents.rs` watcher.
- [ ] Notarized .pkg (requires Apple Developer Program).

### Phase 6 — real-time v2 (Windows minifilter)
- [ ] EV code-signing cert.
- [ ] Minifilter driver project.
- [ ] Communication port with daemon.
- [ ] Attestation signing via Microsoft Partner Center.
- [ ] (Stretch) ELAM enrolment.

### Phase 7 and beyond
- [ ] AMSI provider for script scanning.
- [ ] Endpoint Security framework on macOS (similar role to minifilter).
- [ ] eBPF-based watcher option on Linux as an alternative to fanotify.
- [ ] Behavioral heuristics layer on top of libclamav's signature engine
      (events from the watcher + ETW + `sysdiagnose` → simple rules).

---

## 14. Open decisions

These are deliberately left open. Each should become an ADR in
`docs/architecture/` once decided.

1. **Product name** — see §2 trademark.
2. **Include UnRAR?** Default recommendation: no. Revisit for v1.1.
3. **Daemon user on Linux.** Create a dedicated system user or reuse
   `clamav`? Reusing means we coexist with an upstream clamav install,
   which is probably wrong. Recommend new user.
4. **Sidecar freshclam vs. libfreshclam FFI.** Start with sidecar for
   simplicity; revisit if we hit protocol limitations.
5. **Plugin system?** Not for v1. Worth designing the daemon so a future
   plugin API can slot in — reserve `plugin.*` namespace in IPC.
6. **Telemetry.** Strong recommendation: opt-in, anonymous, very minimal
   (version, OS, rough signature version), behind a setting that
   defaults off. v2 concern.
7. **Crash reporting.** Same as telemetry. Opt-in. Probably Sentry with
   a self-hosted backend or minidumps uploaded on demand.
8. **Documentation site.** mdBook under `docs/`, deployed via GitHub
   Pages. Deferred to phase 2.
9. **Localization process.** Probably Weblate. Deferred to phase 3.
10. **Support matrix.** Windows 10 22H2+ and Windows 11 for v1. Older
    Windows drops with Tauri 2 / WebView2 constraints.

---

## 15. What this doc does not cover

- Detailed UI mockups (that's a Figma / sketches task, not a markdown
  one).
- API documentation for the IPC protocol (will live in
  `docs/ipc-protocol.md`; this doc only sketches the shape).
- The audit of upstream libclamav bugs — see `AUDIT_FINDINGS.md`.
- The Rust crate structure of `upstream/libclamav_rust/`. We treat it as
  opaque until we need to change it.
- CI and code-signing key management. Separate ops doc.
- Translation and community governance. Separate governance doc.
- Marketing, website, download page. Not our problem at this stage.

---

## Appendix A — why not X?

- **Why not just write the GUI against `clamd`?** Could. clamd's
  protocol is crude (newline-terminated text, commands like
  `nINSTREAM`, very little progress reporting) and would require
  patching upstream for features like per-scan progress. A new daemon
  is cleaner and we stop needing to ship clamd at all.

- **Why Rust for the daemon instead of C++?** libclamav and friends are
  already C. The upstream `libclamav_rust/` crate shows Cisco is
  comfortable with Rust in-tree. Rust gives us memory safety on the new
  surface (IPC, watcher, quarantine) without giving up libclamav
  compatibility. Async runtime (tokio) is production-grade.

- **Why not use existing `clamonacc` as-is on Linux and write something
  totally new for Windows?** We do, in v1 — `linux_fanotify.rs` wraps
  clamonacc. It's just that the GUI needs one daemon to talk to, so we
  proxy clamonacc events through our daemon.

- **Why not ship with unrar?** License incompatibility with GPLv2 per
  upstream README. Upstream takes the risk; a new fork should not.
  Ship without by default; document a build flag for users who need it.

- **Why a full GUI and not just a tray icon?** Tray-icon-only
  experiences feel abandoned. Beginners want a visible "I am protected"
  screen. A tray icon is complementary (see phase 2).

- **Why not Electron?** Bigger binary, higher memory, Node
  dependency footprint. Tauri gives us the same web frontend story at a
  fraction of the size, and our backend is already Rust.

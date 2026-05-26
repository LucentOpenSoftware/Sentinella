# Sentinella v0.1.0 — Working State Snapshot

**Date locked:** 2026-05-26
**Status:** Installer working end-to-end on Windows 10/11 x64
**Purpose:** Document the verified-working configuration so future changes don't regress it.

This file describes EXPECTED behavior after running `Sentinella_0.1.0_x64-setup.exe`.
Any future commit that breaks anything listed here is a regression and must be reverted or fixed before merge.

---

## 1. Build artifacts (Cargo)

| Crate | Binary name | Notes |
|-------|-------------|-------|
| `crates/sentinelld` | `sentinelld.exe` | Antivirus daemon, runs as Windows service |
| `crates/argusd` | `argusd.exe` | ARGUS subprocess worker |
| `crates/sentinella-cli` | `sentinella.exe` | Command-line client |
| `gui/src-tauri` | `Sentinella.exe` | **Must be `Sentinella.exe`, NOT `gui.exe`** — autostart registry depends on this name |

The GUI binary is named via `[[bin]] name = "Sentinella"` in `gui/src-tauri/Cargo.toml`.
If this is renamed, the NSIS autostart entry breaks → tray never appears at login.

## 2. Windows service (Sentinella Daemon)

| Property | Value |
|----------|-------|
| Service name | `SentinellaDaemon` |
| Display name | `Sentinella Protection Service` |
| Start mode | `AUTO_START (DELAYED)` — starts ~2 min after boot |
| Account | `LocalSystem` |
| Failure recovery | restart 5s / 10s / 30s, reset after 1 day |
| Binary path | `"C:\Program Files\Sentinella\daemon\sentinelld.exe" --log-level info --runtime-root "C:\ProgramData\Sentinella" --dll-dir "C:\Program Files\Sentinella\daemon" --db-dir "C:\ProgramData\Sentinella\signatures"` |

**Critical**: daemon MUST be invoked WITHOUT `--foreground` so it enters Windows Service dispatcher mode.
The `windows-service` crate handles SCM handshake (`StartPending` → `Running` → `Stopped`).
Without proper service integration, `sc start` fails with `ERROR 1053` (timeout).

## 3. Install layout (per-machine)

```
C:\Program Files\Sentinella\          (NSIS installMode: perMachine, requires UAC)
├── Sentinella.exe                    (GUI, Tauri 2 + React)
├── uninstall.exe
└── daemon/                           (Tauri resources mapping, NOT resources/daemon/)
    ├── sentinelld.exe
    ├── argusd.exe
    ├── sentinella-cli.exe
    ├── freshclam.exe
    ├── libclamav.dll
    ├── libclammspack.dll
    ├── libfreshclam.dll
    ├── (other ClamAV runtime DLLs: zlib1, libssl-3-x64, libcrypto-3-x64, etc.)
    ├── LICENSE / NOTICE.md
    ├── certs/clamav.crt
    └── runtime/
        ├── config/{freshclam.conf, sentinelld.toml}
        ├── argus/rules/yara/*.yar       (29 packs, ~177 rules)
        ├── argus/manifests/pack_manifest.json
        ├── rules/ioc_hashes.txt
        └── signatures_bootstrap/         (113 MB: main.cvd, daily.cvd, bytecode.cvd + .sign)

C:\ProgramData\Sentinella\            (runtime data, daemon writes here)
├── config/                           (freshclam.conf + sentinelld.toml copied at install)
├── signatures/                       (bootstrap CVDs copied at install)
├── argus/rules/yara/                 (YARA rules copied at install)
├── argus/manifests/
├── rules/ioc_hashes.txt
├── state/{sentinella.db, scan_cache.db, trust_graph.db, calibration.db, ipc_secret, vault_integrity_key}
├── logs/sentinelld.log
├── cache/
├── clamav_tmp/
├── quarantine/
├── diagnostics/
├── enhanced_signatures/
└── update_staging/
```

## 4. Registry

| Key | Value | Purpose |
|-----|-------|---------|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Sentinella` | `"C:\Program Files\Sentinella\Sentinella.exe" --minimized` | Auto-launches GUI at login, hidden in tray |

## 5. PathManager resolution

`crates/sentinelld/src/paths.rs::detect_root()` priority:
1. Dev mode: CWD has `Cargo.toml` → `<cwd>/runtime/`
2. Portable mode: exe dir has `runtime/` → `<exe_dir>/runtime/`
3. Installed mode: `C:\ProgramData\Sentinella` (or `--runtime-root` override)

When running as service, NSIS hook passes `--runtime-root "C:\ProgramData\Sentinella"` explicitly.

## 6. Tauri 2 GUI windows

| Window | `visible` default | Behavior |
|--------|-------------------|----------|
| `main` | `false` | Hidden by default. Shown after splash completes (normal launch) or via tray "Open Sentinella" |
| `splash` | `false` | Hidden by default. Shown explicitly only when NOT `--minimized`. Closes when daemon ready or 15s timeout |

**Launch behaviors:**
- Manual launch (no flag): splash shows → wait for daemon (15s max) → swap to main window
- Autostart with `--minimized`: splash closed immediately, main never shown, only tray visible

## 7. ClamAV engine memory profile

| Metric | Value |
|--------|-------|
| Signatures loaded | ~3.6 million (main + daily + bytecode CVDs) |
| Engine compile time | ~5-8 seconds (after bootstrap signatures copy) |
| Mpool total | ~970 MB (file-backed mapping, not RSS) |
| Private bytes after trim | ~9 MB (post `SetProcessWorkingSetSize` trim) |
| Peak working set | ~970 MB during compile (briefly), drops to single digits after trim |
| YARA rules compiled | 177 rules across 29 files |

File-backed mpool is active when `cache_mb=977` and `file_backed=true` appear in logs.
If file-backed fails, fallback is anonymous allocation — engine still works but uses more private bytes.

## 8. IPC

- Named pipe: `\\.\pipe\sentinelld`
- Authentication: 256-bit secret in `state/ipc_secret`, validated constant-time
- Challenge tokens required for: quarantine restore/delete, sources.set/update, protection.set_critical
- Rate-limited per method class
- Per-method payload caps enforced
- Method registry: 43 methods (policy.rs)

## 9. Update system

- Tauri updater plugin wired
- Endpoint: `https://github.com/LucentOpenSoftware/Sentinella/releases/latest/download/latest.json`
- Public key: embedded in `tauri.conf.json` (private key in `keys/sentinella-update.key`, gitignored)
- UI: "Check for Updates" button in About page
- Updates download only the bundle delta (~8MB), not the full 137MB installer

## 10. Installer flow (NSIS, perMachine)

1. UAC elevation prompt
2. Install files to `C:\Program Files\Sentinella\`
3. NSIS `NSIS_HOOK_POSTINSTALL` runs (elevated):
   - Creates ProgramData directory tree
   - Copies config templates (if not present — preserves user edits)
   - Copies YARA rules + IOC hashes + manifests to ProgramData
   - Copies bootstrap signatures to ProgramData (only if `main.cvd` missing — preserves freshclam updates)
   - Stops + deletes existing service (upgrade)
   - Registers service via `sc create` with full CLI args
   - Sets description + failure recovery
   - Starts service
   - Writes autostart registry key for GUI

4. NSIS `NSIS_HOOK_PREUNINSTALL` runs:
   - Deletes autostart registry
   - Kills running GUI process
   - Stops + deletes service

## 11. Tests baseline

- `cargo test --workspace`: **426 passing**, 0 failed
- ARGUS: 158 tests
- ETW: 40 tests
- Daemon (sentinelld): 228 tests

Any commit that drops the count below 426 (without explicit reason like removing dead code with its tests) is a regression.

## 12. Build commands

```powershell
# Release build
cargo build --workspace --release

# Copy ClamAV DLLs alongside binaries
$src = "build\clamav"; $dst = "target\release"
foreach ($dll in @("libclamav\Release\libclamav.dll", "libclammspack\Release\libclammspack.dll", "libfreshclam\Release\libfreshclam.dll")) {
    Copy-Item (Join-Path $src $dll) $dst -Force
}
Copy-Item "$src\freshclam\Release\freshclam.exe" $dst -Force

# Stage release package
scripts\stage-windows-package.bat

# Copy bootstrap signatures to staging (113 MB, gitignored)
Copy-Item "runtime\signatures_bootstrap\*" "release\staging\windows\runtime\signatures_bootstrap\" -Force

# Build NSIS installer (requires private signing key)
$env:TAURI_SIGNING_PRIVATE_KEY_PATH = "keys\sentinella-update.key"
cd gui
pnpm tauri build --bundles nsis

# Output: gui/src-tauri/target/release/bundle/nsis/Sentinella_0.1.0_x64-setup.exe (~137 MB)
```

## 13. Verification checklist after install

```powershell
# 1. Service is RUNNING
sc query SentinellaDaemon
# Expected: STATE = 4 RUNNING

# 2. Service binPath correct
sc qc SentinellaDaemon
# Expected: BINARY_PATH includes --runtime-root and --dll-dir

# 3. Autostart registered
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Sentinella
# Expected: REG_SZ "C:\Program Files\Sentinella\Sentinella.exe" --minimized

# 4. Install files present
ls "C:\Program Files\Sentinella\Sentinella.exe"
ls "C:\Program Files\Sentinella\daemon\sentinelld.exe"
ls "C:\Program Files\Sentinella\daemon\libclamav.dll"

# 5. Signatures present
ls "C:\ProgramData\Sentinella\signatures\main.cvd"
ls "C:\ProgramData\Sentinella\signatures\daily.cvd"

# 6. Daemon log shows successful startup
Get-Content "C:\ProgramData\Sentinella\logs\sentinelld.log" -Tail 30
# Expected lines:
#   "Signatures loaded ... signatures=3627866"
#   "ARGUS Heuristics Engine initialized"
#   "YARA rules compiled successfully rules=177"
#   "IPC server listening"
#   "real-time watcher started"

# 7. After reboot: tray icon visible, NO splash flash, NO main window pop-up
```

## 14. Known limitations (not regressions)

- Unsigned installer → SmartScreen warning ("Windows protected your PC" → More info → Run anyway)
- First-run requires UAC (perMachine install)
- `freshclam` update is scheduled by daemon, not run during install (bootstrap signatures ship with installer)
- Manifest verification on signature updates is soft-fail when provider returns 403/404 (they don't serve manifests yet)
- libclamav.dll may crash once during long sessions (logged as APPCRASH, service auto-recovers via failure recovery policy)

---

## DO NOT BREAK

If you touch any of these areas, verify all of section 13 still passes:

- `gui/src-tauri/Cargo.toml` `[[bin]] name = "Sentinella"` → autostart depends on this
- `gui/src-tauri/tauri.conf.json` `windows.nsis.installMode: "perMachine"` → ProgramData writes need admin
- `gui/src-tauri/tauri.conf.json` `splash` and `main` both `visible: false` → minimized startup
- `gui/src-tauri/nsis-hooks.nsh` paths use `$INSTDIR\daemon\*` (not `resources\daemon`)
- `crates/sentinelld/src/main.rs` Windows service dispatcher when not `--foreground`
- `crates/sentinelld/Cargo.toml` `windows-service = "0.7"` dependency
- Bootstrap signatures copy in NSIS hook is idempotent (skips if `main.cvd` already exists)

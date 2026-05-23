# Sentinella Field Testing Guide

**Version**: 0.1.0-alpha  
**Date**: May 2026

---

## Who Should Test

- Developers who built Sentinella from source
- Users with a secondary or test machine
- Anyone comfortable recovering from quarantine actions

## Who Should NOT Test Yet

- Users on their only/primary work machine
- Users without backups of important files
- Production servers or shared machines
- Machines where Defender cannot be adjusted

---

## Windows Defender Coexistence

Sentinella and Defender can run simultaneously, but you may see:

- Defender flagging ClamAV DLLs as "potentially unwanted"
- Both products quarantining the same file
- Performance impact from double-scanning

**Recommended for testing:**

1. Keep Defender active (do not disable it)
2. Add Sentinella's install/project directory to Defender exclusions:
   - Settings > Virus & threat protection > Exclusions > Add
   - Exclude: `C:\Users\<you>\Desktop\sentinella\` (dev mode)
3. If Defender flags ClamAV DLLs, allow them in Defender history

---

## Installation (Dev Mode)

```bat
:: 1. Build everything
cargo build --workspace --release

:: 2. Build GUI
cd gui
pnpm install
pnpm build

:: 3. Start daemon
cd ..
.\target\release\sentinelld.exe

:: 4. Start GUI (separate terminal)
cd gui
pnpm tauri dev
```

For release builds:
```bat
cd gui
pnpm tauri build
:: Installers at: gui/src-tauri/target/release/bundle/
```

---

## First Run

1. Start the daemon (`sentinelld.exe`)
2. Start the GUI
3. First-run wizard appears → follow steps
4. Click "Update Signatures Now" → wait for download
5. Dashboard should show "Your System is Protected"

---

## Updating Signatures

- GUI: Update page → "Check for Updates"
- CLI: `freshclam.exe --config-file=runtime\config\freshclam.conf`
- Signatures stored in `runtime/signatures/`

---

## Testing the Watcher

The watcher monitors Downloads, Desktop, and Temp for new/modified files.

**Test:**
1. Download any `.exe` from the internet → watcher should scan it
2. Check daemon logs for `watcher scan: clean` or threat detection
3. Create EICAR test file in Downloads → should detect + auto-quarantine

**EICAR test string** (paste into a `.txt` then rename to `.com`):
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

**Verify no noise:**
- Run `cargo build` with project on Desktop → no `.rlib` quarantine
- Run `npm install` → no `node_modules` scanning
- Edit `.json`/`.md` files → no watcher triggers

---

## Testing the Idle Scanner

The idle scanner crawls files when your system has spare capacity.

**Observe:**
1. Dashboard → "Background" tile shows state
2. States: Scanning (slow/normal/fast), Paused (cpu/disk/fullscreen/battery), Waiting, Done
3. Open Task Manager → sentinelld CPU should stay low (<5%) during idle scan
4. Start a heavy task (build, game) → idle scanner should pause
5. Return to idle → scanner should resume

**IPC check:**
```
sentinella.exe status  (if CLI available)
```

---

## Reporting False Positives

If Sentinella flags a legitimate file:

1. Note the file name, path, and detection name
2. Check the ARGUS score and verdict
3. Note the signer (if any) from "Why this verdict?"
4. Open a GitHub issue using the False Positive template
5. Include SHA-256 hash (visible in scan results or quarantine page)

**Do NOT:**
- Upload the actual file to GitHub
- Paste any credentials, tokens, or personal data
- Share proprietary/licensed software files

**Do:**
- Share the SHA-256 hash
- Share the detection name and score
- Mention if the file is publicly downloadable

---

## Recovering Quarantined Files

1. GUI → Quarantine page
2. Expand the quarantined item
3. Click "Restore" → confirmation dialog
4. File is decrypted and placed back at original location
5. If restore fails, check that the original directory exists

**If quarantine vault is corrupted:**
- Vault files are in `runtime/quarantine/`
- Each file is AES-256-GCM encrypted
- Without the vault key (`runtime/quarantine/.vault_key`), files cannot be recovered
- Back up `.vault_key` if testing with important files

---

## Uninstalling (Dev Mode)

```bat
:: Stop daemon
Ctrl+C in daemon terminal

:: Remove runtime data (optional)
rmdir /s /q runtime\signatures
rmdir /s /q runtime\state
rmdir /s /q runtime\logs
rmdir /s /q runtime\quarantine
```

For MSI/NSIS installs: use Windows Add/Remove Programs.

---

## Performance Observation

Monitor during testing:

| Metric | Where | Expected |
|---|---|---|
| Daemon idle CPU | Task Manager | <1% |
| Daemon scan CPU | Task Manager | 10-30% (4 threads) |
| Idle scanner CPU | Task Manager | <3% |
| RAM | Task Manager | 50-150 MB |
| Disk I/O during idle scan | Resource Monitor | <5 MB/s |
| GUI responsiveness | Use the app | No freezes |
| Notifications | System tray | No spam, dedupe works |

**Red flags to report:**
- Daemon CPU >50% when idle
- RAM >500 MB
- GUI shows "Disconnected" repeatedly
- Notification storm (>5 toasts in 1 minute)
- Files quarantined that shouldn't be

---

## Diagnostics

Export a diagnostic snapshot:
- GUI: About page (future) or use CLI
- IPC: `stats.runtime` returns all subsystem states
- Logs: `runtime/logs/sentinelld.log`

When filing bugs, include:
- Sentinella version (About page)
- Windows version (`winver`)
- Protection state (Dashboard)
- Recent daemon log entries (last 50 lines)

---

## Controlled Rollout Phases

| Phase | Scope | Duration | Criteria to Advance |
|---|---|---|---|
| **Phase 1** | Dev machine only | 3-5 days | No crashes, no self-quarantine, no data loss |
| **Phase 2** | Secondary daily machine | 5-7 days | No FPs on common software, stable idle scanner |
| **Phase 3** | 2-3 additional test machines | 7-14 days | Consistent behavior, <3 FP reports |
| **Phase 4** | GitHub beta release | After Phase 3 | README + install guide + known issues |

**Rollback:** At any phase, stop the daemon and delete `runtime/` to reset completely.

---

*This guide assumes pre-release testing. Do not distribute to non-technical users yet.*

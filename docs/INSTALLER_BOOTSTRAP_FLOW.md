# Sentinella Installer & Bootstrap Flow

**Status**: Design — installer not yet built  
**Date**: May 2026

---

## Install Sequence

```
1. MSI installer runs (requires admin for service registration)
2. Install files to C:\Program Files\Sentinella\
   ├── sentinelld.exe          (daemon)
   ├── sentinella.exe          (CLI)
   ├── Sentinella.exe          (GUI — Tauri bundle)
   ├── libclamav.dll           (ClamAV engine)
   ├── libclammspack.dll       (ClamAV dependency)
   ├── libfreshclam.dll        (ClamAV updater)
   ├── freshclam.exe           (signature updater)
   ├── sentinelld.ico          (branding)
   ├── certs/                  (ClamAV TLS certificates)
   └── runtime/
       ├── config/             (created, sentinelld.toml generated)
       ├── argus/
       │   ├── rules/yara/     (bundled YARA rules)
       │   └── manifests/      (pack metadata)
       └── rules/
           └── ioc_hashes.txt  (bundled IOC database)
3. Register Windows service: SentinellaDaemon (delayed-auto start)
4. Configure service recovery: restart on failure (3 attempts)
5. Create runtime directories: signatures, state, logs, quarantine
6. Register shell context menu (HKCU)
7. Create Start Menu shortcut
8. Optionally create Desktop shortcut
```

## First Launch Sequence

```
1. Service starts automatically (or user clicks shortcut)
2. Daemon bootstraps:
   a. Create missing runtime directories
   b. Load config (create defaults if missing)
   c. Attempt ClamAV engine load
      - If DLLs present + signatures exist → engine ready
      - If DLLs present + NO signatures → engine skipped, log warning
      - If DLLs missing → log error, continue without scanning
   d. Initialize ARGUS engine (always succeeds — heuristics don't need ClamAV)
   e. Load IOC hashes (if present)
   f. Compile YARA rules (if present)
   g. Start IPC server
   h. Start real-time watcher (if engine loaded)
   i. Start scheduler
3. GUI launches (first-run wizard detects no completion flag)
4. Wizard:
   a. Welcome screen
   b. Check daemon connection (retry if not ready)
   c. Check signature status
      - If signatures loaded → show count, offer update
      - If NO signatures → strongly recommend update
   d. User clicks "Update Signatures Now" → freshclam runs
   e. Engine reloads with new signatures
   f. Optional quick scan
   g. Wizard completes → localStorage flag set
5. Dashboard shows full status
```

## Freshclam Bootstrap

```
First-time signature download:
1. freshclam.exe must be bundled with installer
2. freshclam.conf must be generated:
   DatabaseDirectory = C:\Program Files\Sentinella\runtime\signatures
   DatabaseMirror = database.clamav.net
   (no log file needed — output captured by daemon)
3. Daemon runs freshclam as child process
4. Downloads: main.cvd (~160MB), daily.cvd (~100MB), bytecode.cvd (~300KB)
5. First download takes 2-5 minutes
6. Engine reloads after download
7. Progress tracked via update_status IPC
```

## Service Registration

```
sc create SentinellaDaemon ^
    binPath= "C:\Program Files\Sentinella\sentinelld.exe --foreground --log-level info" ^
    DisplayName= "Sentinella Protection Service" ^
    start= delayed-auto ^
    obj= LocalSystem

sc failure SentinellaDaemon ^
    reset= 86400 ^
    actions= restart/5000/restart/10000/restart/30000

sc description SentinellaDaemon ^
    "Sentinella antivirus daemon — ClamAV + ARGUS heuristic intelligence engine."
```

## Portable vs Installed Mode

| Aspect | Installed (MSI) | Portable (dev-run) |
|---|---|---|
| Location | `C:\Program Files\Sentinella\` | Project directory |
| Service | Windows service (auto-start) | Manual (dev-run.bat) |
| Config | `%ProgramData%\Sentinella\` | `runtime/config/` |
| Data | `%ProgramData%\Sentinella\` | `runtime/state/` |
| Shell menu | Installer registers | Manual script |
| Updates | Auto (service restart) | Manual |

## Required DLLs

From ClamAV build (`build/clamav/`):
- `libclamav.dll` — core scanning engine
- `libclammspack.dll` — archive extraction
- `libfreshclam.dll` — signature update (if needed)

From system (should already be present):
- `ntdll.dll`, `kernel32.dll`, `userenv.dll`, `dbghelp.dll`
- `ws2_32.dll` (networking for freshclam)
- `crypt32.dll` (TLS for freshclam)
- `wintrust.dll` (Authenticode verification)

## Fallback Behavior

| Scenario | Behavior |
|---|---|
| Missing ClamAV DLLs | ARGUS heuristics + YARA only (no signature scanning) |
| Missing signature DB | Recommend update, watcher monitors but can't ClamAV-scan |
| Missing YARA rules | Heuristic layers + ClamAV still active |
| Missing IOC hashes | Skip IOC matching, other layers active |
| Corrupt config | Backup + reset to defaults |
| DB corruption | Recreate SQLite schema |
| Service crash | Auto-restart (3 attempts, 5/10/30s delays) |

## Uninstall Expectations

```
1. Stop service
2. Remove service registration
3. Remove shell context menu entries
4. Remove program files
5. Optionally remove runtime data (prompt user)
6. Remove Start Menu shortcut
7. Do NOT remove quarantine without user confirmation
   (quarantined files may need recovery)
```

---

*Installer implementation requires WiX 4 authoring + code signing certificate.*

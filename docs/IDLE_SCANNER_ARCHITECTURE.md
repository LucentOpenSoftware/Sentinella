# Idle Scanner Architecture

**Status**: Implemented (v1)  
**Date**: May 2026

---

## Core Principle

The idle scanner asks: **"Can I scan without the user noticing?"**

Not: "Is the user away?"

A user browsing the web with low CPU is idle enough. A locked screen is
even better. A game running fullscreen is not.

## Why "Idle" Does Not Mean "User Absent"

Traditional idle detection uses keyboard/mouse timers (`GetLastInputInfo`).
This is wrong for a background scanner because:

- Scrolling a webpage = mouse active, but system idle
- Watching a video = no input, but may be high CPU (decode)
- Compiling code = keyboard idle, but CPU/disk maxed

Sentinella tracks **system capacity**, not human presence:

| Signal | Meaning |
|---|---|
| CPU load < 50% | System has spare compute |
| Disk latency < 50ms | No I/O contention |
| No fullscreen app | Not gaming/presenting |
| Not on battery | Has power budget |
| No foreground scan | Not already scanning |
| Screen locked | User away → scan faster |

## Decision Tree

```
every 1-2 seconds before each file:
  if on_battery AND idle_scan_on_battery=false
      → sleep 60s
  else if fullscreen_or_busy (game, presentation)
      → sleep 30s
  else if foreground scan or update running
      → sleep 10s
  else if system_cpu > threshold (default 50%)
      → sleep 10s
  else if disk_read_latency > threshold (default 50ms)
      → sleep 5s
  else if screen_locked
      → scan at fast speed
  else if idle for >5 minutes
      → scan at normal speed
  else
      → scan at slow speed
```

## Adaptive Speed Model

| Speed | When | Delay Between Files |
|---|---|---|
| **Slow** | First 5 minutes of idle window | 1500–2500ms (randomized) |
| **Normal** | Stable idle >5 min | 400–1000ms (randomized) |
| **Fast** | Screen locked / user away | 100–300ms (randomized) |
| **Paused** | High CPU / disk / fullscreen / battery / scan running | Full pause |

Randomized delays prevent a steady disk I/O pattern that users notice
subconsciously. No hum. No rhythm.

## Windows APIs Used

| API | Purpose | Feature |
|---|---|---|
| `GetSystemTimes()` | CPU idle/busy delta | `Win32_System_Threading` |
| `GetSystemPowerStatus()` | Battery/AC detection | `Win32_System_Power` |
| `SHQueryUserNotificationState()` | Fullscreen/game/presentation | `Win32_UI_Shell` |
| `fs::metadata()` on ntdll.dll | Disk latency probe | Std library |

### Not Used (Documented for Future)

| API | Purpose | Why Deferred |
|---|---|---|
| `GetLastInputInfo()` | Keyboard/mouse idle time | Not primary signal — mouse alone ≠ busy |
| `WTSQuerySessionInformation()` | Precise screen lock state | `SHQueryUserNotificationState` covers this via QUNS_NOT_PRESENT |
| ETW process events | Process launch detection | v1.5+ traffic awareness layer |

## Scan Targets (Priority Order)

1. `%USERPROFILE%\Downloads`
2. `%USERPROFILE%\Desktop`
3. `%TEMP%`
4. `%APPDATA%` (Discord, Telegram caches)
5. `%LOCALAPPDATA%`
6. `%USERPROFILE%\Documents`

Does NOT scan entire `C:\` by default.

## File Priority Within Each Directory

1. Executables (exe, dll, scr, com, pif)
2. Scripts (bat, cmd, ps1, vbs, js)
3. Installers (msi, msix, appx)
4. Archives (zip, rar, 7z, iso)
5. Documents with macro capability (docm, xlsm, pdf)
6. Shortcuts (lnk, url)
7. Everything else

Recently modified files scan before older ones (within same priority).

## Performance Budget

- Max recursion depth: 8 levels
- Max files per session: 10,000 (configurable)
- Max file size: 256 MB (configurable)
- Thread priority: `THREAD_PRIORITY_BELOW_NORMAL` via `SetThreadPriority`
- 30-second startup delay before first scan cycle
- 30–60 minute random pause between cycles

## Pause / Resume

The scanner checks resources **before every single file**. This means:

- User opens a game → fullscreen detected → immediate pause
- Cargo build starts → CPU spikes → pauses within 1-2 seconds
- User unplugs laptop → battery detected → pauses within 60 seconds
- User returns from lunch → screen unlocks → drops from fast to slow

No position tracking needed — the scanner simply walks the directory list
sequentially. If interrupted, next cycle starts from the beginning
(cache prevents rescanning clean files).

## Safety

The idle scanner respects:

- `is_sentinella_path()` — never scans own files
- `is_build_or_dev_path()` — skips target/, node_modules/, .git/, etc.
- `should_skip_file()` — skips system/temp/lock files
- Scan cache — skips files already verified this session
- Extension filter — skips images, fonts, audio, build artifacts
- Notification dedupe/storm control — no toast spam

Auto-quarantine uses `scan_id = "idle_scan"` for audit trail.

## Configuration (sentinelld.toml)

```toml
idle_scan_enabled = true
idle_scan_on_battery = false
idle_scan_cpu_pause_threshold = 50
idle_scan_max_file_size_mb = 256
idle_scan_fullscreen_pause = true
idle_scan_disk_latency_pause_ms = 50
idle_scan_max_files_per_session = 10000
idle_scan_slow_delay_min_ms = 1500
idle_scan_slow_delay_max_ms = 2500
idle_scan_normal_delay_min_ms = 400
idle_scan_normal_delay_max_ms = 1000
idle_scan_fast_delay_min_ms = 100
idle_scan_fast_delay_max_ms = 300
```

## IPC Endpoint

`idle_scanner.status` returns:

```json
{
  "state": "scanning_normal",
  "files_scanned_session": 1234,
  "current_target": "Downloads",
  "last_pause_reason": "high_cpu",
  "last_completed": 1747123456
}
```

States: `disabled`, `waiting_for_capacity`, `scanning_slow`, `scanning_normal`,
`scanning_fast`, `paused_cpu`, `paused_disk`, `paused_fullscreen`,
`paused_battery`, `paused_scan_running`, `completed`.

## Limits and Non-Goals

- No kernel-mode driver (user-mode only — cannot block access)
- No startup scan yet (architecture ready, implementation deferred)
- No thread priority lowering (Windows `SetThreadPriority` deferred)
- No ETW integration yet (planned v1.5+)
- Does not scan `C:\Windows`, `C:\Program Files` (too broad for v1)
- Does not track scan position across daemon restarts

## Future Enhancements

- ~~**v1.1**: SetThreadPriority(IDLE)~~ → Done (BELOW_NORMAL)
- **v1.2**: Startup quick scan (recent executables in Downloads/Desktop/Temp)
- **v1.5**: ETW process events for smarter idle detection
- **v2.0**: Persistent scan position + progress tracking

---

*The idle scanner makes Sentinella a complete protection tool — it doesn't
just catch what arrives, it eventually finds what's already there.*

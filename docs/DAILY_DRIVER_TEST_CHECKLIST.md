# Sentinella Daily-Driver Smoke Test Checklist

Run before any release or after major changes.

---

## 1. Daemon Startup
- [ ] `dev-run.bat` completes without errors
- [ ] Daemon logs show: "ClamAV library initialized"
- [ ] Daemon logs show: "Signatures loaded" with count > 0
- [ ] Daemon logs show: "Engine compiled and ready"
- [ ] Daemon logs show: "ARGUS Heuristics Engine initialized"
- [ ] Daemon logs show: "IOC hash database loaded" with count > 0
- [ ] Daemon logs show: "YARA rules compiled successfully" with rules ≥ 119
- [ ] Daemon logs show: "IPC server listening"
- [ ] Daemon logs show: "real-time watcher started"
- [ ] No stack overflow or crash during startup

## 2. GUI Startup
- [ ] First-run wizard appears on fresh install (clear localStorage)
- [ ] Wizard connects to daemon
- [ ] Wizard shows signature update option
- [ ] Wizard offers quick scan
- [ ] Wizard completes and opens Dashboard
- [ ] Dashboard shows "Connected" badge
- [ ] Dashboard shows ARGUS Intelligence summary with rule count
- [ ] Dashboard shows correct signature count

## 3. Scan Operations
- [ ] **File scan**: Select a file → scan completes → shows result
- [ ] **Quick scan**: Start → progress bar advances → completes with report
- [ ] **Folder scan**: Select folder → scans all files → completes
- [ ] **Cancel scan**: Start quick scan → cancel → scan stops cleanly
- [ ] **Drag-and-drop**: Drop file on window → navigates to scan page
- [ ] **Context menu**: Right-click file → "Scan with Sentinella" works (if installed)

## 4. EICAR Test
- [ ] Download EICAR test file (or create: `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
- [ ] Single file scan detects it as infected
- [ ] ClamAV signature name shown
- [ ] Quarantine button appears

## 5. Quarantine
- [ ] Quarantine infected file → file removed from original location
- [ ] Quarantine page shows item with SHA-256, path, signature
- [ ] Quarantine item count header visible
- [ ] Restore button: click → confirmation dialog appears
- [ ] Restore button disabled when vault file missing (`restorable: false`)
- [ ] Confirm restore → file appears at original path
- [ ] Restore toast shows "Restored to [path]"
- [ ] Restore error → error toast with message
- [ ] Delete button: click → confirmation dialog appears
- [ ] Confirm delete → item removed from list
- [ ] Delete toast shows "Threat permanently deleted"
- [ ] List refreshes automatically after restore/delete
- [ ] IPC contract: `id` field (not `quarantine_id`) in quarantine.list response
- [ ] IPC contract: `signature` field (not `virus_name`) in quarantine.list response
- [ ] IPC contract: `restorable` boolean present in quarantine.list response

## 6. ARGUS Analysis
- [ ] Scan a PE file → ARGUS findings appear
- [ ] Score badge shows (0-100)
- [ ] Verdict classification shown (Clean/Low Suspicion/Suspicious/etc.)
- [ ] "Why this verdict?" section shows suspicion + trust reasons
- [ ] Known installer (e.g., Git setup) → score near 0 (reputation + Authenticode discount)
- [ ] Unsigned suspicious file → score reflects findings

## 7. Tray Behavior
- [ ] System tray icon shows Sentinella sentinel shield
- [ ] Tray tooltip shows "Protected (X sigs)" when connected
- [ ] Tray menu: Open / Protection: Active / Run Quick Scan / About
- [ ] No "Quit" option in tray menu
- [ ] Clicking "Open" shows window
- [ ] Double-click tray icon shows window

## 8. Window Close Behavior
- [ ] Click X → window hides to tray (does NOT exit)
- [ ] Alt+F4 → window hides to tray
- [ ] App continues running in tray after close

## 9. Settings
- [ ] Settings page loads all tabs
- [ ] Theme toggle persists across restart
- [ ] Accent color persists across restart
- [ ] Exclusion editor: add/remove folders works
- [ ] Scheduled scan time/type saved
- [ ] Protection shutdown: requires typed "DISABLE PROTECTION"

## 10. Update
- [ ] Update page shows signature info
- [ ] "Check for Updates" starts update
- [ ] Progress bar shows during update
- [ ] Current file name shown during download
- [ ] Update completes → engine reloads
- [ ] ARGUS Intelligence Packs section shows all packs with rule counts
- [ ] "Reload Rules" button recompiles YARA rules

## 11. History
- [ ] History page shows past scans
- [ ] Click scan → drill-down shows detections + ARGUS verdicts
- [ ] Export button downloads JSON report

## 12. Error Handling
- [ ] Start GUI without daemon → shows "Daemon Not Connected"
- [ ] Kill daemon while GUI open → shows "Disconnected" after 3 failed polls
- [ ] Restart daemon → GUI reconnects automatically
- [ ] No blank screen in any scenario

## 13. Known-Good Regression
- [ ] `notepad.exe` → Clean (score 0)
- [ ] `cmd.exe` → Clean (score 0)
- [ ] Signed installer (Git/Python/Notepad++) → Clean or Low Suspicion
- [ ] ARGUS's own `.rlib` files → NOT scanned (self-exclusion)

## 14. IPC/GUI Contract Verification
- [ ] All GUI buttons produce visible feedback (toast or state change)
- [ ] Quarantine restore → success/error toast
- [ ] Quarantine delete → success/error toast
- [ ] Settings save → success/error feedback
- [ ] Signature update → progress bar + completion status
- [ ] Scan cancel → scan stops + status updates
- [ ] ARGUS pack reload → success message
- [ ] No internal fields leaked (vault_path, internal IDs)
- [ ] `quarantine.list` returns `id`/`signature`/`restorable` (not raw DB fields)

## 15. Self-Exclusion
- [ ] Watcher does NOT scan files under `target/release/`
- [ ] Watcher does NOT scan files under `gui/src-tauri/target/`
- [ ] Watcher does NOT scan files under `runtime/`
- [ ] Watcher does NOT scan files under `crates/`
- [ ] Build artifacts not auto-quarantined

## 16. Windows Toast Notifications
- [ ] EICAR detection → threat toast appears ("Threat detected")
- [ ] File quarantined → toast appears ("File quarantined")
- [ ] Quick scan with threats → toast on completion
- [ ] Clean scan → NO toast (silent)
- [ ] Signature update failure → toast appears
- [ ] Kill daemon with GUI open → degraded toast after 3 polls
- [ ] Settings → Notifications tab: all toggles work
- [ ] Disable "Enable notifications" → no toasts fire
- [ ] Enable quiet mode → no toasts fire
- [ ] Re-enable → toasts resume
- [ ] Permission denied by Windows → app does not crash
- [ ] First-run update → "Sentinella is ready" toast with sig count
- [ ] Repeated EICAR detection → only 1 toast (dedupe 5-min cooldown)
- [ ] Rapid watcher quarantine (5+ files) → aggregate "X files quarantined"
- [ ] Severity threshold "threat" → suppresses update/scan-complete toasts
- [ ] Severity threshold "critical" → only quarantine failure / protection loss
- [ ] Repeated update failure → only 1 toast per 5-min window

## 17. Idle Background Scanner
- [ ] Idle scanner starts 30s after daemon boot
- [ ] `idle_scanner.status` IPC returns valid state
- [ ] Scanner pauses when CPU > 50% (check state = `paused_cpu`)
- [ ] Scanner pauses when foreground scan running
- [ ] Scanner pauses when on battery (if `idle_scan_on_battery = false`)
- [ ] Scanner continues during light web browsing
- [ ] Scanner skips files in `target/`, `node_modules/`, `.git/`
- [ ] Scanner skips Sentinella's own runtime directories
- [ ] Scanner does not quarantine `.rlib`, `.rmeta`, `.pdb` files
- [ ] No notification spam during idle scan
- [ ] `idle_scan_enabled = false` in config → scanner does not start
- [ ] Scan cache prevents rescanning clean files

## 18. Watcher Noise
- [ ] `cargo build` in project on Desktop → no `.rlib` quarantine
- [ ] `npm install` in project → no `node_modules/` scan
- [ ] `.git/` directory changes → not scanned
- [ ] `.json`, `.md`, `.txt` changes → not scanned by watcher
- [ ] Only executable/script/archive file changes trigger watcher scan

## 19. Service Scripts
- [ ] `install-service-windows.bat` syntax valid (run as admin)
- [ ] `start-service-windows.bat` syntax valid
- [ ] `stop-service-windows.bat` syntax valid
- [ ] `uninstall-service-windows.bat` syntax valid

## 20. Diagnostics Export
- [ ] `diagnostics.export` IPC returns valid JSON
- [ ] Export contains version, protection state, engine status
- [ ] Export contains YARA rule count, signature count
- [ ] Export contains idle scanner state + cache stats
- [ ] Export contains recent errors (max 10)
- [ ] Export contains quarantine metadata only (no file contents)
- [ ] No secrets, credentials, or personal file paths in export

## 21. Field-Test Readiness
- [ ] EICAR test file detected + quarantined
- [ ] Known-clean installers score 0-15 (not flagged)
- [ ] `cargo build` on Desktop produces no quarantine
- [ ] `npm install` produces no watcher events on node_modules
- [ ] Defender coexistence: no conflicts with exclusion set
- [ ] Uninstall: stopping daemon + deleting runtime/ is clean

## 22. Orchestrator Pilots (when enabled)
- [ ] File scan with `orchestrator_file_scan_enabled=true` → queued → completed
- [ ] Folder scan with `orchestrator_folder_scan_enabled=true` → queued → scanning → completed
- [ ] Quick scan with `orchestrator_quick_scan_enabled=true` → queued → scanning → completed
- [ ] Cancel queued scan → immediately cancelled
- [ ] Cancel running orchestrated scan → cancelling → cancelled
- [ ] Diagnostics export shows orchestrator state
- [ ] Daemon remains reachable during orchestrated folder scan
- [ ] Legacy path works when all flags are false
- [ ] Worker panic recovery (crash count increments, next job succeeds)

## 23. Memory Pressure (Wave 2+)
- [ ] Startup footprint logged: working_set_mb, pressure state
- [ ] `diagnostics.export` contains `footprint` section
- [ ] `diagnostics.export` contains `memory_pressure` section
- [ ] `health` endpoint shows `memory_pressure` field
- [ ] Pressure state = `normal` at idle (<800MB)
- [ ] Post-scan: `delta_since_last_scan_mb` < 50 (memory returned)
- [ ] No monotonic growth after 3+ scan cycles
- [ ] Warning level matches working_set_mb thresholds
- [ ] `warning_level` = "normal" for typical usage

## 24. FISH Observe-Only (Wave 2+)
- [ ] `diagnostics.export` contains `fish` section
- [ ] `fish.enabled` = false (not yet active by default)
- [ ] `fish.observe_only` = true
- [ ] Watcher feeds events to FISH MutationWindow
- [ ] Rename burst (25+ renames in 30s) → logged as warning
- [ ] Cooldown suppresses repeated bursts within 60s
- [ ] `top_mutated_extensions` populated during activity
- [ ] `top_mutated_directories` populated during activity
- [ ] No user-facing FISH notifications (observe-only)
- [ ] No process kill, no rollback, no blocking

## 25. Protection Disable/Enable (Wave 2+)
- [ ] `quarantine.challenge` → returns token
- [ ] `protection.disable` with valid token → state = `user_disabled`
- [ ] Watcher stops after disable
- [ ] TopBar shows "Protection paused by user" (red variant)
- [ ] `protection.enable` → watcher restarts, state = `fully_protected`
- [ ] Intentional disable does NOT trigger auto-restart
- [ ] Activity log shows disable/enable events

## 26. Resilience Telemetry (Wave 2+)
- [ ] `diagnostics.export` contains `resilience` section
- [ ] `worker_panics` = 0 under normal operation
- [ ] `worker_timeouts` = 0 under normal operation
- [ ] `watcher_heartbeat_stale` = false while watcher active
- [ ] `orchestrator_heartbeat_stale` = false after scans

---

*Last updated: May 2026*

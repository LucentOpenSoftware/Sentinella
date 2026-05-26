# Sentinella — Antivirus Behavior Baseline Reference

> Behavioral and architectural baseline inspired by mature desktop antivirus products.
>
> This document is **not** a reverse-engineering document and does not describe
> proprietary internals. It summarizes commonly documented end-user behaviors and
> translates them into realistic implementation guidance for Sentinella, built
> around the unmodified ClamAV engine.

---

## 1. Philosophy of Modern Desktop Antivirus

A mature desktop antivirus product is not a scanning tool with a GUI bolted on. It is a **system service** that integrates deeply with the operating system's file lifecycle and presents a minimal, trustworthy surface to the user.

The defining characteristics:

### 1.1 Low system impact

The antivirus must not be the reason the user's computer feels slow. This means:

- scanning happens at **lower-than-normal thread priority**;
- I/O is throttled when other applications are active;
- large files are scanned in chunks or deferred;
- files already known-clean are skipped via cache;
- archive recursion has hard depth and size limits;
- on battery, non-critical scans are paused or deferred.

### 1.2 Background operation

The user should forget the antivirus is running during normal use. It surfaces itself only when:

- a threat is found;
- protection is degraded (engine down, signatures stale, watcher disabled);
- the user explicitly opens the dashboard.

Everything else — signature updates, idle scans, cache maintenance, watcher restarts — happens silently.

### 1.3 Calm UX

Mature products avoid fear-based language. The interface communicates:

- **green/blue**: system is protected, everything normal;
- **amber**: something needs attention but is not critical (stale DB, watcher paused);
- **red**: confirmed threat or protection failure.

No flashing, no countdown timers, no "YOUR COMPUTER IS AT RISK" banners for routine states.

### 1.4 Trust through consistency

The product earns trust by behaving predictably:

- the same file always produces the same scan result (given the same signatures);
- a clean scan says "clean", not "probably clean";
- if the engine cannot scan a file (access denied, corrupted archive), it says so clearly instead of pretending it scanned;
- protection status is computed from real facts, not cosmetic state.

### 1.5 Layered protection

No single mechanism catches everything. Mature products layer:

1. Real-time filesystem monitoring (first line);
2. On-demand scanning (user-initiated deep check);
3. Scheduled scanning (periodic coverage);
4. Startup inspection (boot-time hygiene);
5. Archive/script/document scanning (nested threat extraction);
6. Behavioral monitoring (runtime anomaly detection — advanced);
7. Cloud reputation (hash lookup — advanced).

Each layer has different performance characteristics, trigger conditions, and UX expectations. Sentinella should implement them incrementally, starting with layers 1–3.

### 1.6 Scan prioritization

Not all files need equal attention:

- **executables** (.exe, .dll, .sys, .scr) are highest priority;
- **scripts** (.ps1, .bat, .vbs, .js) are high priority;
- **documents with macros** (.docm, .xlsm) are high priority;
- **archives** (.zip, .rar, .7z) are medium priority (scan contents);
- **plain data** (.txt, .csv, .json) are low priority;
- **media files** (.mp4, .jpg, .png) are lowest priority.

A smart scan targets the first three categories. A full scan covers everything.

### 1.7 Incremental scanning and cache

The most important performance optimization: **do not rescan files that have not changed since the last clean result**.

A scan cache maps:

```
(file_path, file_size, mtime, content_hash, signature_db_version) → last_result
```

If all inputs match, the cached result is valid. After a signature update, the `signature_db_version` changes, invalidating all cache entries. This means:

- day-to-day real-time monitoring is fast (most files are cached);
- after a signature update, the next scan pass is slower (cache is cold);
- the cache is an optimization, not a security guarantee — if in doubt, rescan.

---

## 2. Protection Layers

### 2.1 Real-time filesystem monitoring

**What it does:** Watches filesystem events (create, write, rename, close) and triggers a scan when a file appears or changes in a monitored location.

**When it activates:** Always on, from daemon startup until shutdown.

**Expected UX behavior:**
- Silent for clean files. The user sees nothing.
- On threat detection: toast notification with file path and detection name.
- Dashboard shows "Real-time monitoring: active" with folder count.
- If the watcher crashes or is disabled, dashboard degrades to amber.

**Expected daemon behavior:**
- Debounce rapid events on the same path (e.g., a file written in 50 small chunks);
- Wait for write stabilization before scanning (don't scan a partially-written file);
- Skip files already in cache;
- Queue scans, don't block the event loop;
- Log detections and errors, but not every clean result.

**Sentinella v1:** User-mode watcher (`ReadDirectoryChangesW` on Windows). Post-write scanning only. Cannot block file access before it happens.

**Sentinella v2+:** Kernel minifilter. Pre-access scanning. Can deny `IRP_MJ_CREATE` if the file is malicious.

### 2.2 On-demand scanning

**What it does:** User-initiated scan of a file, folder, or predefined target set.

**When it activates:** User clicks "Scan" in GUI, runs CLI command, or uses context menu.

**Expected UX behavior:**
- Immediate feedback: scanning indicator, current file path, progress counter.
- Cancellable at any time.
- Result summary: files scanned, threats found, errors.
- Detections listed with path and signature name.

**Expected daemon behavior:**
- Scan runs in a worker thread, not the IPC thread.
- Progress updates are polled by the GUI at ~2 Hz.
- Cooperative cancellation between files (not mid-file).
- Errors on individual files do not abort the scan.

### 2.3 Scheduled scans

**What it does:** Recurring scans triggered by a time-based schedule.

**When it activates:** Configured by user (e.g., "every Sunday at 03:00 AM").

**Expected UX behavior:**
- Runs silently. No popup unless threats are found.
- If the user is active, the scan runs at low priority.
- Result available in scan history.
- Missed schedules (computer was off) may optionally run on next boot.

**Expected daemon behavior:**
- Scheduler checks time triggers periodically.
- Spawns a scan job identical to an on-demand scan.
- Low thread priority.

### 2.4 Memory scanning

**What it does:** Scans running processes' memory for known malicious patterns.

**When it activates:** Advanced feature. May run at startup, on schedule, or on demand.

**Sentinella status:** Not implemented. ClamAV does not expose a process-memory scanning API. This would require custom implementation. Deferred to future.

### 2.5 Boot/startup inspection

**What it does:** Inspects files in autostart locations after boot.

**Targets:**
- `HKLM\...\Run` and `HKCU\...\Run` registry keys;
- Startup folders;
- Scheduled tasks;
- Services;
- Recently modified executables in system directories.

**Sentinella status:** Future feature. Should be a narrow, fast scan — not a full-disk scan at boot.

### 2.6 Archive scanning

**What it does:** Extracts and scans contents of compressed archives (ZIP, 7z, RAR, TAR, etc.).

**Behavior:**
- ClamAV handles this natively within `cl_scanfile`.
- Recursion depth is limited (default: 17 levels in ClamAV).
- Maximum extracted size is limited.
- If extraction fails, the file is flagged as an error, not a threat.

**Sentinella status:** Works via ClamAV. No additional implementation needed.

### 2.7 Script scanning

**What it does:** Analyzes script files (JavaScript, VBScript, PowerShell, batch) for malicious patterns.

**Sentinella status:** ClamAV includes script signature matching. Works automatically when scan options include `CL_SCAN_PARSE_HTML` and related flags.

### 2.8 Email filtering

**What it does:** Scans email attachments and message bodies for threats.

**Sentinella v1:** Not implemented. ClamAV can scan MBOX/EML files on demand, but real-time email filtering requires MTA integration (clamav-milter) or proxy-based interception. Deferred.

### 2.9 Web filtering

**What it does:** Intercepts HTTP/HTTPS traffic and blocks access to malicious URLs or downloads.

**Sentinella v1:** Not implemented. Would require a network proxy or browser extension. Deferred.

### 2.10 Behavior monitoring

**What it does:** Observes runtime process behavior (API calls, registry modifications, network connections) and flags anomalies.

**Sentinella status:** Not implemented. Would require deep OS integration (ETW on Windows, eBPF on Linux). This is EDR-level functionality. Explicitly deferred.

### 2.11 Cloud reputation

**What it does:** Sends file hashes to a cloud service to check against a reputation database.

**Sentinella status:** Not implemented. Sentinella's design principle is no cloud dependencies by default. Could be added as an opt-in feature later.

---

## 3. Real-Time Protection Behavior

### 3.1 Event model

Mature real-time protection follows this pipeline:

```
Filesystem event (create/write/rename/close)
  → debounce (coalesce rapid events on same path)
  → wait for write stabilization (~500ms after last write)
  → check scan cache
  → if cached clean: skip
  → classify file type
  → enqueue scan at appropriate priority
  → scan via engine
  → if clean: update cache, no notification
  → if threat: alert user, optionally quarantine
  → if error: log, continue monitoring
```

### 3.2 Pre-access vs post-write scanning

| Approach | What it means | Sentinella status |
|---|---|---|
| **Post-write** | File is scanned after it has been fully written. The malware already exists on disk. Detection is reactive. | v1 (user-mode watcher) |
| **Pre-access** | File is scanned before the OS allows any process to open/execute it. The scan can block access. Prevention is proactive. | v2+ (kernel minifilter) |

Post-write is a meaningful protection layer: it catches threats shortly after they land on disk. But it cannot prevent a fast-acting executable from running before the scan completes. The user should understand this distinction.

### 3.3 Trusted unchanged files

The single most impactful optimization for real-time monitoring: **do not rescan files that have not changed**.

Implementation:

```rust
struct ScanCacheEntry {
    path: PathBuf,
    size: u64,
    mtime: SystemTime,
    sha256: [u8; 32],    // computed on first scan
    db_generation: u64,   // signature DB version at time of scan
    result: ScanVerdict,  // Clean or detection name
}
```

On a filesystem event:
1. Look up the path in cache.
2. If `size + mtime` match, and `db_generation` is current, return cached result.
3. Otherwise, scan the file and update the cache entry.

After a signature update, increment `db_generation`. All cache entries become stale.

**Sentinella status:** Not yet implemented. This is a high-priority optimization for real-time protection performance.

### 3.4 Silent clean handling

The vast majority of filesystem events produce clean results. Mature products handle these silently:

- no log entry (or trace-level only);
- no notification;
- no GUI update;
- only the cache is updated.

The user should never see a stream of "file X is clean" messages. The product's job is to be invisible when everything is fine.

### 3.5 Notification thresholds

Notify the user for:

- confirmed threat detection;
- quarantine action (success or failure);
- protection degraded (engine error, watcher stopped, signatures stale > 7 days);
- scan completed (only for user-initiated scans).

Do not notify for:

- clean scan results;
- signature update success (show in dashboard, not as popup);
- watcher restart after transient error;
- individual file scan errors during a bulk scan.

### 3.6 Heavy I/O deferral

During heavy disk activity (large file copy, game loading, IDE indexing), real-time scanning should reduce its impact:

- lower scan thread priority;
- increase debounce delay;
- defer non-critical scans;
- never compete with the user's foreground application for disk I/O.

**Sentinella status:** Not yet implemented. Thread priority control is straightforward; I/O-aware throttling requires monitoring system load.

---

## 4. Scan Types

### 4.1 Quick Scan

**Target scope:** High-risk user locations: Downloads, Desktop, Temp, Documents.

**Aggressiveness:** Moderate. Scans all files in target directories, recursing to bounded depth. Scans inside archives.

**Expected duration:** 1–5 minutes on a typical system.

**Priority level:** Normal. User explicitly requested this scan.

**UI expectations:** Progress card showing files scanned, current path, threats found, elapsed time, cancel button.

**Sentinella status:** Implemented. Targets Downloads, Desktop, Temp. Max recursion depth 5. Max file size 512 MB.

### 4.2 Smart Scan

**Target scope:** Files that are most likely to matter, determined by heuristics:

- recently changed files (mtime within last N days);
- executable and script file types;
- files not scanned since the last signature update;
- startup-sensitive locations.

**Aggressiveness:** Targeted. May skip large media files entirely.

**Expected duration:** 2–10 minutes.

**Priority level:** Normal to low.

**Sentinella status:** Not yet implemented. Requires scan cache and file-type classification.

### 4.3 Full Scan

**Target scope:** All files on all local drives.

**Aggressiveness:** Thorough. Everything is scanned.

**Expected duration:** 30 minutes to several hours depending on disk size.

**Priority level:** Low (background). Should not noticeably slow the system.

**UI expectations:** Long-running progress with percentage, ETA, pause/cancel. May recommend running when idle.

**Sentinella status:** Not yet implemented. Requires the scan job model to support very large file sets and low-priority scheduling.

### 4.4 Custom Scan

**Target scope:** User-selected file or folder.

**Aggressiveness:** Same as Quick Scan within the selected scope.

**Expected duration:** Varies by selection size.

**UI expectations:** Folder picker, same progress UI as Quick Scan.

**Sentinella status:** Single-file scan implemented. Folder scan not yet implemented.

### 4.5 Context Menu Scan

**Target scope:** File or folder selected in Windows Explorer.

**Trigger:** Right-click → "Scan with Sentinella".

**Expected behavior:** Launches a scan job in the daemon, shows a minimal result notification or small window.

**Sentinella status:** Not implemented. Requires Windows shell extension registration. Deferred to installer milestone.

### 4.6 Startup Scan

**Target scope:** Autostart locations only. Fast and narrow.

**Trigger:** Daemon startup, or after a signature update.

**Expected duration:** Under 30 seconds.

**Priority level:** Elevated (runs before user is fully active).

**Sentinella status:** Not yet implemented.

### 4.7 Idle-Time Scan

**Target scope:** Deep scan of areas not recently covered.

**Trigger:** System idle (screensaver, locked, no user input for N minutes).

**Expected behavior:**
- Starts automatically when idle;
- Pauses immediately when user returns;
- Runs at lowest priority;
- Does not run on battery;
- Covers areas that Quick Scan does not reach.

**Sentinella status:** Not yet implemented. Requires idle detection (Windows `GetLastInputInfo` API or similar).

---

## 5. Performance Optimization Patterns

### 5.1 File hashing cache

After scanning a file, store its SHA-256 hash alongside the scan result and signature DB version. On subsequent encounters (filesystem event or scheduled scan), compare the hash + DB version to skip rescanning. This is the highest-impact optimization for real-time monitoring.

### 5.2 Timestamp cache

Before computing a hash (which requires reading the entire file), check `(path, size, mtime)` against the cache. If these match, the file is very likely unchanged — skip the hash computation and use the cached result directly. This avoids reading files that have not been modified.

### 5.3 Exclusion system

Allow users to exclude:

- specific file paths;
- directory trees;
- file extensions;
- processes (future: files accessed by trusted processes).

Exclusions should be checked before any scanning work, including hash computation.

### 5.4 Trusted process lists

Future optimization: files written by known-safe processes (e.g., Windows Update, signed Microsoft binaries) can be scanned at lower priority or deferred. Requires process identification via PID → executable path → signature verification.

### 5.5 Archive recursion limits

ClamAV's default limits (17 levels of recursion, configurable max extracted size) are appropriate. Exceeding these limits should produce a warning, not a crash or hang.

### 5.6 Large file handling

Files larger than a configurable threshold (default: 512 MB) should be:

- skipped by Quick Scan;
- scanned by Full Scan at low priority;
- scanned on demand if the user explicitly selects them;
- never block the scan queue waiting for a single large file.

### 5.7 Low-priority background threads

All background scanning (real-time, scheduled, idle) should use:

- `SetThreadPriority(THREAD_PRIORITY_BELOW_NORMAL)` on Windows;
- `nice` values on Linux;
- I/O priority hints where available.

### 5.8 Throttling during gaming/fullscreen

Detect when a fullscreen application is running and reduce scanning activity. On Windows, this can be checked via `SHQueryUserNotificationState`.

### 5.9 Battery-aware scanning

On laptops, disable or defer non-critical scans when on battery. Only real-time monitoring and user-initiated scans should run. Scheduled and idle scans should wait for AC power.

---

## 6. Quarantine Behavior

### 6.1 Purpose

Quarantine is a reversible safety mechanism. It neutralizes a detected threat by:

1. Moving the file out of its original location;
2. Encrypting or otherwise rendering it non-executable;
3. Recording metadata for potential restoration;
4. Presenting the quarantined item in the GUI for user review.

### 6.2 Metadata storage

Each quarantined item should record:

```json
{
  "id": "uuid",
  "original_path": "C:\\Users\\...\\malware.exe",
  "vault_path": "runtime/quarantine/<uuid>.bin",
  "sha256": "a1b2c3...",
  "detection_name": "Win.Trojan.Agent-1234",
  "engine_version": "ClamAV 1.6.0",
  "signature_db_version": 27458,
  "quarantined_at": "2026-05-12T10:30:00Z",
  "original_size": 131072,
  "original_permissions": "...",
  "status": "quarantined"
}
```

### 6.3 Vault encryption

The quarantined file should be encrypted at rest (AES-256-GCM) to prevent:

- other malware from extracting it;
- accidental execution;
- antivirus scanners from re-detecting it inside the vault.

The encryption key is stored in a daemon-controlled location with restricted permissions.

### 6.4 Restore behavior

Restore should:

- decrypt the file;
- write it back to the original path (or a user-chosen alternate path);
- warn that the file will likely be detected again unless excluded;
- log the restore action.

Future enhancement: "restore and exclude" — restore the file and add an exclusion rule in one action.

### 6.5 Automatic vs manual quarantine

- **Automatic quarantine:** On real-time detection, immediately quarantine without asking. This is the safest default for confirmed threats. The user can review and restore from the quarantine page.
- **Manual quarantine:** On on-demand scan detection, report the finding and let the user choose. This is appropriate when the user is actively reviewing scan results.

**Sentinella v1:** Report only, no automatic quarantine. The quarantine vault is not yet implemented.

### 6.6 Retention

Quarantined items should be automatically purged after a configurable retention period (default: 90 days). The user should be warned before items are purged.

### 6.7 False positive recovery

If a user believes a detection is a false positive:

1. Restore the file from quarantine.
2. Add an exclusion for the file path or hash.
3. Optionally submit the file to ClamAV's false positive reporting process.

---

## 7. Update Behavior

### 7.1 Silent background updates

Signature updates should happen automatically, silently, and frequently. The default interval for ClamAV's `freshclam` is every 4 hours. This is appropriate.

The user should not see:

- progress bars for routine updates;
- "updating..." spinners in the dashboard during background updates;
- popups announcing successful updates.

The user should see:

- "Last updated: 2 hours ago" in the dashboard;
- a warning if signatures are stale (> 24 hours since last successful update);
- an error if updates have been failing for > 48 hours.

### 7.2 Incremental updates

ClamAV supports both full CVD downloads and incremental CDIFF patches. When possible, incremental updates are preferred to reduce bandwidth.

### 7.3 Retry and fallback

If an update fails:

- retry after a short delay (1 minute);
- retry with exponential backoff (up to 1 hour);
- try alternate mirrors if configured;
- log the failure;
- surface a warning in the dashboard only after sustained failures.

### 7.4 Post-update actions

After a successful signature update:

- reload the engine (or at minimum, note the new DB version);
- invalidate the scan cache generation;
- optionally run a narrow startup scan against autostart locations;
- update the dashboard's "Last updated" display.

### 7.5 Stale database warnings

| Staleness | Dashboard state |
|---|---|
| < 24 hours | Normal (green) |
| 24–72 hours | Amber warning: "Signatures may be outdated" |
| > 72 hours | Red warning: "Signatures are stale — update now" |
| Never updated | Red: "No signature database installed" |

---

## 8. Notification Philosophy

### 8.1 Core principle

Sentinella should be calmer than commercial antivirus products. It should not compete for the user's attention. Notifications are reserved for situations that require awareness or action.

### 8.2 Notify for

- Confirmed threat detection (real-time or on-demand);
- Quarantine action (file moved to vault);
- Protection degraded (engine error, daemon crash, signatures stale);
- Scan completed (user-initiated only);
- Update failure persisting > 24 hours.

### 8.3 Do not notify for

- Clean scan results;
- Individual file scans during a batch scan;
- Successful signature updates;
- Watcher restarts after transient errors;
- Cache maintenance;
- Normal daemon lifecycle events.

### 8.4 Notification tone

| Bad (fear-based) | Good (calm, informative) |
|---|---|
| "WARNING! THREAT DETECTED! YOUR PC IS AT RISK!" | "Threat detected: Win.Trojan.Agent — quarantined" |
| "URGENT: UPDATE YOUR VIRUS DEFINITIONS NOW!" | "Signatures haven't been updated in 3 days" |
| "YOUR COMPUTER IS UNPROTECTED!" | "Real-time monitoring is paused" |

---

## 9. GUI Behavior Patterns

### 9.1 Dashboard refresh

- Poll daemon status every 5 seconds via IPC;
- Show loading state on first connect;
- Show disconnected state if daemon is unreachable;
- Show stale-data banner if daemon disconnects mid-session;
- Never show cosmetic/hardcoded values.

### 9.2 Protection state computation

The dashboard's "Protected" / "Attention needed" / "At risk" status should be computed from daemon-side facts:

```
Protected = daemon_running
         AND engine_state == Ready
         AND signature_count > 0
         AND signatures_not_stale
         AND (realtime_enabled OR user_acknowledged_disabled)
```

If any condition fails, show exactly which component is degraded.

### 9.3 Scan progress UX

- Show current file path (truncated);
- Show files scanned counter;
- Show threats found counter;
- Show elapsed time;
- Show cancel button;
- Poll at 500ms intervals during active scan;
- On completion, show summary card with detections list.

### 9.4 Cancellation UX

- Cancel is cooperative (checked between files);
- The current file scan completes before cancellation takes effect;
- Partial results are preserved and shown;
- State transitions to "cancelled" with final counts.

### 9.5 System tray (future)

- Tray icon indicates protection state (green/amber/red);
- Right-click menu: Quick Scan, Update, Open Dashboard;
- Notifications originate from the tray;
- Clicking the tray opens the main window.

---

## 10. Mapping to Sentinella Architecture

### 10.1 GUI (Tauri + React)

- Displays daemon state;
- Requests scans, updates, settings changes;
- Shows results;
- Never owns antivirus truth;
- Polls daemon via IPC.

### 10.2 Tauri bridge

- IPC client wrapper (named pipe on Windows, UDS on Linux);
- File/folder picker via native dialog;
- No antivirus logic.

### 10.3 Daemon (sentinelld)

- Engine lifecycle (init, load, compile, free);
- Scan job queue and worker threads;
- Watcher state management;
- Updater orchestration (freshclam sidecar);
- Quarantine vault management;
- Scan scheduler;
- Activity log;
- Runtime state snapshots for IPC queries.

### 10.4 ClamAV engine (libclamav)

- Signature loading from CVD/CLD files;
- File scanning against loaded signatures;
- Archive extraction and recursive scanning;
- Detection result reporting.

Sentinella uses libclamav as a **black box** via FFI. The engine is not modified.

### 10.5 Watcher

- v1: User-mode (`ReadDirectoryChangesW` on Windows, `fanotify` on Linux);
- v2+: Kernel minifilter on Windows, Endpoint Security on macOS;
- Feeds events into the scan queue.

### 10.6 Quarantine service

- Encrypts and stores detected files;
- Tracks metadata in SQLite;
- Supports restore and permanent delete;
- Enforces retention policies.

### 10.7 Update service

- v1: Wraps `freshclam` as a child process;
- v2: Native Rust HTTP client with CVD verification;
- Triggers engine reload after successful update.

### 10.8 Scan scheduler

- Time-based trigger system;
- Supports cron-like schedules;
- Battery-aware and idle-aware (future);
- Spawns scan jobs identical to on-demand scans.

---

## 11. Sentinella v1 vs Future Roadmap

### Achievable in v1

| Feature | Status |
|---|---|
| Single-file scan via GUI and CLI | Implemented |
| Quick Scan (Downloads, Desktop, Temp) | Implemented |
| Scan progress polling | Implemented |
| Scan cancellation | Implemented |
| Scan history | Implemented |
| Engine status dashboard | Implemented |
| Daemon IPC (JSON-RPC over named pipe) | Implemented |
| Signature updates via freshclam | Implemented |
| Activity log | Implemented |
| Daemon-driven dashboard (no mocks) | Implemented |
| File picker scan from GUI | Implemented |
| Disconnected daemon detection | Implemented |

### Should implement next

| Feature | Complexity |
|---|---|
| Folder scan (custom scan) | Low |
| User-mode real-time watcher | Medium |
| Quarantine vault | Medium |
| Scan cache | Medium |
| Scheduled scans | Low |
| Stale signature warnings | Low |
| System tray | Low |
| Full Scan | Medium (performance tuning) |

### Future advanced features

| Feature | Notes |
|---|---|
| Kernel minifilter (Windows) | Requires WDK, EV cert, WHQL |
| Endpoint Security (macOS) | Requires Apple entitlement |
| Context menu shell integration | Requires COM registration |
| Startup scan | Narrow scope, requires autostart enumeration |
| Idle-time scan | Requires idle detection API |
| Smart Scan | Requires scan cache + file classification |
| Behavioral monitoring | ETW/eBPF, research-level |
| Cloud reputation | Opt-in, privacy-sensitive |
| Web/email filtering | Proxy or extension, complex |
| Enterprise management | Console, policies, deployment — different product |

---

## 12. Explicit Non-Goals

Sentinella should not become:

- **Scareware.** No fake threat counts, no exaggerated risk warnings, no urgency timers.
- **An EDR clone.** Behavioral analysis, process trees, and incident response workflows are out of scope for v1.
- **A SIEM dashboard.** No correlation engines, no log aggregation from external sources.
- **A cloud-first telemetry agent.** No data leaves the machine unless the user explicitly opts in.
- **A browser extension bundle.** No toolbar, no search redirect, no "safe browsing" addon.
- **A firewall suite.** Network filtering is a separate product domain.
- **Fake AI antivirus.** No "AI-powered" labels unless actual machine learning is implemented and its behavior is documented.
- **A product that claims pre-access blocking before it exists.** User-mode monitoring is truthfully labeled as such.
- **Bloatware.** The installer should not include unrelated utilities, system cleaners, VPN offers, or password managers.

---

## 13. Final Direction

Sentinella should become a **calm, modern, open-source desktop protection layer** built around a transparent scanning engine and thoughtful system behavior.

Its strength comes not from pretending to be a giant commercial suite, but from doing the essential antivirus workflows **cleanly, honestly, and reliably**:

- scan files with a real, maintained signature database;
- monitor the filesystem for new threats;
- quarantine detected threats safely;
- keep signatures current automatically;
- show the user exactly what is happening, without noise or fear;
- respect system resources and user attention;
- remain open source, auditable, and trustworthy.

The product should feel like a well-built system utility — present when needed, invisible when not, always honest about its capabilities and limitations.

---

## 14. Engineering Rules for the Agent

When implementing new features:

1. **Prefer daemon state over frontend fixtures.** The daemon is the source of truth.
2. **Prefer truthful incomplete states over fake polished states.** "Not yet implemented" is better than a cosmetic placeholder.
3. **Keep ClamAV upstream unmodified** unless absolutely necessary for toolchain compatibility.
4. **Keep unsafe FFI small and wrapped.** One safe Rust wrapper; no raw pointers in business logic.
5. **Never delete or quarantine automatically** until the quarantine system is complete and tested.
6. **Preserve user trust** through accurate labels and honest status reporting.
7. **Use calm UI states**, not fear-based language.
8. **Build small milestones** that each produce a working, testable increment.

---

## 15. Reference Sources

These categories of publicly documented behavior informed the baseline:

- Real-time filesystem protection (open/create/execution/removable media triggers)
- Configurable scan parameters (file types, sizes, archives, heuristics levels)
- Idle-state scanning and detection triggers
- Startup / boot-time scanning
- Quarantine semantics (encrypt, isolate, restore, delete)
- Scan-while-downloading patterns
- General antivirus industry best practices documented across multiple products

All references describe publicly documented, observable end-user behavior.
No proprietary internals are described or speculated upon.

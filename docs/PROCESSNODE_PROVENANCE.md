# ProcessNode provenance audit — v0.1.12 (workstreams M+N+O)

Scope: `crates/sentinelld/src/plm/`. Audit date: 2026-07-30, against HEAD
`fec0328` (post F-1 ETW system-logger reconstruction `b60f296`).

## 1. Production construction/mutation sites

Contrary to the round briefing's "9 production construction sites", the
audit found exactly **two** production `ProcessNode` construction sites;
every other site is `#[cfg(test)]`. There are no in-place field
mutations anywhere — nodes are only wholesale-replaced via
`LineageGraph::record_process` (`HashMap::insert`).

| # | Site | Path | Trigger | command_line (before) | command_line (after this round) |
|---|------|------|---------|----------------------|--------------------------------|
| P1 | `plm/etw_intake.rs` `etw_event_callback` (~L830) | ETW process-create (kernel `Process` provider, opcode 1) | real-time, per process start | `None` | `SharedCommandLineQuerier::query(pid)` at event time |
| P2 | `plm/mod.rs` `snapshot_processes` (~L1000) | ToolHelp32 `Process32FirstW/NextW` poll | on first sighting or identity change (`needs_record`) | `None` | same querier, at discovery time |

Mutation semantics worth knowing:

- `record_process` replaces the whole node keyed by PID. In ETW mode the
  process-create event fires once per real start; in snapshot-only mode a
  recycled PID with different identity (parent/image) is re-recorded (the
  `needs_record` identity check, which is also the PID-reuse guard's
  data source).
- Because replacement is wholesale, a command line captured at P1/P2
  survives until eviction (TTL 1 h) or identity-change re-record — which
  then re-queries. No path ever *clears* a collected command line back
  to a non-`Present` state except a genuine identity change.

## 2. Field-population matrix

Fields that exist on `ProcessNode`. The briefing's matrix also named
`user/sid`, `arch`, `source`, `confidence`, `collection_error` — these
**do not exist** on the struct; the notes column says what that costs.

| Field | Source API (P1 ETW / P2 snapshot) | Availability | Privilege need | Race window | Spoofing risk | Fallback | Absence disables a rule? |
|---|---|---|---|---|---|---|---|
| `pid` | ETW: `EVENT_RECORD.EventHeader.ProcessId` (authoritative, kernel) / snapshot: `PROCESSENTRY32W.th32ProcessID` | always | none (snapshot), SYSTEM-logger slot (ETW) | PID reuse between event and downstream use (mitigated by `created_at` guard in `get_chain`) | none — kernel-supplied | none needed | n/a (never absent) |
| `parent_pid` | ETW: `ParentId` at `ptr_size+4` in `Process_TypeGroup1` payload (x86/x64 offset fixed in the F-1 round) / snapshot: `th32ParentProcessID` | always | as above | parent may exit before child start is processed (inherited-PID stale-parent artifact, OS-level, unavoidable) | low — kernel-supplied; a process can however be *created* by an arbitrary parent handle | none | lineage depth only, not a specific rule |
| `image_path` | ETW: wide-string scan of event payload (`extract_image_from_event`), else `get_process_image(pid)` ToolHelp fallback, else `pid:{pid}` / snapshot: `szExeFile` (**file name only, NOT a full path** — ToolHelp32 limitation) | usually | none | process exit before ToolHelp fallback → `pid:{pid}` sentinel | medium: path is where the image *was mapped from*, but the file can be replaced/renamed after start; treated as context, not identity | ToolHelp fallback, then sentinel | `query_by_image_path` correlation; `SecurityUpdatesAppData`/`Pjibf` path pivots degrade to image-name-only |
| `image_name` | derived: `image_path.rsplit('\\')` | always (except sentinel case) | — | — | high in isolation (any exe can be renamed `javaw.exe`) — never used alone for identity | — | WeedHack transition/artifact signals pivot on it; combined with cmdline/signer |
| `command_line` | **this round**: `NtQueryInformationProcess(ProcessCommandLineInformation)` at discovery time, both P1 and P2, via `cmdline::SharedCommandLineQuerier` | most processes; NORMAL failures: PPL/secure processes (AccessDenied), exited processes (ProcessExited) | `PROCESS_QUERY_INFORMATION` (fallback `..._LIMITED`); service runs as SYSTEM | start→query window is µs–ms; short-lived children can still exit first → `ProcessExited`, counted | **attacker-controlled verbatim** — creator supplies it, runtime can rewrite own PEB copy. NEVER identity; bounded (64 KiB cap), header-validated, NUL-truncated | none by design — no fabricated substitute | **Yes — 4 WeedHack signals** (`JavaSecurityUpdaterTask`, `UpdaterVbsLaunch`, `DefenderDisableUnderJava`, `RunKeyFromJava`) fire only on `Present` |
| `is_signed` | never populated in production (`None` at P1/P2) | — | — | — | — | WinTrust verification exists but lives in `wintrust_verifier` for the ImageLoad path, not lineage nodes | chain scoring does not consume it today |
| `integrity_level` | never populated (`None` at P1/P2) | — | — | — | — | — | no rule consumes it |
| `created_at` | `Instant::now()` at record | always | — | — | none (local clock) | — | PID-reuse lineage guard depends on it |
| `timestamp` | `chrono::Utc::now()` at record | always | — | wall-clock adjustments | none | — | `query_by_image_path` recency pick |

Non-existent fields the briefing asked about, for the record:

- `user/sid`: `Process_TypeGroup1` carries `UserSID` but the parser does
  not extract it; no rule consumes it today. Adding it is future work.
- `arch`: not collected. Would matter only for PEB reading, which was
  rejected (see §3).
- `source` (ETW vs snapshot): not recorded per-node; `PlmMonitor::mode`
  + ETW stage machine carry it at the subsystem level.
- `confidence`: not modeled; confidence lives in the campaign tracker's
  tier machine, not on nodes.
- `collection_error`: modeled **per-field** by
  `cmdline::CommandLineState` (this round) rather than as a node-level
  blob; per-state counters in `PlmDiagnostics.command_line`.

## 3. Command-line source decision (workstream N)

**Decision: `NtQueryInformationProcess(ProcessCommandLineInformation)` at
process-discovery time, behind `cmdline::CommandLineBackend` with a fake
backend for tests.**

Evaluated in briefing order:

1. **ETW process-start payload — rejected (verified, not assumed).**
   The SentinellaPLM session is a privately-named *system logger* with
   `EnableFlags = PROCESS | IMAGE_LOAD | FILE_IO_INIT`. Its process-start
   event is the kernel MOF `Process_TypeGroup1` layout, whose fields are
   `UniqueProcessKey, ProcessId, ParentId, SessionId, ExitStatus,
   DirectoryTableBase, Flags, UserSID, ImageFileName` — **there is no
   CommandLine field**. A `CommandLine` exists only on the manifest-based
   `Microsoft-Windows-Kernel-Process` provider (event ID 1) and on
   security event 4688 with the command-line audit GPO. Consuming either
   would require a second ETW session with `EnableTraceEx2` — explicitly
   out of scope per `etw_intake.rs` module docs. No offsets were
   invented; nothing is scraped speculatively from the MOF payload beyond
   the documented image-name scan.

2. **Event-time enrichment — chosen.** Both discovery paths query the
   command line the moment a process is first recorded. This wins the
   exit race against WeedHack's short-lived persistence children
   (`schtasks.exe`, `reg.exe`, `wscript.exe` live for milliseconds) that
   any lazy scan-time query would lose.

   API comparison:
   - **`NtQueryInformationProcess(ProcessCommandLineInformation)` — chosen.**
     Kernel-mediated copy into our own bounded buffer: no
     `ReadProcessMemory`, no PEB walk, and therefore **no WOW64 problem**
     (a 64-bit service reading a 32-bit PEB needs a second pointer
     layout — that entire failure class disappears because the kernel
     does the read). Documented on MS Learn. Handle-availability
     failures map cleanly onto the state enum.
   - **Direct PEB reading — rejected.** Requires `ReadProcessMemory`
     chains (PEB → RtlUserProcessParameters → CommandLine) with separate
     32/64-bit layouts from a 64-bit service; strictly more unsafe
     surface for zero benefit over the syscall.
   - **WMI `Win32_Process` / `Get-CimInstance` — rejected.** Spawns a
     WmiPrvSe round-trip per process start with seconds-scale latency
     under load — re-creates the event-time-vs-late-query race this
     workstream exists to close, at ~1000× the cost. The codebase's
     `amsi/ps_bridge.rs` was checked for reuse: it is a PowerShell
     **script-block log** reader (event 4104), not a process-query
     helper — nothing to reuse. `win_process.rs` is likewise only a
     `Command`-spawning helper.

Threat handling (all in `plm/cmdline.rs`, pure functions unit-tested
cross-platform):

- 64 KiB hard cap (`MAX_COMMAND_LINE_UTF16_UNITS = 32768` units — the
  legal `CreateProcessW` maximum, so no legitimate command line is ever
  truncated); the kernel can never force a larger allocation.
- `UNICODE_STRING` header parsed field-by-field from raw bytes (no
  struct punning, no alignment assumptions) and fully validated — even
  length, payload pointer inside our buffer, payload extent inside our
  buffer — before one code unit is read. Violations are `Malformed`,
  never decoded.
- Embedded NUL truncates; lone surrogates decode lossily; missing
  terminator is normal (Length rules, not NUL).
- `AccessDenied` (PPL, System, secure processes — NORMAL even for a
  SYSTEM service) and `ProcessExited` are first-class states with their
  own PLM diagnostics counters, not errors.

## 4. WeedHack signal reachability (workstream O)

The enum has 10 signals: the 7 original `weedhack_runtime::evaluate_chain`
signals plus the 3 ETW-wave signals. "Reachable post-F-1" assumes the
real system-logger session delivers events; "post-cmdline" assumes this
round's collection path.

| Signal | Required inputs | Reachable post-F-1? | Reachable post-cmdline fix? | FP risk | Test coverage | Active after this round |
|---|---|---|---|---|---|---|
| `UnnaturalJavaChild` | image_name of parent+child in a chain | yes (ETW + snapshot both supply image names) | yes (unchanged) | low–med (build tooling edge cases; weight 32, corroboration-weighted) | `weedhack_runtime` unit tests | **yes** |
| `JavaSecurityUpdaterTask` | cmdline contains `JavaSecurityUpdater` | **no — cmdline always None** | **yes** (any node, not java-gated) | ~zero (literal is WeedHack-unique) | new state-gating tests + existing positive test | **yes** (end-to-end needs live box) |
| `UpdaterVbsLaunch` | cmdline contains `Updater.vbs` | **no** | **yes** | ~zero (dropped-artifact name) | new state-gating tests + existing | **yes** (live box for e2e) |
| `SecurityUpdatesAppData` | cmdline OR image_path contains `\microsoft\securityupdates` | partially (image-path pivot already reachable) | yes, both pivots | low (folder is a WeedHack artifact) | existing tests | **yes** |
| `DefenderDisableUnderJava` | java root in chain + powershell image + cmdline `disablerealtimemonitoring` etc. | **no** | **yes** | low (java-gated; Set-MpPreference alone doesn't fire) | new state-gating tests + existing | **yes** (live box for e2e) |
| `Pjibf` | image name/path or cmdline references `Pjibf.exe` | yes (image pivot) | yes, all pivots | ~zero (random unique name) | existing tests | **yes** |
| `RunKeyFromJava` | java root + reg/powershell image + cmdline `currentversion\run` | **no** | **yes** | low (java-gated; benign Java updaters noted in weight comment) | new state-gating tests + existing | **yes** (live box for e2e) |
| `EtherHidingFromJava` | HTTP POST body to Eth-RPC host containing `0xce6d41de` from a java process | **no — dormant by design**: WinHTTP/WinINet ETW providers expose no HTTPS request bodies; no body source is shipped (see `weedhack_http_intake.rs` docs) | no change | zero when it fires (3-condition fingerprint) | pipeline fully tested via `ingest_http_post` | **no — needs a body source** (JNI agent / future hook); not a live-box gap, a source gap |
| `BrowserInjectionFromJava` | ImageLoad ETW event: browser target + user-writable unsigned module + java ancestor | yes (Wave 4 pump shares the F-1 session) | unchanged | low (signer + lineage + canonical detector gates) | filter/detector unit tests with mocks | **needs-live-box** to confirm kernel ImageLoad delivery end-to-end |
| `WalletHarvestBurst` | FileIO ETW: one java PID reads ≥3 distinct wallet/browser stores in 10 s | yes (Wave 6 pump shares the F-1 session) | unchanged | low (breadth + java gate + one-shot) | detector unit tests | **needs-live-box** to confirm kernel FileIO delivery end-to-end |

State-gating contract (new, pinned by tests): the 4 cmdline-pivot
signals fire ONLY on `CommandLineState::Present` with matching content.
`NotCollected / Failed / AccessDenied / ProcessExited / Empty /
Malformed` (and degenerate `Present("")`) are "no data" — silent. Tests:
`*_silent_for_every_non_present_state` × 4 signals, plus positive
controls (`present_with_matching_content_fires_all_four_cmdline_signals`,
`present_with_unrelated_content_stays_silent`). No thresholds were
lowered and no matching was broadened.

## 5. What needs a live box

1. End-to-end cmdline capture: spawn a real short-lived process
   (`cmd /c exit`) under the ETW session and assert a `Present` command
   line lands in the graph + `command_line.present` counter increments.
   The opt-in elevated test `etw_live_system_logger_delivers_events`
   now wires a production querier and is the natural place to extend.
2. PPL/secure-process behavior: confirm `AccessDenied` (not `Failed`)
   for e.g. MsMpEng / csrss.
3. WOW64: confirm a 32-bit child's command line is captured (the chosen
   API should make this free — verify once).
4. Kernel ImageLoad/FileIO delivery for the two ETW-wave signals above.

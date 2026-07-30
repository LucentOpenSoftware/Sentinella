# Sentinella v0.1.12 — External Review Response

Scope: workstreams A (detection efficacy / calibration), B (is the runtime
stack alive), C (attack the design). Method note: every claim is labeled
**VERIFIED** (executed, command + output) or **REASONED** (code/docs read,
`file:line` cited). Raw per-workstream reports and harness output artifacts
are preserved under `.audit/` (`ws-agent-3*.md`, `.audit/eval/*.tsv`).

---

## 1. Executive summary — the 5 things that matter most

1. **The cheapest evasion is a string and a byte.** Take any
   hash-signature-detected sample, flip one byte (kills ClamAV `.hdb` and
   the IOC layer — the oracle was VERIFIED live against the running
   daemon), embed the ASCII marker `Nullsoft Inst` anywhere in the PE
   (full-buffer substring `is_known_installer` → Structural/Packer ÷3,
   installer-class YARA ÷2), and drop it in `%LOCALAPPDATA%\Programs` —
   VERIFIED not realtime-watched on the live box. Real-time protection
   never fires and the heuristic score collapses below threshold.
2. **The real quarantine bar is not 76 — it's 85, ARGUS-only.**
   `unify_detection_filtered` (`ipc/state.rs:6414-6422`): ClamAV hit →
   always a threat; ARGUS-only needs score ≥ 85 — and 76–84 ARGUS-only
   is silently dropped, not even recorded. Every threshold discussion in
   this report must be read against 85, not the documented 76.
3. **The ETW session delivers zero events — and the brief's hypothesized
   fix would have broken it further.** `SentinellaPLM` is not a system
   logger by any documented criterion, so its kernel `EnableFlags` are
   invalid; setting `Wnode.Guid = SystemTraceControlGuid` (the brief's
   hypothesis) makes `StartTraceW` fail with `ERROR_INVALID_PARAMETER`.
   The doc-correct fix is `EVENT_TRACE_SYSTEM_LOGGER_MODE` + a fresh
   private session GUID. Lineage survives via snapshot fallback —
   degraded, not blind; browser-injection and wallet-harvest detectors
   are dead code today.
4. **Measured FP rate: 0/100 clean System32 binaries at Suspicious+** —
   but only because a purely path-based −20 discount absorbs pervasive
   structural noise (and masks a genuine YARA FP on stock `wmi.dll`);
   heuristic-only `Malicious` is reachable with 2 cheap signals
   (Mime 45 is uncapped) yet unreachable with 3 medium ones — the weight
   model is bimodal, not decorative.
5. **No unprivileged "kill the AV" primitive exists, but the management
   plane is soft.** Service DACL, process DACL, cache MAC, and vault ACLs
   all hold from medium IL (several VERIFIED live); however 64 parked
   pipe connections still starve every GUI/CLI client (post-`1a8b118`
   shed semantics), the world-readable secret tier leaks the full
   blind-spot map (`settings.get`, `watcher.status` — VERIFIED live), and
   the daemon will attach to a squatter's pipe after 10 failed creates
   (fired 5× benignly on this box). Also: unreadable files score
   0 = "Clean" (fail-open), and there is still no true-positive
   measurement — the harness now exists (`crates/argus/examples/eval.rs`)
   and is blocked only on a malware corpus (§3.6).

---

## 2. Findings

Severity reflects product impact, not code elegance. Each entry: the
refutation attempted, the failure mode, and a fix direction. Full
evidence in §3–§5.

### F-1 [HIGH] ETW kernel session receives no events; silent-zero is invisible
`crates/sentinelld/src/plm/etw_intake.rs:79,157-170` — **VERIFIED**
(session start success in daemon logs, 80 boots) + **REASONED**
(non-delivery follows from cited MS Learn contract; one elevated counter
read still pending, §4.6).
- *Refutation attempted:* three alternate hypotheses (EnableFlags works
  on plain sessions; GUID_NULL auto-promotes; another module enables
  providers) — each killed by a specific doc sentence or grep, §4.2.
- *Failure mode:* all three ETW-fed detectors (browser-injection,
  wallet-harvest, image-load signer verification) are dead in production;
  the session looks "running" in diagnostics, the snapshot fallback
  silently drops to a 30 s cadence, and the watchdog can't fire because
  give-up only triggers on access-denied.
- *Fix direction:* §4.4 proposed diff (`EVENT_TRACE_SYSTEM_LOGGER_MODE` +
  private session GUID + 1450 give-up + zero-event alarm). Risk to the
  working snapshot path: none directly; residual risk analyzed.

### F-2 [HIGH] Uncapped MimeValidation lets two trivial signals convict
`crates/argus/src/engine.rs:982-988` (cap table), `mime.rs:74-89` —
**VERIFIED** (probe p2: MZ+`%PDF-` renamed `.pdf` → 80 Malicious).
- *Refutation attempted:* tried to reach 76 via three *medium* signals
  instead — impossible (§3.3); the conviction path is specifically the
  uncapped 45 + Deception 35.
- *Failure mode:* FP conviction of disguised-but-benign files; more
  importantly, weight distribution that makes one cheap signal worth more
  than a YARA rule — calibration inversion. **Caveat from workstream C:**
  the *label* convicts at 76 but ARGUS-only auto-quarantine requires 85
  (F-7) — p2's 80 would display Malicious yet be silently dropped from
  detection handling. The over-weight is real either way.
- *Fix direction:* weight 45→~25–35 and/or fold into Deception cap;
  re-run harness probes to confirm p2 lands below 76 while p4-style
  script attacks still convict.

### F-3 [HIGH] Unsigned-system-path −20 discount is a laundering primitive
`crates/argus/src/layers/authenticode.rs:283-294,315-316,375-381` —
**VERIFIED** (100-file clean run: 804 structural points absorbed; the one
real YARA FP masked 30→10; forward-slash run shows the same file scoring
30/Suspicious without the discount).
- *Failure mode:* admin-level malware drops an unsigned binary into
  `C:\Windows\System32` and banks −20, no signature check involved. Also
  fragile: separator-inconsistent prefix matching (forward slashes lose
  the discount — discovered when it corrupted the first harness run).
- *Fix direction:* reduce to −10 and/or gate on catalog-signature
  verification eligibility rather than path prefix; normalize separators.

### F-4 [MEDIUM] Unreadable/blocked files verdict "Clean" (fail-open)
`crates/argus/src/engine.rs:224+` — **VERIFIED** (EICAR on this box:
`os error 225` → score 0, verdict Clean, single Info finding).
- *Failure mode:* on hosts where another AV (or ACLs) interposes,
  Sentinella reports Clean; users can't distinguish "scanned, benign"
  from "never read".
- *Fix direction:* distinct `Unknown/Error` verdict; do not let it feed
  the scan cache or trust graph as clean (round-1 fixed this for
  sentinelld scan paths; the engine-level verdict still reads "Clean").

### F-5 [MEDIUM] Orphaned ETW session leak on every shutdown
`etw_intake.rs:187-202` (stale-cleanup path) — **VERIFIED**: every one of
80 logged boots shows `stale session cleaned, will retry` immediately
before start — the previous session is never stopped on shutdown.
- *Failure mode:* leaked kernel session per unclean exit; first start
  after boot costs a stop+retry. With the F-1 fix making this a real
  system logger, leaks consume one of the 8 system-logger slots.
- *Fix direction:* `ControlTraceW(..., STOP)` in the daemon shutdown
  path; keep the stale-cleanup as defense.

### F-6 [LOW] YARA rule FP on stock `wmi.dll` ("WMIC process creation", w22)
**VERIFIED** (harness clean run; same DLL scores 30/Suspicious when not
under the System32 prefix). Rule fires on DLL content, not process
behavior.
- *Fix direction:* restrict the rule to process-creation contexts or
  require MZ+executable characteristics; add wmi.dll to the FP
  regression corpus (§3.6).

### F-7 [CRITICAL] Installer-marker forgery + 1-byte mutation = total evasion
`crates/argus/src/engine.rs:1183-1186,1218-1219,1251-1253` (marker scan),
`:499-528` (discount before aggregation), `ipc/state.rs:6414-6422` (the
85 bar) — **REASONED** from code + oracle **VERIFIED live**
(`runtime.scan_buffer` on EICAR returned the bare SHA-256 IOC layer,
weight 90).
- *Refutation attempted (failed):* markers are not offset-anchored
  (`data.windows(n).any()`, `engine.rs:1183`); `1a8b118` closed only the
  OLE2 free-text branch, PE markers remain by design; the discount runs
  before dedup/caps so they cannot restore the score; Context re-addition
  is suppressed under trust discounts and Zone.Identifier is
  attacker-stripped.
- *Failure mode (privilege: none, cost: minutes):* byte-flip kills hash
  signatures/IOC; `Nullsoft Inst` (or Inno/InstallShield/Advanced
  Installer strings) anywhere in the PE earns Structural+Packer ÷3 and
  installer-class YARA ÷2 — a heuristic-only 90 becomes ≈36. Combined
  with F-8 placement, realtime never fires.
- *Fix direction:* anchor framework detection structurally (NSIS overlay
  structure/CRC, Inno signature at known offset, OLE2+extension for MSI);
  bare ASCII markers at most a weak hint; alert (not silently drop)
  ARGUS-only 76–84; measure real post-mutation scores with the §3.1
  harness once the corpus exists.

### F-8 [HIGH] The documented quarantine threshold is wrong: ARGUS-only needs 85
`crates/sentinelld/src/ipc/state.rs:6414-6422` — **REASONED**.
- *Failure mode:* ARGUS-only scores 76–84 are labeled Malicious by the
  engine but `(false, None)` in detection unification — not recorded,
  not quarantined, not surfaced. Every threshold calibration (§3.3) must
  target 85, not 76; at 85, heuristic-only conviction is materially
  harder than §3.3's 76-arithmetic suggests (p2=80 and p4=78 both fall
  short ARGUS-only).
- *Fix direction:* document the split; decide deliberately whether
  76–84 should alert; re-derive calibration against 85.

### F-9 [HIGH] Realtime watch gap: `%LOCALAPPDATA%\Programs` not watched
**VERIFIED live** (`watcher.status` on this box: watched = Downloads,
Desktop, Documents, OneDrive, `AppData\Roaming`, `AppData\Local\Temp`,
`C:\Windows\Temp`, `C:\ProgramData` — the canonical per-user
install/persistence location is absent; daemon comments admit the class,
`ipc/mod.rs:1313-1317`).
- *Failure mode:* payload dropped there is only caught by idle/scheduled
  scans; combines with F-7 into durable placement evasion.
- *Fix direction:* add per-user `AppData\Local\Programs` (and
  equivalent) to realtime roots; ship the watched-roots list in the
  operator docs.
- **FIXED (v0.1.12, workstream J):** `AppState::start_watcher` now
  unconditionally enumerates `C:\Users\<user>\AppData\Local\Programs` for
  every real user profile (skipping Default/Public/etc. and non-existent
  dirs, deduped case-insensitively) — same SYSTEM-safe profile enumeration
  as the idle scanner. `%LOCALAPPDATA%` also added to the config
  `realtime_roots` env-expansion list. Unit tests cover case-insensitive
  dedup, missing-dir skip, env expansion, and the no-duplicate-watch
  invariant.

### F-10 [MEDIUM] Management-plane starvation via 64-connection parking
`crates/sentinelld/src/ipc/mod.rs:296-304,355-362` — **REASONED**
(post-`1a8b118` semantics reviewed), corroborated live (accept path
answers instantly when not exhausted).
- *Refutation attempted (partial):* the shed path keeps the acceptor
  alive — but permits are held for whole sessions with a 60 s idle timer
  restarting per frame, and there is no per-PID/per-identity quota; a
  competent holder of 64 connections starves GUI/tray/CLI indefinitely
  while protection silently continues.
- *Fix direction:* per-identity connection cap, reserved slots for
  elevated clients, or LRU eviction of idle same-identity connections.

### F-11 [MEDIUM] The world-readable-secret tier leaks the blind-spot map
`ipc/policy.rs` (AuthenticatedRead/Action classes),
`ipc/state.rs:239-256` (deliberate `BUILTIN\Users:(R)`), plus
`sentinelld.toml` itself `BUILTIN\Users:(RX)` — **VERIFIED live**
(`settings.get` returned full config incl. update cadence;
`watcher.status` returned watched roots; `icacls` on the config file).
- *Failure mode:* malware reads exactly where realtime doesn't look,
  signature staleness windows, and any admin-added exclusions — the
  targeting package. Default exclusions are empty
  (`config/mod.rs:231-234`), so the exclusion-drop needs a pre-existing
  admin exclusion; the watched-roots gap needs nothing.
- *Fix direction:* move recon-sensitive methods (`watcher.status`,
  `settings.get*`, `detections.list`, `diagnostics.export`, …) behind
  elevation, or redact exclusion/watched-root detail in the
  unelevated response.

### F-12 [MEDIUM] `update.start` churn: rolling cache invalidation + compile spikes
`ipc/policy.rs:307-310` (AuthenticatedAction, not challenge-gated),
`ipc/state.rs:4140,4265,3789-3793` — **REASONED** (no refutation found).
- *Failure mode:* unprivileged caller triggers freshclam → on exit 0
  (even "up-to-date") unconditional engine reload → full scan-cache +
  trusted-cache invalidation and ~2× engine compile memory spike, at
  10/min in a bucket shared with legitimate scan control. Permanent
  cold-scanning on a box already reporting `memory_pressure:"elevated"`.
- *Fix direction:* skip reload when freshclam reports no changes;
  challenge-gate or separately rate-limit `update.start`.

### F-13 [MEDIUM] Named-pipe squatting / orphan-attach: forged "all good" console
`ipc/mod.rs:142-168` — mechanism **VERIFIED** to have fired 5× on this
box (benignly; log shows `attached to existing pipe (orphan owner)`).
- *Failure mode:* during any service downtime, medium-IL malware
  pre-creates `\\.\pipe\sentinelld`; the restarted SYSTEM service
  attaches after 10 failed first-instance attempts; no client-side server
  authentication exists (`GetNamedPipeServerProcessId` appears nowhere in
  the tree) → the squatter serves forged health/status on its share of
  client connections.
- *Fix direction:* never attach to a pipe whose owner SID isn't
  SYSTEM/this-service; clients verify server image path/signer.

### F-14 [MEDIUM] `argus.analyze` / `runtime.scan_buffer`: oracles as SYSTEM
`ipc/mod.rs:1454-1500`, `policy.rs:81` — **REASONED**; scan_buffer oracle
**VERIFIED live** (exact per-layer weights returned to an unprivileged
caller).
- *Failure mode:* (a) guided-evasion oracle against the deployed config,
  no file writes needed; (b) `argus.analyze` stats+reads any local path
  as SYSTEM and returns sha256/mime/findings — existence/content
  integrity oracle over other users' files; (c) 10×60 s/min of shared
  engine budget crowds out realtime analysis (saturation→watcher-delay
  link not fully traced — low confidence).
- *Fix direction:* elevation-gate `argus.analyze`; coarsen
  `runtime.scan_buffer` output for unelevated callers (verdict without
  per-layer weights).

### F-15 [MEDIUM] First-run-as-user ACL residue collapses file protections
**VERIFIED on this box:** `C:\ProgramData\Sentinella` and `...\state`
carry `Nicolas:(F)`; `.vault_key` carries `Nicolas:(R)` — the MSI sets
no ACLs (`installer/windows/Product.wxs` has no `Permission` elements,
VERIFIED grep) and the daemon only ACLs specific files, never the data
root. On any install whose state tree was first created by a user-context
process, the installing user can rewrite/delete the scan cache, config,
DBs, and read the vault key.
- *Fix direction:* set an explicit DACL on the data root at
  install/first-run (SYSTEM/Admins only); re-ACL on service start if
  drifted.

### Attacks refuted for medium-IL (with evidence)

- **ETW session stop/flush:** VERIFIED `etw_probe.exe` as user →
  `StartTraceW: ERROR_ACCESS_DENIED (5)`; session control requires
  admin/PLU per MS docs. Moot. (Event flooding possible but low value.)
- **Cache poisoning:** `scan_cache.db` ACL `SYSTEM/Admins:(F)`; per-entry
  keyed SipHash with a SYSTEM-only key; MAC failure fails toward rescan.
  (All VERIFIED via `icacls` + code.)
- **Quarantine vault read/plant:** `.vault_key` SYSTEM/Admins-only in the
  production ACL function; blobs AES-256; restore paths are
  challenge+elevation-gated (VERIFIED denied, -32005) and
  destination-blocklisted; DB is `Users:(RX)`.
- **Service stop / process kill:** service SDDL grants interactive users
  query only (VERIFIED `sc sdshow`); SYSTEM process DACL denies
  medium-IL terminate; no IPC panic path found (frame caps, handled JSON
  errors, `catch_unwind` on dispatch).
- **Excluded-detection manipulation:** `settings.set*` and
  `protection.*` are challenge+elevation-gated — VERIFIED denied from
  medium IL. (Caveat for admins: exclusion matching is plain substring,
  `state.rs:6477-6489`.)

---

## 3. Workstream A deliverables — detection efficacy & calibration

### 3.1 The harness (delivered, in-tree)

`crates/argus/examples/eval.rs` (319 lines, zero new dependencies, std +
argus public API). Constructs the engine exactly as the daemon does
(`ArgusEngine::new(ArgusConfig::default())`; 177 YARA rules and 13 IOC
hashes loaded from `runtime/` — VERIFIED at startup). Per file it emits
verdict, total and raw score, per-finding layer/severity/post-cap weight,
installer flag, discounts, plus a clearly-labeled RECON replica that
inverts the installer ÷3/÷2 divisions. Summary mode: verdict buckets,
per-layer totals, cap-saturation inference.

Run it: `cargo run --release --example eval -p argus -- <dir> --verbose`.
Artifacts: `.audit/eval/system32-clean-bs.tsv` (authoritative clean run),
`test-corpus.tsv`, `probes/`.

### 3.2 VERIFIED measurements on this box

**EICAR.** On disk: unreadable (Defender interposes, os error 225) →
score 0 / Clean — see F-4. In memory (`--eicar-buffer` →
`analyze_buffer`): **Malicious 90** — but only because EICAR's SHA-256 is
in the curated IOC list (weight 90, `ioc.rs`). It tests IOC-list
membership, not heuristics; there is no ClamAV layer inside ARGUS.

**Clean corpus — 100 System32 .exe/.dll (smallest-first, ≤50 MB,
backslash root).** `scanned=100`; buckets: **Clean 98, LowSuspicion 2;
0 Suspicious, 0 HighSuspicion, 0 Malicious.** Rule of three: 95% upper
bound on the Suspicious+ FP rate ≈ **3%** for this file class at n=100.
The 2 non-Clean: `wmi.dll` 10 (raw 30 − 20 path discount; F-6 YARA FP +
structural 8) and `msvcr100_clr0400.dll` 3. Structural noise was
pervasive (804 points / 98 files: "small import table", "future
timestamp") and entirely absorbed by the path discount (F-3). Only
1/100 files received any authenticode/reputation discount — the trusted
publisher DB does not cover catalog-signed Microsoft binaries.
**Refutation performed:** the first run (forward-slash root) reported 97
LowSuspicion + 1 Suspicious; traced to separator-sensitive
`is_windows_system_path`; re-run with backslashes is the authoritative
result above.

**test-corpus/.** 24 files, all Clean 0 — synthetic placeholders; the
repo corpus exercises plumbing, carries no detection signal, and cannot
measure TP/FP.

**Crafted probes (all VERIFIED):**

| Probe | Construction | Score | Fired |
|---|---|---|---|
| p1 polyglot `.exe` | MZ + `%PDF-` | 35 Suspicious | Deception 35 |
| p2 same bytes, `.pdf` | extension mismatch | **80 Malicious** | Mime 45 + Deception 35 |
| p3 double-ext | `invoice.pdf.exe` | 50 | Deception 35+35→capped 25+25 |
| p4 `evil.ps1` | `-enc`, cradles, AmsiScanBuffer, Reflection | **78 Malicious** | Script raw 100→cap 39; YARA 20+19 |
| p5 polyglot + ZoneId=3 ADS in Downloads | real ADS | 43 | +Context 8 |
| p6 double-ext + ADS | real ADS | 59 | 50 + Context 9 |
| p7 RTLO filename | U+202E | 49 | RTLO 50 + 35 → capped 29+20 |
| p9 `report.ps1` | `-enc` + ADS | 52 HighSuspicion | Script 25 + YARA 22 + Context 5 |
| nsis probe | notepad.exe + "Nullsoft Inst" + 2.5 MB pad | 1, installer=true | structural 5→1 |

### 3.3 Threshold arithmetic (REASONED, citations) + VERIFIED reachability

Caps at `engine.rs:982-988`, applied as proportional floor-scaling per
layer (`engine.rs:1010-1016`); dedup (same BehaviorTag + same layer)
before caps (`engine.rs:979,934-963`); `raw_score` = post-cap sum
(`engine.rs:1018`); `max(reputation, authenticode)` discount after caps
(`engine.rs:1020-1021`); installer discount (Structural/Packer ÷3,
installer-class YARA ÷2) **before** dedup/caps (`engine.rs:497-526` vs
`aggregate_score` at `:560`).

| Category | Cap | Max single finding | Realistic max |
|---|---|---|---|
| Structural | 30 | 30 (`pe_heuristics.rs`) | 30 |
| YARA | 40 | 40 (9 shipped rules at weight 40) | 40 |
| Context | 15 | 15 (internally capped, `context.rs:19,204`; needs pre-score ≥5) | 15 |
| Packer | 20 | 22 | 20 |
| Pattern | 25 | 45 (`patterns.rs:500`) | 25 |
| Script | 40 | stacks past 100 (p4: raw 100→40) | 40 |
| Deception | 50 | 50+35+35 stack (RTLO/double-ext/polyglot) | 50 |
| **Mime** | **UNCAPPED** | 45 | 45 |
| IoC | uncapped | 90 — signature-class, excluded | — |

- Capped sum 220 + Mime 45 = **265 theoretical without IoC/signature**.
- **Is 76 reachable from heuristics alone? YES — VERIFIED twice** (p2:
  2 signals; p4: 78). Minimum observed: **2 high-weight signals in
  distinct layers**.
- **Can three medium signals reach 76? NO.** Three ≤25-weight signals in
  distinct layers sum ≤75. Best observed attempt: 59 (p6). Conviction
  requires one ≥45 Mime mismatch, a near-saturated cap (Script 40 /
  Deception 50 / YARA 40), or 4+ mediums.
- **⚠ Cross-check against workstream C (F-8):** the engine *label*
  convicts at 76, but ARGUS-only auto-quarantine requires **85**
  (`ipc/state.rs:6414-6422`). Against the operational bar, neither p2
  (80) nor p4 (78) would be quarantined ARGUS-only — heuristic-only
  conviction is materially harder than the 76-arithmetic suggests, and
  all re-calibration (§3.7) must target 85.
- So the heuristics are **not decorative** — but conviction is bimodal:
  trivially easy to *label* via Mime+Deception, impossible via
  accumulated mediums, and gated at 85 for action.

### 3.4 Installer-discount trade

**0 of 100 clean System32 files matched `is_known_installer`** (VERIFIED)
— on OS files the discount never fires and costs nothing. Mechanism
VERIFIED on the synthetic NSIS probe (structural 5→1). Worst-case
suppression is bounded: ≤(30+20)/3 ≈ 17 points + ≤20 halved-YARA.
**The FN cost is not measurable without installer-framework malware
samples** — blocked on §3.6 corpus. The round-2 gate fix (MZ/OLE2-only)
means the abuse surface is now: be a real PE/MSI wearing installer
markers.

### 3.5 Trust-graph value — cannot measure without a live daemon

The trust graph is daemon-side; the argus-only harness cannot exercise
it (engine-side `EventCorrelator` is record-only, `engine.rs:581`).
**Experiment design (live box):** baseline scan of a seeded-malware set
with `trust_graph.db` wiped → seed familiarity by running the benign
parent chain N times from a consistent signer/path → rescan identical
payloads. "Helps" = benign-churn FP rate drops with zero TP loss;
"launders" = any seeded-malware sample loses ≥8 points or drops below 76
from familiarity alone. Include the revocation control: tamper one node,
confirm integrity-mismatch → no discount (fail-closed,
`trust_graph/mod.rs:26-58`).

### 3.6 Corpus acquisition plan (legal material only)

- **EICAR** (eicar.org, free): sanity only — shown to test IOC
  membership, not heuristics.
- **ClamAV test files** (in-repo `clamav-main/` + upstream; GPL-2.0):
  tens of files; exercises the ClamAV layer, not ARGUS.
- **MalwareBazaar (abuse.ch)**: bulk API by family/tag; free (API key
  for queries); research ToS, no redistribution; ~10–50 recent Windows
  samples per family.
- **theZoo (GitHub)**: ~300 live samples, educational-use terms, mixed
  per-sample licensing; supplement only.
- **VX-Underground**: largest collection; manual curation.
- **Clean set**: fresh-install Windows file set (sample 2–5k of ~200k),
  winget top-100 installed + harvested, PortableApps suite, dev
  toolchains (VS Build Tools, Rust, Go, Node — deliberately stresses the
  Go/Rust static-binary installer leniency, `engine.rs:1266-1278`), game
  launchers (Steam/Epic — Electron/Unity markers).
- **Target composition:** 30–50 families × ~20 samples = 600–1,000
  malware; clean ≥1,000 (≥200 installer/framework binaries for the
  discount-FN measurement, ≥500 non-installer).
- **Statistics honesty:** 0 FPs on N=1,000 clean → 95% upper bound 0.3%
  (rule of three, ~3/N); a 0.1% FP rate needs ~3,000 clean files;
  per-family TP at n=20 has ±~11pp Wilson intervals — report per-family,
  never pooled.

### 3.7 Re-calibration recommendations (evidence-backed)

1. **Cap/fold MimeValidation** (F-2): the only uncapped content layer;
   two zero-sophistication signals convict. Re-weight 45→25–35 or fold
   into Deception; re-run probe suite to confirm p2 < 76 ≤ p4.
2. **Shrink and harden the system-path discount** (F-3): −20→−10,
   separator-normalized, ideally gated on catalog-verification
   eligibility. It currently does all the FP-suppression work for
   structural noise — pair this with tuning the noisy structural rules
   (804 points/98 files) rather than masking them.
3. **Introduce an `Unknown/Error` verdict** (F-4) distinct from Clean.
4. **Then** re-baseline thresholds on the §3.6 corpus; do not tune
   thresholds before the corpus exists — current numbers are n=100,
   one file class.

---

## 4. Workstream B deliverables — is the runtime stack alive?

### 4.1 What the code does (REASONED, cited)

- Session name `"SentinellaPLM"` — `etw_intake.rs:79`.
- `Wnode.Guid` never set (zero-init buffer, `:157`; only BufferSize
  `:159`, ClientContext `:160`, Flags `:161` assigned).
- `LogFileMode = 0x100` (`EVENT_TRACE_REAL_TIME_MODE` only) — `:162`.
- `EnableFlags = PROCESS | IMAGE_LOAD | FILE_IO_INIT` — `:164-170`.
- `StartTraceW` at `:178-184`; error 183 → stop+retry (`:187-202`); other
  errors logged (`:204-207`).
- **No `EnableTraceEx2` anywhere in `crates/`** (grep VERIFIED; the
  architecture comment at `:8` describes a call that doesn't exist).
- Diagnostics exist (`etw_events`, `etw_running`, `image_load_etw.*`,
  `fileio_etw.*`; `ipc/state.rs:4625-4644`, `plm/mod.rs:697-771`) but
  nothing alarms on `running && events==0`; give-up fires only on
  access-denied (`etw_intake.rs:102-115`).

### 4.2 The definitive answer (VERIFIED doc fetches)

- **EVENT_TRACE_PROPERTIES** (learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-event_trace_properties):
  *"EnableFlags is only valid for system loggers, i.e. trace sessions
  that are started using the EVENT_TRACE_SYSTEM_LOGGER_MODE logger mode
  flag, the KERNEL_LOGGER_NAME session name, the SystemTraceControlGuid
  session GUID, or the GlobalLoggerGuid session GUID."*
- **StartTraceW** (…/nf-evntrace-starttracew): system loggers require
  one of: `EVENT_TRACE_SYSTEM_LOGGER_MODE` (preferred), the two GUIDs
  (deprecated), or `KERNEL_LOGGER_NAME` (deprecated). *"In most cases,
  you will set Properties.Wnode.Guid to all-zero… to allow the ETW system
  to generate a new GUID"* — exactly Sentinella's case. And:
  *"`ERROR_INVALID_PARAMETER`: The Wnode.Guid member is
  SystemTraceControlGuid, but the InstanceName parameter is not
  KERNEL_LOGGER_NAME."* — **the brief's hypothesized fix breaks the
  session.**
- **Configuring and Starting a System Trace Provider Session**
  (…/configuring-and-starting-a-systemtraceprovider-session): Win8+ allow
  8 multiplexed system logger sessions (2 reserved); a privately-named
  one must set `EVENT_TRACE_SYSTEM_LOGGER_MODE`, keep its private name,
  and *"make sure the Wnode.Guid member… is not set to
  SystemTraceControlGuid. You must assign a new GUID to this member."*

**Answer: with the current configuration Windows delivers no kernel MOF
Process/ImageLoad/FileIo events to `SentinellaPLM`.** The session starts,
`ProcessTrace` blocks on an empty stream, and nothing logs an error —
which is precisely how this survived two audits.

VERIFIED live corroboration (this box, Windows 11 build 26100):
`sentinelld` running (v0.1.12), daemon log shows 80× "PLM ETW kernel
trace session started", **every boot preceded by "stale session
cleaned"** (F-5 orphan leak), and the "kernel trace session" log line
(`:210`) is factually wrong per the contract. The 0-events confirmation
itself needs one elevated counter read (§4.6).

### 4.3 Dead-code census

| Signal | State today | Evidence |
|---|---|---|
| ETW process-create intake | **dead pending F-1 fix** | `etw_intake.rs:79,157-170`, `:355-357` |
| Process lineage (ASTRA/scans) | **alive via snapshot fallback** | `plm/mod.rs:582-587,883-971`; caveat: 30 s cadence, watchdog can't fire |
| Generic chain suspicion (LOLBin/Office) | **alive via fallback** | `plm/mod.rs:208-233` |
| Chain-based WeedHack signals (incl. pathognomonic `Pjibf`) | **alive via fallback** | `weedhack_runtime.rs:58-73,172`; callers `idle_scanner/mod.rs:828`, `watcher/mod.rs:672` |
| WeedHack campaign confirmation | **alive, degraded** — ETW corroborators can't contribute | `weedhack_campaign.rs:71-93` |
| BrowserInjectionFromJava (ImageLoad pump) | **dead pending F-1 fix** | `etw_intake.rs:335-339`, `etw_image_load.rs:48-51` |
| WalletHarvestBurst (FileIO pump) | **dead pending F-1 fix** | `etw_file_io.rs:7-10`, `etw_intake.rs:347-351` |
| EtherHidingFromJava (HTTP intake) | **dormant by design** (no listener shipped; unrelated to ETW) | `weedhack_http_intake.rs:3-45`, `plm/mod.rs:777-782` |
| WinTrust signer verifier | **alive but unreachable** (only called from ImageLoad worker) | `plm/mod.rs:500-517` |

Severity read: the product is **degraded, not blind** — lineage context
and the chain-based WeedHack signals work via snapshot. Lost: all
real-time ETW speed, browser-injection and wallet-harvest detection,
and 3 corroborator classes that accelerate campaign confirmation.

### 4.4 Minimal fix design (proposed, NOT applied)

Per the doc crux: private name + `EVENT_TRACE_SYSTEM_LOGGER_MODE` + a
**new** session GUID (not `SystemTraceControlGuid`). Full proposed diff
in `.audit/ws-agent-36.md`; essence:

- `props.Wnode.Guid = SESSION_GUID;` (fixed, randomly generated once,
  private)
- `props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;`
- Treat `ERROR_NO_SYSTEM_RESOURCES` (1450) like access-denied: count
  toward give-up so the watchdog restores 5 s snapshot-primary.
- Any persistent `StartTraceW` failure (≥5 consecutive, any code) should
  set `etw_gave_up` — today only error 5 does.
- Add the missing alarm: `etw_running && events_seen == 0` for ~2 min →
  loud warn + snapshot boost.
- Add shutdown-time `ControlTraceW(STOP)` (F-5).
- Fix the misleading log line at `:210`.

**Risk statement:** nothing touches `plm_loop`/`snapshot_processes`; the
snapshot thread spawns unconditionally (`plm/mod.rs:582-587`). Residual
risk: a *new* StartTraceW failure mode retrying forever at 30 s with
snapshot stuck supplemental — mitigated by the any-failure give-up above.
Slot exhaustion (8 max, 2 reserved) handled via 1450 give-up. Daemon runs
as SYSTEM, satisfying the documented privilege requirement. Rejected as
non-minimal: switching to manifest-based `Microsoft-Windows-Kernel-*`
providers via `EnableTraceEx2` (breaks every MOF parser offset).

### 4.5 Validation procedure (elevated, <10 min)

Pre-fix (proves the bug): `logman query -ets` (elevated) shows
`SentinellaPLM` → run
`scripts\collect-weedhack-runtime-diagnostics.ps1 -AuthSecretPath C:\ProgramData\Sentinella\state\ipc_secret`
elevated → generate activity (spawn processes, open a browser) → wait
60 s → collect again. **Smoking gun (pre-fix): `image_load_etw.running ==
true` with `events_seen == 0` everywhere, while `plm.events_seen`
(snapshot) grows.** Post-fix acceptance: 5 spawned processes →
`etw_events ≥ 5`; GUI-app launch → `image_load_etw.events_seen` in the
hundreds within a minute; `fileio_etw.events_filtered ≈ 99%`;
`confirmed_total == 0` throughout; degradation test with 8 system loggers
→ clean give-up to snapshot-primary. (Full steps in `.audit/ws-agent-36.md`.)

### 4.6 Still needs a live elevated box

- The literal `events_seen == 0` counter read (auth-gated; VERIFIED
  rejection as non-admin).
- That the proposed diff compiles, starts, and delivers events (§4.5
  steps 5–7).
- MOF parser correctness against a live kernel stream — parsers are
  heuristic wide-string scans never validated on build 26100; the file's
  own comment admits real events carry NT device paths
  (`etw_intake.rs:460-477`).

---

## 5. Workstream C deliverables — attack the design

Environment note: this box runs a live 0.1.12 daemon (SYSTEM), so many
claims were VERIFIED against the production install via read-only/
negative-test IPC probes (PowerShell `NamedPipeClientStream`); no state
was modified. Full evidence: `.audit/ws-agent-37.md`.

### 5.1 Ranked attack list (privilege × effort × impact)

| # | Attack | Privilege | Effort | Impact | State |
|---|---|---|---|---|---|
| A1 | Installer-marker forgery + 1-byte hash-sig mutation (F-7) | none | minutes | **total evasion** of hash-sig/IOC detection; heuristic-only 90 → ≈36 | REASONED + oracle VERIFIED live |
| A2 | 64-connection parking starves management plane (F-10) | none | 1 process | GUI/tray/CLI locked out indefinitely | REASONED |
| A3 | Recon: `settings.get`/`watcher.status`/config file (F-11) | none | read-only | complete blind-spot map + staleness windows | **VERIFIED live** |
| A4 | `update.start` churn → rolling cache wipe + RAM spikes (F-12) | none | 10/min loop | permanent cold-scanning, ScanControl bucket starvation | REASONED |
| A5 | Pipe squatting during service downtime (F-13) | none | race | forged "all good" health to GUI clients | mechanism VERIFIED (fired 5× benign) |
| A6 | Score oracle + SYSTEM file-read oracle (F-14) | none | API calls | guided evasion; existence/sha256 oracle on other users' files | oracle VERIFIED live |
| A7 | ETW stop/flush | **admin required** | — | moot for medium IL | **REFUTED** (VERIFIED err 5) |
| A8 | Cache poisoning | — | — | fails toward rescan | **REFUTED** (ACL+MAC VERIFIED) |
| A9 | Vault read / plant-restore | — | — | ACLs + crypto hold | **REFUTED** (but see F-15 anomaly) |
| A10 | Kill the AV (service stop, process kill, IPC crash, config tamper) | — | — | no unprivileged primitive found | **REFUTED** (SDDL VERIFIED) |
| A11 | Data-root ACL residue rewrites everything (F-15) | installing user | trivial | cache/config/DBs rewritable, vault key readable | **VERIFIED on this box** |

### 5.2 IPC partition verdict

The auth/elevation split is **defensible where it matters**: every
kill-vector and privileged-mutation method sits behind challenge-token +
daemon-side elevation check (VERIFIED denied from medium IL, `-32005`);
tokens are method-scoped, single-use, 60 s, burn-on-mismatch
(`ipc/state.rs:1125-1186`); the dead-PID bypass fails closed. The weak
tier is **AuthenticatedAction**: `update.start`, `scan.cancel`,
`scan.start`, `argus.analyze` have real side effects yet need only a
secret that is world-readable by design — that tier boundary is where
the theatre is. The compact per-method table (all ~40 methods with
class, gate, and worst outcome) is in `.audit/ws-agent-37.md` §"Per-method
IPC table".

### 5.3 The single cheapest reliable evasion (the brief's item 7)

> **Flip one byte in a non-executed region of any hash-detected sample,
> embed the ASCII string `Nullsoft Inst` anywhere in the PE, strip
> Zone.Identifier, drop it in `%LOCALAPPDATA%\Programs\...`**

Privilege: none. Cost: minutes. Result: no ClamAV/IOC hit; Structural/
Packer ÷3 and installer-class YARA ÷2 drop the heuristic score to roughly
the 20–50 band — below the ARGUS-only auto-quarantine bar of 85 and
usually below the 76 threat label; realtime watcher never fires (F-9).
Confirmable against the deployed config for free via
`runtime.scan_buffer` (oracle VERIFIED live). The one element that is
arithmetic rather than measurement is the final score of a *real* sample
— the §3.1 harness replaces that arithmetic once a corpus exists.

### 5.4 Updater supply chain

- **freshclam/ClamAV:** `DatabaseMirror database.clamav.net` (VERIFIED
  config); freshclam's default transport is plain HTTP but CVD/cdiff
  content is signature-verified inside freshclam (REASONED, standard
  behavior) → content forgery infeasible; a network attacker can still
  suppress updates / spoof the DNS version check → standing
  staleness-DoS window (`signature_stale_days:7`). The enhanced-provider
  pipeline enforces HTTPS + pinned SHA-256 from an **unsigned** manifest
  (signing deferred) — trust anchor is TLS to the provider host.
- **Tauri updater:** minisign pubkey present, single HTTPS GitHub
  endpoint (VERIFIED `tauri.conf.json`). Solid; residual exposure is
  release-pipeline compromise, which the minisign key exists to bound.

---

## 6. Prioritised roadmap

Effort = engineering time; Regression risk = chance of breaking working
behavior (per the round-2 calibration lesson: any scoring/budget change
gets a harness re-run, not just `cargo test`).

| # | Item | Effort | Regr. risk | Validates on |
|---|---|---|---|---|
| 1 | F-1 ETW fix (§4.4) + F-5 shutdown stop | 0.5–1 day | **Medium** (kernel session semantics; mitigations designed) | Needs live elevated box (§4.5) |
| 2 | F-7 installer-marker hardening (structural NSIS/Inno anchors) | 1–2 days | Med (FP shift on real installers) | Harness + installer corpus (#5) |
| 3 | F-9 close the `%LOCALAPPDATA%\Programs` watch gap | 1 h | Low-Med (more watcher load) | Live box |
| 4 | F-8 reconcile 76 vs 85 (document; alert 76–84) | 2 h | Low | Harness |
| 5 | §3.6 corpus acquisition + harness CI | 2–3 days | None (data) | — |
| 6 | F-4 Unknown/Error verdict | 0.5 day | Low | Harness (EICAR probe) |
| 7 | F-12 `update.start`: skip reload on no-change; re-gate | 2 h | Low | Code + live |
| 8 | F-10 per-identity connection quota | 0.5 day | Med (GUI connection patterns!) | Live box + GUI soak |
| 9 | F-15 data-root DACL at install/first-run | 0.5 day | Low-Med (installer change) | Clean VM install test |
| 10 | F-13 pipe-owner check + client server verification | 0.5 day | Med (orphan-GUI flows rely on attach) | Live box |
| 11 | F-11 redact/elevate recon-sensitive methods | 0.5–1 day | Med (GUI reads settings unelevated!) | GUI regression pass |
| 12 | F-2 Mime cap/re-weight | 2 h | Low-Med (FP/TP shift) | Harness probes; corpus later |
| 13 | F-3 path-discount hardening | 0.5 day | Med (97-file clean run depended on it — pair with structural-rule tuning) | Harness clean corpus |
| 14 | F-14 gate `argus.analyze`; coarsen `scan_buffer` | 2 h | Med (GUI/dev-console callers) | GUI/CLI regression pass |
| 15 | §3.5 trust-graph live experiment | 1 day | None (measurement) | Live box |
| 16 | F-6 wmi.dll YARA rule fix | 1 h | Low | Harness |
| 17 | Threshold re-baseline (against **85**, per F-8) | 1–2 days | Med | **Blocked on #5** |
| 18 | Manifest signing (deferred from round 1) | 1–2 days + key mgmt | Low | Provider infra |

**Explicitly not yet validatable:** TP rate, installer-discount FN cost,
trust-graph value (need corpus/live box); ETW event delivery post-fix
(needs elevated run); MOF parser correctness on real streams; F-10/F-13
fixes' interaction with real GUI connection churn.

---

## 7. Low-confidence appendix

- Real-world prevalence of 8-slot system-logger exhaustion — no data;
  the 1450 give-up is insurance.
- FileIo event volume vs the 99%-prefilter CPU budget on busy dev boxes —
  unmeasured; the Phase-2 CPU criteria in `WEEDHACK_LIVE_VALIDATION.md`
  exist because this is unproven.
- EICAR-on-disk read being Defender-blocked is box-specific; other hosts
  with different AV interposition may differ (F-4 stands regardless —
  ACL-blocked reads behave the same).
- **Cache TOCTOU** — fingerprint verified, then file handed to scanner
  non-atomically; an oplock/hardlink race could serve clean bytes at hash
  time and malicious bytes at use. Inherent, hard to exploit, unverified.
- **ARGUS saturation → realtime drop** — 10×60 s/min of attacker analysis
  against one shared engine plausibly delays watcher analysis; the
  watcher backpressure/drop path was not fully traced.
- **Alert-noise as cover** — the live daemon log shows continuous
  `FISH: slow-burn mass mutation` and trust-graph `INTEGRITY MISMATCH`
  warnings on benign Firefox/Defender churn (VERIFIED log tail). Whether
  real signal can hide in that noise is unquantified; it also shows the
  trust-graph integrity keying rejecting routine churn in production.
- **`excluded_detections` is plain substring matching**
  (`state.rs:6477-6489`) — admin-only to set, but a short exclusion
  ("Win") suppresses broadly. Noted for config review.
- **`dev.set_developer_mode`** accepts online password guessing at
  10/min; prize is a perf dump. Low value, noted.
- **First-run ACL residue generalization (F-15)** — VERIFIED on this dev
  box; how many production installs share the history is unknown. Needs a
  clean-VM MSI install check.
- **AMSI-path enforcement of `runtime.scan_buffer`** — `should_block:true`
  returned advisory JSON in the probe; whether any consumer enforces it
  was not traced.

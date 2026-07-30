# Sentinella — Implementation Round Handoff (post-v0.1.12)

Round base: `06229a8` (external review artifact). 19 commits, 80 files,
+15,558/−716. Every commit message states prior behavior, invariant,
boundary, tests, and limitations. This document is the map for the
second, adversarial AI: attack everything below.

Build/test transcript (exact commands at the end). Test totals at round
close: **1,009 green, 0 failed** (argus 329 lib + 33 installer_spoofing
+ 10 + 8 integration + 20 eval; sentinelld 552 + 2 ignored; sandboxd
51; sentinella-common 20+; cli/argusd/sentinella-argus/clamavd
suites). The sentinelld test binary intermittently trips a Windows
Defender heuristic (`Trojan:Win32/Cryware.B`, os error 225 on exec) —
it contains the WalletHarvest detector and ACL-repair code; transient,
cleared on every occasion; add a `target\` exclusion if it recurs.

---

## VERIFIED RECORD

| Finding | Status | Fix commit |
|---|---|---|
| F-1 ETW zero-event (sentinelld) | **confirmed, fixed** | `b60f296` |
| C-1 ETW inert in sandboxd + etw_probe | **confirmed, fixed** | `8495927` |
| Aligned-storage UB (etw_intake Vec<u8> cast) | **confirmed, fixed** | `a585857` |
| F-7 PE installer substring evasion (NSIS/Inno/WiX) | **confirmed, fixed** | `854d80a`,`84762a5`,`40c2fdd`,`03376b5`,`8449cda` |
| F-8 76-vs-85 semantics | **confirmed (docs/comments), fixed** | `8a18ed6` |
| F-8 strengthened: 76–84 ARGUS-only cached clean | **confirmed, NOT changed** (product-policy decision documented; out of round scope per brief) | — |
| F-9 `%LOCALAPPDATA%\Programs` not watched | **confirmed, fixed** | `e9f980d` |
| F-10 connection parking | **stale** (try_acquire shed since `1a8b118`); residual fairness **fixed** | `5a32ee7` |
| C-5 global request-rate limiter starvation | **confirmed, fixed** (verified live pre-fix with probe) | `fec0328` |
| F-15 data-root DACL missing | **confirmed, fixed** | `afe8749` |
| C-4 vault-key DACL creation-only | **confirmed, fixed** | `afe8749` |
| C-6 `ProcessNode.command_line` None in production | **confirmed (2 sites, not 9), fixed** | `c8bd050` |
| F-5 ETW session leak "every boot" | **narrowed**: real defect was `PlmMonitor::Drop` missing join; **fixed** | `b60f296` |
| F-2 MIME-45 uncapped | **confirmed, mitigated by design** (≥40 veto blocks mitigation-stacking; value NOT retuned — corpus decision) | `8449cda` |
| F-3 system-path −20 discount | **confirmed, NOT changed** (retuning needs corpus; orthogonal to mitigation pass) | — |
| F-4 unreadable file → Clean | **confirmed, NOT changed** (Unknown/Error verdict is a schema change; deferred with design) | — |
| F-6 wmi.dll YARA FP | **confirmed, NOT changed** (rule fix needs FP corpus; documented) | — |
| F-11 recon via world-readable secret tier | **confirmed, NOT changed** (GUI-compat policy decision; documented as accepted residual) | — |
| F-12 `update.start` churn | **confirmed, mitigated** (per-principal rate budgets bound it) | `fec0328` |
| F-13 pipe squatting/orphan-attach | **confirmed, NOT changed** (owner-SID check design noted; needs downtime-race handling) | — |
| F-14 `argus.analyze`/`scan_buffer` oracles | **confirmed, NOT changed** (gating = GUI-breaking policy decision; documented) | — |
| `SystemTraceControlGuid` proposal (review §4.4 sketch) | **refuted** (private name + that GUID = ERROR_INVALID_PARAMETER); correct design implemented | `b60f296` |
| 'rDlPtS0Xe87ev' Inno anchor (brief's model) | **refuted** (exists in no tagged Inno ≥5.4.3 source); real anchor = `TSetupLdrOffsetTable` in `.rsrc` | `40c2fdd` |
| 16-byte NSIS firstheader (brief's model) | **refuted** (it is 28 bytes per fileform.h) | `84762a5` |
| Public docs advertise 76 as quarantine threshold | **refuted** (canonical #15; `scripts/check-threshold-docs.ps1` guards) | `8a18ed6` |
| ETW SDK constant `0x200` literal (introduced mid-round) | **confirmed bug, caught in cross-agent review, fixed** (SDK-sourced consts + cross-check test) | `b60f296` |

## IMPLEMENTED INVARIANTS

1. **Weak textual hints never activate security-reducing installer
   mitigation.** Enforced in exactly one place —
   `FrameworkDetection::build` (`crates/argus/src/layers/framework/mod.rs`):
   `mitigation_safe = confidence >= Corroborated && >=1 structural
   evidence source`; private field, no setter; overclaiming detectors
   downgraded to WeakHint. Tests: 13 invariant tests in mod.rs.
2. **Score mitigation requires full structural proof.** Engine-side
   policy (`FrameworkMitigation::evaluate`, `engine.rs`): confidence ==
   Structural AND mitigation_safe AND no high-confidence veto. Tampered
   archives (NSIS CRC mismatch), truncated downloads (Inno),
   unverifiable containers (Burn) get **no** mitigation. Tests:
   `mitigation_nsis_crc_mismatch_gets_no_mitigation` et al.
3. **Installer identity never erases malicious evidence.** Any
   pre-mitigation finding ≥ 40 vetoes mitigation entirely.
   Tests: `mitigation_high_confidence_finding_vetoes`,
   `mitigation_mime45_finding_vetoes`,
   `mitigation_adding_malicious_evidence_never_lowers_score`.
4. **Appending installer text cannot lower a threat score.**
   Metamorphic tests in `engine/adversarial.rs` +
   `tests/installer_spoofing.rs`.
5. **Session start ≠ working ETW.** `etw_running` derives
   conservatively from a stage machine (true only at ConsumerOpened+);
   zero events for 120 s → loud Degraded. `plm/etw_intake.rs`;
   tests: stage transitions, conservative derivation, zero-event alarm.
6. **ETW constants cannot drift from the SDK.** All mode/flag constants
   sourced from windows-crate bindings; `session_constants_match_sdk`
   test in etw_intake.rs + sandboxd equivalent.
7. **ETW properties storage is always correctly aligned.**
   `sentinella_common::etw_props` is the only constructor
   (compile-time align assert, checked arithmetic). 18+ layout tests;
   all three components migrated.
8. **Missing telemetry never becomes a fabricated default.**
   `CommandLineState` enum (cmdline.rs); 4 WeedHack signals pinned
   silent for every non-Present state (7 contract tests).
9. **One principal cannot consume the whole connection or request
   budget.** fairness.rs (8/SID, capped unidentified bucket) +
   policy.rs two-layer rate limiter (global ceiling unchanged).
   16 fairness/rate tests + live probe script.
10. **Secret-file ACLs converge at every startup, not just creation.**
    `acl::assert_secret_acl` on every vault-key load; data-root policy
    compare-first idempotent. 19 pure policy tests + opt-in elevated
    roundtrip.
11. **Quarantine threshold documentation cannot silently diverge.**
    `argus_only_quarantine_threshold_is_85_not_76` test +
    `scripts/check-threshold-docs.ps1` (31 files pass).
12. **New parsers are total functions.** Seeded truncation/mutation
    sweeps over pe/nsis/inno/wix/etw_props/cmdline parsers; fuzz
    targets + seed corpora in `fuzz/`.

## TESTS NOT RUN

| Test | Missing prerequisite |
|---|---|
| `etw_live_system_logger_delivers_events` (sentinelld, `#[ignore]`) | elevated Windows shell; run `cargo test -p sentinelld -- --ignored etw_live` |
| sandboxd `etw_live_system_logger_session_delivers_events` | same, `-- --ignored etw_live` |
| `acl::imp::tests::elevated_repair_roundtrip` | elevated shell; `-- --ignored acl` |
| Live libFuzzer runs (4 new + 5 old targets) | libfuzzer-sys 0.4 `FuzzerExtFunctionsWindows.cpp` needs MSVC `__pragma` semantics — MinGW g++ and gnu-target clang both fail on this box. Use WSL2/Linux or clang-cl. `scripts/fuzz-smoke.ps1` now reports BUILD-BLOCKED (exit 2) instead of fake crashes. |
| `scripts/probe-request-rate-fairness.ps1` post-fix pass | requires restarting the daemon/service on the new build (live box currently runs pre-fix v0.1.12 — probe correctly FAILs against it, demonstrating C-5) |
| Non-Windows `cargo check` | no non-Windows target installed; all Windows code cfg-gated by construction |
| GUI `tsc`/build | not touched this round; last green at v0.1.12 |

## KNOWN LIMITATIONS

- **No structural detectors for InstallShield/AdvancedInstaller/
  Qt/Squirrel/Go/Rust/Electron/MSI-OLE2.** Those frameworks now get ZERO
  leniency (fail-safe, FP-prone for large unsigned legit apps — bounded
  to Suspicious labels by the 85 bar). Highest-value follow-up:
  structural MSI validation via OLE2 stream-directory storage names.
- **NSIS probe window** is `[overlay_start, +512]` — stubs with larger
  own-overlay are missed (fail-closed; 7-Zip scans 1 MB). CRC_ANAL
  builds downgrade to Corroborated → no mitigation.
- **Inno pre-5.x** undetected (no verifiable source; fail-safe).
  Relinked stubs with renamed `.rsrc` false-negative.
- **WiX v4/v5 magic constants** inferred from identical layout; a future
  bump downgrades to WeakHint (fail-safe). `guidBundleId`/checksum
  unvalidated (matches engine's own static behavior).
- **CRC-32 anchors are forgeable** — a dedicated attacker can craft a
  fully consistent NSIS/Inno/Burn container. That *is* shipping the
  framework structure, the accepted cost model. The free evasion
  (injected strings) is what's closed.
- **Veto is weight-based (≥40) and evaluated pre-context-amplification.**
  Future high-weight layers must be consciously classified against
  `HIGH_CONFIDENCE_VETO_WEIGHT`; the ordering is load-bearing.
- **ETW config builder is triplicated** (sentinelld/sandboxd/etw_probe) —
  dedup into sentinella_common is deliberately deferred (the SDK
  cross-check tests guard drift meanwhile).
- **MOF parser offsets never validated against a live kernel stream**
  (needs elevated box; the ignored tests assert it).
- **ETW health `Degraded` keeps `etw_running=true`** by design;
  consumers should read `etw_stage`/`etw_zero_event_alarm`.
- **Defender FP** on freshly-linked sentinelld test binaries
  (Cryware.B heuristic) — transient; a `target\` exclusion is the
  operator fix.
- **Root DACL repair failure is fail-loud** (daemon continues degraded)
  — fail-closed is a product-policy decision not made here.
- **icacls localization**: write paths use raw SIDs + exit status
  (immune); display output is never parsed.
- **F-8 strengthened (76–84 cached clean)**, F-4 (unreadable → Clean),
  F-13 (pipe squatting), F-14 (oracles), F-11 (recon tier), F-3
  (path discount), F-6 (wmi.dll YARA FP): confirmed, deliberately not
  changed this round — each is a product-policy or corpus-gated
  decision, documented in `docs/IMPLEMENTATION_ROUND_MATRIX.md` and the
  external review.

## ATTACK THIS IMPLEMENTATION

Do not trust the test suite. Everything below is an entry point.

### Installer detection (highest value)

1. **Structural marker spoofing.** Forge a full NSIS firstheader with
   valid CRC-32 over your chosen span (CRC is forgeable — compute it).
   Expected secure: detector fires (it *is* structurally NSIS-shaped) —
   the real question is whether mitigation then lets a malicious payload
   through; combine with class 4. Files: `layers/framework/nsis.rs`.
   Harness: `fixtures::PeBuilder`, `tests/installer_spoofing.rs`.
   Falsifier: a forged-but-consistent archive getting mitigation AND
   dropping a real ≥85 detection below the bar.
2. **Overlay confusion.** Place the Inno offset table at the exact
   `.rsrc` section *boundary* (first/last bytes, straddling);
   NSIS header at overlay_start±1, at +512 exactly, at +513.
   Expected: boundary arithmetic follows the documented windows
   (off-by-one either way = bug). Files: `inno.rs`, `nsis.rs`,
   `pe.rs` (`overlay_start` computation).
3. **Section overlap / overlay-inside-section.** Declare sections whose
   raw ranges nest or overlap the header region or each other; declare
   raw_ptr+raw_size = u32::MAX. Expected: `parse` flags via warnings and
   overlay = max-of-ends (no smuggled overlay). Files: `pe.rs`.
   Sweeps: `engine/adversarial.rs`, fuzz target `framework_pe_parse`.
4. **Valid-installer-plus-malware.** Take a genuinely structural NSIS
   (fixture exists) and add IoC-weight evidence / dropper YARA.
   Expected: ≥40 veto → full score; ≤25 installer-YARA → /2 but label
   persists. Falsifier: any path where Structural classification +
   mitigation drops a ≥85 to <85. Files: `engine.rs`
   (`FrameworkMitigation::evaluate`, `HIGH_CONFIDENCE_VETO_WEIGHT`).
5. **Mitigation stacking.** Combine: structural NSIS + legacy "ASAR"
   string + name "setup.exe" + `.msi` rename + MZ/OLE2 polyglot.
   Expected: exactly one mitigation pass, WeakHints grant nothing.
   Test: `mitigation_stacked_weak_markers_grant_nothing` — extend it.
6. **Weak-evidence promotion.** Try to construct a `FrameworkDetection`
   with `mitigation_safe: true` without structural evidence — via
   `build` overclaim, via `append_warnings`, via serde, via a new
   EvidenceSource variant that is attacker-controllable but marked
   structural. Files: `framework/mod.rs` (the invariant's whole point).
7. **Parser differentials.** Compare against 7-Zip/innounp/unpackers:
   files they accept as NSIS/Inno that we reject (probe window, CRC
   strictness, `.rsrc`-only window) and vice versa. Falsifier: a
   differential that turns into a *security* gap (we accept, they
   reject, and acceptance grants mitigation).
8. **Polyglot/nested files.** MZ+PDF, MZ+ZIP, NSIS-inside-ZIP,
   Inno-signed-with-Appended-Authenticode (signed-tail case exists —
   extend past it), OLE2 named `.exe`, PE named `.msi`.
9. **Corpus regression.** Run `eval --compare-old-new` over a real
   installer corpus (MS Store/NSIS/Inno downloads) — hunt
   `lost_classification` entries that are GENUINE installers (the
   System32 run had zero; a real corpus is the honest test).
10. **TOCTOU scan→quarantine.** The fingerprint/verdict is computed on
    bytes read at scan time; swap the file between verdict and
    quarantine. Files: `sentinelld/src/scan/cache.rs`,
    `ipc/state.rs` quarantine path. Pre-existing, not introduced here.

### ETW

11. **Provider-disabled-but-healthy.** Force StartTraceW success with
    zero delivery (occupy 8 system-logger slots, or temporarily break
    the mode bit in a scratch build). Expected: stage ≤ SessionAlive or
    Degraded within 120 s, `etw_running=false`, snapshot boosted.
    Falsifier: any diagnostics surface still reporting healthy.
12. **Stage-machine confusion.** Drive rapid start/stop/fail sequences;
    error codes 5/87/1450/183/53 in odd orders. Expected: classifier
    dispositions hold, no resurrection from terminal stages, give-up
    after 5 counted failures. Files: `plm/etw_intake.rs`
    (`classify_start_error`, `set_stage`).
13. **Properties storage.** Call the shared storage with adversarial
    name lengths (0, 1, u32-boundary, interior NUL, usize::MAX).
    Expected: exact offsets, termination, overflow rejection.
    Files: `sentinella-common/src/etw_props.rs`; fuzz target
    `etw_props_layout`.
14. **Stale-session races.** Kill -9 the daemon mid-session; start two
    daemons; occupy the session name from another process.
    Expected: 183-class cleanup by name, Drop-join stop, no
    double-consume. Needs elevated live box.
15. **sandboxd drift.** Diff `sandboxd/src/etw_config.rs` against
    `plm/etw_intake.rs` config constants — the SDK cross-check tests
    are the tripwire; the triplication is the weak point.
16. **Malformed MOF payloads.** Fuzz the event parsers with real-ish
    headers + garbage bodies (NT device paths, truncated wide strings).
    Files: `etw_intake.rs:483-600`, `etw_image_load.rs`,
    `etw_file_io.rs`. Never validated against a live kernel stream —
    the richest unmined seam in the round.

### Command line / WeedHack

17. **Truncation/decoding.** UNICODE_STRING with odd lengths, extent
    past buffer, embedded NUL, missing terminator, 64 KiB+ claims.
    Files: `plm/cmdline.rs`; fuzz target `cmdline_decode`.
18. **Short-lived / protected processes.** Process exits between
    create-event and query (assert ProcessExited, not garbage); PPL
    (AccessDenied); 32-bit child under 64-bit daemon. Expected: correct
    non-Present states, signals silent. Live box required.
19. **Restored-signal FPs.** Craft cmdlines that *almost* match the 4
    restored WeedHack patterns (case, spacing, quoting, homoglyphs).
    Expected: no fire (matching unchanged); signals fire only on
    Present+match. Files: `plm/weedhack_runtime.rs`.

### ACL

20. **Inheritance/reparse tricks.** Data root as junction to
    attacker dir; vault key as hardlink/symlink; child with hostile
    owner; deny-ACE ordering; SDDL parser differentials (hex vs letter
    rights, SID aliases, duplicate ACEs). Files: `sentinelld/src/acl.rs`.
    Falsifier: a permissive effective ACL the policy comparer calls
    conforming.
21. **Repair race.** Two repairs concurrently; kill mid-repair
    (`icacls /reset /T` interrupted); read-only FS. Expected:
    idempotent convergence or loud fail-closed for secrets.

### IPC

22. **Fairness bypass.** Rotate SIDs (multi-user malware), churn
    processes to stress the unidentified bucket (cap 16), hold 8
    connections per SID across N SIDs (global 64), race permit
    release/reacquire, disconnect mid-frame. Files: `ipc/fairness.rs`,
    `ipc/policy.rs`. Falsifier: a second principal starved, or
    unbounded map growth (256-entry LRU is the bound — attack it).
23. **Serialization mismatch.** Old argusd JSON ↔ new sentinelld and
    vice versa (framework_mitigation present/absent); GUI against the
    new diagnostics fields. Expected: serde(default) both directions —
    verified by grep, attack with real skewed binaries.

### Scoring/provenance

24. **Provenance mismatch.** Compare `framework_mitigation` trace
    against recomputed weights for a corpus — any op where
    before/after doesn't match the actual finding weights is a lie in
    the audit trail. Harness: `eval --json`.
25. **Veto gaming.** Craft findings at weight 39 (just under veto)
    across many layers to stack near-cap scores with mitigation ON;
    or push one finding to 40 to veto mitigation on a legit installer
    (FP direction). Files: `engine.rs` veto + cap ordering
    (`aggregate_score`).

## Exact build/test transcript

```
cargo check --workspace --all-targets        # clean, 0 warnings
cargo test --workspace                       # see totals above; 0 failed
cargo test -p sentinelld -- --ignored etw_live acl   # NOT RUN (needs elevation)
cargo check --manifest-path fuzz/Cargo.toml  # compiles
scripts/fuzz-smoke.ps1 -Quick -Target fuzz_paths     # BUILD-BLOCKED (exit 2, toolchain)
powershell scripts/check-threshold-docs.ps1          # OK, 31 files
scripts/probe-request-rate-fairness.ps1              # FAILs against pre-fix daemon (demonstrates C-5) — rerun post-deploy
cargo run --example eval -p argus --release -- <corpus> --compare-old-new --json --report out.txt
```

## Commit-by-commit summary

`e9f980d` F-9 watch roots · `8a18ed6` threshold docs + guard · `5a32ee7`
connection fairness · `a585857` aligned ETW storage (all components) ·
`9ca37df` verification matrix · `afe8749` DACL policy + vault-key
re-assert · `b60f296` ETW system-logger reconstruction (F-1) ·
`8495927` sandboxd/etw_probe parity (C-1) · `fec0328` request-rate
fairness (C-5) · `854d80a` framework evidence model + PE parser (P) ·
`c8bd050` command-line capture + WeedHack restoration (M+N+O) ·
`84762a5` NSIS detector (Q) · `03376b5` WiX/Burn detector (S) ·
`aa51656` warning cleanup · `40c2fdd` Inno detector (R) · `8449cda`
mitigation integration + provenance (T+U) · `e8335e9` corpus
instrumentation (Z) · `2e9178c` changelog · `e56e3f9` adversarial suite
+ fuzz (X+Y).

## Final diffstat

`git diff --stat 06229a8..HEAD`: **80 files changed, +15,558 / −716.**

---

## ROUND-2 RE-VERIFICATION (independent adversarial review of this round)

A second verifier re-ran headline claims and attacked the five
highest-risk surfaces empirically (compiled + crafted inputs through the
shipped scanner). 17 confirmed findings (7H/6M/4L), 6 refuted. Disposition:

**Fixed (4 commits, 2026-07-30):**
- **ACL hardening was a local privilege escalation (HIGH)** — `icacls /T`
  follows junctions; reproduced unelevated. Replaced with a verified
  Rust-side walk (never `/T`; reparse entries skipped + counted) and fixed
  the root-reset convergence bug → `2dadc63`.
- **Fairness re-keyed (HIGH)** — SID-only keying put same-user malware and
  the GUI in one bucket (lockout 8× cheaper). First-party pool keyed on
  kernel-reported image path under the trusted install dir → `722703e`.
- **Inno needle-flood DoS (HIGH, measured 472 s/100 MB)** — candidate
  cap (32) before any CRC work + `engine.rs` budget/cancel guard on
  framework detection → `651640f`.
- **ETW wrong-process command line (HIGH)** — header PID is the creator
  on process-start; now keyed on payload PID/PPID → `a03be54`.
- **Command-line privacy (MEDIUM)** — `CommandLineState` redacts on
  serialization (len + truncated hash, never raw) → `a03be54`.
- **Transient-error permanent give-up, discarded `ProcessTrace` result,
  unreachable shutdown join, 183 livelock (MEDIUM/LOW)** — persistent-vs-
  transient classifier, stream-loss → Failed+reconnect, explicit
  `PlmMonitor::shutdown()` wired into main, bounded stale cleanup → `a03be54`.

**Held for design decision (as the verifier recommended):**
- **F-7 NSIS anchor strength** — the detector grants Structural for a
  28-byte self-consistent firstheader; `FH_FLAGS_NO_CRC` skips CRC;
  512-alignment is stock. Forgery cost rose from a 13-byte string to a
  28-byte header + (usually) a CRC — real but not decisive. Options:
  (a) decompress+validate the header block (real archive proof),
  (b) refuse mitigation when NO_CRC is set, (c) accept the cost model.
  **Open** — guessing here has burned us twice; decide with corpus data.

**Verifier's process note adopted:** verification must assert per-suite
test counts, not just `0 failed` — the Defender FP silently dropped the
entire 552-test sentinelld suite from one run. Refuted items, and the
good work they confirmed, stand as recorded above.

Final state: 24 commits `06229a8..HEAD`; **1,020 tests, 0 failed**;
`cargo check --workspace --all-targets` 0 warnings.

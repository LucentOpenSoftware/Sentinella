# Competitive Gap Analysis — Sentinella vs ESET (2026-07-30)

Source: adversarial-review session following the v0.1.12 implementation
round. Sentinella-side claims verified against the code (this file's
appendix); ESET-side claims from ESET's own v19 help trees, with two
caveats flagged inline. This document deliberately does **not** frame
the gap as "feature parity": parity with ESET is three companies' worth
of work — a detection engine, a network stack, and a cloud/enterprise
business. The useful split is "what makes Sentinella not-yet-an-AV"
versus "what's suite bloat."

## Tier 0 — Structural. Everything else is downstream of these.

| Gap | Reality today | Verification |
|---|---|---|
| **Kernel minifilter / on-access driver** | None. Realtime = user-mode `notify` crate (`ReadDirectoryChangesW`), **post-write only** | no `FltRegisterFilter`/`.sys` in tree |
| **Pre-execution / process-creation blocking** | None. Cannot stop a file from running, only notice it afterwards | follows from the row above |
| **Windows Security Center registration** | Not registered — Windows still treats Defender as the active AV | no `WscRegister*`/`IWscProduct` anywhere |
| **AMSI provider** | `AmsiMonitor` is dead code — defined, `#[allow(dead_code)]`, never instantiated; no COM provider | `amsi/mod.rs:24`; `ipc/state.rs:4726` reports `"AMSI provider not yet registered"` |
| **Self-protection driver / ELAM** | User-mode only (service DACL + `runtime_integrity.rs`) | — |

The first row is the ballgame. A minifilter **blocks a file open until
the scan returns a verdict**; a directory-change watcher learns a file
appeared *after* it already exists and possibly after it already
executed. Every "real-time protection" claim rests on that distinction.
It is a category difference, not a feature gap.

## Tier 1 — Missing protection surfaces (real AV features, buildable without a company)

- **Web protection**: no URL/DNS filtering, no phishing blocking, no
  browser extension, no HTTPS inspection.
- **Firewall + network attack protection**: none. The only firewall use
  is `sandboxd` writing temporary block rules for a detonated sample.
  (ESET also: botnet protection, brute-force protection, network
  inspector.)
- **Email / mail-client scanning**: none.
- **Removable media / USB control + autorun protection**: none —
  `targeting/full_disk.rs:46-61` scans only `DRIVE_FIXED`; removable
  and network drives are explicitly out of scope.
- **Rootkit scanner, MBR/bootkit, UEFI scan, boot-time scan, rescue
  media**: none.
- **Exploit mitigation / HIPS ruleset / ASR rules**: none.
- **Application control / allowlisting**: none.

## Tier 2 — Requires infrastructure to *operate*, not just write

- **Cloud reputation** (LiveGrid equivalent) — a service, a telemetry
  pipeline, and a privacy policy.
- **Cloud sandbox** (LiveGuard equivalent).
- **ML/AI classification model** — needs a labelled corpus that does
  not exist yet.
- **Threat-intel feed + research team producing detections.**
- **Signed update-manifest pipeline** — already on Sentinella's own
  deferred list (`docs/DEEP_AUDIT_2026-07.md`).

## Tier 3 — Enterprise (a second product entirely)

Central management console; EDR/XDR (telemetry store, incident
timeline, remote response: isolate/kill/remediate); multi-tenancy +
RBAC; SIEM/syslog forwarding; full-disk encryption; MDM;
vulnerability/patch management; Server/Exchange/Cloud-Office variants.

## Tier 4 — Suite bloat. Do not chase.

Password manager, VPN, identity monitoring, parental control,
anti-theft, webcam/mic guards, antispam, PC tune-up, file shredder.
None of it is antivirus; all of it is surface area and support burden.
For a local-first open-source AV this tier is worth **nothing**.

## What Sentinella *does* have (for balance)

15 ARGUS analysis layers, ClamAV + YARA + IOC, structural
installer-framework detectors, trust graph, ecosystem correlation,
convergence ledger, ransomware shield (FISH), sandbox, memory scanner,
process lineage (post-F-1 ETW fix), WeedHack campaign tracker,
quarantine, scheduler, idle scanner, 12-page bilingual GUI. The static
engine is genuinely substantial — the gaps are concentrated in *where
and when* it runs, and in everything network-facing.

## The list that matters more than any of the above

Features that **exist but don't work** are worse than missing features,
because they're claimable:

- **No true-positive measurement exists.** The only measured number is
  an FP *bound* (0/100 clean System32 at Suspicious+), which leaned on
  the −20 path discount absorbing 804 points of structural noise.
  `test-corpus/` is 24 synthetic files that all score 0.
- **ETW MOF parser offsets never validated against a live kernel
  stream**; live-delivery tests are `#[ignore]`d and unrun.
- **ARGUS-only 76–84 is silently dropped** — engine says Malicious,
  product records nothing (documented, unchanged).
- **Unreadable/blocked files return Clean** (fail-open).
- **8 installer frameworks now get zero leniency** (InstallShield, Qt,
  Squirrel, Go, Rust, Electron, AdvancedInstaller, OLE2 MSI) —
  fail-safe but FP-prone on large unsigned legitimate apps.
- **libFuzzer targets don't build** on the current toolchain
  (`FuzzerExtFunctionsWindows.cpp` needs MSVC `__pragma` semantics), so
  the seed corpora have never been exercised by a real fuzzer.

## Recommendation (from the review session)

Parity is the wrong target right now. Two items dominate:

1. **Measure the detection rate.** Nobody knows whether Sentinella
   catches malware. The harness (`crates/argus/examples/eval.rs`) and
   the corpus plan (`docs/EXTERNAL_REVIEW_v0.1.12.md` §3.6) exist;
   without a TP number, tuning is guesswork and parity discussion is
   premature.
2. **The minifilter.** Not because ESET has one, but because without
   it "real-time protection" means "we notice afterwards." It is the
   difference between an antivirus and a file auditor.

Everything in Tier 1 is worth more than Tiers 2–4 combined.

## Caveats on ESET-side claims

- ESET's official docs confirm `ekrn.exe` runs as a protected process;
  ELAM and Security Center registration could **not** be confirmed from
  ESET's own documentation (only forum/KB threads) — not asserted here.
- Tier attribution across Essential/Premium/Ultimate was inferred from
  which product help tree documents each feature, since ESET's
  comparison tables render inconsistently.

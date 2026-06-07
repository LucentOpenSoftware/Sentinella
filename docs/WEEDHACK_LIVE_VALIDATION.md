# WeedHack Runtime — Live Validation & Tuning Runbook

This is the operator-side companion to Wave 8. The synthetic test suite
(`cargo test`) exercises every code path; this runbook describes the
**live runs on a real Windows desktop** that must complement those
tests before the WeedHack stack is considered production-ready.

> Why a runbook and not a script? Live validation is **observation
> work** — the daemon runs, real users do real things, the operator
> watches counters and notes surprises. The script automation here is
> for capture (Phase 5), not for autonomous validation.

## Pre-flight

- Build: `cargo build --release -p sentinelld` (or use the installer).
- Confirm the diagnostics endpoint shape with a synthetic positive:
  `cargo test -p sentinelld live_pattern_synthetic_full_chain_reaches_confirmed`
- Locate the IPC secret:
  - Dev: `<repo>\runtime\state\ipc_secret`
  - Installed: `%ProgramData%\Sentinella\state\ipc_secret`

## Phase 1 — Admin vs non-admin behavior

### Non-admin run

1. Start the daemon as a normal user (no Administrator elevation).
2. Wait 60 seconds.
3. Run `scripts\collect-weedhack-runtime-diagnostics.ps1` to capture.
4. **Verify** in the captured JSON:
   - `weedhack_campaigns.image_load_etw.running == false`
   - `weedhack_campaigns.image_load_etw.access_denied == true`
   - `weedhack_campaigns.image_load_etw.gave_up == true`
   - `weedhack_campaigns.fileio_etw.running == false`
   - PLM fallback to snapshot mode is logged once (no spam).
5. **Verify** in `tail -F` on the daemon log: no repeated
   `access denied` lines — the retry-cap should fire after 5 attempts
   and then go silent.

### Admin run

1. Start the daemon elevated.
2. Wait 60 seconds.
3. Collect.
4. **Verify**:
   - `image_load_etw.running == true`
   - `image_load_etw.events_seen > 0` and growing
   - `fileio_etw.running == true`
   - `fileio_etw.events_seen > 0` (will be much larger than image_load)
   - `weedhack_campaigns.active == 0`
   - `weedhack_campaigns.confirmed_total == 0`

## Phase 2 — Normal-desktop baseline (30–60 minutes)

With the daemon running elevated, exercise normal workloads:

- Chrome browsing (incl. signed-in Gmail / Google Drive)
- Edge browsing
- Firefox browsing (if installed)
- Open Discord, idle in a channel
- Launch Minecraft via official launcher, play a vanilla world for 5 min
- Open IntelliJ / VS Code and build a small project
- Normal file activity (copy folders, open Office docs)

Collect once at the end. Read counters. Acceptance criteria:

| Counter | Expected |
|---|---|
| `image_load_etw.events_seen` | Tens of thousands |
| `image_load_etw.signals_emitted` | **0** ideally; small if any |
| `image_load_etw.signer.trusted` | Much larger than `untrusted+unknown` (cache warms) |
| `image_load_etw.signer.cache_hits` | Dominant over `cache_misses` after first 5 min |
| `fileio_etw.events_seen` | Hundreds of thousands |
| `fileio_etw.events_filtered` | ~99% of events_seen (substring prefilter drops most) |
| `fileio_etw.wallet_store_hits` | Single-digit during normal browsing (your own Chrome Login Data, your own Discord LevelDB) |
| `fileio_etw.burst_signals` | **0** |
| `http_intake.events_seen` | 0 unless an upstream source is wired |
| `weedhack_campaigns.confirmed_total` | **0** — non-negotiable |
| `weedhack_campaigns.high_confidence_total` | **0** ideally |
| `weedhack_campaigns.suspicious_total` | 0 ideally; anything > 0 must be explainable |

### CPU / memory baseline

Measure with `Get-Process sentinelld | Select-Object CPU, WorkingSet, PrivateMemorySize64`:

- Expected steady-state CPU: < 2% averaged over 5 min
- Expected working set: < 200 MB (depends on overall daemon)
- ImageLoad ETW + FileIO ETW combined overhead: < 0.5% CPU additional
  vs. the same workload with WeedHack waves disabled

If any number is out of range, the tuning workflow in **Phase 4** applies.

## Phase 3 — Synthetic positive validation

The full Confirmed-tier path is exercised by:

```sh
cargo test -p sentinelld live_pattern_synthetic_full_chain_reaches_confirmed
```

For an **end-to-end live test through the running daemon**, you can
inject events via the public ingestion APIs from a small Rust binary or
PowerShell that imports the crate. The pipeline is intentionally
public-API-driven:

```rust
plm.ingest_image_load(ImageLoadRawEvent { ... });
// 3x calls to detector.observe_file_read via FileIO sim
plm.ingest_http_post(HttpPostRawEvent { body_snippet: Some(jsonrpc_with_selector), ... });
```

After all three: collect diagnostics. **Verify**:

- `weedhack_campaigns.confirmed_total == 1`
- `weedhack_campaigns.recent_findings[]` contains a `confirmed` tier entry
- The UI Intelligence page surfaces the campaign panel with red tier badge

The next file-scan trigger on that PID's chain will route a Critical
finding through `ConvergenceLedger` per Wave 2 — no ETW-driven bypass.

## Phase 4 — Noise tuning workflow

If Phase 2 produces unexpected signals:

1. **Triage**: read `recent_findings` narrative. Identify which signal
   class fired (BrowserInjection / WalletHarvest / EtherHiding / chain).
2. **Reproduce**: write a synthetic test in
   `crates/sentinelld/src/plm/mod.rs::tests` mirroring the live trigger.
   Assert the surprising tier first to confirm the reproduction works,
   then assert the *desired* outcome.
3. **Tune**: adjust the relevant constant:
   - Wave 3: `USER_WRITABLE_MARKERS` or `BROWSER_IMAGES` in
     `weedhack_browser_injection.rs`
   - Wave 5: cache TTL or signer mapping in `wintrust_verifier.rs`
   - Wave 6: `WALLET_PATH_MARKERS` in `etw_file_io.rs`
   - Wave 6: `canonical_key` in `weedhack_wallet_harvest.rs`
   - Rate limits in any pump
4. **Run the new test + full suite**: `cargo test --workspace`
5. **Document the rationale** in the PR description.

**Do NOT** change campaign scoring (Wave 1 tier rules) unless every test
in `weedhack_campaign::tests::tier_*` is updated with explicit rationale.

## Phase 5 — Diagnostics collection

`scripts\collect-weedhack-runtime-diagnostics.ps1` ships with the daemon.

Usage:

```powershell
# Public health only (no auth):
.\scripts\collect-weedhack-runtime-diagnostics.ps1 -NoAuth

# Full diagnostics (auto-discovers secret):
.\scripts\collect-weedhack-runtime-diagnostics.ps1

# Explicit secret path:
.\scripts\collect-weedhack-runtime-diagnostics.ps1 `
    -AuthSecretPath C:\ProgramData\Sentinella\state\ipc_secret `
    -OutputDir C:\temp\weedhack-snapshots
```

Output: timestamped JSON file with **defense-in-depth scrubbing**:
- Fields named `*_path`, `url`, `host_hint`, `body_snippet`,
  `command_line`, `narrative`, `description`, `technical_detail` are
  redaction-stubbed even though the daemon already redacts at source.
- Strings matching `^[A-Z]:\` (Windows paths) or `^https?://` are
  replaced with `[redacted-path]` / `[redacted-url]`.
- Counters, canonical store keys (`chromium:login-data` etc.), tier
  names, PIDs preserved.

Share these JSONs in regression-test PRs — they document the live state
the test reproduces.

## Phase 6 — Regression test discipline

Every false-positive or surprising live behavior **must** be turned
into a test before any tuning lands:

1. Pull the relevant slice from the diagnostics JSON.
2. Add a `live_pattern_*` test in `plm::tests` that constructs the same
   chain / signal sequence.
3. Assert the *current* (incorrect) behavior — the test fails.
4. Tune. Test passes.
5. Re-run the full suite.

This is the "no untested tuning" rule from the Wave 8 spec.

## Phase 7 — Remaining risks (operator-visible)

- **Java-based crypto wallet** (none mainstream) that legitimately calls
  Eth-RPC with the WeedHack selector pattern: extremely unlikely;
  HighConfidence tier ceiling alone, requires corroboration for
  Confirmed.
- **Corporate Java agent** that writes to `\Microsoft\SecurityUpdates`
  (impersonating the WeedHack path) for legitimate purposes: would emit
  `SecurityUpdatesAppData` chain signal. Operator can add allowlist or
  rename the corporate folder.
- **Active staking node** running Java-based Ethereum client (Besu /
  Teku) generating constant Eth-RPC traffic: not currently observable
  since the WinHTTP body capture is dormant; if Java-side
  instrumentation is added in a future wave, an allowlist for
  known-staker process images may be needed.

## Quickref — when to escalate

| Live observation | Action |
|---|---|
| ImageLoad signal during normal Chrome update | Capture diagnostics, reproduce, tune `USER_WRITABLE_MARKERS` |
| FileIO Suspicious during password-manager use | Capture, reproduce, tune `WALLET_PATH_MARKERS` (likely already excluded since canonicalization scopes to wallet-specific filenames) |
| HighConfidence during normal use | Stop. Capture. Reproduce as test first. Do not tune blindly. |
| Confirmed during normal use | Stop immediately. This shouldn't happen without 3 distinct signals — file a bug with the diagnostics JSON attached. |
| CPU > 5% sustained | Check rate limits + cache hit ratios in diagnostics |
| `events_dropped` growing | Channel under pressure — investigate worker latency before raising capacity |

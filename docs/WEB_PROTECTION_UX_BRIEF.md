# Web protection: from "built" to "usable" — implementation brief

Audience: implementer working without access to the conversation that
produced this. Everything you need is here or cited by path.

## Where the feature actually is

The daemon subsystem is complete and hardened: DNS proxy, four-step
self-test, NRPT rule installation, out-of-process boot reconciler, liveness
watchdog, 30-second upstream re-discovery. That part is not your task and
should not be modified except where this document says so.

Everything a user would touch is missing:

| piece | state today |
|---|---|
| IPC surface | one method, `webprotection.status`, read-only |
| GUI | **zero** files reference web protection |
| `[web_protection]` in `FullConfig` | absent — no IPC mutation path exists |
| `[web_protection]` in the shipped `sentinelld.toml` | **not written by the installer** |
| Blocklists | `Vec::new()`; the field holds FILE PATHS the operator supplies |

Read that last row carefully. **Nothing ships or downloads a blocklist.**
`release/staging/windows/runtime/rules/` contains only `ioc_hashes.txt`,
which belongs to ARGUS, not DNS. Fully enabled, web protection today blocks
nothing except its own canary domain. It is a filtering engine with no
filter.

Turning it on at all currently means hand-writing a config section the
installer never creates, then restarting the daemon.

## The governing rule, which overrides every other consideration here

> **Under any uncertainty the system degrades to "no filtering", never to
> "no DNS".**

A machine that cannot resolve names is broken in a way that a machine
without domain blocking is not. Every design decision in this subsystem
follows from that sentence. If a change you are making could leave an NRPT
rule pointing at a listener that is not answering, the change is wrong, and
"it only happens if X crashes" is not a defence — X crashing is the case the
rule exists for.

## What is IN scope for you

Four tasks, ordered by what unblocks what. **Do not start task 3 or 4 before
task 1 is merged** — they consume its wire schema.

---

### Task 1 — `[web_protection]` on the config wire

**Files you own**: `crates/sentinella-ipc-proto/src/full_config.rs`,
`crates/sentinelld/src/config/mod.rs`.

`Config.web_protection` exists (`crates/sentinelld/src/web_protection/config.rs`,
`WebProtectionConfig`) but has no counterpart in `FullConfig`, so
`settings.set_full` cannot reach it and `critical_diff` does not guard it.

Add the mirror, and add every field path to:
- `FullConfig` itself (a `WebProtectionSection` sub-struct, mirroring how
  `fish` and `sandbox` are handled — follow the existing shape exactly),
- `impl From<&Config> for FullConfig` (`config/mod.rs`, near the existing
  `signature_stale_notify_days` line),
- `Config::apply_non_critical` (same file),
- `RestartRequirementMap::build()`'s path list,
- `CRITICAL_FIELDS`.

**THE TRAP THAT MADE THIS DEFERRED ONCE ALREADY.** `FullConfig` is
`#[serde(default)]`. If you land the daemon half without the GUI sending the
section, an older or partial GUI PUTs a `FullConfig` with the section
missing, serde fills it with `Default`, and `apply_non_critical` writes those
defaults over the user's settings — silently turning web protection off, or
worse, changing `listen` while a rule is live. **Both halves must land in the
same change**, and the GUI must round-trip the section it received. There is
a test for exactly this class in `config/mod.rs`
(`apply_non_critical_preserves_kill_vector_fields`) — extend it, do not
replace it.

**Classification**: every `web_protection.*` path goes in `CRITICAL_FIELDS`.
Changing `listen`, `upstreams` or `enabled` is a kill vector: it can take
DNS off the machine. They must require `protection.set_critical` (challenge
token + UAC), never plain `settings.set_full`.

**Restart requirement**: mark them `DaemonRestart` for now. Hot enable/disable
is task 3 of the OTHER list (not yours) and until it exists, claiming
`None` would be a lie the GUI repeats to the user.

**Done when**: a round-trip test proves a `FullConfig` built from a `Config`
with a non-default `[web_protection]`, serialised, deserialised and applied,
yields the identical section — and a second test proves a payload with the
section ABSENT leaves the stored config untouched rather than defaulted.

---

### Task 2 — Blocklist provisioning

**Files you own**: new module under `crates/sentinelld/src/web_protection/`,
`scripts/stage-windows-package.bat`, `scripts/release-sanity-windows.bat`,
`gui/src-tauri/nsis-hooks.nsh`.

Without this the feature has no content. Deliver:

1. **A bundled starter list.** Ship one blocklist in
   `release/staging/windows/runtime/rules/dns/` and have the installer copy
   it to `%ProgramData%\Sentinella\rules\dns\`, alongside how
   `signatures_bootstrap` is handled today (`nsis-hooks.nsh`, the
   `main/daily/bytecode` block — copy that structure, including the
   per-file "already present?" guard so an update never overwrites a list
   the user has since replaced).
2. **A fetcher** that refreshes lists on the existing signature-update
   cycle. `crates/sentinelld/src/updater/mod.rs` is the model: it is
   invoked from `AppState::start_update` in `ipc/state.rs`. Add the list
   refresh to the same cycle so there is one update story, not two.
3. **Staging + sanity coverage.** Both scripts must fail loudly if a list is
   missing, the way `:check_either` does for the signature databases. A
   release that ships an empty filter must not pass sanity.

**Format**: the config field is `Vec<String>` of `path` or `path|suffix`
specs (see `load_lists` in `web_protection/service.rs`). Parsing already
exists in `crates/dnsguard/src/filter.rs` and handles hosts-file syntax —
do not write a second parser.

**Licensing is a decision, not an implementation detail.** Propose the
source (StevenBlack, oisd, hagezi are the obvious candidates) and its
licence terms in the PR description; do not simply pick one and vendor it.
The project is GPLv2 and attribution obligations must be met in `NOTICE.md`.

**Do NOT** make the fetcher able to disable filtering on failure. A list
that fails to download leaves the previous list in force; an empty list is
never installed over a working one. `filter.rs`'s partial-load semantics
already distinguish "truncated" from "failed" — use them.

---

### Task 3 — GUI surface

**Files you own**: `gui/src-tauri/src/lib.rs`, `gui/src/api/sentinella.ts`,
`gui/src/types/sentinella.ts`, a new `gui/src/pages/WebProtection.tsx`,
`gui/src/pages/Dashboard.tsx`, `gui/src/i18n/en.ts` + `es.ts`.

The IPC method already exists and is auth-gated. Wire it exactly like the
watcher status does:

```rust
// gui/src-tauri/src/lib.rs, next to get_watcher_status (line ~270)
#[tauri::command]
async fn get_web_protection_status() -> Result<Value, String> {
    daemon_client::call_auth("webprotection.status", serde_json::json!({}))
        .await
        .map_err(Into::into)
}
```
Register it in the `invoke_handler` list, then add the TS binding beside
`getWatcherStatus` (`api/sentinella.ts` line ~177).

**The response shape** is `WebProtectionStatus`
(`crates/sentinelld/src/web_protection/status.rs`). Transcribe it into
`types/sentinella.ts` by hand — **the TS types are NOT generated from the
Rust**, so `tsc` is structurally blind to drift here. That is precisely how
a settings control shipped inert in 0.1.13.

**THE ONE RENDERING RULE.** The status reports intent and fact as separate
fields, deliberately:

- `enabled` — what the user asked for (config).
- `nrpt_installed: Option<bool>` — whether a rule of ours is on the system
  right now, read back from the registry.

`None` means **"could not tell"** and is NOT `Some(false)`. Rendering it as
"not installed" claims knowledge you do not have. Render the three states
distinctly. A UI that shows only `enabled` will tell a user they are
protected when the rule is absent — that is the specific failure this split
exists to prevent.

Also surface `state` (`Disabled | BindFailed | SelfTestFailed | Serving`)
with its `detail` string. `BindFailed` almost always means something else
owns `127.0.0.1:53`, and saying so is the difference between a user fixing
it and filing a bug.

**Dashboard tile**: follow `StatusTile` in `Dashboard.tsx`. Colour by the
combination, not by `enabled` alone.

**No toggle yet.** Until hot enable/disable exists, a toggle would either lie
or require a restart it does not mention. Render state only, and link to
Settings.

**i18n**: `en.ts` and `es.ts`. Do not machine-translate the other seven —
they fall back to English by design (`gui/src/i18n/index.ts`).

---

### Task 4 — Network-change subscription

**File you own**: `crates/sentinelld/src/web_protection/upstreams.rs` (add a
subscriber; leave `resolve()` alone).

Today `service.rs` re-discovers upstreams every 30 seconds
(`UPSTREAM_REFRESH_INTERVAL`). That closes the indefinite outage but reacts
slowly: connect a VPN and up to 30 seconds of DNS goes to resolvers that no
longer answer.

Replace the poll with a `NotifyIpInterfaceChange` subscription
(`Win32_NetworkManagement_IpHelper`), **keeping the poll as a fallback** at a
longer interval. Callback-driven FFI in a service that must not crash: the
callback must do nothing but signal a channel — no allocation, no locks, no
logging inside it.

`UpstreamsHandle::set` already validates and **keeps the previous list on
error**. Preserve that: a change event that yields an empty or invalid list
must leave the working list in place. Degrading to "stale but working"
beats degrading to "no resolver".

---

## What is NOT in scope for you

Do not implement these. They are being handled separately because each one
can take DNS off a machine, and they need the design decisions made first:

- **Hot enable/disable** (`WebProtection::start`/`stop` driven at runtime by
  IPC). Currently `start` is called once from `main.rs`. Every transition
  installs or removes an NRPT rule.
- **Pause with auto-resume** ("disable for 10 minutes"). An expiry that
  fails to fire leaves the rule live with the proxy stopped.
- **Anything under `crates/nrpt/`, `crates/sentinella-dnsreconcile/`, or
  `web_protection/rule.rs`.** These own the rule lifecycle. If a task above
  seems to need a change there, stop and say so instead.

## Ground rules

- **Preserve CRLF** in files that use it; this repo is mixed.
- **Tests must fail if the fix is reverted.** A test that passes either way
  is worse than no test — it certifies the bug. Before submitting each one,
  revert your change mentally and ask whether it still passes.
- **Every comment you write must be true of the code beside it.** This
  project has been bitten repeatedly by confidently wrong comments: a doc
  describing a mechanism that was deleted, a header claiming two subsystems
  were unimplemented when both shipped, a "same threshold as X" that was off
  by nine points. If you are unsure whether a claim still holds, check it or
  do not write it.
- `cargo test --workspace` and `npx tsc --noEmit` (from `gui/`) must be
  clean. State what you ran in the PR.
- If a finding contradicts this brief, the code wins — say so rather than
  implementing something you can see is wrong.

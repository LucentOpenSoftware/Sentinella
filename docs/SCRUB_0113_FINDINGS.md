# 0.1.13 defect scrub — 91 confirmed findings

20 independent review lenses across the whole shipping surface, up to 10
findings each; 181 candidates, each attacked by a separate agent instructed
to refute it and to default to refuted when uncertain. 90 were refuted.
201 agents.

Severity: 22 critical, 14 high, 23 medium, 32 low.
62 of the 91 predate the 0.1.13 work.

## Status

| | |
|---|---|
| 22 critical (6 distinct defects, each found by several lenses) | CLOSED — `4b1e690` |
| 54 of the remaining 69 | CLOSED — `8cad296` |
| cross-group handoffs | CLOSED — `353e938` |
| 2 findings | REJECTED: wrong on inspection |
| 4 findings | DEFERRED: redesigns, listed below |

Fixes were made by seven agents with exclusive, disjoint file ownership,
each group then audited by a separate agent that could not edit anything.
That audit caught five fixes that had only landed halfway and two comments
that asserted something untrue of the code beside them.

## Still open

1. **`[web_protection]` has no IPC mutation path at all.** It is absent from
   `FullConfig`, so `settings.set_full` cannot reach it and `critical_diff`
   never guards it. Deferred because `FullConfig` is `#[serde(default)]`:
   landing the daemon half alone would let an older GUI silently reset the
   whole section to defaults, which is worse than the gap.
2. **`update_mirror` is inert.** Validated, clamped, persisted and rendered
   as an editable field that no code reads — freshclam gets a hardcoded
   `DatabaseMirror`. Either template it into `freshclam.conf` or remove the
   setting; today the UI claims it works.
3. **The dnsguard response cache has no eviction policy.** Once full it stops
   caching new names entirely until entries expire. The byte cap is closed;
   choosing an eviction policy is a design decision, not a defect fix.
4. **217–228 UI keys missing from 7 locales.** Machine-translating
   security-critical settings labels would be worse than the English
   fallback that renders today.
This list was built from the raw findings rather than from the state after
the fixes, so it originally also named the freshclam CDN cool-down. That one
is CLOSED in `8cad296`: `freshclam_output_is_cooldown` splits the cool-down
run out before anything stamps `last_update_timestamp`, matching
"cool-down until after" rather than the bare word, because freshclam logs
"Cool-down expired, ok to try again." immediately before a real fetch and
matching that would suppress the freshness stamp on every recovery run.

Findings below are listed most-severe first, each with file, line, failure
scenario and the evidence it was verified against.

---

## 1. [CRITICAL] crates/sentinelld/src/web_protection/service.rs:171  <nrpt-registry>

`WebProtection::start` never reconciles a pre-existing live NRPT rule when it refuses to serve, and the out-of-process reconciler only runs at BOOT — so a daemon crash plus an SCM restart leaves the machine with a catch-all rule pointing at a dead listener until the next reboot.

**Failure:** Machine has web_protection.enabled=true, healthy, rule G live, %ProgramData%\Sentinella\state\nrpt-rule.guid contains G. sentinelld is killed non-gracefully (panic, `taskkill /F`, the SCM's 30s stop timeout, OOM) — `stop()` never runs, so rule G stays in HKLM. Windows service recovery (`sc failure ... restart/5000`, nsis-hooks.nsh:124) restarts the daemon 5s later. `Proxy::bind` fails because the dead process's UDP socket on 127.0.0.1:53 is not yet released → `Self::refused(ProxyState::BindFailed, ...)` at line 228, `rule_guid: None`. Nothing in this path calls `nrpt::recorded_guid` + `nrpt::remove_rule`. Rule G is still routing every name on the machine to 127.0.0.1:53 where nothing is listening. The daemon never retries, the watchdog was never spawned, and the boot reconciler is a BootTrigger task — it will not run again until reboot. The machine has NO DNS, indefinitely, and `webprotection.status` reports `nrpt_installed: null` ("could not tell") because `installed_now(None)` returns None. Identical outcome via the self-test path (line 252-274) and via `enabled=false` (line 172) if config was edited between the crash and the restart. mod.rs:41-45 asserts the opposite: "Three mechanisms can take the rule away ... and the out-of-process boot reconciler for everything else — crash, kill, disabled service, quarantined binary, power loss." A crash+restart without a reboot is covered by none of the three.

**Evidence:** service.rs:170-173 `pub async fn start(cfg: &WebProtectionConfig) -> Self { if !cfg.enabled { return Self::disabled(); }` — and every other refusal (`Self::refused(...)` at 182, 190, 228; the SelfTestFailed struct literal at 252-274) constructs a handle with `rule_guid: None` without ever reading `nrpt::recorded_guid()`. The only `nrpt::` call on the start path is service.rs:288, inside the success branch. `grep -rn "nrpt" crates/sentinelld/src/` confirms `nrpt::remove_rule` is reachable only from `rule::remove`, called only from `spawn_watchdog` and `WebProtection::stop`.

---

## 2. [CRITICAL] gui/src-tauri/nsis-hooks.nsh:13  <nrpt-registry>

The shipping installer's PREINSTALL hook hard-kills sentinelld with `taskkill /F` before `sc stop`, so the daemon's NRPT-rule removal never runs on an upgrade — and the meticulous `--remove`-then-`--remove-task` ladder lives only in PREUNINSTALL, which an upgrade does not execute.

**Failure:** User on 0.1.13 with web protection enabled and rule G live runs the 0.1.14 installer (or the in-app updater). In the generated installer.nsi:310-312, `${If} $UpdateMode = 1 ... Goto reinst_done` — update mode ALWAYS skips the previous uninstaller; in interactive upgrade mode the non-uninstall radio choice does the same (installer.nsi:325-330). So NSIS_HOOK_PREUNINSTALL — the only place `sentinella-dnsreconcile.exe --remove` is invoked — never runs. `Section Install` then fires NSIS_HOOK_PREINSTALL, which at line 13 does `taskkill /F /IM sentinelld.exe`: the process dies without `WebProtection::stop()`, so rule G is left in HKLM. `sc stop` at line 16 is a no-op against an already-dead process. From that instant the machine has NO DNS (catch-all rule → 127.0.0.1:53, nothing listening) for the whole install, and line 18 `sc delete SentinellaDaemon` removes the service. If the install then aborts — `CheckIfAppIsRunning` at installer.nsi:633, a locked file, disk full, user cancel — there is no service, no daemon, and a live catch-all rule: no DNS until the next reboot. Even on a clean upgrade, if the new daemon's bind or self-test fails, finding #1 means the rule is never removed. The `taskkill` lines predate web protection; the hazard they now create does not.

**Evidence:** nsis-hooks.nsh:11-19 `nsExec::ExecToLog 'taskkill /F /IM sentinelld.exe'` ... `nsExec::ExecToLog 'sc stop SentinellaDaemon'` ... `nsExec::ExecToLog 'sc delete SentinellaDaemon'`. Contrast nsis-hooks.nsh:180-209, which for uninstall states "ORDER IS LOAD-BEARING and this is the only place it can be enforced" and runs `--remove`, checks its exit code, and Aborts on failure. installer.nsi:310-312 `${If} $UpdateMode = 1 / Goto reinst_done` and 626-631 `Section Install / !insertmacro NSIS_HOOK_PREINSTALL`.

---

## 3. [CRITICAL] crates/sentinelld/src/web_protection/service.rs:288  <nrpt-task>

`WebProtection::start` never reconciles a rule that a PREVIOUS run installed. Every refusal path (`enabled=false`, BindFailed, SelfTestFailed, and `rule::install` refusing) leaves the live NRPT rule in the registry with `rule_guid = None`, which also disables the watchdog and the shutdown removal — the daemon becomes structurally incapable of ever taking that rule away.

**Failure:** Daemon is serving with rule {G} installed and recorded. It dies without a graceful stop — a crash, or the installer's own `taskkill /F /IM sentinelld.exe` on upgrade — so `stop()` never runs and {G} stays live in the registry. The SCM restarts it 5 s later (`sc failure ... restart/5000`) on a laptop whose Wi-Fi has not re-associated: `upstreams::resolve` returns `NoneConfigured`, `start()` returns `Self::refused(ProxyState::Disabled, ...)` at line 190 with `rule_guid: None`. Rule {G} is still pointed at 127.0.0.1:53 and nothing is listening. Machine has NO DNS. The watchdog is never spawned (line 288 Err arm), `stop()` at line 352 sees `rule_guid == None` and removes nothing, so even an orderly `sc stop` later does not fix it; `installed_now(None)` returns `None`, so the status surface reports "cannot tell" about a rule it recorded itself. Only a reboot (where the out-of-process reconciler runs) restores DNS. The warn! at line 301 asserts the exact opposite of the truth: "NO NRPT rule installed — the machine's DNS does not go through this proxy".

**Evidence:** line 171: `if !cfg.enabled { return Self::disabled(); }` — no rule lookup at all.
line 288: `match super::rule::install(bound, nrpt::recorded_guid(&nrpt::default_state_file())) { ... Err(e) => { warn!(%e, "web protection: serving, but NO NRPT rule installed — the machine's DNS does not go through this proxy"); (None, None) } }`
line 352: `if let Some(guid) = self.handle.rule_guid.clone() && let Err(e) = super::rule::remove(&guid)`
`grep -rn "rule::remove|remove_rule|recorded_guid" crates/sentinelld/src` returns exactly two call sites: service.rs:288 and service.rs:353. There is no startup reconcile anywhere in the daemon.

---

## 4. [CRITICAL] gui/src-tauri/nsis-hooks.nsh:192  <nrpt-task>

The uninstaller silently skips BOTH `--remove` and `--remove-task` when `sentinella-dnsreconcile.exe` is missing, then deletes everything anyway. The `no_reconciler` branch is a bare `Goto` with no message and no `Abort`, so an uninstall completes leaving a live catch-all NRPT rule with the product gone.

**Failure:** The reconciler binary is absent from both `$INSTDIR\daemon` and `$INSTDIR\resources\daemon` — quarantined by the product's own engine, lost to an interrupted upgrade (`File` extraction failed partway), or removed by a user cleaning up a broken install. Web protection had installed rule {G}. The user uninstalls Sentinella. `IfFileExists ... 0 no_reconciler` jumps straight past the rule removal, the macro ends, and Section Uninstall proceeds to `Delete`/`RMDir` the whole install tree. Result: NRPT rule {G} still in `HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig` routing `.` (every name on the machine) to 127.0.0.1, the scheduled task still registered but pointing at a deleted `<Command>`, and no Sentinella binary left to run `--remove`. Every boot forever after: the task fires, fails 0x2 (file not found), the rule stays, nothing answers on 127.0.0.1:53. The machine has no name resolution at all and the software that could explain why has been uninstalled. Contrast line 195-205, where the *other* failure mode of the same operation correctly shows a MessageBox and `Abort`s.

**Evidence:** ```
IfFileExists "$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" 0 no_reconciler
  nsExec::ExecToLog '"$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" --remove'
  ...
  rule_gone:
  nsExec::ExecToLog '"$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" --remove-task'
no_reconciler:
!macroend
```
installer.nsi:811-905 confirms Section Uninstall runs the hook first and then unconditionally Deletes `$INSTDIR\daemon\sentinella-dnsreconcile.exe` and RMDirs the tree. The comment at line 182 claims "ORDER IS LOAD-BEARING and this is the only place it can be enforced" — the enforcement has a hole straight through it.

---

## 5. [CRITICAL] gui/src-tauri/nsis-hooks.nsh:13  <nrpt-task> (preexisting)

NSIS_HOOK_PREINSTALL hard-kills the daemon with `taskkill /F` BEFORE `sc stop`, destroying the only in-process path that removes the NRPT rule, and never runs `sentinella-dnsreconcile.exe --remove`. Every upgrade therefore runs with the machine's DNS pointed at a dead listener, and an aborted upgrade leaves it that way until reboot.

**Failure:** User upgrades 0.1.13 -> 0.1.14 (or the Tauri updater runs the installer). Line 13 SIGKILLs sentinelld.exe, so `WebProtection::stop()` — the code that removes the rule on shutdown — never executes. The `sc stop` on line 16 is then a no-op on an already-dead process. From this instant the NRPT catch-all rule routes every name on the machine to 127.0.0.1:53 with nothing bound there. The window lasts until POSTINSTALL finishes: up to 30 s of stop-polling (lines 92-100), up to 15 s of delete-polling (lines 107-115), plus extraction of ~150 MB of bootstrap signatures — so 30-90 s of total DNS outage on every single upgrade. If the install then fails or the user cancels, `sc delete SentinellaDaemon` (line 18) has already run, so there is no service left to reinstall the rule and no service to remove it: the machine has no DNS until it is rebooted. PREUNINSTALL gets this right (`--remove` before touching anything, with an Abort on failure); PREINSTALL was never wired up to match when web protection landed.

**Evidence:** ```
!macro NSIS_HOOK_PREINSTALL
  nsExec::ExecToLog 'taskkill /F /IM sentinelld.exe'   ; line 13 - kills before any graceful stop
  ...
  nsExec::ExecToLog 'sc stop SentinellaDaemon'        ; line 16 - too late, process is gone
  nsExec::ExecToLog 'sc delete SentinellaDaemon'      ; line 18
!macroend
```
No `--remove` invocation anywhere in the macro. `git blame` shows lines 8-20 date from 26b62ba (v0.1.0), i.e. they predate web protection and were not revisited by ec8456b, which added the uninstall-side rule removal today. service.rs:344-356 confirms rule removal only happens inside `stop()`, which `taskkill /F` cannot reach.

---

## 6. [CRITICAL] crates/sentinelld/src/web_protection/service.rs:171  <reconciler-main>

A daemon that starts while a rule from a previous run is still live never removes it on any path where it does not itself serve — the machine keeps DNS pointed at a dead port until the next boot, and `stop()` will not clean it up either.

**Failure:** Instance A has web protection healthy: NRPT rule G is live, catch-all, single server 127.0.0.1. A is killed hard (the installer's own `taskkill /F /IM sentinelld.exe`, an OOM kill, a crash) so `stop()` never runs and G stays in the registry. SCM's `restart/5000` starts instance B. B's self-test fails for any transient reason (upstream flaky for 3s, `Proxy::bind` losing the race with A's not-yet-released socket, or the operator has meanwhile set `enabled = false` as the documented "emergency fix"). Every one of those paths returns from `start()` with `rule_guid: None`. Rule G is still live and nothing is listening on 127.0.0.1:53, so every name lookup on the machine fails for every user and every service. `stop()` only removes `self.handle.rule_guid`, which is `None`, so even `sc stop SentinellaDaemon` leaves it. The only remover is the boot task, so the outage lasts until someone reboots — on a desktop that sleeps, days. The daemon already holds the identity it needs: line 288 reads `nrpt::recorded_guid(...)` and uses it solely to re-install.

**Evidence:** pub async fn start(cfg: &WebProtectionConfig) -> Self {
    if !cfg.enabled {
        return Self::disabled();          // rule_guid: None; nothing removed
    }
... return Self::refused(ProxyState::BindFailed, format!("bind {listen}: {e}"));   // ditto
... state: ProxyState::SelfTestFailed, ... rule_guid: None,                          // ditto
// line 288 — the GUID of any live rule is right here, used only to re-install:
let (rule_guid, watchdog) = match super::rule::install(bound, nrpt::recorded_guid(&nrpt::default_state_file())) {
// stop(), line 352 — the ONLY caller of rule::remove in the daemon:
if let Some(guid) = self.handle.rule_guid.clone() && let Err(e) = super::rule::remove(&guid)

---

## 7. [CRITICAL] gui/src-tauri/nsis-hooks.nsh:13  <reconciler-main>

NSIS_HOOK_PREINSTALL hard-kills sentinelld.exe *before* `sc stop`, so the daemon's rule-removal shutdown path never runs, and nothing on the install path ever calls `sentinella-dnsreconcile --remove`.

**Failure:** User with web protection enabled runs the installer (upgrade or repair). PREINSTALL executes `taskkill /F /IM sentinelld.exe`, which terminates the process without an SCM stop, so `WebProtection::stop()` — the only in-daemon rule remover — never runs. The catch-all NRPT rule stays live pointing at 127.0.0.1:53 with nothing bound. Tauri then unpacks the bundle (signatures included, minutes), the WebView2 bootstrapper at installer.nsi:586/612 may try to *download* over a machine that now has no name resolution, and the new service only re-installs the rule after it boots, loads ClamAV databases and passes a four-step self-test. So every upgrade is a multi-minute total DNS outage; if the new daemon then fails to serve (finding #1) it lasts until reboot. The reconciler binary that fixes this in one call is already on disk and is invoked in PREUNINSTALL with `--remove`, but not here — and PREUNINSTALL's own comment states the correct ordering ("Stopping first gives the daemon its own chance to remove the rule cleanly") which PREINSTALL inverts.

**Evidence:** !macro NSIS_HOOK_PREINSTALL
  nsExec::ExecToLog 'taskkill /F /IM sentinelld.exe'   ; kill first...
  ...
  nsExec::ExecToLog 'sc stop SentinellaDaemon'        ; ...stop the corpse second
  Sleep 3000
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
!macroend   ; no '--remove' anywhere on the install path

---

## 8. [CRITICAL] C:\Users\Nicolas\Desktop\sentinella\crates\sentinelld\src\web_protection\rule.rs:239  <dnsguard-protocol> (preexisting)

The watchdog's resolution half can never reach the strike threshold: 2 of every 3 ticks unconditionally reset `strikes` to 0, so a total resolution outage never removes the NRPT rule.

**Failure:** Every configured upstream becomes unreachable (ISP resolver outage, or the adapter DNS captured at start is on a network the laptop has left). The canary is short-circuited inside `handle_query` before decide/cache/forward, so `probe_canary` keeps returning the local signature and `canary_probes` keeps moving -> `serving == true` forever. `probe_resolves` runs only when `tick.is_multiple_of(RESOLVE_EVERY)` (RESOLVE_EVERY=3) and fails. On ticks 1,2,4,5,7,8... `resolving` is hard-coded `true` and `serving` is true, so `strikes = 0` executes. The strike sequence is therefore 0,0,1,0,0,1,... and never reaches WATCHDOG_STRIKES=3. The NRPT rule -- which carries exactly one server, our own proxy (rule.rs:29-33: 'there is no secondary to fall back to') -- is never removed, so every name on the machine SERVFAILs indefinitely. This is precisely the outage the file's own doc says this code exists to prevent ('Measured on this branch: canary signature ok, counter moved, and www.microsoft.com returning SERVFAIL with zero answers, indefinitely, with every guard reporting green'). The only test of this half, `resolution_probe_rejects_answers_that_are_not_resolutions`, exercises `probe_resolves` in isolation and stays green; `watchdog_threshold_is_about_a_minute` asserts WATCHDOG_INTERVAL*WATCHDOG_STRIKES in [45s,120s] and therefore pins the exact constant pair that makes the path unreachable.

**Evidence:** const WATCHDOG_STRIKES: u32 = 3;  // line 68
const RESOLVE_EVERY: u64 = 3;     // line 75

let resolving = if tick.is_multiple_of(RESOLVE_EVERY) {
    if health_name_is_allowed(&engine, &health_check_name) {
        probe_resolves(listen, &health_check_name).await
    } else { warn!(...); true }
} else {
    true
};

if serving && resolving {
    strikes = 0;
    continue;
}
strikes += 1;
...
if strikes < WATCHDOG_STRIKES { continue; }

---

## 9. [CRITICAL] C:\Users\Nicolas\Desktop\sentinella\crates\sentinelld\src\web_protection\service.rs:108  <dnsguard-protocol> (preexisting)

`upstreams_handle` is dead code — the upstream list is resolved once at daemon start and never re-read, so any network change strands the machine on unreachable resolvers while NRPT still routes all DNS to us.

**Failure:** `WebProtection::start` is called exactly once (crates/sentinelld/src/main.rs:502) and calls `upstreams::resolve` once. The returned `UpstreamsHandle` is stored behind `#[allow(dead_code)] // consumed by the network-change re-read in commit C` and `.set(...)` is never called anywhere in crates/ (grep confirms: the only non-dnsguard hits are the field declaration and the two initializers). Concrete failure: daemon starts on the home LAN, discovery yields upstream 192.168.1.1, self-test passes, NRPT rule installed pointing all names at 127.0.0.1. The user joins a different Wi-Fi (or brings up a VPN with split DNS). dnsguard keeps forwarding to 192.168.1.1; `udp_exchange` times out after `upstream_timeout` (3 s) and `handle_query_inner` answers SERVFAIL for every query. NRPT overrides the adapter's new, correct DNS servers, so the machine has NO working DNS for the whole session — and finding #1 means the watchdog never removes the rule. `crates/dnsguard/src/proxy.rs:363-365` asserts the opposite is happening: 'Live upstream list, mutable via `Proxy::set_upstreams` so the daemon can re-read adapter DNS on network-change events without rebinding.'

**Evidence:** pub struct WebProtection {
    handle: Arc<WebProtectionHandle>,
    watchdog: Option<tokio::task::JoinHandle<()>>,
    #[allow(dead_code)] // consumed by the network-change re-read in commit C
    upstreams_handle: Option<UpstreamsHandle>,
    ...
}
// grep -rn "upstreams_handle" crates/ --include=*.rs -> only proxy.rs (definition/doc),
// proxy_loopback.rs (test), and service.rs lines 6/108-109/153/236/270/329. No `.set(` caller.

---

## 10. [CRITICAL] crates/sentinelld/src/web_protection/rule.rs:239  <dnsguard-transport>

The watchdog's resolution probe can never accumulate enough strikes to fire, so a proxy that answers the canary but resolves nothing keeps the NRPT catch-all rule forever — the machine is left with no DNS at all.

**Failure:** RESOLVE_EVERY=3 and WATCHDOG_STRIKES=3. On ticks that are not a multiple of 3, `resolving` is hard-coded `true`, and `serving` is true because the canary is short-circuited inside handle_query before forward (and the 'BUSY IS NOT DEAD' clause rescues it whenever any user traffic moved `queries`). So `if serving && resolving { strikes = 0 }` fires on 2 of every 3 ticks. State machine when every upstream is dead: tick3 resolve fails -> strikes=1; tick4 -> strikes=0; tick5 -> strikes=0; tick6 -> strikes=1; ... `strikes` never reaches 3, `remove(&guid)` is never called. Concretely: laptop is serving with the rule installed, the user moves off the network whose resolver (192.168.1.1) was discovered at startup. Every real query now SERVFAILs after upstream_timeout, `probe_resolves` returns false every third tick, and the rule pointing every name at 127.0.0.1 stays installed indefinitely — no browsing, no updates, no DNS, until the daemon restarts. This is the exact failure the file's own header says the watchdog exists to prevent ('Without it a proxy that dies mid-session leaves the machine without DNS until the next reboot'), and the doc on spawn_watchdog claiming 'Neither alone is enough, and the first alone is what an earlier version of this file certified as healthy' is false about the code beneath it: the first alone is what it certifies now.

**Evidence:** const WATCHDOG_STRIKES: u32 = 3;
const RESOLVE_EVERY: u64 = 3;
...
let resolving = if tick.is_multiple_of(RESOLVE_EVERY) {
    if health_name_is_allowed(&engine, &health_check_name) { probe_resolves(listen, &health_check_name).await } else { warn!(...); true }
} else {
    true
};

if serving && resolving {
    strikes = 0;
    continue;
}
strikes += 1;

---

## 11. [CRITICAL] C:\Users\Nicolas\Desktop\sentinella\crates\sentinelld\src\web_protection\rule.rs:239  <wp-config-upstreams>

The watchdog resets `strikes` to 0 on every tick that does not run the resolution probe, and the probe only runs every 3rd tick, so resolution failures can never accumulate to WATCHDOG_STRIKES and the rule is never removed for a proxy that answers the canary but resolves nothing.

**Failure:** RESOLVE_EVERY=3 and WATCHDOG_STRIKES=3. `resolving` is hardcoded true on ticks not divisible by 3 (line 236). A proxy whose every upstream is dead still answers the canary (it is short-circuited before forward), so `serving` stays true. Trace: tick1 serving&&resolving -> strikes=0; tick2 -> strikes=0; tick3 probe fails -> strikes=1; tick4 resolving=true -> strikes=0. `strikes` provably never reaches 3, so the `remove(&guid)` at line 261 is unreachable via the resolution half. Concretely: the user's ISP retires the resolver that was discovered at daemon start; the proxy SERVFAILs every real name indefinitely while the NRPT rule keeps pointing the whole machine at it, and webprotection.status reports state="serving", nrpt_installed=true. That is verbatim the failure the doc comment at rule.rs:156-167 claims this probe closed ("Measured on this branch: canary signature ok, counter moved, and www.microsoft.com returning SERVFAIL with zero answers, indefinitely, with every guard reporting green"). No test catches it: `resolution_probe_rejects_answers_that_are_not_resolutions` (line 428) exercises probe_resolves in isolation and stays green if the whole strike block is deleted, and `watchdog_threshold_is_about_a_minute` (line 471) only multiplies two constants.

**Evidence:** rule.rs:219  let resolving = if tick.is_multiple_of(RESOLVE_EVERY) {
220      ... probe_resolves(listen, &health_check_name).await
235  } else {
236      true                       // <-- non-probe ticks are unconditionally "resolving"
237  };
239  if serving && resolving {
240      strikes = 0;               // <-- two of every three ticks clear the counter
241      continue;
242  }
243  strikes += 1;
251  if strikes < WATCHDOG_STRIKES { continue; }

---

## 12. [CRITICAL] C:\Users\Nicolas\Desktop\sentinella\gui\src-tauri\nsis-hooks.nsh:13  <wp-config-upstreams>

NSIS_HOOK_PREINSTALL force-kills sentinelld.exe without first running `sentinella-dnsreconcile.exe --remove`, so an in-place upgrade strands a live NRPT rule pointing at a proxy that is being deleted and replaced.

**Failure:** An upgrade over an existing install with web protection on. Tauri's PageLeaveReinstall short-circuits the old uninstaller in update mode (`${If} $UpdateMode = 1 ... Goto reinst_done`, installer.nsi:303) and the user can also decline it on the reinstall page, so NSIS_HOOK_PREUNINSTALL - the one place that runs `--remove` and refuses to proceed if it fails - never executes. PREINSTALL then runs `taskkill /F /IM sentinelld.exe` at line 13, three lines before `sc stop`, so the daemon dies with no shutdown path and WebProtection::stop() (service.rs:344) never removes the rule. The registry still routes every name on the machine to 127.0.0.1:53 while the installer copies the bundled ClamAV/YARA payload, polls up to 30 s for the service to stop plus 15 s for the delete, recreates the service, and the new daemon then ACL-hardens the data root, loads config and the ClamAV database before it ever reaches WebProtection::start (main.rs:502). The machine has no DNS for that entire window - minutes on a slow disk - and the reconciler cannot help because its task is BootTrigger-only. If the new daemon's self-test then fails (plausible while the box is thrashing on signature load) the rule stays live indefinitely, per the first finding. One `nsExec::ExecToLog '"$SENTI_DAEMON\sentinella-dnsreconcile.exe" --remove'` before the taskkill is the missing step; the uninstall hook already does exactly this.

**Evidence:** nsis-hooks.nsh:9   !macro NSIS_HOOK_PREINSTALL
13   nsExec::ExecToLog 'taskkill /F /IM sentinelld.exe'   ; hard kill, no rule removal
15   nsExec::ExecToLog 'sc stop SentinellaDaemon'
... compare NSIS_HOOK_PREUNINSTALL, which does it correctly:
     nsExec::ExecToLog '"$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" --remove'
     ... StrCmp $0 "0" rule_gone 0  -> MessageBox + Abort

---

## 13. [CRITICAL] C:\Users\Nicolas\Desktop\sentinella\crates\sentinelld\src\web_protection\service.rs:186  <wp-config-upstreams>

Upstreams are discovered once at daemon start and never re-read; the UpstreamsHandle that exists precisely to fix this is stored and never called, and no network-change subscriber exists anywhere in the daemon.

**Failure:** A laptop boots at home. upstreams::resolve discovers 192.168.1.1:53, the self-test passes, the NRPT rule is installed. The user closes the lid and reopens it on a different network (office Wi-Fi, tethered phone, corporate VPN with split DNS). 192.168.1.1 is now unreachable. State::upstreams still holds the old list; `forward` (dnsguard/proxy.rs:1668-1678) picks one entry round-robin and has no failover, so every query SERVFAILs after the 3 s upstream timeout. Nothing re-reads adapter DNS: `upstreams_handle` is captured at service.rs:236, stored at 329 and marked `#[allow(dead_code)] // consumed by the network-change re-read in commit C` at 108 - grep across crates/sentinelld finds no call to `.set(`, no NotifyIpInterfaceChange, no NLM subscriber. The NRPT catch-all still routes every name to us, so the machine has no DNS for as long as it stays on that network, and the watchdog cannot rescue it because of the strike-reset defect above. dnsguard's own docs (proxy.rs:565-584) state the design 'requires re-reading adapter DNS on network-change events'; it is simply not wired, and this shipped as 0.1.13 'web protection'.

**Evidence:** service.rs:186  let resolved = match upstreams::resolve(&cfg.upstreams, listen) {  // once, at start
service.rs:108  #[allow(dead_code)] // consumed by the network-change re-read in commit C
service.rs:109  upstreams_handle: Option<UpstreamsHandle>,
dnsguard/proxy.rs:1674  let upstream = state.pick_upstream().ok_or_else(...)?;
dnsguard/proxy.rs:1677  forward_via(state, query_bytes, query, via_tcp, upstream).await   // no failover

---

## 14. [CRITICAL] crates/sentinelld/src/web_protection/rule.rs:239  <wp-rule-watchdog>

The watchdog's resolution probe can never reach the strike threshold: RESOLVE_EVERY == WATCHDOG_STRIKES == 3, and every tick that does NOT run the probe hard-codes `resolving = true` and resets `strikes` to 0. A proxy that answers the canary but resolves nothing keeps its NRPT rule forever.

**Failure:** Every configured upstream becomes unreachable (router dies, VPN rewrites the adapter DNS, ISP resolver goes down) while the daemon keeps running. The canary is short-circuited inside `handle_query` before forward, so `probe_canary` still returns true and `canary_probes` still moves -> `serving = true` on every tick. Tick 1: resolving=true (1 % 3 != 0) -> strikes=0. Tick 2: strikes=0. Tick 3: `probe_resolves` gets SERVFAIL -> resolving=false -> strikes=1, `1 < 3` -> continue. Tick 4: serving && resolving(hard-coded true) -> strikes=0. The counter oscillates 0,0,1,0,0,1... and never reaches 3, so `remove(&guid)` at line 261 is unreachable from a resolution failure. The catch-all NRPT rule stays in the registry pointing at a proxy that SERVFAILs every name, indefinitely, on this boot and every subsequent one. This is verbatim the failure the file's own doc comment (lines 158-162) says the resolution probe was added to catch: "canary signature ok, counter moved, and www.microsoft.com returning SERVFAIL with zero answers, indefinitely, with every guard reporting green." The probe was added; the arithmetic that would let it act was not. The two tests that look like they cover this do not: `resolution_probe_rejects_answers_that_are_not_resolutions` exercises `probe_resolves` in isolation (never the strike loop), and `watchdog_threshold_is_about_a_minute` only asserts `WATCHDOG_INTERVAL * WATCHDOG_STRIKES` is between 45s and 120s - it is green with the resolution half of the watchdog completely dead.

**Evidence:** const WATCHDOG_STRIKES: u32 = 3;
const RESOLVE_EVERY: u64 = 3;
...
let resolving = if tick.is_multiple_of(RESOLVE_EVERY) {
    if health_name_is_allowed(&engine, &health_check_name) {
        probe_resolves(listen, &health_check_name).await
    } else { ... true }
} else {
    true
};

if serving && resolving {
    strikes = 0;
    continue;
}
strikes += 1;
...
if strikes < WATCHDOG_STRIKES {
    continue;
}

---

## 15. [CRITICAL] crates/sentinelld/src/web_protection/service.rs:172  <wp-rule-watchdog>

No path in `WebProtection::start` reconciles a rule already recorded in the state file when the daemon is not going to install one. `enabled = false`, a failed self-test, or a refused install all leave a previously installed catch-all NRPT rule live in the registry with `rule_guid = None`, so `stop()` will never remove it either. rule.rs:84's "Refusing is always safe here: it costs FILTERING, never DNS" is false.

**Failure:** Web protection is enabled and working: rule G is in the registry, `%ProgramData%\Sentinella\state\nrpt-rule.guid` contains G. The daemon is then killed rather than stopped - `nsis-hooks.nsh:13` does exactly this (`taskkill /F /IM sentinelld.exe`) on every upgrade, and `sc failure SentinellaDaemon ... restart` (nsis-hooks.nsh:124) restarts it after any panic. `stop()` never runs, so rule G survives with no reboot in between (the boot reconciler only runs at boot). The daemon restarts and takes any non-installing path: (a) the user set `web_protection.enabled = false` - which config.rs:8-10 documents as "the emergency fix" - so `start` returns `Self::disabled()` at line 172 before reading the state file at all; or (b) the upstreams are momentarily unreachable at service start so the four-step self-test fails and `start` returns at line 252 with `rule_guid: None`; or (c) `install` refuses because `reconciler_task_installed()` transiently returned false (the Tasks XML was locked, `SystemRoot` unreadable) and service.rs:300 logs a warning with `rule_guid = None`. In every case rule G still routes 100% of the machine's name resolution to 127.0.0.1:53, where nothing is now listening. `stop()` at line 352 is guarded on `self.handle.rule_guid`, which is None, so an orderly shutdown will not remove it either. The machine has NO name resolution at all until someone reboots. In case (a) the documented emergency fix is what causes the outage; in case (c) the daemon serves happily under a live rule it does not know about and spawns no watchdog for.

**Evidence:** pub async fn start(cfg: &WebProtectionConfig) -> Self {
    if !cfg.enabled {
        return Self::disabled();   // never reads nrpt::recorded_guid()
    }
...
// the ONLY read of the recorded GUID in the whole daemon:
let (rule_guid, watchdog) = match super::rule::install(bound, nrpt::recorded_guid(&nrpt::default_state_file())) {
    Ok(guid) => { ... }
    Err(e) => {
        warn!(%e, "web protection: serving, but NO NRPT rule installed — the machine's DNS does not go through this proxy");
        (None, None)
    }
};
...
pub async fn stop(&mut self) {
    if let Some(guid) = self.handle.rule_guid.clone()      // None => nothing removed
        && let Err(e) = super::rule::remove(&guid)

---

## 16. [CRITICAL] crates/sentinelld/src/web_protection/rule.rs:239  <wp-service-lifecycle>

The watchdog's resolution check can never accumulate the 3 strikes it needs to fire, because the two intervening ticks that skip the resolution probe reset the counter — so the exact failure the probe was added to catch (canary alive, every upstream dead) still never removes the NRPT rule.

**Failure:** Web protection is serving on 127.0.0.1:53 with the NRPT catch-all rule installed, so the whole machine resolves through the proxy. Every configured upstream then dies (ISP resolver outage, VPN drop, corporate DNS ACL change). The canary is short-circuited inside handle_query before decide/cache/forward, so probe_canary keeps succeeding and counters.canary_probes keeps moving → `serving = true` on every tick. probe_resolves fails (SERVFAIL/NODATA) but only runs when `tick.is_multiple_of(3)`. Trace: tick1 serving&&resolving→strikes=0; tick2→strikes=0; tick3 resolving=false→strikes=1, 1<3 continue; tick4 resolving=true→strikes=0. Simulated the loop verbatim for 200 ticks (66 minutes): strikes never exceeds 1 and the rule is never removed. Result: the machine has no working name resolution indefinitely while the daemon runs and `webprotection.status` reports state="serving". The doc block at rule.rs:152-167 asserts this case is covered ("Measured on this branch: canary signature ok, counter moved, and www.microsoft.com returning SERVFAIL with zero answers, indefinitely, with every guard reporting green") — it still is. Neither test covers the loop: `resolution_probe_rejects_answers_that_are_not_resolutions` exercises probe_resolves in isolation, and `watchdog_threshold_is_about_a_minute` only asserts WATCHDOG_INTERVAL*WATCHDOG_STRIKES arithmetic, so deleting the resolution probe entirely would leave both green.

**Evidence:** const WATCHDOG_STRIKES: u32 = 3;
const RESOLVE_EVERY: u64 = 3;
...
    let resolving = if tick.is_multiple_of(RESOLVE_EVERY) {
        if health_name_is_allowed(&engine, &health_check_name) {
            probe_resolves(listen, &health_check_name).await
        } else { true }
    } else {
        true          // <-- ticks 1,2 of every 3
    };

    if serving && resolving {
        strikes = 0;  // <-- wipes the strike scored on tick 3
        continue;
    }
    strikes += 1;
    ...
    if strikes < WATCHDOG_STRIKES { continue; }

---

## 17. [CRITICAL] crates/sentinelld/src/web_protection/service.rs:228  <wp-service-lifecycle>

WebProtection::start never reconciles an NRPT rule left behind by a previous run: every refusal path (disabled, unparseable listen, no upstreams, bind failed, self-test failed) returns with rule_guid=None and touches nothing, and the only out-of-process remover is a BootTrigger-only scheduled task.

**Failure:** Machine is serving with rule {G} installed and %ProgramData%\Sentinella\state\nrpt-rule.guid recording {G}. sentinelld dies without a graceful stop — a panic, an SCM hard-kill after the stop budget, or an upgrade that overwrites the binary. The service is registered with `sc failure SentinellaDaemon reset= 86400 actions= restart/5000/...` (gui/src-tauri/nsis-hooks.nsh:124), so it restarts ~5 s later, inside the same boot. On restart the self-test's step (ii) requires EVERY configured upstream to answer NOERROR (proxy.rs:707), so one still-unreachable upstream — or a Wi-Fi/VPN link that has not come back — yields `Self::refused(ProxyState::SelfTestFailed, ...)`. The proxy is dropped, nothing is bound on 127.0.0.1:53, and rule {G} is still in HKLM\...\DnsPolicyConfig pointing the whole machine's DNS there. The reconciler is registered with a bare `<BootTrigger>` and `<StartWhenAvailable>false</StartWhenAvailable>` (sentinella-dnsreconcile/src/task.rs:49-53, 65), so it will not run again until the next reboot. The machine has zero name resolution until someone reboots it — the exact degrade-to-no-DNS the module docs (mod.rs:13-17) say cannot happen. Confirmed by grep: `rule::remove` has exactly two call sites (stop() at service.rs:353 and the watchdog at rule.rs:261), both keyed on a GUID this process installed itself; `recorded_guid` is read only at install time.

**Evidence:** // every refusal path leaves the registry untouched:
fn refused(state: ProxyState, detail: impl Into<String>) -> Self { Self::inert(true, state, detail.into(), None) }
...
    return Self::refused(ProxyState::BindFailed, format!("bind {listen}: {e}"));
...
        return Self { handle: Arc::new(WebProtectionHandle { ..., rule_guid: None }), ... };  // self-test failed

// and stop() can only remove what THIS run installed:
pub async fn stop(&mut self) {
    if let Some(guid) = self.handle.rule_guid.clone()
        && let Err(e) = super::rule::remove(&guid) { ... }

---

## 18. [CRITICAL] crates/sentinelld/src/ipc/state.rs:4330  <update-state-machine> (preexisting)

start_update's freshclam-missing early return calls self.log_activity() while still holding the `inner` MutexGuard; log_activity re-locks the same non-reentrant std::sync::Mutex<Inner>, self-deadlocking a tokio worker while it holds the daemon's global state lock.

**Failure:** State: freshclam.exe absent (partial install, competing-AV removal, Defender quarantine of the sidecar) OR freshclam.conf absent. Input: user clicks "Update Now" (ipc/mod.rs:1449 -> AppState::start_update, run directly on a tokio worker via dispatch_sync, NOT via run_blocking), or the scheduler's first 60s tick (scheduler/mod.rs:87). Flow: line 4323 acquires `inner`; 4324-4329 write the flags; 4330 calls log_activity, which at line 1714 does `let mut inner = self.lock_inner();` on the SAME thread -> SRWLOCK exclusive re-acquire -> blocks forever. `inner` is never released. Every later IPC that touches it -- engine.status (1889), scan.status (3349), stats.runtime (4511), update.status (4193), activity.list fallback -- blocks its own tokio worker, so the GUI's normal poll bundle wedges all workers within one or two cycles; the scheduler thread wedges on its next log_activity; the realtime watcher wedges the next time it records a detection. Result: daemon alive but totally unresponsive, no scanning telemetry, no UI, requires a kill. I reproduced the exact pattern (lock_inner with poison recovery + a nested lock_inner inside the guard's scope) in a standalone rustc binary: thread still blocked after 3s, end-of-function never reached. The author knew this hazard -- line 1232 in this same file does `drop(inner);` immediately before its log_activity call for exactly this reason; line 4330 is the only site in the file that misses it.

**Evidence:** state.rs:4323-4331
                let mut inner = self.lock_inner();
                inner.update_running = false;
                inner.last_update_error = Some(msg.to_string());
                inner.last_update_error_notifiable |= manual;
                self.log_activity("warning", "update", "Update failed", msg, None);
                return serde_json::json!({"ok": false, "error": msg});

state.rs:376  inner: Mutex<Inner>,          // std::sync::Mutex (line 15 import)
state.rs:1624 fn lock_inner(&self) -> MutexGuard<'_, Inner> { self.inner.lock().unwrap_or_else(...) }
state.rs:1701 pub fn log_activity(...) { ... 1714: let mut inner = self.lock_inner(); ... }
state.rs:1232 (correct sibling)  drop(inner);  then  self.log_activity(...)

---

## 19. [CRITICAL] gui/src-tauri/nsis-hooks.nsh:13  <installer>

PREINSTALL hard-kills sentinelld.exe and deletes the service without ever removing the NRPT rule, so every install/upgrade leaves the machine with zero DNS for the whole install, and permanently until reboot if the install does not finish.

**Failure:** taskkill /F is TerminateProcess: it bypasses WebProtection::stop() (service.rs:352), which is the ONLY place the daemon removes the rule. Line 16's sc stop then runs against an already-dead process. From line 13 until sc start at line 130 (which includes extracting an 89 MB main.cvd) the rule is live with nothing on 127.0.0.1:53 and the machine cannot resolve any name. The auto-updater path makes this unavoidable: tauri-plugin-updater launches the NSIS installer with /UPDATE, and installer.nsi:311-313 (`If $UpdateMode = 1 -> Goto reinst_done`) skips the old uninstaller entirely, so the careful --remove ladder in PREUNINSTALL never runs on an update. If the install then aborts (disk full, CheckIfAppIsRunning cancel at installer.nsi:817, power loss, sc create failure), DNS stays dead until the next boot. PREUNINSTALL deliberately stops the service gracefully first for exactly this reason; PREINSTALL does the opposite and never calls --remove.

**Evidence:** nsExec::ExecToLog 'taskkill /F /IM sentinelld.exe'  (line 13, before the sc stop on line 16)

---

## 20. [CRITICAL] crates/sentinelld/src/ipc/state.rs:4330  <concurrency> (preexisting)

`start_update` calls `self.log_activity(...)` while still holding the `inner` MutexGuard it took eight lines earlier; `log_activity` re-locks the same non-reentrant `std::sync::Mutex`, so the thread self-deadlocks with the daemon's central lock held forever.

**Failure:** On any install where `freshclam.exe` is absent (quarantined, partial install, staging miss) or no `freshclam.conf` exists at any of the three candidate paths, the `_ =>` arm at state.rs:4317 is taken. The scheduler thread reaches it automatically ~60 s after service start (`scheduler/mod.rs:87`, `last_update_at == None` → `should_update == true`), or the GUI's `update.start` reaches it on demand (`ipc/mod.rs:1449`). `let mut inner = self.lock_inner();` (4323) is still in scope at 4330; `log_activity` executes `let mut inner = self.lock_inner();` (1714) on the same thread → hard deadlock. The guard is never released, so every subsequent `engine.status` (1889), `update.status` (4193), `scan.status` fallback (3349/3384), `activity.list` (4492), `stats.runtime` (4511), `scan.start` (2282) and every scan worker completion blocks forever on `inner`. The daemon process stays alive and the service shows Running while its entire IPC control plane is dead until a manual restart. The authors' own code proves they know the hazard: `validate_challenge_token` does `drop(inner);` at 1231 before logging, and the failure branch at 4460 does `drop(inner);` before logging at 4462 — this one branch omits it.

**Evidence:** let mut inner = self.lock_inner();                 // 4323
inner.update_running = false;
inner.last_update_error = Some(msg.to_string());
inner.last_update_error_notifiable |= manual;
self.log_activity("warning", "update", "Update failed", msg, None);   // 4330 — re-enters lock_inner()
return serde_json::json!({"ok": false, "error": msg});

// log_activity, state.rs:1713
{
    let mut inner = self.lock_inner();
    inner.activity.push(ActivityEntry { ... });

---

## 21. [CRITICAL] gui/src-tauri/nsis-hooks.nsh:13  <concurrency>

The installer's PREINSTALL hook force-kills sentinelld.exe with `taskkill /F` BEFORE `sc stop`, so the daemon's graceful shutdown — the only in-session code that removes the NRPT rule — never runs on an upgrade.

**Failure:** Web protection is on, so an NRPT catch-all rule points every name on the machine at 127.0.0.1:53. The user runs the 0.1.x upgrade installer. PREINSTALL line 13 issues `taskkill /F /IM sentinelld.exe` (TerminateProcess), so `run_daemon`'s cleanup — `web_protection.stop().await` at main.rs:636, which calls `rule::remove(&guid)` — is never reached. Line 16's `sc stop` then acts on an already-dead process. From that instant the machine has NO name resolution: the rule is live, nothing is bound to 127.0.0.1:53. The gap lasts through file copy, `sc create`, `sc start`, and the new daemon's startup (ACL hardening, config load, ClamAV engine compile in `ipc::Server::with_engine` at main.rs:400) before `WebProtection::start` at main.rs:502 rebinds — tens of seconds to minutes. If the new instance then fails to reach `Serving` (bind refused because the socket from the killed process has not been released, or the self-test fails while the network is momentarily unavailable), `start` returns via `Self::refused(...)` and never touches the rule at all — the machine has no DNS until the next reboot lets the boot reconciler run. The PREUNINSTALL hook gets this right and says so ("Stopping first gives the daemon its own chance to remove the rule cleanly"); PREINSTALL does the exact opposite.

**Evidence:** !macro NSIS_HOOK_PREINSTALL
  nsExec::ExecToLog 'taskkill /F /IM gui.exe'
  nsExec::ExecToLog 'taskkill /F /IM Sentinella.exe'
  nsExec::ExecToLog 'taskkill /F /IM sentinelld.exe'   ; line 13 — ungraceful
  ...
  nsExec::ExecToLog 'sc stop SentinellaDaemon'         ; line 16 — too late

---

## 22. [CRITICAL] crates/sentinelld/src/web_protection/service.rs:228  <concurrency>

`WebProtection::start` only consults `nrpt::recorded_guid` on the Serving path; every refusal path (`disabled()`, `BindFailed`, `SelfTestFailed`, unparseable listen) returns with `rule_guid: None`, leaving a rule installed by a previous process in force — and `status().nrpt_installed` then reports `None` ("cannot tell") instead of the truth.

**Failure:** The daemon terminated without its graceful path (crash, `taskkill /F`, SCM failure-restart at nsis-hooks.nsh:124, competing AV) while an NRPT rule was live and recorded in `%ProgramData%\Sentinella\state\nrpt-rule.guid`. The SCM restarts the service, or an admin flips `web_protection.enabled = false` and restarts it. `start` takes the `!cfg.enabled` early return at line 171-173, or `refused(ProxyState::BindFailed, ...)` at 228 if something now owns :53, or `SelfTestFailed` at 252-273. None of those read the recorded GUID and none call `rule::remove`. The reconciler that would fix it runs only at boot, so the machine has no DNS for the entire session. Worse, `WebProtectionHandle::status()` (line 81) calls `installed_now(self.rule_guid.as_deref())`, and `rule::installed_now` starts with `let guid = guid?;` — with `rule_guid: None` it returns `None`, i.e. "we could not tell". The one field status.rs:35-39 says a caller MUST read to know whether the machine's DNS goes through the proxy reports "unknown" in precisely the state where the answer is "yes, and nothing is answering". The doc on `WebProtectionStatus::disabled()` (status.rs:61-65) still justifies that `None` with "with no NRPT code in this commit we genuinely do not know" — false as of this branch, which ships rule.rs with `rule_exists` and a recorded GUID on disk.

**Evidence:** // service.rs:288 — the ONLY read of the recorded GUID, on the serving path
let (rule_guid, watchdog) = match super::rule::install(bound, nrpt::recorded_guid(&nrpt::default_state_file())) {

// service.rs:128 — every refusal
fn refused(state: ProxyState, detail: impl Into<String>) -> Self { Self::inert(true, state, detail.into(), None) }
// inert(): rule_guid: None, watchdog: None, shutdown: None, task: None

// rule.rs:147
pub fn installed_now(guid: Option<&str>) -> Option<bool> { let guid = guid?; nrpt::rule_exists(guid).ok() }

---

## 23. [HIGH] gui/src-tauri/nsis-hooks.nsh:192  <reconciler-main>

If the reconciler executable is missing at uninstall time the uninstaller silently jumps past BOTH the rule removal and the task removal and completes successfully, leaving a live catch-all NRPT rule that nothing on the machine can ever undo.

**Failure:** `sentinella-dnsreconcile.exe` is absent from $INSTDIR\daemon — quarantined by a competing AV (an unsigned exe that registers scheduled tasks and rewrites DNS policy is textbook heuristic bait, and web_protection/mod.rs lists "a quarantined binary" as a state this design must survive), deleted by a user cleaning up, or unpacked to a third layout. The `IfFileExists ... 0 no_reconciler` branch skips straight to `no_reconciler:` with no message and no error: the rule is not removed, the scheduled task is not removed, and the uninstaller then deletes $INSTDIR. The machine is left with a catch-all NRPT rule pointing at 127.0.0.1:53, a boot task whose exe no longer exists (so it fails every boot), no daemon, and no product. Every subsequent boot has zero name resolution, and the user cannot search for the fix because search does not resolve. The failure branch two lines above proves the authors know this outcome is unrecoverable — it aborts the uninstall with an explicit MessageBox — but only for the case where the exe exists and returns non-zero.

**Evidence:** IfFileExists "$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" 0 no_reconciler
    nsExec::ExecToLog '"$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" --remove'
    ... MessageBox MB_ICONSTOP|MB_OK "...Uninstalling now would leave this machine unable to resolve names..."
    Abort
  rule_gone:
    nsExec::ExecToLog '"$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" --remove-task'
  no_reconciler:      ; <- falls through here, uninstall proceeds, rule survives

---

## 24. [HIGH] crates/sentinelld/src/web_protection/service.rs:109  <dnsguard-transport>

`UpstreamsHandle` is captured and stored but never called anywhere in the daemon, so the upstream list is frozen at process start and goes silently stale on every network change.

**Failure:** `grep -rn 'upstreams_handle\|\.set(' crates/sentinelld/src` shows the handle is only constructed (service.rs:236) and stored (service.rs:329); there is no `NotifyIpInterfaceChange`/`NotifyAddrChange` subscriber anywhere in sentinelld, and the field carries `#[allow(dead_code)] // consumed by the network-change re-read in commit C`. dnsguard's own doc on `upstreams_handle` states 'The design requires re-reading adapter DNS on network-change events, which happens only while serving' — nothing does it. Concretely: the daemon starts on home Wi-Fi, discovers 192.168.1.1, self-tests green, installs the NRPT catch-all. The user closes the lid, opens it on a corporate VPN / hotel network where 192.168.1.1 is unreachable. dnsguard keeps forwarding every query to 192.168.1.1 forever, each one burning upstream_timeout and returning SERVFAIL, while the machine's DNS is pinned to us by the NRPT rule. Combined with finding 1 (the watchdog cannot strike out on resolution failure), the machine has no DNS until sentinelld is restarted. Note the dnsguard integration test `upstreams_can_be_replaced_while_the_proxy_is_serving` asserts the API works — it does; nobody calls it.

**Evidence:** #[allow(dead_code)] // consumed by the network-change re-read in commit C
upstreams_handle: Option<UpstreamsHandle>,
// ... only other uses:
let upstreams_handle = proxy.upstreams_handle();   // service.rs:236
upstreams_handle: Some(upstreams_handle),          // service.rs:329

---

## 25. [HIGH] gui/src-tauri/nsis-hooks.nsh:13  <wp-rule-watchdog>

The upgrade path force-kills the daemon (`taskkill /F`) before `sc stop`, so `WebProtection::stop()` never runs and the NRPT rule is stranded for the whole install; the install path never invokes `sentinella-dnsreconcile --remove`, even though the binary from the previous install is sitting right there.

**Failure:** A user with web protection enabled runs the 0.1.14 installer over 0.1.13. `NSIS_HOOK_PREINSTALL` issues `taskkill /F /IM sentinelld.exe` as its third statement, before `sc stop SentinellaDaemon` on line 16 - the process dies immediately, so the graceful cleanup in main.rs:636 (`web_protection.stop().await`) is never reached and the catch-all NRPT rule stays in the registry pointing at a proxy that no longer exists. NSIS then unpacks the full bundle (signatures, YARA rules, the ClamAV DLLs - tens to hundreds of MB) and polls up to 45s for service stop/delete. For that entire window the machine cannot resolve a single name. If the install then aborts for any reason (disk full, user cancel, the `sc create` failing), or if the new daemon's self-test fails on first start, the machine stays with no DNS until it is rebooted. `NSIS_HOOK_PREUNINSTALL` gets this right - it runs `--remove` first and aborts the uninstall if it fails (lines 193-205) - and the install path, which kills the daemon just as hard, does nothing equivalent.

**Evidence:** !macro NSIS_HOOK_PREINSTALL
  nsExec::ExecToLog 'taskkill /F /IM gui.exe'
  nsExec::ExecToLog 'taskkill /F /IM Sentinella.exe'
  nsExec::ExecToLog 'taskkill /F /IM sentinelld.exe'   ; <- rule stranded here
  ...
  nsExec::ExecToLog 'sc stop SentinellaDaemon'          ; <- too late, process is gone
  Sleep 3000
!macroend
; no '"...\sentinella-dnsreconcile.exe" --remove' anywhere in the install path

---

## 26. [HIGH] crates/sentinelld/src/ipc/state.rs:4392  <updater-retry> (preexisting)

freshclam exits 0 when it is on a ClamAV CDN cool-down (403/429) without downloading anything; the daemon treats that as a successful update, stamps last_update_timestamp = now, and the signature-age card — the product's designated user-facing signal — can then never fire for the life of the daemon process.

**Failure:** Machine hits a 403 (region/IP block) or 429 (rate limit) from database.clamav.net. freshclam writes retry_after into freshclam.dat and on every subsequent run takes the cool-down branch in fc_update_databases: it prints "You are still on cool-down until after: <date>", sets status = FC_SUCCESS and returns, so the process exits 0. run_freshclam_bounded sees status.success() -> (true, combined); run_freshclam_with_retry returns success; start_update takes the `if success` branch, sets inner.last_update_timestamp = Some(now) and logs activity "Signatures updated successfully". runtime_stats() then computes effective_ts = max(last_update_timestamp, newest_signature_db_mtime), so the fresh `now` always wins, db_stale = false and db_stale_hours = 0. The 4-hour scheduler re-stamps `now` on every cycle. Result: a machine that has been blocked by the CDN for weeks shows a green "Up to date" hero and "Signatures updated successfully" in the activity log while its daily.cvd rots. The activity detail also cannot reveal it: the success path stores `message.chars().take(200)` — the FIRST 200 chars, i.e. the banner — while the cool-down warning is at the tail. Only a daemon restart (which drops last_update_timestamp to None and falls back to file mtimes) exposes the truth, and a SYSTEM service runs for weeks.

**Evidence:** state.rs:4388-4396: `if success { { let mut inner = state.lock_inner(); inner.last_update_timestamp = Some(chrono::Utc::now().timestamp()); ... } let trimmed = message.chars().take(200).collect::<String>();`
third_party/clamav/libfreshclam/libfreshclam.c:844-876 (fc_update_databases): `if (g_freshclamDat->retry_after > 0) { if (g_freshclamDat->retry_after > time(NULL)) { ... logg(LOGG_WARNING, "You are still on cool-down until after: %s\n", retry_after_string); status = FC_SUCCESS; goto done; }`
state.rs:4536-4548: `let effective_ts = [inner.last_update_timestamp, self.newest_signature_db_mtime_secs()].into_iter().flatten().max();`

---

## 27. [HIGH] crates/sentinelld/src/ipc/state.rs:1051  <stats-staleness> (preexisting)

AppState::fish_config is hardcoded to FishConfig::default() and never updated, so the FISH ransomware shield's active response (suspend/terminate) is unreachable in every shipped build.

**Failure:** User elevates, calls protection.set_critical with fish.observe_only=false and fish.active_response="terminate" (ipc/mod.rs:2673-2686 accepts and persists both). Ransomware then mass-rewrites Documents; MutationWindow trips a RewriteBurst; watcher/mod.rs:1121 -> fish_handle_burst -> state.fish_diagnostics() -> MutationWindow::diagnostics(&self.fish_config), which reads the boot-time DEFAULT (observe_only: true, active_response: "observe"). watcher/mod.rs:1223 therefore always selects ResponseType::Observe. The encrypting process is never suspended or terminated; the daemon writes 'Observe-only — no action taken' to the activity log while the Settings UI shows 'Active response: terminate'. fish_record_suspension/fish_record_termination are unreachable, so the counters stay 0 forever.

**Evidence:** state.rs:1051 `fish_config: crate::fish::FishConfig::default(),` — the only place it is ever assigned. state.rs:4993-4999 `pub fn load_fish_config(&self, config: FishConfig) { let mut guard = self.fish_window.lock()...; *guard = MutationWindow::new(&config); // Can't easily update fish_config since it's not behind a Mutex. }`. state.rs:5004 `guard.diagnostics(&self.fish_config)`. watcher/mod.rs:1223 `let response_mode = if fish_diag.observe_only { ResponseType::Observe } else { ResponseType::from_config(&fish_diag.active_response) };`. fish/mod.rs:88 `observe_only: true`, :99 `active_response: "observe".into()`.

---

## 28. [HIGH] crates/sentinelld/src/config/mod.rs:673  <config-validate> (preexisting)

The excluded_paths drive-root guard checks the raw string, but the consumer strips ALL trailing separators before prefix-matching — so a doubled separator ("C://", "C:\\\\", "C:\\/") survives validation and then collapses to "c:", excluding every file on the drive from every scan profile.

**Failure:** Put `excluded_paths = ["C://"]` in sentinelld.toml (or send it through protection.set_critical, whose is_dangerous_path only does trim_end_matches('\\') and therefore also passes "c://"). Config::validate keeps it: trimmed.len()==4 so the `< 3` reject misses it, `chars().all(sep)` is false, and is_drive_root requires `bytes.len() <= 3` so a 4-byte entry is never classified as a drive root. At scan time scan::is_excluded pops trailing separators in a loop — "c://" -> "c:/" -> "c:" — then path_str "c:\\users\\alice\\ransom.exe".starts_with("c:") is true and rest starts with '\\', so is_excluded returns true. Realtime watcher, idle scanner, quick scan and full scan all consult is_excluded, so the entire C: drive becomes unscannable while the UI reports protection enabled and shows one innocuous-looking exclusion entry.

**Evidence:** config/mod.rs:672-684 — `let bytes = lower.as_bytes(); let is_drive_root = bytes.len() <= 3 && bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes.len() == 2 || bytes[2] == b'\\' || bytes[2] == b'/');`  vs  scan/mod.rs:70-79 — `while excl_lower.ends_with('\\') || excl_lower.ends_with('/') { excl_lower.pop(); } ... if path_str.starts_with(&excl_lower) { let rest = &path_str[excl_lower.len()..]; if rest.is_empty() || rest.starts_with('\\') || rest.starts_with('/') { return true; } }`  and ipc/mod.rs:2546-2553 — `let stripped = lower.trim_end_matches('\\'); matches!(stripped, "" | "c:" | "c:/" | ...)`

---

## 29. [HIGH] crates/sentinelld/src/ipc/mod.rs:2238  <config-validate> (preexisting)

settings.set deserializes a whole `Config` (which is `#[serde(default)]`) and pins only 15 of the 20 CRITICAL_FIELDS — fish.enabled, fish.observe_only, fish.active_response, sandbox.enabled, clamav_isolation and the entire [web_protection] section are silently reset to defaults and persisted.

**Failure:** An elevated client (the shipped GUI still registers the `save_settings` Tauri command, and any scripted caller works) sends `settings.set` with `{auth, token, max_file_size_mb: 1024}`. Every field it omitted deserializes to its serde default because Config carries `#[serde(default)]`. The handler pins realtime_enabled/auto_quarantine/argus_worker_*/excluded_*/trusted_hashes/realtime_roots/heuristic_alerts/idle_scan_enabled/scheduled_scan_enabled/enhanced_signature_provider/developer.password_sha256 from `current` — but not the five fields the v0.1.9 audit added to CRITICAL_FIELDS, and not web_protection. config.validate() then save() writes the defaults to disk. A machine configured with clamav_isolation="subprocess", fish.active_response="terminate", sandbox.enabled=true and web_protection.enabled=true silently reverts to in-process ClamAV (re-exposing the in-engine CVEs the field was made critical for), observe-only ransomware response, no sandbox, and web protection off with its blocklists/allowlist arrays emptied — all changes that settings.set_full/critical_diff would have rejected outright.

**Evidence:** ipc/mod.rs:2198 `serde_json::from_value::<crate::config::Config>(req.params.clone())`; pin list ends at 2238 `config.enhanced_signature_provider = current.enhanced_signature_provider;` then 2249 `config.developer.password_sha256 = ...` — no fish.*, sandbox.enabled, clamav_isolation or web_protection. Compare full_config.rs:122-126 CRITICAL_FIELDS (`"fish.enabled", "fish.observe_only", "fish.active_response", "sandbox.enabled", "clamav_isolation"`) and config/mod.rs:9 `#[serde(default)] pub struct Config`.

---

## 30. [HIGH] crates/sentinelld/src/ipc/state.rs:1051  <wire-schema> (preexisting)

AppState::fish_config is a plain field initialised to FishConfig::default() and never reassigned, so the FISH ransomware shield's active response is permanently pinned to observe-only regardless of config — the UAC-gated setting reports success and does nothing, and even a daemon restart does not fix it.

**Failure:** User opens Settings → Ransomware, turns OFF "observe only", selects "terminate", elevates, saves. protection.set_critical writes fish.observe_only=false / fish.active_response="terminate" to sentinelld.toml, returns {ok:true}, and logs "Critical settings changed: fish.observe_only=false, fish.active_response=terminate". Ransomware then starts mass-renaming C:\Users\bob\Documents. watcher/mod.rs:1219 fish_handle_burst calls state.fish_diagnostics(), which is fish/mod.rs:496 diagnostics(&self.fish_config) — and self.fish_config is still FishConfig::default() (observe_only: true, active_response: "observe"). watcher/mod.rs:1223 therefore takes the `if fish_diag.observe_only` branch, logs "Observe-only — no action taken", and the encrypting process is never suspended or terminated. main.rs:491 load_fish_config only rebuilds fish_window (thresholds); state.rs:4997 says outright "Can't easily update fish_config since it's not behind a Mutex". The same stale default is what webprotection-adjacent status/diagnostics report to the GUI, so runtime.status also claims enabled/observe_only/active_response values that are not the user's.

**Evidence:** state.rs:395 `fish_config: crate::fish::FishConfig,` (plain field, AppState is used behind Arc → immutable)
state.rs:1051 `fish_config: crate::fish::FishConfig::default(),`
state.rs:4993-4999 `pub fn load_fish_config(&self, config: FishConfig) { let mut guard = self.fish_window.lock()...; *guard = MutationWindow::new(&config); /* Can't easily update fish_config since it's not behind a Mutex. */ }`
state.rs:5002-5005 `pub fn fish_diagnostics(&self) -> FishDiagnostics { let guard = self.fish_window.lock()...; guard.diagnostics(&self.fish_config) }`
watcher/mod.rs:1219-1226 `let fish_diag = state.fish_diagnostics(); let response_mode = if fish_diag.observe_only { ResponseType::Observe } else { ResponseType::from_config(&fish_diag.active_response) };`
fish/mod.rs:85-87 `Default for FishConfig { enabled: true, observe_only: true, ... active_response: "observe".into() }`
state.rs:1814-1816 alr

---

## 31. [HIGH] crates/sentinelld/src/ipc/mod.rs:2873  <wire-schema> (preexisting)

protection.set_critical writes trusted_hashes to disk but only calls state.load_detection_exclusions — never state.load_trusted_hashes — so the runtime SHA-256 allowlist the scanner consults is unchanged until the daemon restarts.

**Failure:** An installer binary is flagged as a false positive. The user adds its SHA-256 via Settings → Protection → Trusted hashes, elevates, saves. protection.set_critical validates and sets config.trusted_hashes (ipc/mod.rs:2802), saves the TOML, returns {ok:true, changes:["trusted_hashes=[1]"]} and logs "Critical settings changed". But state.trusted_hashes (state.rs:453, initialised empty at state.rs:1121, populated only by main.rs:522 at boot and only `if !config.trusted_hashes.is_empty()`) is still empty, so watcher/mod.rs:791 and :981 `state.is_hash_trusted(&sha256)` keep returning false and the file keeps being detected and auto-quarantined. The opposite direction is the security-relevant one: a user who REMOVES a hash after learning the file was actually malicious gets {ok:true} while the daemon continues whitelisting that exact SHA-256 for the rest of the daemon's uptime. restart_requirement("trusted_hashes") returns EngineReload, so the GUI at most prompts for an engine reload — which also does not call load_trusted_hashes.

**Evidence:** ipc/mod.rs:2861-2874 (protection.set_critical save arm) `match config.save(&path) { Ok(()) => { state.log_activity("warning","protection",&format!("Critical settings changed: {}", changes.join(", ")), ...); state.load_detection_exclusions(config.excluded_detections.clone()); Ok(json!({"ok": true, "changes": changes})) }` — no load_trusted_hashes call
main.rs:519-523 `if !config.trusted_hashes.is_empty() { ... server.state().load_trusted_hashes(config.trusted_hashes.clone()); }` is the ONLY call site (grep for load_trusted_hashes returns state.rs:5119 definition + main.rs:522)
state.rs:5128 `pub fn is_hash_trusted(&self, sha256: &str) -> bool { let guard = self.trusted_hashes.lock()...; guard.iter().any(|h| h == &sha256.to_lowercase()) }`

---

## 32. [HIGH] gui/src/pages/Settings/hooks/useFullConfig.ts:310  <gui-pages> (preexisting)

Saving the Engine tab's ARGUS worker toggle/path always fails and wedges the Settings page, because set_critical mirrors the value into scan.* but the GUI draft does not.

**Failure:** Elevated user opens Settings → Engine, flips "ARGUS worker" off→on (and optionally edits Log level on Advanced), clicks Save. save() computes criticalDiff = {argus_worker_enabled:true} only — draft.scan.argus_worker_enabled is still false so it is not in the diff. setCriticalSettings succeeds and the daemon handler executes `config.argus_worker_enabled = v; config.scan.argus_worker_enabled = v;` (ipc/mod.rs, "Keep the [scan] mirror in sync") and writes the TOML. save() then calls saveFullSettings(draft) with draft.scan.argus_worker_enabled = false. settings.set_full reloads the config (scan.argus_worker_enabled = true) and runs critical_diff, which pushes "scan.argus_worker_enabled" (config/mod.rs:1476) → the daemon returns INSUFFICIENT_PRIVILEGE. invoke rejects, save() catches, returns {ok:false}, and reload() is never reached, so `baseline` stays stale: isDirty remains true, the footer shows the raw daemon message "rejected: kill-vector fields can only be changed via protection.set_critical: scan.argus_worker_enabled", every other non-critical edit in that save is silently dropped, and every subsequent Save click repeats the identical failure until the user navigates away from Settings and back. Same path for argus_worker_path (scan.argus_worker_path is mirrored identically).

**Evidence:** useFullConfig.ts save(): `for (const path of CRITICAL_FIELDS) { const dv = getPath(draft, path); const bv = getPath(baseline, path); if (!eqValue(dv, bv)) criticalDiff[path] = dv; }` … `const r = await saveFullSettings(draft);` — draft still carries the un-mirrored scan.* values. Daemon: `config.argus_worker_enabled = v; // Keep the [scan] mirror in sync — orchestrator reads both.  config.scan.argus_worker_enabled = v;` and config/mod.rs critical_diff: `if self.scan.argus_worker_enabled != full.scan.argus_worker_enabled { diffs.push("scan.argus_worker_enabled"); }`

---

## 33. [HIGH] crates/sentinelld/src/ipc/mod.rs:2593  <concurrency> (preexisting)

In `protection.set_critical`, turning `realtime_enabled` off calls `disable_protection()` (which sets `user_disabled_protection = true`), but turning it back on is gated on `!state.is_user_disabled()` — the very flag the off-path set — so re-enabling the real-time master switch never restarts the watcher while reporting success.

**Failure:** User opens Settings → Protection, flips "Real-time protection" off (UAC prompt, `set_critical_protection(realtime_enabled: false)` → `protection.set_critical`). Line 2592 runs `state.disable_protection()`: `user_disabled_protection = true`, watcher stopped. The user flips it back on. Line 2589 writes `config.realtime_enabled = true` and the handler returns `ok`; line 2593 evaluates `!state.is_user_disabled()` → `!true` → false, so `state.enable_protection()` at 2594 is skipped. The saved config now says real-time protection is enabled, the GUI toggle renders on, `restart_requirement("realtime_enabled")` returns `None` so the GUI shows no "needs restart" pill (full_config.rs:82) — and the `RealtimeWatcher` is dead and `user_disabled_protection` is still true for the rest of the daemon's life. The same defect is reachable from the CLI (`sentinella-cli/src/main.rs:358` sends `realtime_enabled: true` to the same handler).

**Evidence:** if let Some(v) = req.params.get("realtime_enabled").and_then(|v| v.as_bool()) {
    config.realtime_enabled = v;
    changes.push(format!("realtime_enabled={v}"));
    if !v {
        state.disable_protection();          // sets user_disabled_protection = true
    } else if !state.is_user_disabled() {    // 2593 — always false after the line above
        state.enable_protection();
    }
}

---

## 34. [HIGH] crates/sentinelld/src/ipc/state.rs:5004  <concurrency> (preexisting)

FISH's active-response decision reads `AppState::fish_config`, a plain field frozen at `FishConfig::default()` in the constructor and never written again, so `fish.observe_only = false` / `fish.active_response = "terminate"` can never take effect — and `load_fish_config`'s comment asserting diagnostics read from the window is false.

**Failure:** An operator sets `[fish] observe_only = false` and `active_response = "terminate"` to have the ransomware shield actually kill the encrypting process. main.rs:491 calls `load_fish_config(config.fish.clone())`, which rebuilds only the `MutationWindow` thresholds (state.rs:4995-4996). `self.fish_config` stays `FishConfig::default()` from state.rs:1051, i.e. `observe_only: true`, `active_response: "observe"`, `enabled: true`. When a rewrite/rename burst fires, `watcher/mod.rs:1219` reads `state.fish_diagnostics()`, which is `guard.diagnostics(&self.fish_config)` (state.rs:5004) → `observe_only == true` → `response_mode = ResponseType::Observe` → the handler logs "Observe-only — no action taken" and returns. Active response is unreachable code in production; a live ransomware run is logged and never interrupted. Symmetrically, `fish.enabled = false` is also inert: `fish_feed_event` is called unconditionally at watcher/mod.rs:258 and diagnostics always report `enabled: true`. `restart_requirement` classifies `fish.observe_only` and `fish.active_response` as hot-applied (full_config.rs falls through to `None`), so the GUI promises the change took effect; not even a daemon restart makes it true.

**Evidence:** // state.rs:1051 — set once, never updated
fish_config: crate::fish::FishConfig::default(),

// state.rs:4993
pub fn load_fish_config(&self, config: crate::fish::FishConfig) {
    let mut guard = self.fish_window.lock()...;
    *guard = crate::fish::MutationWindow::new(&config);
    // Can't easily update fish_config since it's not behind a Mutex.
    // The diagnostics method reads from the window's internal state.   <-- FALSE
}
// state.rs:5004
guard.diagnostics(&self.fish_config)
// fish/mod.rs:498-511 — enabled/observe_only/active_response all come from that config arg

---

## 35. [HIGH] crates/sentinelld/src/ipc/mod.rs:2592  <ipc-surface> (preexisting)

protection.set_critical applies the realtime-protection side effect (stops the watcher) before its validation phase can reject the request, so a REJECTED call still leaves real-time protection off while config.toml and the Settings UI still say it is on.

**Failure:** Elevated GUI Settings save: user toggles Real-time protection OFF and in the same save adds an exclusion the daemon rejects. useFullConfig.save() builds criticalDiff = {realtime_enabled:false, excluded_paths:[..., "C:\\Windows"]} and calls protection.set_critical once. The handler processes realtime_enabled FIRST (line 2588-2596): it sets config.realtime_enabled=false and calls state.disable_protection(), which sets user_disabled_protection=true and calls watcher.stop() (state.rs:5027-5046). Only afterwards does excluded_paths validation push "C:\\Windows" would exclude critical system area into `errors`, and line 2839 returns INVALID_PARAMS *without ever calling config.save*. Net state: ReadDirectoryChangesW watcher stopped, config.toml still `realtime_enabled = true`, GUI keeps its baseline (realtime ON) and shows only a validation error. Real-time protection is off with no persisted record of it; the next service restart silently turns it back on. The same divergence occurs on the success path if config.save() fails at line 2876 (disk full / locked config) - the handler returns {"ok":false,...} after protection is already down.

**Evidence:** if let Some(v) = req.params.get("realtime_enabled").and_then(|v| v.as_bool()) {
    config.realtime_enabled = v;
    changes.push(format!("realtime_enabled={v}"));
    if !v {
        state.disable_protection();          // <-- side effect, line 2592
    } else if !state.is_user_disabled() {
        state.enable_protection();
    }
}
... 240 lines later ...
if !errors.is_empty() {
    ...
    return serde_json::to_vec(&RpcErrorResponse::err(req.id, error_codes::INVALID_PARAMS,
        format!("validation failed: {}", errors.join("; ")))).unwrap_or_default();   // line 2847
}

---

## 36. [HIGH] crates/sentinelld/src/ipc/mod.rs:2873  <ipc-surface> (preexisting)

protection.set_critical persists a new trusted_hashes list but never refreshes the in-memory mirror the real-time watcher consults, so removing a hash from the whitelist has no effect until the daemon service restarts - while the UI shows it removed.

**Failure:** User discovers a file they previously whitelisted is malware and removes its SHA-256 in Settings -> Trusted hashes. The GUI sends protection.set_critical {token, trusted_hashes:[...without the hash...]}. The handler validates the list, writes it to config.toml, logs "Critical settings changed: trusted_hashes=[N]", and calls state.load_detection_exclusions(...) for excluded_detections - but there is no matching state.load_trusted_hashes(...) call. AppState::load_trusted_hashes is invoked exactly once in the whole daemon, at boot (main.rs:522). The real-time watcher's detection path calls state.is_hash_trusted(&sha256) (watcher/mod.rs:791 and :981), which reads that boot-time snapshot. The malware therefore keeps being waved through by the on-access scanner indefinitely, while settings.get / settings.get_full (which re-read config.toml) show the hash as removed. RestartRequirementMap classifies trusted_hashes as EngineReload, so the GUI shows a "reload engine" pill - but reload_engine_inner never touches trusted_hashes either, so clicking it does not fix the divergence. The sibling field excluded_detections, validated by the same helper five lines earlier, IS refreshed - this is the one-sink-fixed pattern.

**Evidence:** // protection.set_critical, after config.save() succeeds:
state.log_activity("warning", "protection", &format!("Critical settings changed: {}", changes.join(", ")), ...);
// Reload exclusions immediately ...
state.load_detection_exclusions(config.excluded_detections.clone());   // line 2873
Ok(serde_json::json!({"ok": true, "changes": changes}))
// no state.load_trusted_hashes(config.trusted_hashes.clone());

// grep -rn "load_trusted_hashes" crates/sentinelld/src/
//   ipc/state.rs:5119  pub fn load_trusted_hashes(...)
//   main.rs:522        .load_trusted_hashes(config.trusted_hashes.clone());   <-- only caller
// watcher/mod.rs:791   if state.is_hash_trusted(&argus_verdict.sha256) {

---

## 37. [MEDIUM] crates/dnsguard/src/proxy.rs:1401  <dnsguard-cache-decide> (preexisting)

DNS-over-TCP response framing truncates the length prefix with an unchecked `as u16`, so a response that `append_client_opt` pushes past 65535 bytes is framed with a wrapped length and desynchronizes the client's stream.

**Failure:** A client sends an EDNS0 query over TCP (Windows' DNS Client does, and every UDP answer larger than the negotiated payload size is routed here by truncation). `tcp_exchange` accepts up to 65535 bytes from the upstream. `strip_opt_records` returns the response unchanged when the upstream sent no OPT (or when the additional section does not parse), then `normalize_client_edns` -> `append_client_opt` adds exactly 11 bytes. `resp.len()` = 65541, and `(65541 as u16) == 5`. VERIFIED with a fake TCP upstream returning a 65530-byte NOERROR TXT answer with arcount=0: the proxy announced a frame length of 5 and then wrote 65541 bytes. The client reads a 5-byte 'message' (unparseable), then reads the next two body bytes as the following length prefix and consumes 65536 further bytes of upstream-controlled data as framed DNS messages. The query never resolves and every subsequent query pipelined on that connection is answered from garbage. The same path is reachable from the cache (`cache_get` returns up to 65535 stored bytes, then the same +11 runs).

**Evidence:** tcp_conn:
    let Some(budget) = left(deadline) else { break };
    let framed_len = (resp.len() as u16).to_be_bytes();
    let written = timeout(budget, async {
        stream.write_all(&framed_len).await?;
        stream.write_all(&resp).await
    })

wire::append_client_opt unconditionally grows the response by 11 bytes, and wire::strip_opt_records is documented "anything that does not parse as a clean additional section is returned unchanged" — so nothing bounds resp.len() to 65535 at this point.

---

## 38. [MEDIUM] crates/dnsguard/src/proxy.rs:1225  <dnsguard-transport> (preexisting)

`shed()` bumps the user-facing `queries` counter and fires the DecisionHook regardless of the `synthetic` flag, so concurrent local traffic during `self_test` reds a healthy proxy and web protection refuses to start.

**Failure:** `udp_loop` is spawned by `self_test` with `synthetic = true`, but the overload branch calls `shed(&state, &bytes, peer, &sock)` — which takes no `synthetic` argument and unconditionally does `bump(&counters.queries)` and `state.emit(...)`. `self_test` then computes `report.filter_ok = ... && after.queries == before.queries && after.blocked == before.blocked`. So: an unprivileged local process floods 127.0.0.1:53 hard enough to saturate the 256-permit UDP pool (rule.rs documents this is achievable with 'one unprivileged process with eight sender tasks'), one shed lands inside the self-test window, `queries` moves, `filter_ok` goes false, service.rs takes the `!report.ok()` branch and NEVER SERVES — web protection is off, no NRPT rule, and the recorded reason is the misleading 'self-test probes leaked into user-facing counters'. Keep the flood running and web protection can never start. This is exactly the concern the U01 comment applied to `canary_probes` ('other local processes may query the canary concurrently... exact equality therefore reds a healthy proxy on concurrent traffic') — the lower-bound fix was applied to one counter and the two exact-equality checks next to it were left. It also falsifies the doc on `udp_loop` and `self_test`: 'every query answered here ... skips the user-facing counters and the decision hook'.

**Evidence:** Err(_) => shed(&state, &bytes, peer, &sock).await,
...
async fn shed(state: &Arc<State>, bytes: &[u8], peer: SocketAddr, sock: &UdpSocket) {
    state.counters.bump(&state.counters.shed);
    state.counters.bump(&state.counters.queries);
    if let Ok(query) = wire::parse_query(bytes) { state.emit(peer, &query, QueryOutcome::Shed); }
...
report.filter_ok = canary_ok && resolves_ok && actual_delta >= expected_delta
    && after.queries == before.queries && after.blocked == before.blocked;

---

## 39. [MEDIUM] crates/dnsguard/src/proxy.rs:1401  <dnsguard-transport> (preexisting)

The DNS-over-TCP length prefix is computed with `resp.len() as u16`, which silently wraps when the EDNS egress normalization pushes a maximal upstream answer past 65535 bytes, desynchronizing the client's framing.

**Failure:** `tcp_exchange` reads a full u16-framed upstream answer, so `fw.bytes` can be 65535 bytes. `handle_query` then runs `normalize_client_edns`: `strip_opt_records` is a no-op when the upstream answer carries no OPT (common — pre-EDNS home CPE forwarders, and mandatory on the `Forwarded::edns_stripped` fallback path, which re-fetches with the OPT removed), and `append_client_opt` then adds exactly 11 bytes whenever the requester sent EDNS. 65535 + 11 = 65546, and `65546 as u16 == 10`. The proxy writes the two-byte prefix `0x000A` followed by 65546 bytes. The client reads 10 bytes as a complete DNS message (garbage), then reads the next two body bytes as the length of the following message — the connection is desynchronized for its whole lifetime, and since a Windows stub arrives on TCP precisely because it was told to retry there (TC), the name is unresolvable with no retry signal. Reachable without controlling the upstream: an attacker-controlled zone serving ~65.5 KB of TXT records, resolved by any EDNS client over TCP (including the ordinary UDP-truncation -> TCP-retry path).

**Evidence:** let framed_len = (resp.len() as u16).to_be_bytes();
let written = timeout(budget, async {
    stream.write_all(&framed_len).await?;
    stream.write_all(&resp).await
}).await;

---

## 40. [MEDIUM] crates/dnsguard/src/proxy.rs:1195  <dnsguard-transport> (preexisting)

The UDP truncation and SERVFAIL fallback responses are built after `handle_query` returns, so they bypass the EDNS egress normalization the comment above `handle_query` explicitly claims covers 'the TC response'.

**Failure:** `handle_query`'s doc says: 'the DATA is fixed once, here: every response we emit has inherited OPTs removed and then exactly one OPT appended iff THIS requester sent one', and names the five sinks it claims to cover including 'the TC response'. But in `udp_loop` the size check runs on the already-normalized `resp`, and when it trips the response is rebuilt from the raw request via `wire::build_truncated_response` (which writes `&[0,0,0,0,0,0]` for AN/NS/AR) or `wire::build_error_response` — neither appends an OPT. Same for `serve_overflow_servfail` on the TCP pool-overflow path. Concretely: a stub advertising EDNS 1232 asks for a name whose answer is 1400 bytes; it receives TC=1 with ARCOUNT=0 and no OPT record. Resolvers that follow RFC 6891/RFC 8906 read a missing OPT in the response as 'this server does not implement EDNS' and cache that per-server, downgrading every subsequent query to the classic 512-byte limit — which pushes far more answers onto the bounded TCP connection pool, exactly the coupling the A1 EDNS-aware-truncation work exists to remove. No test covers this: `edns_client_gets_large_answer_over_udp_non_edns_gets_tc` asserts only length and the TC bit on the truncated case, never ARCOUNT.

**Evidence:** let resp = if resp.len() > udp_limit {
    let rcode = wire::response_info(&resp).map_or(wire::RCODE_NOERROR, |info| info.rcode);
    match wire::build_truncated_response(&bytes, rcode) {
        Some(truncated) => truncated,
        None => match wire::build_error_response(&bytes, wire::RCODE_SERVFAIL, false) { ... },
    }
} else { resp };
let _ = sock.send_to(&resp, peer).await;   // <- never re-normalized

---

## 41. [MEDIUM] C:\Users\Nicolas\Desktop\sentinella\crates\sentinelld\src\web_protection\upstreams.rs:151  <wp-config-upstreams>

filter_usable drops only the EXACT self-reference, but dnsguard::validate_upstreams rejects ANY loopback upstream on the listen port, so a single leftover loopback DNS entry makes Proxy::bind refuse the whole list - discarding usable LAN upstreams that were in it.

**Failure:** A machine whose adapter DNS is [::1, 192.168.1.1] - the normal leftover of a removed dnscrypt-proxy / AdGuard Home / Pi-hole-on-host install, which sets both loopback families - or [127.0.0.2, 192.168.1.1]. filter_usable keeps ::1 because SocketAddr::new(::1, 53) != 127.0.0.1:53, and keeps 127.0.0.2 for the same reason, so resolve() returns [[::1]:53, 192.168.1.1:53]. Proxy::bind then calls validate_upstreams (dnsguard/proxy.rs:1042-1046), whose rule is `upstream.port() == listen.port() && upstream.ip().is_loopback() && listen.ip().is_loopback()` - true for both ::1 and 127.0.0.2 - and returns InvalidInput for the ENTIRE list. start() reports ProxyState::BindFailed with 'bind 127.0.0.1:53: upstream [::1]:53 is self-referential', even though 192.168.1.1:53 was right there and perfectly usable. The two halves of the same safety rule disagree, and the narrower one runs first. The module doc directly above the code asserts the broader behaviour is what happens.

**Evidence:** upstreams.rs:22   //! ... So loopback entries are dropped, and if that leaves nothing we report NO upstreams
upstreams.rs:151  if ip.is_loopback() && SocketAddr::new(ip, DNS_PORT) == listen {   // exact match only
dnsguard/proxy.rs:1042  let self_referential = *upstream == listen
1043      || (listen.port() != 0
1044          && upstream.port() == listen.port()
1045          && upstream.ip().is_loopback()
1046          && (listen.ip().is_loopback() || listen.ip().is_unspecified()));

---

## 42. [MEDIUM] crates/nrpt/src/lib.rs:227  <wp-rule-watchdog> (preexisting)

`reconciler_task_installed()` proves only that a task definition FILE exists and contains no `<Enabled>false</Enabled>`. It never checks that the `<Command>` executable in that file is present, so the precondition passes for a task that fails to launch - and rule.rs:12 explicitly lists "a quarantined binary" among the failures this gate is supposed to cover.

**Failure:** `C:\Program Files\Sentinella\daemon\sentinella-dnsreconcile.exe` is removed - by this product's own quarantine, by a competing AV, by a user cleaning up, or by a partial uninstall that took the `no_reconciler` branch at nsis-hooks.nsh:210 (which skips both `--remove` and `--remove-task` when the exe is already gone, leaving the task registered). `%SystemRoot%\System32\Tasks\Sentinella\DnsReconcile` is untouched by any of those, so `std::fs::read` succeeds and `task_definition_is_enabled` returns true. The daemon starts, `install()` passes precondition 2, and writes a catch-all NRPT rule. The daemon then crashes or the service is disabled. At the next boot Task Scheduler starts the task, fails with 0x80070002 (file not found), and nothing removes the rule. The machine resolves no names, on this boot and every boot afterwards, with the only mechanism able to undo it deleted. This is a check-then-act by path name rather than by the identity of the thing that must actually run; the doc's claim "registered AND able to run" and rule.rs's claim that the task covers "a quarantined binary" are both false as written.

**Evidence:** /// Is the boot reconciler's scheduled task registered AND able to run?
pub fn reconciler_task_installed() -> bool {
    let Ok(root) = std::env::var("SystemRoot") else { return false; };
    let path = std::path::Path::new(&root)
        .join("System32").join("Tasks").join("Sentinella").join("DnsReconcile");
    let Ok(bytes) = std::fs::read(&path) else { return false; };
    task_definition_is_enabled(&bytes)   // parses <Enabled>; never looks at <Command>
}

---

## 43. [MEDIUM] gui/src-tauri/nsis-hooks.nsh:81  <updater-retry> (preexisting)

The installer ships one prebuilt freshclam.dat to every machine. That file holds freshclam's UUID, which freshclam puts in the HTTP User-Agent for every CDN request, so the entire Sentinella install base presents as a single client to ClamAV's rate limiter.

**Failure:** NSIS_HOOK_POSTINSTALL copies $SENTI_DAEMON\runtime\signatures_bootstrap\freshclam.dat into C:\ProgramData\Sentinella\signatures on every fresh install. The shipped file (release/staging/windows/runtime/signatures_bootstrap/freshclam.dat, 90 bytes) contains the release builder's UUID 77955c61-1cb0-4ecb-aa5c-9f529aea2ed3. freshclam only regenerates a UUID when the .dat is absent or unparseable, so every install of a given release keeps that one. libfreshclam puts it verbatim into the User-Agent: "ClamAV/<ver> (OS: ..., UUID: %s)". ClamAV's CDN rate-limits by that identity and its own 429 advisory says to set up a private mirror past ~10 hosts. So as the install base grows past that, Cloudflare 429s the shared UUID and puts EVERY Sentinella user on a cool-down simultaneously — and by finding #1 that cool-down is reported as a successful update. One product-wide event silently stops signature updates fleet-wide while every UI says "Up to date". It also fingerprints the whole user base to a third party as one correlatable client.

**Evidence:** nsis-hooks.nsh:81: `CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\freshclam.dat" "$SENTI_DATA\signatures\"` (packaged by installer.nsi:699)
`od -c release/staging/windows/runtime/signatures_bootstrap/freshclam.dat` -> `FreshClamData\001\0\0\0 77955c61-1cb0-4ecb-aa5c-9f529aea2ed3` then all-zero retry_after
libfreshclam_internal.c:619-622: `snprintf(userAgent, sizeof(userAgent), PACKAGE "/%s (OS: ..., UUID: %s)", get_version(), g_freshclamDat->uuid);`

---

## 44. [MEDIUM] crates/sentinelld/src/ipc/mod.rs:2873  <stats-staleness> (preexisting)

protection.set_critical persists a new trusted_hashes list but never calls state.load_trusted_hashes, so the in-memory whitelist the watcher actually consults stays at its boot value until a daemon restart.

**Failure:** Removal case (security): admin has a hash whitelisted, later discovers the file is malicious and removes the hash via the elevated Trusted Hashes UI. protection.set_critical validates, writes the TOML, logs 'Critical settings changed: trusted_hashes=[0]', returns ok. state.trusted_hashes still contains the hash, so watcher/mod.rs:791 `if state.is_hash_trusted(&argus_verdict.sha256)` and :981 keep skipping quarantine for that malware indefinitely. Addition case (usability): admin adds a hash to stop a false positive; the file is re-quarantined on the next write. In both cases the GUI's restart pill says EngineReload (full_config.rs:63), but reload_engine (state.rs:3776/3839) never touches trusted_hashes either, so following the GUI's instruction does not fix it.

**Evidence:** ipc/mod.rs:2787-2806 mutates `config.trusted_hashes = norm;` then ipc/mod.rs:2861-2874 saves and calls only `state.load_detection_exclusions(config.excluded_detections.clone());`. Repo-wide grep for `load_trusted_hashes` yields exactly one call site: main.rs:522, guarded by `if !config.trusted_hashes.is_empty()`. state.rs:5119 is the only mutator of `self.trusted_hashes`.

---

## 45. [MEDIUM] crates/sentinelld/src/ipc/state.rs:4993  <stats-staleness> (preexisting)

load_fish_config is called only from main.rs at boot; no IPC save path re-applies FISH thresholds, yet restart_requirement() classifies them as hot-applied and a unit test asserts that classification.

**Failure:** User lowers fish.rename_threshold from 50 to 10 in Settings to catch slower ransomware. The GUI renders no restart pill because restart_requirement("fish.rename_threshold") returns None (full_config.rs:81) — a property the test at full_config.rs:551-554 explicitly locks in. settings.set_full writes the TOML and calls only refresh_staleness_thresholds (ipc/mod.rs:2484). The live MutationWindow keeps rename_threshold=50 (built once at state.rs:1052 and rebuilt only by load_fish_config, whose sole caller is main.rs:491). Detection stays at the old sensitivity with no indication anywhere. The watcher's own 5s live config reloader (watcher/mod.rs:238-253) refreshes excluded_paths/excluded_extensions/heuristic_alerts/sandbox but deliberately not fish, so nothing closes the gap. Same shape for clamav_worker_timeout_sec (state.rs:449, written only by main.rs:475) and scan.orchestrator_*_enabled (state.rs:364-367 plain bools, set only at state.rs:1032), both also classified hot-applied.

**Evidence:** state.rs:4993 `pub fn load_fish_config(&self, config: crate::fish::FishConfig)`; grep across crates/ shows one caller: main.rs:491 `server.state().load_fish_config(config.fish.clone());`. ipc/mod.rs:2478-2492 (settings.set_full success arm) calls only `state.refresh_staleness_thresholds(&config)`. full_config.rs:80-82 `// Everything else is hot-applied.  _ => None,`.

---

## 46. [MEDIUM] crates/sentinelld/src/fish/mod.rs:292  <stats-staleness> (preexisting)

fish.enabled is a UAC-gated CRITICAL_FIELD exposed in Settings, but nothing in the daemon ever reads it — FISH event recording runs unconditionally whether it is true or false.

**Failure:** An admin disables the ransomware shield (fish.enabled=false) via protection.set_critical to stop FISH false positives on a bulk-encryption workload. The value is validated, persisted and logged as a change. But watcher/mod.rs:258 calls fish_feed_event unconditionally, MutationWindow::new (fish/mod.rs:241-262) does not store `enabled`, and MutationWindow::record (fish/mod.rs:292) never checks it — so every mutation is still recorded, bursts still evaluate, and 'FISH: rewrite burst detected' warnings keep filling the activity log. fish_diagnostics() compounds the confusion by reporting enabled: true regardless, because it reads the never-updated default fish_config.

**Evidence:** fish/mod.rs:241-262 `pub fn new(config: &FishConfig) -> Self { Self { events, window, rename_threshold, rewrite_threshold, ext_mutation_threshold, cooldown, slow_burn_window, slow_burn_threshold, ... } }` — no `enabled` field. fish/mod.rs:292 `pub fn record(&mut self, event: FileMutationEvent) -> FishDecision { self.total_events += 1; ...` — no gate. watcher/mod.rs:257-258 `// ── FISH: feed all relevant events (observe-only) ──  fish_feed_event(&event, &state);`. ipc/mod.rs:2669-2671 accepts and persists the flag.

---

## 47. [MEDIUM] crates/sentinelld/src/config/mod.rs:792  <config-validate> (preexisting)

Config::validate() slices a `&str` at a fixed byte offset while logging an invalid trusted_hashes entry; a non-ASCII entry whose byte 16 falls inside a multi-byte character panics, and validate() runs on every Config::load — including the daemon's startup load.

**Failure:** Hand-edit sentinelld.toml (the documented way to manage the whitelist) to `trusted_hashes = ["aaaaaaaaaaaaaa\u{65e5}x"]` — 18 bytes, byte 16 is inside the 3-byte CJK char. The entry fails the `len != 64 || !all_hexdigit` test, so the warn! arm runs and evaluates `&trimmed[..trimmed.len().min(16)]` = `&trimmed[..16]`, which panics with "byte index 16 is not a char boundary". I reproduced this exact panic with rustc (exit 101). main.rs:333 calls config::load during startup, so the daemon aborts before binding IPC — no realtime protection, no scanning, no service. The same panic fires on the idle scanner's per-cycle Config::load and inside IPC handler threads. Any non-ASCII character (a smart quote or a stray accented letter pasted from a web page) positioned so that byte 16 is mid-character triggers it.

**Evidence:** config/mod.rs:788-798 — `self.trusted_hashes.retain(|h| { let trimmed = h.trim(); if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) { warn!(entry = &trimmed[..trimmed.len().min(16)], "trusted_hashes: invalid SHA-256 format — removed"); return false; } true });`

---

## 48. [MEDIUM] crates/sentinella-ipc-proto/src/full_config.rs:81  <wire-schema> (preexisting)

The eight numeric fish.* threshold fields are classified RestartRequirement::None, but the MutationWindow that holds them is rebuilt only by load_fish_config, whose sole call site is main.rs:491 at daemon start — a settings.set_full write never reaches it.

**Failure:** A user gets FISH false positives from a nightly build job and raises fish.rename_threshold from 50 to 400 and fish.window_seconds from 30 to 120 in Settings → Ransomware → Thresholds, then saves. settings.set_full applies both into Config (config/mod.rs:1394-1395), saves the TOML, and returns ok. The Ransomware tab shows no restart pill for these rows (rr("fish.rename_threshold") == "none"; the ipc-proto test at full_config.rs:552-555 asserts exactly that). state.fish_record — reached from watcher/mod.rs:1121 on every file event — keeps evaluating against the MutationWindow built at boot from rename_threshold=50 / window=30s, so the alerts continue unchanged until the service is restarted, and the user has no indication that a restart is what is needed.

**Evidence:** full_config.rs:59-82 restart_requirement lists only `fish.enabled` under DaemonRestart; every other fish.* path hits `_ => None`
full_config.rs:551-555 test asserts `restart_requirement("fish.rename_threshold") == RestartRequirement::None`
state.rs:4993-4998 `pub fn load_fish_config(&self, config: FishConfig) { let mut guard = self.fish_window.lock()...; *guard = MutationWindow::new(&config); }` — grep returns exactly one call site: main.rs:491 `server.state().load_fish_config(config.fish.clone());`
fish/mod.rs:241-264 `MutationWindow::new` copies window/rename_threshold/rewrite_threshold/ext_mutation_threshold/cooldown/slow_burn_* into owned fields at construction
ipc/mod.rs:2475-2495 settings.set_full save arm calls only refresh_staleness_thresholds

---

## 49. [MEDIUM] gui/src/pages/Settings/hooks/useFullConfig.ts:310  <wire-schema> (preexisting)

The two-phase save sends the raw draft to save_full_settings after protection.set_critical has already normalised the critical values on disk, so any normalising edit makes the second call fail critical_diff and discards every non-critical change in the same save.

**Failure:** User adds excluded extension "TXT" (or pastes an uppercase certutil SHA-256 into trusted_hashes, or types %USERPROFILE%\Downloads into realtime_roots) and in the same visit bumps quarantine_retention_days from 90 to 30. save() puts the critical field into criticalDiff and calls set_critical_settings first; protection.set_critical accepts it and normalises — ipc/mod.rs:2752-2756 lowercases and dot-strips to ["txt"], ipc/mod.rs:2801 lowercases the hash, Config::load's expanded() rewrites the %VAR% root — then saves. Step 3 then posts the unchanged draft (still ["TXT"]) to settings.set_full; the daemon reloads the config from disk, config.critical_diff(&full) sees excluded_extensions ["txt"] != ["TXT"] and returns INSUFFICIENT_PRIVILEGE with "rejected: kill-vector fields can only be changed via protection.set_critical: excluded_extensions". The quarantine-retention change is silently dropped, the user is told to use the UAC path they just used, and an "attempted kill-vector tampering" warning is written to the activity log for a legitimate save.

**Evidence:** useFullConfig.ts:291-310 `if (Object.keys(criticalDiff).length > 0) { const r = await setCriticalSettings(criticalDiff); ... }` then `const r = await saveFullSettings(draft);` — draft is never re-synced with what the daemon persisted
ipc/mod.rs:2752-2756 `let norm: Vec<String> = list.into_iter().map(|s| s.trim().trim_start_matches('.').to_lowercase()).collect(); config.excluded_extensions = norm;`
ipc/mod.rs:2448-2474 `let diffs = config.critical_diff(&full); if !diffs.is_empty() { ... return RpcErrorResponse::err(req.id, error_codes::INSUFFICIENT_PRIVILEGE, ...) }`
config/mod.rs:1455-1457 `if self.excluded_extensions != full.excluded_extensions { diffs.push("excluded_extensions"); }`

---

## 50. [MEDIUM] gui/src/hooks/useDaemon.ts:214  <gui-daemon-hook> (preexisting)

The `qReliable` guard protects every quarantine snapshot except the seeding one: when `prevRef.current` is null it evaluates to true even for a fallback empty list, so a single transient quarantine.list failure on the first poll makes every pre-existing quarantine item re-notify as freshly caught.

**Failure:** User launches the GUI while sentinelld is mid engine-reload. engine.status and stats.runtime answer (uptime_secs>0, state="ready"), but quarantine.list — which is auth-gated and, per the author's own comment at line 187-189, 'can be busy mid-reload' — times out and fetchDashboard substitutes []. healthyThisPoll is true, prev is null so the notification loop is skipped, and the seeding block computes qReliable = ([].length > 0) || ((null?.quarantineCount ?? 0) === 0) = (false || 0===0) = TRUE. prevRef is therefore seeded with `new Set()` from the fallback. On the next poll the real list returns the user's 40 historical quarantine entries; none are in prev.quarantineIds, so notifyQuarantined fires for all 40 -> 3 individual toasts naming malware caught weeks ago plus a '40 files quarantined' storm summary, and 4 bogus rows written into localStorage notification history. This is precisely the phantom-flash bug the comment at lines 200-207 claims to have closed; the fix only covers the case where prev already exists.

**Evidence:** const prevSnap = prevRef.current;
const qReliable =
  result.quarantine.length > 0 || (prevSnap?.quarantineCount ?? 0) === 0;
...
quarantineIds: qReliable
  ? new Set(result.quarantine.map(q => q.id))
  : (prevSnap?.quarantineIds ?? new Set()),

---

## 51. [MEDIUM] gui/src/hooks/useDaemon.ts:127  <gui-daemon-hook> (preexisting)

`setData(result)` commits the synthetic disconnect fallback into shared state unconditionally, with no marker distinguishing it from real data — which makes the Dashboard's offline screen unreachable and resurrects the exact 'Signatures never updated' false banner that v0.1.8 claims to have fixed.

**Failure:** Two concrete sinks. (1) Daemon not running at all: poll 1 returns the all-fallback object, healthyThisPoll is false but setData still runs, so `data` is non-null from then on. Dashboard.tsx:38 guards its whole offline UI with `if (!connected && !data)`, which can now never be true, so the WifiOff card, the \\.\pipe\sentinelld hint and the Retry button are dead code; the user instead gets the normal dashboard rendered over zeros. (2) Single transient stats.runtime timeout while the supervisor still reports "connected": App.tsx falls into its else branch and reads the fallback stats (db_stale=true, db_stale_hours=0, signature_count=0), so reallyNeverUpdated = true && 0===0 && 0===0 = true and showStaleBanner fires t("notice.never_updated") — a red 'Signatures have never been updated' banner with an Update-now button, on a machine holding a current signature DB. The v0.1.8 guard quoted at App.tsx:163-171 ('if the daemon reports ANY signatures loaded, suppress') cannot help, because the fallback reports zero signatures by construction.

**Evidence:** setData(result);              // useDaemon.ts:127 — runs whether or not healthyThisPoll
// Dashboard.tsx:38   if (!connected && !data) {
// App.tsx:174        const reallyNeverUpdated =
//                      stats.db_stale && stats.db_stale_hours === 0 && sigCount === 0;
// sentinella.ts:366  getRuntimeStats().catch(() => ({ uptime_secs: 0, ..., db_stale: true, db_stale_hours: 0, ... signature_count: 0 ...

---

## 52. [MEDIUM] crates/sentinella-ipc-proto/src/full_config.rs:81  <gui-pages> (preexisting)

Every FISH ransomware threshold the Settings UI edits is classified "applies immediately", but the running MutationWindow is built once at boot and is never rebuilt after a settings write.

**Failure:** User goes to Settings → Ransomware → Thresholds, lowers fish.rename_threshold from 50 to 10 (to catch ransomware faster) and shortens fish.window_seconds. restart_requirement() returns None for both, so SettingRow renders NO "needs restart" pill and the footer reports "All saved". settings.set_full writes the TOML and then only calls `state.refresh_staleness_thresholds(&config)` (ipc/mod.rs:2484) — it never calls `load_fish_config`. AppState::fish_window was constructed by `MutationWindow::new(&config.fish)` and the values were COPIED into the struct (fish/mod.rs:241-260: `rename_threshold: config.rename_threshold`, `window: Duration::from_secs(config.window_seconds)`, `cooldown`, `slow_burn_*`). load_fish_config has exactly one caller in the whole repo — main.rs:491, at daemon startup. So a ransomware burst of 30 renames after the save is still measured against the boot-time threshold of 50 and no alert fires, while the UI told the user the new threshold was live. Same for rewrite_threshold, ext_mutation_threshold, slow_burn_window_secs, slow_burn_threshold, alert_cooldown_seconds.

**Evidence:** restart_requirement(): fish.* thresholds fall through to `_ => None,` and RestartRequirement::None is documented "Applies immediately on save (most threshold/timing knobs)." state.rs:4993 `pub fn load_fish_config(&self, config: crate::fish::FishConfig)` — grep across the repo returns only the definition and `server.state().load_fish_config(config.fish.clone());` in main.rs:491.

---

## 53. [MEDIUM] gui/src/App.tsx:175  <gui-pages> (preexisting)

The "signatures never updated" banner fires off the disconnect fallback stats, and the comment defending the guard is wrong about exactly that case.

**Failure:** getRuntimeStats() throws for one poll (daemon mid-engine-reload, PIPE_BUSY under scan load). fetchDashboard's per-call .catch substitutes a synthetic RuntimeStats with db_stale:true, db_stale_hours:0, signature_count:0, protection_state:"unprotected" (api/sentinella.ts:366), and useDaemon commits it unconditionally via `setData(result)` (useDaemon.ts:127) even though healthyThisPoll is false. getConnectionState() is a separate supervisor call that still returns "connected", so App.tsx takes the else branch, computes reallyNeverUpdated = true && 0===0 && 0===0 = true, and pushes a red-flag banner reading "Signatures have never been updated" with an "Update now" button — on a machine with a fully loaded signature database. The in-file comment says the guard works because "if the daemon reports ANY signatures loaded, suppress the never-updated case — the daemon DID load them from somewhere"; in the fallback the daemon reported nothing at all, which is the one shape the guard cannot distinguish from a genuinely empty DB.

**Evidence:** App.tsx: `const sigCount = stats.signature_count ?? 0; const reallyNeverUpdated = stats.db_stale && stats.db_stale_hours === 0 && sigCount === 0;` against api/sentinella.ts:366 `getRuntimeStats().catch(() => ({ ... signature_count: 0, db_stale: true, db_stale_hours: 0, ... protection_state: "unprotected" ... }))`

---

## 54. [MEDIUM] gui/src-tauri/nsis-hooks.nsh:78  <installer> (preexisting)

The installer ships no daily.cvd, so every fresh install bootstraps with main.cvd only, and the skip_bootstrap guard keys on main.* so daily is never bootstrapped afterwards either.

**Failure:** stage-windows-package.bat:124 falls back to the developer's live freshclam DB (C:/ProgramData/Sentinella/signatures), where freshclam has already converted daily.cvd to the incremental daily.cld. Line 127's 'if exist daily.cvd' is therefore false and no daily DB is staged — confirmed: release/staging/windows/runtime/signatures_bootstrap contains only main.cvd, bytecode.cvd, two .sign files and freshclam.dat, and the generated installer.nsi:697-701 packs exactly those. nsis-hooks.nsh:78 then CopyFiles /SILENT a file that is not in the bundle and silently no-ops. A fresh install lands main.cvd (dated 2026-05-26) with no daily signatures, i.e. none of ClamAV's recent-malware coverage, and on an offline machine that state is permanent. Lines 75-76 skip the bootstrap block entirely once main.cvd/main.cld exists, so a later corrected bundle cannot repair it. scripts/release-sanity-windows.bat:46 already asserts this file exists in staging — the current staging tree fails that check.

**Evidence:** CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\daily.cvd" "$SENTI_DATA\signatures\"   — daily.cvd is absent from staging and from installer.nsi's File list

---

## 55. [MEDIUM] scripts/preflight-staging-versions.ps1:21  <installer>

The header claims the guard is 'Wired into npm run tauri:build via gui/package.json prebuild hook'; gui/package.json has neither a tauri:build script nor any prebuild hook, so the documented build command runs no staleness check at all.

**Failure:** gui/package.json scripts are exactly: dev, build, preview, tauri, preflight:staging, release:build. Only release:build chains the preflight. Every comment in the sibling script tells the developer to run 'pnpm tauri build' (prep-installer-staging.ps1 lines 22, 25, 135) and installer.nsi was produced by that path. Running 'pnpm tauri build' or 'npm run tauri -- build' — the exact command printed in this script's own failure recipe at line 122 — invokes the `tauri` script directly and bypasses the guard entirely. The v0.1.7 stale-daemon class the file exists to prevent therefore ships unguarded on the command everyone actually types.

**Evidence:** # Wired into npm run tauri:build via gui/package.json prebuild hook.   vs gui/package.json: "tauri": "tauri", "release:build": "npm run preflight:staging && tauri build"

---

## 56. [MEDIUM] crates/sentinelld/src/main.rs:543  <concurrency> (preexisting)

`config.realtime_enabled` is never consulted at daemon startup: `start_watcher()` is called unconditionally, and `start_watcher` itself only reads `realtime_roots`, so the persisted "Real-time protection: off" master switch is silently discarded on every restart.

**Failure:** User turns the real-time master switch off; `protection.set_critical` writes `realtime_enabled = false` to sentinelld.toml and stops the watcher for the current session (`user_disabled_protection` is an in-memory `AtomicBool`, state.rs:1048). The machine reboots or the service restarts. `AppState::new` initialises `user_disabled_protection: AtomicBool::new(false)`, and main.rs:543 calls `server.state().start_watcher()` with no `if config.realtime_enabled` gate — `start_watcher` loads the config only to compute `realtime_roots` (state.rs:3958). Real-time scanning is running again while the Settings page, which renders `draft.realtime_enabled` from the saved config (gui/src/pages/Settings/tabs/Protection.tsx:65), shows the switch off and the tooltip says "Master switch. When off, only on-demand scans run." A grep confirms the field is read nowhere else in the daemon except the heartbeat monitor's restart guard (state.rs:4939).

**Evidence:** // main.rs:541-543
// Start real-time watcher (if engine is available).
// Watcher runs even in audit mode (minimal protection).
server.state().start_watcher();

// grep realtime_enabled in crates/sentinelld: config/mod.rs decl+default, ipc/mod.rs:2589 (write),
// state.rs:4939 (heartbeat restart guard), main.rs:334 (log line). No startup gate.

---

## 57. [MEDIUM] crates/sentinelld/src/ipc/state.rs:4955  <concurrency> (preexisting)

The watcher heartbeat is touched only when a debounce flush actually carries filesystem events, so "positive but stale" means "the filesystem was quiet", not "the watcher stalled" — the heartbeat monitor therefore tears down and rebuilds the watcher every ~80 s on an idle machine, and the comment above the check claims the opposite.

**Failure:** `watcher/mod.rs:333` calls `state.touch_watcher_heartbeat()` inside `if (!recent.is_empty() || !overflow_dirs.is_empty()) && (force_flush || last_flush.elapsed() >= DEBOUNCE_MS)` — i.e. only when at least one qualifying Create/Modify event was queued. On a locked or idle machine overnight, no watched root produces an event for 60 s. `hb` is non-zero (the watcher ticked earlier in the session) and `now - hb > 60`, so the monitor logs "watcher heartbeat stalled — restarting", takes `protection_toggle_lock`, and calls `start_watcher()`. That re-reads the config, re-enumerates `C:\Users`, canonicalises and re-registers up to 128 recursive `ReadDirectoryChangesW` watches, and constructs a brand-new `RealtimeWatcher` whose per-watcher `ScanCache` (watcher/mod.rs:69) starts empty, discarding the realtime dedup cache. `touch_watcher_heartbeat()` at 4977 resets the clock, so the cycle repeats every ~80 s (20 s poll + 60 s threshold) for the whole idle period, inflating `watcher_restarts_total` — the counter the `health` IPC surfaces as a tamper signal — until it is meaningless. The comment at 4949-4951 asserts "hb==0 means ... just no FS events on a quiet box. Only act on a positive-but-stale heartbeat (real stall signal)", which is exactly backwards once the watcher has ticked once.

**Evidence:** // state.rs:4948-4955
let hb = state.watcher_last_heartbeat.load(Ordering::Relaxed);
// hb==0 means the watcher hasn't ticked yet — could be
// start-pending or just no FS events on a quiet box. Only
// act on a positive-but-stale heartbeat (real stall signal).
if hb == 0 || now < hb { continue; }
if now - hb > 60 { ... state.start_watcher(); }

// watcher/mod.rs:314-333 — the ONLY touch site, inside the has-events flush
if (!recent.is_empty() || !overflow_dirs.is_empty()) && (force_flush || last_flush.elapsed() >= ...) {
    ...
    state.touch_watcher_heartbeat();

---

## 58. [MEDIUM] crates/sentinelld/src/ipc/mod.rs:2238  <ipc-surface> (preexisting)

settings.set pins only 15 of the 20 CRITICAL_FIELDS; because Config is #[serde(default)], a params object that simply omits the fish / sandbox / clamav_isolation / web_protection sections silently resets them to defaults and persists that - bypassing the kill-vector gate that settings.set_full enforces via critical_diff.

**Failure:** A caller (the still-registered save_settings Tauri command, the CLI, or any elevated IPC client) sends settings.set with a partial config object - e.g. {auth, token, max_file_size_mb:512, log_level:"info"}. serde_json::from_value::<Config> succeeds because config/mod.rs:8 declares #[serde(default)] on the struct, filling every absent field from Default. The handler then pins realtime_enabled, auto_quarantine, argus_worker_*, scan.argus_worker_*, excluded_*, trusted_hashes, realtime_roots, heuristic_alerts, idle_scan_enabled, scheduled_scan_enabled, enhanced_signature_provider and developer.password_sha256 back to `current` - but NOT fish.enabled / fish.observe_only / fish.active_response / sandbox.enabled / clamav_isolation, all five of which are in CRITICAL_FIELDS, nor web_protection which is not in that list at all. config.save() then writes: fish.active_response="observe" and fish.observe_only=true (ransomware shield downgraded from enforcing to observe-only), sandbox.enabled=false, clamav_isolation="in_process" (the exact downgrade full_config.rs:118-121 calls out as re-exposing in-engine memory-corruption CVEs), and web_protection reset to enabled=false with blocklists and allowlist emptied. settings.set_full refuses precisely these mutations via Config::critical_diff; settings.set has neither the pin nor the diff check, and its own comment claims otherwise.

**Evidence:** // ipc/mod.rs settings.set - the complete pin list:
config.excluded_paths = current.excluded_paths;
config.excluded_extensions = current.excluded_extensions;
config.excluded_detections = current.excluded_detections;
config.trusted_hashes = current.trusted_hashes;
config.realtime_roots = current.realtime_roots;
config.heuristic_alerts = current.heuristic_alerts;
config.idle_scan_enabled = current.idle_scan_enabled;
config.scheduled_scan_enabled = current.scheduled_scan_enabled;
config.enhanced_signature_provider = current.enhanced_signature_provider;   // line 2238 - ends here
// (no config.fish / config.sandbox / config.clamav_isolation / config.web_protection)

// config/mod.rs:7-9
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {

// full_config.rs:122-126  CRITICAL_FIELDS
"fish.enabled", "fish.observe_only", "fish.active_response", "sandbox.enabled"

---

## 59. [MEDIUM] crates/sentinelld/src/ipc/mod.rs:2594  <ipc-surface> (preexisting)

protection.set_critical calls enable_protection() -> start_watcher() before it writes the new config, and start_watcher re-reads realtime_roots from disk, so a request that re-enables protection and changes the watched roots starts the watcher on the OLD roots while the UI reports the new ones.

**Failure:** Elevated user re-enables Real-time protection and adds D:\Work to Watched folders in one Settings save. criticalDiff = {realtime_enabled:true, realtime_roots:[..., "D:\\Work"]}. The handler processes realtime_enabled first: config.realtime_enabled=true (in-memory only) and state.enable_protection() -> start_watcher(), which at state.rs:3958 does `let cfg = crate::config::Config::load(None)` - reading the on-disk config.toml, which still holds the OLD realtime_roots because config.save() does not run until line 2861. The watcher therefore registers ReadDirectoryChangesW on the old root set. Validation then passes, the new roots are persisted, and the GUI reports success and renders D:\Work as a watched folder. Nothing re-reads the roots afterwards, so on-access scanning for D:\Work stays off until the service is restarted or the watcher is restarted for an unrelated reason - a watched directory that the UI claims is protected and isn't. (The same read-before-write ordering means the in-memory config the handler is building is discarded by start_watcher for every field it consults.)

**Evidence:** // mod.rs:2588-2596
if let Some(v) = req.params.get("realtime_enabled").and_then(|v| v.as_bool()) {
    config.realtime_enabled = v;
    ...
    } else if !state.is_user_disabled() {
        state.enable_protection();      // line 2594 -> start_watcher()
    }
}
// ... realtime_roots is only assigned into `config` at line 2829, and
// config.save(&path) is only reached at line 2861.

// state.rs:3934-3958  pub fn start_watcher(self: &Arc<Self>) {
//     let cfg = crate::config::Config::load(None).unwrap_or_default();   <-- reads DISK
//     let config_roots: Vec<PathBuf> = cfg.realtime_roots.iter()...

---

## 60. [LOW] crates/sentinella-dnsreconcile/src/main.rs:389  <reconciler-main>

`everything_this_binary_prints_is_ascii` asserts on hand-copied duplicates of six messages rather than on the strings the code emits, so it stays green if any of those messages regresses — and it does not cover the two `remove_task` messages at all.

**Failure:** Someone edits `log(&state_file, "no recorded rule — nothing to reconcile")` to use an em-dash (the surrounding doc comments are full of them, so this is the natural thing to type). The binary now writes UTF-8 the support engineer's legacy-codepage console renders as mojibake in the one file that has to be readable on a machine with no DNS — and this test still passes, because it asserts on its own private copy of the old literal. Delete the ASCII discipline from every message in `run()` and `remove()` and the test remains green; only `USAGE`, the one item referenced by constant, is actually covered. The two messages in `remove_task` (lines 138 and 148) are not in the list at all, and line 138 is exactly the message the uninstaller's abort dialog tells the user to go read.

**Evidence:** for m in [
    "no recorded rule - nothing to reconcile".to_string(),          // a copy, not the code's string
    format!("recorded rule {guid} is absent - clearing stale record"),
    ...
    USAGE.to_string(),                                              // the only real reference
] { assert!(m.is_ascii(), ...); }

---

## 61. [LOW] C:\Users\Nicolas\Desktop\sentinella\crates\dnsguard\src\proxy.rs:1401  <dnsguard-protocol> (preexisting)

DNS-over-TCP length prefix is `resp.len() as u16`; the egress OPT appended by `normalize_client_edns` can push a response past 65535, producing a truncated frame length and permanent stream desync.

**Failure:** `tcp_exchange` reads an upstream answer of up to 65535 bytes (u16 length prefix). `normalize_client_edns` then strips inherited OPTs and, if THIS requester sent an OPT, appends 11 bytes. When the upstream answer carries no OPT of its own — which is exactly the case on the `edns_stripped` fallback path (we re-query plain, so the answer has no OPT) and on any upstream that does not echo one — an answer of 65525..65535 bytes becomes 65536..65546. I measured: 65530-byte response + `append_client_opt` = 65541 bytes, `65541 as u16` = 5. We then `write_all` a 5-byte length prefix followed by 65541 bytes. A DO=1 TCP client asking for a name with a large signed RRset reads 5 bytes as a complete DNS message, then re-frames the remaining 65536 bytes as further length-prefixed messages: the connection is desynchronised and every pipelined query on it gets garbage. The same answer is cached, so every later TCP requester with EDNS reproduces it.

**Evidence:** let framed_len = (resp.len() as u16).to_be_bytes();
let written = timeout(budget, async {
    stream.write_all(&framed_len).await?;
    stream.write_all(&resp).await
}).await;

// measured: len after append_client_opt = 65541 ; framed as u16 = 5

---

## 62. [LOW] C:\Users\Nicolas\Desktop\sentinella\crates\dnsguard\src\proxy.rs:1224  <dnsguard-protocol> (preexisting)

Two comments justify answering SERVFAIL by claiming the client can 'fail over to the NRPT secondary'; the rule this product installs has no secondary and cannot have one.

**Failure:** `crates/sentinelld/src/web_protection/rule.rs:29-33` states: 'The rule we install carries exactly ONE server: our own proxy. An NRPT rule overrides the adapter's DNS configuration for every matching name ... so there is no secondary to fall back to.' `install()` confirms it: `let servers: Vec<IpAddr> = vec![listen.ip()];`. So the documented rationale for the shed path — and for the self-test's reasoning at proxy.rs:773-774 ('because nothing SERVFAILs, no client fails over to the NRPT secondary either') — rests on a fallback that does not exist. Operationally: when the UDP in-flight pool saturates (an unprivileged local process can drive this at will, per rule.rs:56-66), the client does not fail over to anything; it gets a hard resolution failure. Anyone reasoning about the overload policy from these comments will conclude the machine degrades to 'unfiltered DNS' when it actually degrades to 'no DNS', which inverts the design's governing rule.

**Evidence:** // proxy.rs:1222-1224
/// Overload path: answer immediately with SERVFAIL. WHY SERVFAIL and not a
/// drop: a dropped query leaves the client's resolver retrying for seconds;
/// SERVFAIL makes it move on (or fail over to the NRPT secondary) at once.

// rule.rs:117-121
let servers: Vec<IpAddr> = vec![listen.ip()];
nrpt::install_rule(&guid, nrpt::NAMESPACE_ALL, &servers)

---

## 63. [LOW] C:\Users\Nicolas\Desktop\sentinella\crates\dnsguard\src\proxy.rs:1195  <dnsguard-protocol> (preexisting)

The UDP truncation path discards the normalized response and rebuilds from the raw request, so an EDNS/DO client receives TC=1 with no OPT record — the one egress point that was supposed to guarantee OPT presence is bypassed.

**Failure:** `handle_query` runs `normalize_client_edns`, which appends exactly one OPT when the requester sent one. `udp_loop` then discards that response whenever `resp.len() > udp_limit` and substitutes `wire::build_truncated_response(&bytes, rcode)`, built from the raw request; that builder emits only header + question and never an OPT. So a client that advertised EDNS0 (e.g. a 1232-byte DO=1 stub asking for a signed RRset) gets a TC=1 answer that asserts the responder is not EDNS-capable. Resolvers that do RFC 8906-style EDNS probing read a response without an OPT as 'this server does not do EDNS' and downgrade subsequent queries — dropping DO and therefore DNSSEC — for as long as they cache that verdict. The same applies to the SERVFAIL branch immediately below it and to `shed()` (line 1231), which also bypass `normalize_client_edns`.

**Evidence:** let resp = if resp.len() > udp_limit {
    let rcode = wire::response_info(&resp).map_or(wire::RCODE_NOERROR, |info| info.rcode);
    match wire::build_truncated_response(&bytes, rcode) {   // <- rebuilt from the raw request
        Some(truncated) => truncated,
        None => match wire::build_error_response(&bytes, wire::RCODE_SERVFAIL, false) { ... },
    }
} else { resp };

// wire.rs build_truncated_response emits: header + (question) only, ARCOUNT hardcoded 0:
//   out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar zeroed

---

## 64. [LOW] crates/dnsguard/src/filter.rs:505  <dnsguard-cache-decide> (preexisting)

A single non-UTF-8 byte anywhere in a blocklist aborts the whole load via `line?`, but the rules ingested before that point stay in the engine — so the daemon logs "SKIPPED", keeps a partially-loaded blocklist, and reports Serving with a rule count.

**Failure:** `reader.lines()` yields `Err(InvalidData, "stream did not contain valid UTF-8")` for any line that is not valid UTF-8 — e.g. a hosts/domain list saved by Notepad in the system ANSI codepage with an accented character in a comment (`# actualis\xE9 2026`), or a mid-file read error on a network path. VERIFIED: a 5004-entry hosts file with one 0xE9 byte on line 3 returned `Err(InvalidData)` with `first.example`/`second.example` already inserted into the engine and all 5001 later rules missing. `HostsLoadStats` is never returned, so `truncated` is never set and no budget warning fires. `load_lists` then logs `warn!(path, e, "blocklist read failed — SKIPPED")` — factually wrong, it was partially applied — and returns `engine.rule_count()`, so `WebProtectionStatus` reports `state: Serving, rules_loaded: 3`. The self-test passes (the canary rule is intact), the NRPT rule installs, and the machine's DNS is routed through a proxy whose blocklist is 0.04% loaded with nothing in the status surface saying so. This directly contradicts the loader's own stated principle ("Silently truncating or silently dropping entries would hide protection gaps").

**Evidence:** ingest_lines:
    let mut limited = reader.take(max_bytes.saturating_add(1));
    for line in limited.by_ref().lines() {
        let line = line?;            // <-- aborts the whole load; rules already added stay

service.rs:431:
    Err(e) => warn!(path = %path, %e, "blocklist read failed — SKIPPED"),

---

## 65. [LOW] crates/dnsguard/src/proxy.rs:1227  <dnsguard-cache-decide> (preexisting)

`shed()` never receives the `synthetic` flag, so the overload path bumps the user-facing `queries` counter and fires the decision hook even inside the self-test's private serving loop — contradicting `udp_loop`'s doc and able to red an otherwise healthy self-test.

**Failure:** `udp_loop` is documented: "When `synthetic` is true (the self-test's private serving loop), every query answered here is a health-check probe: it skips the user-facing counters and the decision hook." That is false for the shed branch — `Err(_) => shed(&state, &bytes, peer, &sock).await` drops `synthetic` on the floor, and `shed` unconditionally does `bump(&counters.queries)` plus `state.emit(peer, &query, QueryOutcome::Shed)`. `Proxy::self_test` computes `report.filter_ok = ... && after.queries == before.queries && after.blocked == before.blocked`. So if the UDP in-flight pool (256 permits) is saturated by any concurrent local traffic during the self-test window, `after.queries != before.queries`, `filter_ok` is false, and `WebProtection::start` takes the `SelfTestFailed` branch — web protection refuses to serve for the entire daemon lifetime with a detail string that blames 'probes leaked into user-facing counters'. It also means real user queries that arrive during the self-test window are logged through the decision hook while every query the loop actually serves is not (once `log_queries` is wired, the query log gets exactly the inverse of the documented set).

**Evidence:** udp_loop:
    Err(_) => shed(&state, &bytes, peer, &sock).await,   // `synthetic` in scope, not passed

async fn shed(state: &Arc<State>, bytes: &[u8], peer: SocketAddr, sock: &UdpSocket) {
    state.counters.bump(&state.counters.shed);
    state.counters.bump(&state.counters.queries);
    if let Ok(query) = wire::parse_query(bytes) {
        state.emit(peer, &query, QueryOutcome::Shed);
    }

self_test:
    report.filter_ok = canary_ok && resolves_ok && actual_delta >= expected_delta
        && after.queries == before.queries && after.blocked == before.blocked;

---

## 66. [LOW] crates/dnsguard/src/proxy.rs:453  <dnsguard-transport> (preexisting)

The response cache is bounded in ENTRIES but not in BYTES; a TCP-fetched answer of up to 65535 bytes is cached whole, so 10,000 entries can reach ~640 MB resident in a service running as SYSTEM.

**Failure:** `cache_store` enforces only `cache.len() >= self.config.cache_capacity` (DEFAULT_CACHE_CAPACITY = 10_000) and then inserts `response.to_vec()`. The stored bytes come from `tcp_exchange`, which reads a full u16-framed answer (up to 65535 bytes) — and the crate's own test `tcp_fetched_oversized_answer_is_truncated_for_udp_full_for_tcp` proves a ~60 KB answer is cached and re-served from cache. So any unprivileged local process (or any web page driving lookups) that resolves 10,000 distinct names under an attacker-controlled zone serving ~60 KB TXT RRsets drives sentinelld's RSS to ~600 MB, held for up to max_ttl (300 s) per entry and trivially refreshed. Secondary effect: once full, `cache_store` returns early rather than evicting, so no new name is cached at all until entries expire — every real query goes upstream. This contradicts lib.rs's stated invariant 'everything is bounded (... cache capacity ...)'; it is the same entries-vs-bytes mistake filter.rs already documents at length for MAX_HOSTS_BYTES ('memory is proportional to RULES, not to input bytes'), left unfixed here.

**Evidence:** pub const DEFAULT_CACHE_CAPACITY: usize = 10_000;
...
if cache.len() >= self.config.cache_capacity {
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);
    if cache.len() >= self.config.cache_capacity { return; }
}
cache.insert(key.clone(), CacheEntry { bytes: response.to_vec(), expires_at: Instant::now() + ttl });

---

## 67. [LOW] crates/dnsguard/src/proxy.rs:870  <dnsguard-transport> (preexisting)

Three doc comments state the self-test asserts the `canary_probes` delta is EXACTLY the number of probes served; the code deliberately checks a lower bound, and an inline comment three lines away says equality would be wrong.

**Failure:** A maintainer reading `Counters::canary_probes` ('The self-test asserts a delta equal to the number of canary probes it actually got SERVED'), `self_test`'s step (iii)(b) ('moved by exactly the number of canary probes SERVED') or `SelfTestReport::filter_ok` ('the canary_probes counter moved by exactly the number of canary probes served') would conclude the check is an equality and could 'restore' it — reintroducing the U01 regression that the inline comment and the test `concurrent_canary_traffic_does_not_red_a_healthy_self_test` exist to prevent (any other local process querying the canary inside the window inflates the counter and reds a healthy proxy, refusing to serve). The narrower half of the same statement is also wrong: `expected_delta` counts probes that SUCCEEDED (`u64::from(canary_ok) + u64::from(report.tcp_ok)`), not probes served.

**Evidence:** // code:
let expected_delta = u64::from(canary_ok) + u64::from(report.tcp_ok);
let actual_delta = after.canary_probes.wrapping_sub(before.canary_probes);
// LOWER BOUND, not equality (round-3 closure review, U01).
if actual_delta < expected_delta { ... }

// docs, three places, all saying the opposite:
// "The self-test asserts a delta equal to the number of canary probes it actually got SERVED"
// "(b) `counters.canary_probes` moved by exactly the number of canary probes SERVED"
// "the `canary_probes` counter moved by exactly the number of canary probes served"

---

## 68. [LOW] C:\Users\Nicolas\Desktop\sentinella\crates\sentinelld\src\web_protection\config.rs:318  <wp-config-upstreams>

validate() and its regression test bless `[::1]:53` as a supported listen address, but every probe in the stack binds IPv4 loopback, so an IPv6 listen can never pass the self-test and web protection silently never starts.

**Failure:** A user sets `listen = "[::1]:53"`, which check_enablable accepts (::1 is loopback, port is 53) and which config.rs:318-323 explicitly asserts 'must remain usable'. Proxy::bind succeeds. Then Proxy::self_test binds its probe socket as IPv4 only - `UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))` at dnsguard/proxy.rs:736 - and probe_exchange calls send_to(probe, [::1]:53) on it, which cannot succeed from an AF_INET socket. canary_ok is false, filter_ok is false, report.ok() is false, and service.rs:243 refuses to serve. The user gets ProxyState::SelfTestFailed forever with no hint that the listen family is the cause, while the test suite says the setting is supported. The watchdog probes have the identical defect (rule.rs:285 and rule.rs:310 both `UdpSocket::bind("127.0.0.1:0")` then connect), and sentinella-dnsreconcile hardcodes PROBE_ADDR = "127.0.0.1:53", so even if the self-test were fixed the boot reconciler would strip the rule on every boot. The test is the tautological shape: it asserts validate() left `enabled` true, not that the address can actually serve.

**Evidence:** config.rs:317  // ...and loopback:53 in either family stays enabled.
config.rs:318  for good in ["127.0.0.1:53", "[::1]:53"] {
config.rs:322      assert!(c.enabled, "{good}: must remain usable");
dnsguard/proxy.rs:736  let sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await;
rule.rs:285  let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await else { return false; };
sentinella-dnsreconcile/src/main.rs:  const PROBE_ADDR: &str = "127.0.0.1:53";

---

## 69. [LOW] crates/dnsguard/src/proxy.rs:1224  <wp-rule-watchdog> (preexisting)

Two comments in dnsguard justify behaviour by clients "failing over to the NRPT secondary". There is no NRPT secondary - the rule this product installs carries exactly one server, and config.rs:38-53 removed the whole `on_proxy_failure` knob for precisely that reason.

**Failure:** A maintainer tuning the overload path reads line 1224 and believes SERVFAIL is safe because the client will fail over to another NRPT-supplied resolver. It will not: `rule::install` builds `let servers: Vec<IpAddr> = vec![listen.ip()];` - one entry - and an NRPT rule overrides the adapter's DNS configuration for every matching name. Under shedding, SERVFAIL is a terminal answer for every name on the machine, not a hint to try elsewhere. The same false model appears at line 773 in `self_test`, where it is used to argue that a filter blocking every name is less bad than it is. Both comments describe a fail-open behaviour that config.rs documents at length as impossible, and they are the kind of confidently-wrong rationale that gets a future change waved through - exactly the reasoning that produced the removed `on_proxy_failure = "fallback"` option in the first place.

**Evidence:** /// Overload path: answer immediately with SERVFAIL. WHY SERVFAIL and not a
/// drop: a dropped query leaves the client's resolver retrying for seconds;
/// SERVFAIL makes it move on (or fail over to the NRPT secondary) at once.

// vs. rule.rs:
let servers: Vec<IpAddr> = vec![listen.ip()];
// vs. config.rs:40-43:
// "fallback" was documented as "fail open: unfiltered DNS via the NRPT
// secondary". There is no NRPT secondary.

---

## 70. [LOW] crates/sentinelld/src/ipc/state.rs:1806  <wp-service-lifecycle>

set_web_protection carries load_developer_config's doc comment and a stray #[allow(dead_code)] wedged between two doc blocks — the rustdoc for the web-protection publisher claims it replaces the developer-mode config.

**Failure:** `cargo doc` and any IDE hover on AppState::set_web_protection render "Replace the cached developer-mode config (called when the mode is toggled at runtime so telemetry gating reflects the new state immediately). Wired by the forthcoming dev.set_developer_mode IPC (B2)." — a confident, entirely false description of the function that publishes the web-protection read handle to the IPC layer. `load_developer_config` (the method the text belongs to, 20 lines below) is left undocumented, and the `#[allow(dead_code)]` intended for it now suppresses dead-code analysis on set_web_protection instead, so if the single call site at main.rs:506 were ever removed the compiler would stay silent and webprotection.status would answer WebProtectionStatus::disabled() forever.

**Evidence:**     /// Replace the cached developer-mode config (called when the mode is toggled
    /// at runtime so telemetry gating reflects the new state immediately).
    /// Wired by the forthcoming `dev.set_developer_mode` IPC (B2).
    #[allow(dead_code)]
    /// Publish the web-protection read handle for the IPC layer.
    ///
    /// A slot rather than a constructor argument because the subsystem
    /// starts AFTER `AppState` exists, ...
    pub fn set_web_protection(&self, handle: std::sync::Arc<crate::web_protection::WebProtectionHandle>) {

---

## 71. [LOW] crates/sentinelld/src/updater/mod.rs:110  <updater-retry>

The retry backoff sleeps BEFORE the budget check, so a cycle can run 12 minutes against a CYCLE_BUDGET documented as a 10-minute wall-clock ceiling "sleeps included" — 120 seconds of it pure dead time after the loop has already decided to give up.

**Failure:** Concrete trace with the shipped constants. t=0: attempt 0 gets remaining = 10m00s, freshclam fails fast (transient) at t=1s. attempt 1: line 110 sleeps 30s -> t=31s; remaining = 9m29s >= 45s, so it runs and hangs; killed by its budget at t=31s+9m29s = 10m00s; returns "freshclam timed out" (transient). attempt 2: line 110 sleeps the full 120s FIRST -> t=12m00s; only then does line 115 compute remaining = CYCLE_BUDGET.saturating_sub(12m) = 0, see 0 < MIN_ATTEMPT_BUDGET, and return. The last 120 seconds are spent sleeping toward an attempt the loop was always going to refuse. During all 12 minutes update_running is held, so every scheduled and every user-pressed update is rejected with "Update already in progress", and a user watching the Update page watches a spinner for 12 minutes. Both doc comments next to this code assert the opposite.

**Evidence:** updater/mod.rs:102-116: `if attempt > 0 { let pause = RETRY_BACKOFF[...]; ... std::thread::sleep(pause); }` THEN `// The backoff sleeps come out of the same budget as the downloads, so the ceiling covers the whole cycle...` `let remaining = CYCLE_BUDGET.saturating_sub(cycle_started.elapsed()); if remaining < MIN_ATTEMPT_BUDGET { ... return last; }`
updater/mod.rs:39-43: `/// Wall-clock ceiling for one cycle, sleeps included.`

---

## 72. [LOW] crates/sentinelld/src/ipc/state.rs:1806  <stats-staleness> (preexisting)

set_web_protection carries load_developer_config's orphaned doc comment plus a stray #[allow(dead_code)], so the published doc for the web-protection publisher describes developer-mode telemetry and the attribute suppresses dead-code detection on a function that is live.

**Failure:** A reader (or a future maintainer auditing the web-protection wiring on this branch) reads state.rs:1806-1817 and is told this function 'Replace[s] the cached developer-mode config (called when the mode is toggled at runtime so telemetry gating reflects the new state immediately). Wired by the forthcoming dev.set_developer_mode IPC (B2).' It does none of that — it publishes the WebProtectionHandle, and it is called from main.rs:506 on the boot path that decides whether webprotection.status can answer at all. The #[allow(dead_code)] sitting between the two doc blocks also means that if the main.rs:506 call is ever dropped, the compiler will not warn that the web-protection status surface has gone permanently dark.

**Evidence:** state.rs:1806-1817: doc block ending `/// Wired by the forthcoming \`dev.set_developer_mode\` IPC (B2).` then `#[allow(dead_code)]` then a second doc block then `pub fn set_web_protection(&self, handle: std::sync::Arc<crate::web_protection::WebProtectionHandle>)`. The real developer-config setter is state.rs:1835 `pub fn load_developer_config(&self, dev: crate::config::DeveloperConfig)`, which now has no doc at all. main.rs:506 `server.state().set_web_protection(web_protection.handle());`

---

## 73. [LOW] crates/sentinelld/src/config/mod.rs:1196  <config-validate>

The FullConfig bridge comment asserts "The compile-time field-coverage test below catches drift after a Config struct add" — no such test exists anywhere in the repo, and the drift it claims to catch has already happened: Config.web_protection is absent from FullConfig.

**Failure:** `grep -rn 'field-coverage\|field_coverage' .` returns exactly one hit: the comment itself. The four tests in full_config_bridge_tests are runtime spot-checks (roundtrip of 4 fields, kill-vector pinning, critical_diff, password redaction); none enumerate Config's fields. Meanwhile [web_protection] — the DNS filtering section added for this 0.1.13 release — has no counterpart in FullConfig, no entry in RestartRequirementMap::build(), and no line in `impl From<&Config> for FullConfig`. Consequence: settings.get_full, the only settings surface the shipped GUI uses (gui/src-tauri/src/lib.rs:528 save_full_settings; nothing in gui/src calls save_settings), cannot read or write any web-protection field, and restart_requirement("web_protection.enabled") silently returns None for a field that requires a daemon restart. The section is configurable only by hand-editing TOML, which is exactly what the comment promises will be caught. A reviewer trusting the comment will add the next Config field and assume the compiler will complain.

**Evidence:** config/mod.rs:1194-1197 `// it to the GUI. The compile-time field-coverage test below catches / // drift after a Config struct add.`; config/mod.rs:95 `pub web_protection: crate::web_protection::WebProtectionConfig,` has no counterpart in full_config.rs:138-216 (FullConfig ends at `pub developer: DeveloperConfigPublic,`) nor in the From impl at config/mod.rs:1209-1310.

---

## 74. [LOW] crates/sentinelld/src/config/mod.rs:1611  <config-validate> (preexisting)

critical_diff's regression test mutates 15 fields but asserts only `diffs.len() >= 13`, so deleting any two checks from critical_diff leaves it green — and it never exercises the five v0.1.9 critical fields at all.

**Failure:** Delete the `if self.heuristic_alerts != full.heuristic_alerts` and `if self.excluded_extensions != full.excluded_extensions` branches from critical_diff (config/mod.rs:1443 and 1455). The test still mutates 15 fields, now produces 13 diffs, `assert!(diffs.len() >= 13)` passes, and neither field appears in the four `diffs.contains(&...)` spot-checks (realtime_enabled, excluded_paths, trusted_hashes, argus_worker_path). The second-layer kill-vector defence is gone and the test suite is green. Separately, the test never mutates fish.enabled, fish.observe_only, fish.active_response, sandbox.enabled or clamav_isolation, so deleting those five checks is completely untested — the only thing guarding them is a `debug_assert!` that checks the opposite direction (diffs ⊆ CRITICAL_FIELDS, never CRITICAL_FIELDS ⊆ diffs). The comment above the assert also states "All 15 critical fields should be flagged" while CRITICAL_FIELDS has 20 entries.

**Evidence:** config/mod.rs:1609-1611 `// All 15 critical fields should be flagged (15 entries because / // both top-level + scan.* argus pairs count). / assert!(diffs.len() >= 13, "critical_diff missed fields: {diffs:?}");` and 1500-1503 `debug_assert!(diffs.iter().all(|f| CRITICAL_FIELDS.contains(f)), ...)`; full_config.rs:93-127 CRITICAL_FIELDS contains 20 entries.

---

## 75. [LOW] crates/sentinelld/src/config/mod.rs:432  <config-validate> (preexisting)

update_mirror is validated, clamped, persisted and rendered as an editable GUI field described as "Hostname of the ClamAV mirror used by freshclam" — but no code in the workspace ever reads it.

**Failure:** A user on an air-gapped or corporate network sets the update mirror to their internal ClamAV mirror in Settings > Updates. The GUI writes it via settings.set_full, the daemon validates it (strips scheme, caps at 253 chars), saves it, and reports ok. Nothing then consumes it: `grep -rn update_mirror crates/` returns only the config struct/default/validate, the FullConfig mirror, the proto settings struct, and i18n strings — the updater invokes freshclam against freshclam.conf (ipc/state.rs:4300-4309 resolves the conf path) and never templates the mirror into it. Signature updates keep going to whatever DatabaseMirror freshclam.conf already contains, so the user believes they have redirected updates and has not. The field is presented with no "not yet wired" hint.

**Evidence:** config/mod.rs:432-453 validates update_mirror; full_config.rs:155/440 mirrors it; gui/src/pages/Settings/tabs/Updates.tsx:86-93 renders it as an editable TextField bound to `draft.update_mirror`; gui/src/i18n/en.ts:943 `"settings.update_mirror_desc": "Hostname of the ClamAV mirror used by freshclam."`. Workspace-wide grep for update_mirror produces no read site in updater/, engine/, or anywhere else in crates/sentinelld.

---

## 76. [LOW] crates/sentinella-ipc-proto/src/full_config.rs:81  <wire-schema> (preexisting)

All five performance.* fields fall through restart_requirement()'s catch-all to RestartRequirement::None ("applies immediately on save"), but AppState::performance_config is a plain non-interior-mutable field loaded once inside AppState::new and never reassigned.

**Failure:** On a 4 GB machine the user lowers performance.memory_critical_mb from 2500 to 800 (and memory_warning_mb to 600) so the daemon backs off before the box swaps, and saves. settings.set_full applies both fields (config/mod.rs:1378-1379), saves the TOML, and calls only refresh_staleness_thresholds — the sole hot-refresh in that handler. The GUI renders no restart pill because restartReqs.fields["performance.memory_critical_mb"] == "none". Every subsequent pressure evaluation (state.rs:5085/5093/5106 `.update(snap.working_set_mb, &self.performance_config)`) and the external-ARGUS routing decision at state.rs:1560 keep using the 1500/2500 values captured at AppState::new, so the daemon never enters the warning/critical states the user configured. Same applies to memory_profile, external_argus_under_pressure and max_resident_workers_on_pressure.

**Evidence:** full_config.rs:80-82 `// Everything else is hot-applied.\n        _ => None,` — no performance.* arm in either the EngineReload or DaemonRestart match arms
state.rs:400 `performance_config: crate::config::PerformanceConfig,` (plain field)
state.rs:1057 `performance_config: { ... let mut pc = crate::config::Config::load(None).map(|c| c.performance).unwrap_or_default(); ... }` — grep for `performance_config` in state.rs returns only lines 400, 1057, 1560, 5085, 5093, 5106: one declaration, one construction-time initialiser, four readers, zero setters
ipc/mod.rs:2484 `state.refresh_staleness_thresholds(&config);` is the only hot-apply performed by settings.set_full

---

## 77. [LOW] crates/sentinella-ipc-proto/src/full_config.rs:81  <wire-schema> (preexisting)

clamav_worker_timeout_sec is classified RestartRequirement::None while clamav_isolation next to it is DaemonRestart, but the timeout only reaches the runtime through set_clamav_subprocess, which main.rs calls once at startup and only when isolation is already "subprocess".

**Failure:** A user running clamav_isolation="subprocess" sees large archives fail with worker timeouts, raises clamav_worker_timeout_sec from 30 to 180 in Settings → Engine, and saves. Engine.tsx:76-81 renders the row with no restart pill because restart_requirement("clamav_worker_timeout_sec") is None. apply_non_critical sets the field (config/mod.rs:1367) and the TOML is written, but state.clamav_worker_timeout_sec (state.rs:449) is only ever stored by set_clamav_subprocess, whose single call site is main.rs:475. The scan path at state.rs:1307-1308 keeps loading the boot value of 30, so every large-archive scan keeps timing out and the user, having been told no restart is required, has no reason to restart.

**Evidence:** full_config.rs:69-78 DaemonRestart arm lists `clamav_isolation` but not `clamav_worker_timeout_sec`, which falls through to `_ => None` at line 81
main.rs:472-476 `if config.clamav_isolation == "subprocess" { server.state().set_clamav_subprocess(true, config.clamav_worker_timeout_sec); ... }` — the only call site (grep for set_clamav_subprocess returns state.rs:4985 definition + main.rs:475)
state.rs:1307-1308 `let use_subprocess = self.clamav_subprocess_enabled.load(Ordering::Relaxed); let timeout_sec = self.clamav_worker_timeout_sec.load(Ordering::Relaxed);`
config/mod.rs:1367 `self.clamav_worker_timeout_sec = full.clamav_worker_timeout_sec;`

---

## 78. [LOW] crates/sentinelld/src/config/mod.rs:1196  <wire-schema> (preexisting)

The FullConfig bridge header claims "The compile-time field-coverage test below catches drift after a Config struct add" — no such test exists in the file or anywhere in the workspace, and that missing guard is exactly what let web_protection be added to Config without ever reaching FullConfig.

**Failure:** A maintainer adds a field to Config, reads the comment at config/mod.rs:1196 asserting a compile-time coverage test guards the bridge, and does not hand-check FullConfig / apply_non_critical / RestartRequirementMap. Nothing fails: `impl From<&Config> for FullConfig` is an exhaustive struct literal for FullConfig, not for Config, so an extra Config field is simply never read and compiles clean. This already happened — web_protection (config/mod.rs:95) is absent from every part of the bridge. `grep -rn 'field-coverage\|field_coverage\|compile-time field' crates/` returns exactly one hit: the comment itself. The parallel false claim on the TypeScript side (gui/src/types/sentinella.ts:444-446, "All fields optional on the TS side so the GUI can render against an older daemon") is likewise untrue — not one field in the FullConfig interface at lines 504-581 carries a `?`.

**Evidence:** config/mod.rs:1195-1197 `// it to the GUI. The compile-time field-coverage test below catches\n// drift after a Config struct add.`
`grep -rn "field-coverage|field_coverage|compile-time field" crates/` → single hit: crates/sentinelld/src/config/mod.rs:1196
config/mod.rs:1508-1633 `mod full_config_bridge_tests` contains only config_roundtrips_through_full_config, apply_non_critical_preserves_kill_vector_fields, critical_diff_flags_every_attempted_kill_vector_mutation, full_config_excludes_password_hash_on_wire — none enumerates Config's fields
gui/src/types/sentinella.ts:504-581 every member of `export interface FullConfig` is declared required (e.g. `realtime_enabled: boolean;`, `max_file_size_mb: number;`)

---

## 79. [LOW] gui/src/notifications/notify.ts:150  <gui-daemon-hook>

The new staleness toast body asserts "Sentinella has not been able to update them", but the trigger it was just retargeted onto (`db_stale_notify`) is purely an age computation that knows nothing about whether any update was attempted or failed.

**Failure:** compute_db_stale_notify(effective_ts, now_ts, threshold_hours) compares timestamps only (state.rs:708-712) and is never gated on config.auto_update or on any update outcome. A user on a metered connection turns auto_update off in Settings > Updates — a supported, first-class toggle (FullConfig.auto_update). Fifteen days later Sentinella interrupts them with 'Your virus signatures are 15 days old. Sentinella has not been able to update them.' Nothing failed; Sentinella never tried, because they told it not to. Same false claim after a laptop is left powered off for a month. The doc comment directly above this function argues at length that update FAILURE is the wrong event to notify on and that AGE is the fact the user can act on — then the message string still asserts the failure. The user is sent to chase a nonexistent network/mirror problem, and the activity log (which the comment says is where failures are recorded) will show no failure to corroborate it.

**Evidence:** send(title, t("notify.signatures_stale_body").replace("{n}", String(days)));
// en.ts: "notify.signatures_stale_body": "Your virus signatures are {n} days old. Sentinella has not been able to update them."
// state.rs:708 fn compute_db_stale_notify(effective_ts, now_ts, threshold_hours) -> bool {
//                match effective_ts { Some(_) => compute_db_stale(...).0, None => false }

---

## 80. [LOW] gui/src/pages/Settings/components/widgets.tsx:429  <i18n-coherence> (preexisting)

`settings.list_full` does not exist in en.ts or any of the 9 locales, so the exclusion-list editor renders the raw key string to the user, and the `|| "list full"` fallback next to it can never fire because `t()` returns the (truthy) key on miss.

**Failure:** Settings → Protection → Excluded paths already holds 60 entries (cap 64). User clicks the folder-picker and multi-selects 10 folders. The loop hits `next.length >= cap` on the 5th path and pushes the error. The red inline error under the field reads literally `settings.list_full`. Same in every locale — en included — because the key is absent from all 9 files.

**Evidence:** widgets.tsx:429  `errs.push(i18n.t("settings.list_full") || "list full");`

i18n/index.ts:73-79 — `export function t(key: string): string { const locale = locales[currentLocale]; if (locale && key in locale) return locale[key]; if (key in en) return en[key]; return key; }`  → returns the key, which is truthy, so `|| "list full"` is dead code.

`grep -n "settings.list_" gui/src/i18n/*.ts` → no matches in any of the 9 locale files. My extraction of all 996 en.ts keys and all 809 literal `t()` call sites found exactly one call site key with no en.ts entry: this one.

Nothing catches it: `i18n/index.ts:14` declares `export type TranslationKey = keyof typeof en;` but it is referenced nowhere in the codebase (`grep -rn TranslationKey gui/src` → 1 hit, the declaration), and `t()` takes `key: string`. `node_modules/.bin/tsc --noEmit` passes clean.

---

## 81. [LOW] gui/src/pages/FirstRun.tsx:86  <i18n-coherence> (preexisting)

The entire first-run wizard — the first screen every user sees — is hardcoded English. FirstRun.tsx never imports `t` at all, so a Japanese/Russian/Chinese user's onboarding is 100% English even though their locale was auto-detected before this screen renders.

**Failure:** Fresh install on a ja-JP Windows box. `initLocale()` resolves `navigator.language` → "ja". `isFirstRunComplete()` is false, so App.tsx:262 renders `<FirstRunWizard>` before anything else. The user is shown "Welcome to Sentinella", "Local-first antivirus powered by ClamAV signatures…", "Waiting for daemon connection...", "Get Started", "Signature Database", "Step 1 of 2", "Run a Quick Scan?" — all English. There is no way to reach the language selector (Settings → Appearance) without first completing the wizard.

**Evidence:** FirstRun.tsx imports (lines 1-8): `useState/useEffect`, `lucide-react`, `Card`, `ShieldIcon`… `api/sentinella`, `notifications`, `types/sentinella`. No `import { t } from "../i18n"`.

Hardcoded strings confirmed by reading the file: :86 `<h1 …>Welcome to Sentinella</h1>`, :97 `<span>Waiting for daemon connection...</span>`, :103 `Get Started`, :117 `Signature Database`, :127 `Signatures Loaded`, :137 `Updating Signatures...`, :147 `Update Complete`, :149 `"Database updated."`, :155 `No Signatures Found`, :190 `Initial Scan`, :200 `Quick Scan Started`, :208 `Run a Quick Scan?`.

App.tsx:26 `const [showWizard, setShowWizard] = useState(!isFirstRunComplete());` and :259-262 gate the whole app behind it.

---

## 82. [LOW] gui/src/components/AppShell.tsx:7  <i18n-coherence> (preexisting)

Every page-header subtitle in the TopBar is a hardcoded English literal in `metaKeys`, even though `meta.dashboard_sub` … `meta.about_sub` exist in all 9 locale files and are referenced nowhere in the codebase.

**Failure:** User sets the language to Deutsch. The sidebar and page titles switch to German (they go through `t(titleKey)`), but the line directly under each title stays English on every page: "System overview", "Run a virus scan", "Isolated threats", "Scan records", "Alert history", "ASTRA adaptive analysis", "Signature database", "Configure Sentinella". The German translations for exactly these strings are shipped in de.ts and never read.

**Evidence:** AppShell.tsx:6-17:
```
/** [title i18n key, subtitle string] per page. */
const metaKeys: Record<Page, [string, string]> = {
  dashboard: ["nav.dashboard", "System overview"],
  scan: ["nav.scan", "Run a virus scan"],
  …
};
```
:28-29 `const [titleKey, subtitle] = metaKeys[currentPage]; const title = t(titleKey);` — only the title is translated. TopBar.tsx:24 renders `{subtitle && <p …>{subtitle}</p>}`.

en.ts:22-29 defines `meta.dashboard_sub` "System overview", `meta.scan_sub` "Run a virus scan", … `meta.about_sub`. All 9 locales carry them. `grep -rn "meta\." gui/src --include=*.tsx --include=*.ts | grep -v i18n/` returns only a comment in app-version.ts — zero call sites.

(There is also no `meta.intelligence_sub` key in en.ts at all, so the Intelligence page would need a new key.)

---

## 83. [LOW] gui/src/App.tsx:216  <i18n-coherence> (preexisting)

The scan-progress and scan-complete TopBar notices are built from English template literals while the five matching keys (`notice.scan_progress`, `notice.view_progress`, `notice.scan_done_clean`, `notice.scan_done_threats`, `notice.view_quarantine`) exist in all 9 locales and are never referenced — and a comment 50 lines above claims this exact class of bug was fixed.

**Failure:** Russian UI, user starts a quick scan. The TopBar shows "Quick scan in progress" with an English "View progress" link, while every other banner around it (`notice.recovering`, `notice.degraded_recovery`, `notice.disconnected`) is in Russian. On completion it shows "Quick scan done — 3 threats found" plus an English "View quarantine" link. Pluralisation is also English-hardcoded (`threat${n > 1 ? "s" : ""}`), which is wrong for ru/ja/zh regardless.

**Evidence:** App.tsx:209-224 `const label = scan.scan_type ? scan.scan_type.charAt(0).toUpperCase() + … : "Scan";` … `message={`${label} scan in progress`}` … `>View progress</button>`
App.tsx:231-234 `` const msg = scanDoneNotice.threats > 0 ? `${label} scan done — ${scanDoneNotice.threats} threat${scanDoneNotice.threats > 1 ? "s" : ""} found` : `${label} scan complete — ${scanDoneNotice.files.toLocaleString()} files clean`; `` ; :247 `>View quarantine</button>`.

`grep -c "notice.scan_progress|notice.view_progress|notice.scan_done_clean|notice.scan_done_threats|notice.view_quarantine"` = 5 in each of en/es/ja/fr/de/it/ru/zh-cn/pt-br — present everywhere, used nowhere.

The false comment, App.tsx:160-162: `//   - "Signatures never updated" was a hardcoded English string  //     (now goes through t() so Spanish/etc. translate)` — one sink was fixed while the two notices immediately below it stayed ha

---

## 84. [LOW] gui/src/notifications/notify.ts:122  <i18n-coherence> (preexisting)

Two of the OS toast paths build their title and body from English literals with no i18n key backing them at all — `notifyScanComplete` and `notifyFirstRunUpdateComplete` — while every other function in the same file goes through `t()`.

**Failure:** Chinese UI, scheduled full scan finds 2 threats. Windows Action Center shows a toast titled "Full scan complete" with body "2 threats found in 148,302 files." — English, in an otherwise Chinese app. The `notify.*` block in en.ts (lines 373-388) has no key for a scan-complete toast, so this cannot even be fixed by translating; new keys are required in all 9 files. Same for the first-run toast body "1,204,881 signatures loaded."

**Evidence:** notify.ts:121-123:
```
const label = scanType === "quick" ? "Quick scan" : scanType === "full" ? "Full scan" : "Scan";
send(`${label} complete`, `${threats} threat${threats > 1 ? "s" : ""} found in ${filesScanned.toLocaleString()} files.`);
recordNotification("scan_complete", `${label} complete — ${threats} threats`);
```
notify.ts:177: `send(t("notify.ready"), `${sigCount.toLocaleString()} signatures loaded.`);` — title translated, body not.

`grep -n '"notify\.' gui/src/i18n/en.ts` returns 16 keys (373-388); none of them covers a scan-complete title/body or a "signatures loaded" body.

---

## 85. [LOW] gui/src/i18n/index.ts:16  <i18n-coherence> (preexisting)

228 keys are absent from pt-br/ja/it/ru/zh-cn and 217 from fr/de — the whole v0.1.9+ Settings page and the WeedHack intelligence panel — and there is no locale-parity test, no test runner in the GUI at all, and no type-level guard, so nothing detects it.

**Failure:** A Japanese user opens Settings. The tab strip, every section header, every setting label and description, every validation message and the unsaved-changes bar render in English (fallback to en), while the sidebar, dashboard and scan pages around them are Japanese. Same for pt-br, it, ru, zh-cn. On the Intelligence page the whole WeedHack campaign card (`intel.weedhack.*`, 11 keys) is English for those five locales — fr and de do have those 11, which is the entire difference between 217 and 228.

**Evidence:** Key counts extracted from all 9 files (top-level `"key":` entries): en 996, es 996, fr 779, de 779, pt-br 768, ja 768, it 768, ru 768, zh-cn 768. Missing-vs-en: es 0, fr 217, de 217, pt-br/ja/it/ru/zh-cn 228 each. No locale has extra keys, no duplicate keys within any file, no empty values, no placeholder mismatches between locales — the gap is purely missing keys.

Nothing guards it: gui/package.json `scripts` = dev/build/preview/tauri/preflight:staging/release:build and `devDependencies` contains no test runner (vitest/jest absent); `find . -name "*.test.*" -o -name "*.spec.*"` under gui/ returns nothing. `i18n/index.ts:16` types the table as `Record<string, Record<string, string>>` and `:14`'s `TranslationKey` is never used, so `tsc --noEmit` (which passes clean) cannot see any of this.

---

## 86. [LOW] gui/src/app-version.ts:13  <i18n-coherence> (preexisting)

The doc comment instructs the next release engineer to run `npm run version:bump-locales`, a script that does not exist, and asserts the locale `app.version` / `meta.about_sub` values "must still be bumped per release" when nothing in the app reads either key.

**Failure:** Release engineer bumps APP_VERSION to 0.1.14, follows the comment, runs `npm run version:bump-locales` and gets `npm ERR! Missing script`. They then hand-sed 18 lines across 9 locale files that no component reads — busywork that also implies the version display is locale-driven, so a future bump that skips a locale is believed to be a shipping bug when it is not (and, conversely, the real version sources — APP_VERSION_TAG in Sidebar.tsx:70, AppShell.tsx:16, About.tsx:59 — get less scrutiny).

**Evidence:** app-version.ts:9-15: `// The i18n locale files (gui/src/i18n/*.ts) still store the version as a  // translation value (app.version, meta.about_sub) … Those must still be bumped per release … bump THIS constant + run \`npm run version:bump-locales\` …`

gui/package.json scripts (read via node): `{dev, build, preview, tauri, preflight:staging, release:build}` — no `version:bump-locales`. There is no root package.json.

`grep -rn "app\.version|meta\.about_sub" gui/src --include=*.tsx --include=*.ts | grep -v i18n/` → only the comment itself. Both keys are in my computed set of 188 en.ts keys with zero literal `t()` call sites. All 9 locales currently carry `"app.version": "v0.1.13"` and `"meta.about_sub": "Sentinella v0.1.13"` as dead data.

---

## 87. [LOW] scripts/prep-installer-staging.ps1:100  <installer>

The version guard is a whole-file ASCII substring scan, and the second half of the check its own comment promises ('require that the OLD version does NOT appear') was never implemented — the scan already matches dependency registry paths in the shipped binaries.

**Failure:** Scanning the current staged binaries shows argusd.exe and sentinelld.exe each contain BOTH 0.1.12 and 0.1.13; the 0.1.12 hits come from panic-location strings for .cargo/registry/src/.../weezl-0.1.12/src/decode.rs. So 'contains the version string' does not mean 'built at that version'. Concretely: bump the workspace to 0.1.14 while any transitive dependency is at 0.1.14 (weezl is at 0.1.12 today), rebuild only sentinelld, and a stale 0.1.13 argusd.exe passes Find-AsciiSubstring via the dependency path and gets staged. preflight-staging-versions.ps1 cannot catch it either: argusd.exe, sentinella.exe and sentinella-dnsreconcile.exe all report no PE FileVersion (verified), so they get only the 24h mtime heuristic, and a binary built the previous day passes that. Result: exactly the v0.1.7 mixed-version installer both scripts exist to prevent.

**Evidence:** $found = Find-AsciiSubstring -Bytes $bytes -Needle $needle   — comment at lines 93-97 says "also require that the OLD version ... does NOT appear as a standalone token. If both checks pass"; no such second check exists

---

## 88. [LOW] gui/src-tauri/nsis-hooks.nsh:95  <installer> (preexisting)

The service-stop poll treats 'service does not exist' as 'not stopped yet', so every fresh install burns the full 30-second cap before doing anything, and the sc create / sc start exit codes that follow are never checked.

**Failure:** On a machine with no prior install, sc query SentinellaDaemon prints the 1060 'service does not exist' error, which contains no ': 1 ', so findstr exits 1 and the loop runs its full 30 iterations of Sleep 1000. Combined with the two 3-second sleeps in PREINSTALL (lines 17, 19) that is ~36 seconds of a frozen, silent progress bar on every clean install of an antivirus — the shape users kill installers over. Worse, when the loop does time out for a real reason (a wedged daemon), execution simply falls through to sc delete, then to sc create at line 118 and sc start at line 130 whose results are never popped or tested. A create that fails with 1072 (marked for deletion) or a start that fails leaves the user with an installer that reported complete success and a machine with no daemon, no realtime protection, and no error anywhere but the scrollback of the details pane.

**Evidence:** nsExec::Exec 'cmd /c sc query SentinellaDaemon | findstr /C:": 1 "'
    Pop $0
    StrCmp $0 "0" stopped_ok 0
    IntCmp $STOP_TRIES 30 stopped_ok 0 stopped_ok

---

## 89. [LOW] crates/sentinelld/src/ipc/state.rs:7478  <concurrency> (preexisting)

Both regression tests that claim to pin the atomic engine/last_error snapshot invariant build a private local `ArcSwap<Snap>` over stand-in payloads and never touch `AppState`, `EngineSnapshot`, `publish_engine_snapshot` or `record_engine_error` — they test the arc_swap crate, so they stay green if the daemon reverts to split primitives.

**Failure:** Delete the fix: change `AppState` back to `engine: ArcSwap<Option<Arc<ClamEngine>>>` plus a sibling `engine_error: RwLock<Option<String>>`, and have `reload_engine_inner` write them separately (the exact pre-audit shape the comment at state.rs:290-303 describes). `arcswap_engine_slot_preserves_in_flight_arc_across_swap` (7477) and `arcswap_engine_snapshot_publishes_engine_and_error_consistently` (7522) both still compile and pass unchanged, because neither references any daemon type — the first declares its own `struct Snap { engine: Option<Arc<u32>> }` and the second `struct Snap { engine: Option<u32>, err: Option<&'static str> }`. The second even asserts "engine + last_error must be a single atomic snapshot" about a value the daemon does not own. There is no test anywhere that exercises `AppState::publish_engine_snapshot` / `record_engine_error` / `read_engine_snapshot`, so the invariant the two tests are named for is unguarded.

**Evidence:** #[test]
fn arcswap_engine_slot_preserves_in_flight_arc_across_swap() {
    use arc_swap::ArcSwap;
    #[derive(Clone)] struct Snap { engine: Option<Arc<u32>> }
    let slot: ArcSwap<Snap> = ArcSwap::new(Arc::new(Snap { engine: Some(Arc::new(11)) }));
    ...
    assert_eq!(*held, 11);
}

---

## 90. [LOW] crates/sentinelld/src/ipc/state.rs:1032  <concurrency> (preexisting)

The four `scan.orchestrator_*_scan_enabled` routing flags are copied into plain `bool` fields at `AppState` construction and read on every `scan.start`, but `restart_requirement` classifies them as hot-applied, so the GUI shows no restart pill for a change that needs a daemon restart.

**Failure:** `full_config.rs:56-84` lists the paths that need `EngineReload` or `DaemonRestart` and falls through to `RestartRequirement::None` for everything else; `scan.orchestrator_file_scan_enabled` and its three siblings are in the settings field list (full_config.rs:478-481) but in neither restart bucket, so `settings.restart_requirements` tells the GUI they apply immediately. In the daemon they are `bool` (not atomics) initialised once from `daemon_config.scan.*` at state.rs:1032-1035 and read directly by the `start_scan` dispatcher at state.rs:2048-2060. A user who turns `scan.orchestrator_full_scan_enabled` off to work around a stuck orchestrator queue saves the setting, sees no restart prompt, presses "Full scan", and is routed through the orchestrator anyway; `orchestrator_diagnostics()` (state.rs:1510-1513) reports the stale boot-time values back, so the diagnostics agree with the wrong behaviour rather than exposing it. This is the same class the constructor comment at state.rs:435-440 says was fixed for the staleness thresholds by making them atomics — these four were left behind.

**Evidence:** // state.rs:364-367 — plain bools, no atomics, no setter
orchestrator_file_scan_enabled: bool,
...
// state.rs:1032 — read once at construction
orchestrator_file_scan_enabled: daemon_config.scan.orchestrator_file_scan_enabled,
// state.rs:2048 — consulted per scan.start
"file" if self.orchestrator_file_scan_enabled => {

---

## 91. [LOW] crates/sentinelld/src/ipc/mod.rs:2435  <ipc-surface> (preexisting)

The settings.set_full envelope-stripping comment justifies itself with a claim about serde(deny_unknown_fields) that is false - the attribute appears nowhere in the workspace, so the strip is load-bearing for nothing and the next reader will draw the wrong conclusion about the schema's strictness.

**Failure:** A maintainer reading line 2433-2435 concludes that FullConfig (or something it nests) rejects unknown fields, and therefore that settings.set_full is protected against extra keys and that settings.set's failure to strip auth/token must be a bug that would make it always fail. Both inferences are wrong: `grep -rn deny_unknown_fields crates/` returns only two comment hits and zero attributes, and every struct in the FullConfig tree carries #[serde(default)] with no strictness attribute, so serde silently ignores auth/token either way. Acting on the false premise - e.g. dropping the strip in settings.set_full as redundant-looking, or adding deny_unknown_fields to FullConfig to "make the comment true" - would break every GUI settings.set_full call, since the GUI sends the envelope keys in the same object.

**Evidence:** // Strip the IPC envelope fields before deserializing into FullConfig
// (they are not part of the config schema and would fail serde even
// with #[serde(default)] because of deny_unknown_fields elsewhere).
let mut params = req.params.clone();

// $ grep -rn "deny_unknown_fields" crates/
// crates/sentinelld/src/config/mod.rs:344:  // unknown forward-compat keys (since `serde(deny_unknown_fields)`
// crates/sentinelld/src/ipc/mod.rs:2435:    // with #[serde(default)] because of deny_unknown_fields elsewhere).
// (no attribute anywhere; full_config.rs declares #[serde(default)] only)

---


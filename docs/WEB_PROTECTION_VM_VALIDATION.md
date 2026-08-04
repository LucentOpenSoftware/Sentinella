# Web protection: live-machine validation plan

**Why this exists.** Every layer that protects the NRPT rule — the four-step
self-test, the reconciler-task precondition, the liveness watchdog, the boot
task, the uninstall ordering — is unit-tested and reasoned about. **None of
it has ever run against a real Windows DNS Client.** No rule has been
installed by anything, ever; the registry write path has not executed
outside tests. v0.1.13 ships the feature off by default for exactly this
reason.

Until this plan passes, treat every claim about the rule lifecycle as
designed-but-unproven, and do not build user-facing surface on top of it.

**The rule everything is measured against:**

> Under any uncertainty the system degrades to "no filtering", never to
> "no DNS".

A scenario "passes" only if the machine can still resolve names at the end.
Filtering being lost is an acceptable outcome everywhere below. Name
resolution being lost is a failure, without exception, no matter how the
scenario got there.

## Setup

Windows 11 VM, **snapshot before every scenario** — several of these end
with a machine that cannot resolve names if the code is wrong, and that is
the point.

Install `Sentinella_0.1.13_x64-setup.exe` elevated. Then enable the feature
by hand (there is no UI yet, and the installer does not write the section):

```toml
# C:\ProgramData\Sentinella\config\sentinelld.toml
[web_protection]
enabled = true
listen = "127.0.0.1:53"
upstreams = ["system"]
# "nxdomain" is the shipped default; "zero_ip" makes a block visible as a
# 0.0.0.0 answer, which is what the canary check below reads.
block_response = "zero_ip"
# Default is "example.com". The watchdog resolves this name to prove the
# proxy still reaches an upstream, so it must be a name you do NOT block.
health_check_name = "example.com"
blocklists = []
allowlist = []
log_queries = true
```

Restart the service: `sc stop SentinellaDaemon && sc start SentinellaDaemon`.

### The four observation points

Use these throughout; each scenario says which must hold.

| what | how |
|---|---|
| Rule present? | `reg query "HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig" /s` — ours has `Name = "."`, `GenericDNSServers = 127.0.0.1` |
| Recorded GUID | `type C:\ProgramData\Sentinella\state\nrpt-rule.guid` |
| Boot task | `schtasks /query /tn "\Sentinella\DnsReconcile" /v /fo list` |
| **DNS actually works** | `nslookup www.microsoft.com` — the one that decides pass/fail |

Proxy answering, independent of Windows: `nslookup -port=53 www.microsoft.com 127.0.0.1`.
Filtering actually engaged: `nslookup webguard-test.sentinella.invalid` must
return `0.0.0.0` (the canary is blocked with an empty blocklist, by design).

---

## Scenarios

### 1 — Clean enable

Restart the service with the config above.

**Expect**: `webprotection.status` reports `state: Serving` and
`nrpt_installed: true`; GUID file present; rule in the registry; browsing
works; canary returns `0.0.0.0`.

**This is also the first real test of the self-test gate** — if the rule
appears while `state` is anything but `Serving`, stop: the precondition that
the whole design rests on does not hold.

### 2 — The case that has never been exercised: hard kill

With the rule live: `taskkill /F /IM sentinelld.exe`.

The SCM restarts the service ~5 s later.

**Expect**: DNS works throughout, or is restored within seconds. Either the
restarted daemon serves again and reuses the same GUID (no second rule), or
it refuses to serve and `reconcile_orphan_rule` removes the rule.

**Watch for**: two rules in the registry (GUID reuse broken), or a rule
present with `state != Serving` and the machine unable to resolve — that is
the forbidden outcome and it means the reconcile-on-refusal path added in
0.1.13 does not work.

### 3 — Kill with the port stolen

Kill the daemon, then immediately occupy the port so the restart cannot
bind (from an elevated shell, any listener on `127.0.0.1:53`).

**Expect**: `state: BindFailed`, **rule removed**, DNS works via the normal
upstreams. This is the single most important scenario in this document: it
is the exact shape of "our listener is gone but the rule points at it", and
the reconcile-on-refusal path is the only thing standing between it and a
machine with no DNS.

### 4 — Reboot with the rule live

Leave the rule installed, reboot.

**Expect**: DNS works from the moment the desktop appears. The boot task
runs before/independently of the service; if the daemon comes up serving,
the rule stays; if not, the task removes it.

**Watch for**: a window early in boot where names do not resolve. Note its
duration — the boot task is `BootTrigger` and the service is
`Automatic`, so their ordering is not guaranteed.

### 5 — Service disabled, then rebooted

`sc config SentinellaDaemon start= disabled`, reboot.

**Expect**: no rule after boot, DNS normal. This is the "user turned it off
and the daemon will never come back" case; only the boot task can save it.

### 6 — Watchdog: alive but not resolving

With the proxy serving, break resolution without killing the process —
block the upstreams outbound with a firewall rule so the canary still
answers locally but real names fail.

**Expect**: within ~60 s (three 20 s ticks) the watchdog removes the rule and
DNS returns via the system resolvers.

**This specific path was broken until 0.1.13** — the resolution half of the
watchdog could never reach its strike threshold because the counter reset on
every non-probe tick. This scenario is what proves the fix.

### 7 — Network change

Connect a VPN, then disconnect. Dock/undock if available.

**Expect**: upstreams refresh (visible in `webprotection.status.upstreams`)
within 30 s; DNS keeps working across the transition.

### 8 — Sleep / resume

Sleep the VM, wait, resume.

**Expect**: DNS works after resume. **Known gap**: nothing handles power
events; the upstream refresh is a 30 s poll. Record how long resolution is
degraded after resume — that measurement is the input to whether
`WM_POWERBROADCAST` handling is needed.

### 9 — Upgrade over a live rule

With the rule live, run the installer again (in-place upgrade).

**Expect**: DNS never breaks. PREINSTALL does `sc stop`, then
`sentinella-dnsreconcile.exe --remove`, then `taskkill`.

**This ordering was wrong until 0.1.13** — it force-killed the daemon before
stopping it, and an upgrade never runs PREUNINSTALL where the careful
removal ladder lives. Verify the rule is actually gone during the install
window, not just at the end.

### 10 — Uninstall

With the rule live, uninstall.

**Expect**: rule gone, task gone, GUID file gone, DNS normal.

Then repeat having first deleted `sentinella-dnsreconcile.exe` by hand.
**Expect**: a dialog explaining the rule cannot be removed, with the
uninstall refusing to continue by default. Confirm the machine still
resolves after choosing to abort.

### 11 — Recovery from the worst state

Reach "rule live, no daemon, no task" deliberately (install rule, kill
daemon, `schtasks /delete`).

**Expect**: this should be unreachable through supported paths — the daemon
refuses to install a rule when the task is absent. If you can reach it,
that precondition has a hole and it is a critical finding. Document how.

Recovery for a user who lands there anyway:
```
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig\{GUID}" /f
ipconfig /flushdns
```

---

## What to record

For each scenario: pass/fail, whether **DNS ever stopped working** and for
how long, the four observation points before and after, and the relevant
lines from `C:\ProgramData\Sentinella\logs\`.

A scenario that leaves the machine unable to resolve names is a **critical**
finding regardless of how contrived the setup was — the design's central
promise is that no path leads there.

## What passing unblocks

Scenarios 1-6 and 9-10 green is the bar for:
- shipping web protection **on by default**,
- giving it a GUI toggle,
- runtime enable/disable without a restart.

Until then the feature stays off by default with no toggle, which is what
v0.1.13 ships and why.

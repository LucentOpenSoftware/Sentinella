# Web Protection — Platform Design (v1: DNS-layer filtering)

Status: design registered; `dnsguard` crate implemented including the
round-2 and round-3 adversarial hardening (hard TCP cap on reads AND
writes, EDNS-aware truncation, clean upstream queries with DO/CD relayed
and every other client-controlled byte stripped, AD cleared on every
response we emit, case-insensitive echo + stray-datagram tolerance,
wire-length normalization, self-identifying canary, FOUR-step self-test,
empty-upstream refusal — each covered by a test verified to fail on the
pre-fix code). Daemon/NRPT wiring and installer lifecycle remain the
integration round. Scope: "lightweight
and functional" — domain-level web protection without a kernel driver,
without HTTPS inspection, without a browser extension. Closes the Tier-1
"Web protection" gap from `docs/COMPETITIVE_GAP_ESET.md`.

## 1. Requirements and honest non-goals

Requirements: block malicious/phishing domains for ALL applications on
the box (not just browsers); log what was blocked and (best-effort) by
which process; fail safe — a Sentinella crash must not take the
machine's DNS down with it; manageable over existing IPC/GUI patterns;
updatable blocklists through the existing signature-source pipeline.

Non-goals (explicit, with the reason): URL/path-level filtering and
phishing-page content analysis (requires TLS interception — rejected:
certificate installation is a large attack surface and breaks pinning);
per-URL browser extension (per-browser maintenance burden, no
protection for non-browser apps); SNI/IP-level TLS blocking (requires
WFP — a kernel driver Sentinella deliberately does not ship); DoH
detection inside TLS (impossible without inspection).

The unavoidable residual of any DNS-layer product, stated up front:
applications doing their own resolution (DoH-enabled browsers, malware
with hardcoded resolvers) bypass system DNS. Mitigations are listed in
the roadmap; v1 accepts this, like every DNS-filtering product does.

## 2. Platform options considered

| Option | Blocks? | Verdict |
|---|---|---|
| Kernel minifilter / WFP callout driver | Yes, at packet level | **Rejected** — the project ships no driver; signing/attestation/BSOD risk budget doesn't exist |
| Packet capture (Npcap) | Observe mostly | **Rejected** — third-party driver = the same problem by proxy |
| Browser extension | Browser only | **Rejected** — no non-browser coverage, N codebases |
| HTTPS/TLS interception proxy | Yes, URL-level | **Rejected** — CA installation attack surface, breaks pinning |
| Adapter DNS change to 127.0.0.1 | Yes, domain-level | Works (dnscrypt-proxy model) but fights VPNs/DoH settings and is rude to revert on uninstall |
| hosts file | Yes, crude | No logging, no process context, system-wide tamper target; not a product |
| ETW DNS-Client observation | **No** (post-hoc) | Valuable *attribution* source, not a block |
| **NRPT + local filtering DNS proxy** | Yes, domain-level | **CHOSEN** |

## 3. Chosen architecture

```
 app ──DnsQuery──> Windows DNS Client (DnsCache service)
                        │  NRPT rule: Namespace "." → 127.0.0.1 (port 53)
                        ▼
              sentinella DNS guard proxy (this crate)
                        │  filter: allowlist → blocklist(suffix/exact)
              blocked ──┴── allowed
                 │           │
            NXDOMAIN      upstream resolvers (system-configured,
           (or 0.0.0.0)   discovered from active adapters), cached
```

**Name Resolution Policy Table** is Windows' built-in per-namespace DNS
routing (Win8+). One catch-all rule
(`Add-DnsClientNrptRule -Namespace "." -NameServers 127.0.0.1`)
routes *all* system DNS through the local proxy — no adapter changes,
no driver, cleanly reversible (`Remove-DnsClientNrptRule`). Verified
facts (MS Learn + field reports):

- **NRPT NameServers are bare IP addresses — there is no port syntax.**
  The DNS Client always queries them on port 53, so **the proxy must
  listen on `127.0.0.1:53`** (verified bindable on a stock Windows 11
  box, unelevated, no conflict). An earlier revision of this doc wrote
  `127.0.0.1:5353` and labeled it verified — that was wrong: the
  citation (Atomic Red Team T1562.001 #76) shows a bare `127.0.0.1`
  with no port, and no documentation supports a port in NameServers.
  Consequence: enabling web protection must first check nothing else
  owns `127.0.0.1:53` (conflict → refuse + loud error, never fight
  over the port).
- Loopback NameServers are accepted — Atomic Red Team T1562.001 test
  #76 uses exactly `-NameServers 127.0.0.1` to silence Defender
  endpoints. (This also means malware can use NRPT offensively — see
  threat model; Sigma already flags the cmdlet.)
- Rules are **persistent across reboots** and live in
  `HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig`
  (local) — so lifecycle management is our job (watchdog below), and
  direct registry writes are an option if cmdlet spawns become hot.
- If ANY GPO NRPT rule exists, local rules are ignored — enterprise
  machines may silently disable us; detect and surface, don't fight it.
- The DNS Client cache must be flushed on rule changes
  (`Clear-DnsClientCache`).

**The proxy** (new crate `crates/dnsguard`, running inside sentinelld):
UDP+TCP listener on 127.0.0.1:53 (see the NRPT port erratum above —
there is no port syntax, so 53 is the only choice); minimal hand-rolled
DNS message
parse/build (no dependency, bounded, total functions — same discipline
as the PE parsers); filter decision; blocked → NXDOMAIN (policy option
`0.0.0.0` for compatibility with clients that mishandle NXDOMAIN);
allowed → forward upstream with timeout, TTL-respecting cache,
negative caching, bounded in-flight queries, structured query log.

**Upstream discovery:** read the active adapters' configured DNS
servers at start (iphlpapi/registry), re-read on network-change events
or a slow poll; never hardcode a public resolver as default (operator
choice in config: `upstream = "system" | explicit list`). Optionally a
**secondary fallback**: if the proxy can't answer (unhealthy), NRPT
rule can list the upstream second — Windows fails over, the machine
keeps resolving (fail-open, monitored) vs. removal of the rule
(fail-closed-ish, monitored). Policy: `on_proxy_failure = "fallback" |
"remove_rule"`, default fallback with a loud health event.

**Process attribution (best-effort):** the
`Microsoft-Windows-DNS-Client` ETW provider (event 3008, query
completed) carries `QueryName`, `QueryStatus`, `QueryResults` and the
header PID of the requesting process — consumed in read-only fashion
to enrich block/log events ("powershell.exe resolved evil.example").
Caveat: only apps using Windows DNS APIs appear (own-resolver apps are
invisible), and field schemas need live validation on build 26100 —
same caveat as the MOF parsers; an `#[ignore]`d live test will assert
it. This runs through the *same* corrected system-logger/session
patterns landed this round; it is a normal user-mode provider session,
NOT the kernel system logger.

## 4. Filter engine

- Precedence: `allowlist > blocklist`, exact-host before suffix rules.
- **Rule kinds are explicit.** Hosts-format entries (`0.0.0.0 host`)
  are **exact-host rules** (Pi-hole semantics — the entry blocks that
  host, not its subtree). Suffix rules require an explicit marker
  (leading dot, `.evil.example`) in user-supplied lists. Rationale:
  real blocklists contain bare labels (e.g. `127.0.0.1 local` in
  StevenBlack's preamble); treating every entry as a suffix rule would
  blackhole entire namespaces (`.local`, or `.com` from a hostile or
  careless list source) — machine-wide breakage from a data file.
- Wire-format safety: DNS labels may contain `.` bytes (a single label
  `microsoft.com` is legal on the wire and collides with the two-label
  name when joined naively). Names are decoded with RFC 4343 escaping
  (`\.`) before presentation/filtering, and **the cache key is the raw
  wire-format name**, never a presentation string — a hostile encoding
  cannot alias a victim domain (pre-integration finding: a one-UDP-
  socket process could otherwise blackhole any domain machine-wide).
- Normalization: case-insensitive ASCII; trailing-dot stripped;
  punycode (`xn--`) matched both as-is and (v2) decoded.
- Scale: blocklists are 10⁴–10⁶ domains — in-memory HashSet for exact,
  label-boundary candidate generation for suffix; no NRPT-per-domain
  (a rule per blocked domain does not scale; the catch-all + in-proxy
  filtering is why).
- Sources (all legal, documented in-tree):
  - **StevenBlack/hosts** (unified, MIT) — ads/malware base list.
  - **URLhaus domain list** (abuse.ch, research use) — active malware
    distribution/C2 domains. High-value, frequently updated.
  - User local rules via IPC/GUI; enterprise import later.
  - Update path: the existing `sources.*` update pipeline (HTTPS,
    pinned SHA-256 where the source offers it, staleness tracking).
- **No shipped source emits the leading-dot marker** — so without a
  dedicated loader, every source is 100% exact-host, and the URLhaus
  domain list (one domain per line, no leading IP token) fed through
  the hosts loader adds NOTHING at all (`rules_added: 0`, Ok). Stated
  plainly: an exact-only load of a C2 feed leaves subdomain-wildcarding
  C2 — the normal shape — unblocked. The domain-list loader
  (`FilterEngine::load_domain_list`) therefore takes a per-source
  `exact|suffix` policy, declared in the source's config entry, never
  inferred from the data: `suffix` for dedicated malware/C2 domain
  feeds (the security-correct choice against wildcarding), `exact`
  (the default) for anything generic — suffix-by-source on a generic
  list is FALSE-POSITIVE-PRONE: one stale or hostile entry blackholes
  its whole subtree. The Pi-hole precedent above covers hosts files;
  Pi-hole ships regex/wildcard lists alongside them, and the suffix
  policy is our equivalent — explicit, per source, and off by default.

## 5. Threat model & failure modes

- **Proxy dies → whole-machine DNS outage** (the catch-all makes us a
  single point of failure). This is THE hazard of the design — an AV
  that breaks DNS is worse than an AV that misses malware — so the
  lifecycle is specified here, before integration, not after:

  1. **Bind before rule.** The proxy binds `127.0.0.1:53` (UDP+TCP) and
     passes a FOUR-step self-test BEFORE any NRPT rule is installed
     (`Proxy::self_test`, implemented; `SelfTestReport::ok()` is the
     conjunction of all four):
     - **(i) `engine_ok`** — the filter engine decides the canary
       (`webguard-test.sentinella.invalid`) as Block. It is blocked by
       default only in `FilterEngine::new()`; `FilterEngine::default()`
       carries no rules at all, and an EXACT allowlist entry for the canary
       still overrides it. That is exactly why this is a checked step and
       not an invariant.
     - **(ii) `upstream_ok`** — a LIVE query for a real resolvable name
       (`health_check_name`, default `example.com`) returns NOERROR from
       **every** configured upstream, not just the first. `forward` does
       NOT fail over, so one dead server in a two-server adapter list is a
       real partial outage; `upstreams_healthy`/`upstreams_total` carry the
       detail.
     - **(iii) `filter_ok`** — all of: **(a)** the canary queried through
       the UDP listener **with qtype A** comes back with the LOCAL
       SIGNATURE — the probe's own transaction ID echoed, NOERROR, AA=1,
       ANCOUNT=1, A `0.0.0.0` (all five, as `is_canary_signature` checks
       them; dropping the txid echo admits a stale or off-path datagram,
       and dropping ANCOUNT=1 admits a multi-answer response that merely
       ends in four zero bytes). The serving path short-circuits the canary
       BY NAME unconditionally — under both `block_response` policies,
       independent of the engine's own canary rule, and before
       decide/cache/forward — but the answer is qtype-dependent: **A**
       yields `0.0.0.0`, AAAA yields `::`, any other qtype yields NXDOMAIN
       with AA=1. Probe with A.
       What this proves, precisely: `.invalid` has no root delegation, so
       any stock resolver NXDOMAINs it (RFC 6761 §6.4 makes that a SHOULD)
       — an NXDOMAIN is obtainable with the product uninstalled and proves
       nothing. The signature is not relayed or cached, so it can only have
       been SYNTHESIZED by whatever process owns the probed socket. Note
       the limit: that identifies *a local zero-IP blocker on that socket*,
       not this binary. Another blocking resolver squatting `127.0.0.1:53`
       with a zero-IP policy produces the same bytes. Pair the signature
       with a counter delta (below) before concluding the listener is ours.
       **(b)** `canary_probes` moved by exactly the number of canary probes
       whose reply matched the signature (the UDP one here plus the TCP one
       in step (iv), so up to 2 — a starved TCP pool SERVFAILs or drops
       before `handle_query` runs, so that probe is neither answered nor
       counted; a probe served but lost in flight makes the delta disagree
       and reds the step, which is the fail-closed direction) while the
       user-facing `queries`/`blocked` counters did not move at all:
       synthetic traffic must never appear as user browsing activity.
       **(c)** the engine decides `health_check_name` as **Allow** AND it
       resolves POSITIVELY through the listener. Both halves are required:
       a `zero_ip` block answer is NOERROR with an A record, so without the
       engine check a filter blocking the health name reads as a
       resolution — one bad suffix rule then blackholes the machine with
       every step green. Checking the decision rather than the answer's
       shape is deliberate: an upstream authoritative for the operator's
       chosen name legitimately sets AA=1, so an `AA == 0` test would
       reject a healthy proxy.
     - **(iv) `tcp_ok`** — the canary returns the LOCAL SIGNATURE through
       the **TCP** listener. Truncation routes oversized answers onto
       DNS-over-TCP, so a health surface probing only UDP can stay green
       while the accept loop, queue, permit pool or framing is dead.

     Bind failure (port conflict — something else owns 53) or any failed
     step MUST make the daemon refuse to enable: loud error, no rule.
     **That is a requirement on the integration round, not existing code.**
     Nothing outside the crate's own tests calls `Proxy::self_test`, and no
     NRPT install path exists at HEAD; the crate supplies only the verdict
     (an `io::Error` from `bind`, and `SelfTestReport::ok()`). Acting on it
     is the wiring's job. By contrast, the next sentence IS implemented, so
     do not read the two with equal authority: binding with an EMPTY
     upstream list is refused outright in `bind`, because a resolver with
     no upstream is a lie (it would pass bind while SERVFAILing every real
     query).
  2. **Rule identity by GUID, not DisplayName.** Rules we create record
     their GUID; reconciliation touches only OUR rule, never a foreign
     one (admin/GPO rules are surfaced, not deleted).
  3. **Boot-time reconciler independent of the daemon.** Every
     mitigation that lives inside sentinelld dies with it — so a
     Scheduled Task (`Sentinella\DnsReconcile`, boot trigger, SYSTEM)
     runs a tiny reconciler that is NOT the daemon: if the service is
     absent/disabled/not-yet-healthy, it removes our rule (by GUID) and
     exits. The daemon (re)installs the rule only after its own
     self-test passes. The reconciler is also the uninstall path —
     but the ORDER matters: uninstalling Sentinella must remove the
     RULE first, THEN the task, then the binaries. The reverse order
     destroys the only out-of-process remover first; any interruption
     between steps would strand a catch-all rule with no listener, no
     reconciler, and no product to clean it up. (The MSI has no
     CustomAction for this today — wiring it is installer work for the
     integration round.)
     Rule removal is a LADDER, never a single attempt — "must succeed"
     specifies an outcome, and the ladder specifies what happens when an
     attempt fails, because a dead end here is one users route around
     destructively (delete the install folder → live catch-all rule with
     no reconciler and no product):
     (1) `Remove-DnsClientNrptRule -GUID <our-guid>`;
     (2) on failure (cmdlet unavailable — Server Core / Nano without the
     DnsClient module, PowerShell ConstrainedLanguage, access denied),
     delete OUR GUID subkey directly under
     `HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig`
     (the exact registry location from §3, written directly just as the
     add path may be) and `Clear-DnsClientCache`;
     (3) if BOTH fail, LEAVE the reconciler task and the binaries in
     place, mark the uninstall BLOCKED with a loud, actionable error,
     and let the boot reconciler retry the removal on next boot. The
     abort must never destroy the remover: "aborts loudly" means the
     uninstall refuses to proceed PAST rule removal, not that it tears
     down the rest of the product around the failure.
     When a GPO NRPT policy is present, local rules are ignored entirely
     (§3) — ours included: the rule is ineffective but still ours, so
     removal is still attempted by GUID (a GPO rule is never touched),
     and a foreign GPO rule never blocks the uninstall; only failure to
     remove our own rule does.
  4. **Runtime watchdog (in-daemon, layered under 1–3, never instead
     of):** an EXTERNAL probe every N s against the PUBLIC socket
     `127.0.0.1:53` — NOT `proxy.local_addr()`. In the shipped
     configuration the two are EQUAL: `local_addr()` just echoes
     `config.listen` back, and only a port-0 listen (test-only) makes them
     differ. The reason to hardcode `127.0.0.1:53` anyway is that
     `local_addr()` is derived from OUR config rather than from the address
     the DNS Client queries — NRPT NameServers carry no port syntax, so the
     DNS Client always uses 53. A watchdog trusting `local_addr()` would
     certify whatever the config said: a proxy misconfigured onto another
     port would report perfectly healthy while every real query went
     nowhere.
     **It cannot be `Proxy::self_test` on a timer, and must not be
     written as one.** `Proxy::run` takes `self` by value, so once the
     daemon spawns the serving future no `&Proxy` survives. The type
     system therefore rules out running the self-test AFTER the serving
     loop — but only that: it does not make the self-test mandatory, and
     `SelfTestReport` is not `#[must_use]`, so `bind(...).run(...)` with
     no self-test at all compiles silently. Keeping the NRPT rule
     downstream of `SelfTestReport::ok()` remains the daemon's obligation.

     The daemon must CAPTURE the long-lived handles before it hands the
     Proxy to `run` — `counters()` and `engine_handle()` are `&self`
     methods, so the watchdog is given the returned
     `Arc<Counters>`/`Arc<RwLock<FilterEngine>>`, never a `&Proxy`:
     ```rust
     let engine    = proxy.engine_handle();
     let counters  = proxy.counters();
     let upstreams = proxy.upstreams_handle();   // network-change re-reads
     tokio::spawn(proxy.run(rx));
     ```
     `upstreams_handle()` is what makes §3's "re-read adapter DNS on
     network-change events" expressible at all: `Proxy::set_upstreams` is
     `&self` and therefore dies with the move, and re-reads happen only
     while serving. The handle carries the same validation as `bind`
     (non-empty, no self-referential address), so a network-change event
     that hands us a garbage list is refused and the previous list is
     kept — the machine is never left with no resolver.
     What the external watchdog can then reproduce is DIFFERENT from the
     four steps, not strictly stronger — better in one way, blind in two:
     - Stronger: it probes the PUBLIC socket the DNS Client actually uses,
       so it can detect a port-53 impostor. `engine_handle()` reproduces
       step (i) exactly; UDP and TCP canary probes reproduce (iii)(a) and
       (iv) — though `is_canary_signature`, `probe_exchange` and
       `tcp_probe_exchange` are all PRIVATE, so the wiring must either
       export a `check_canary_signature` or re-implement the five-part
       predicate against the pub `wire` constants.
     - Blind: it does NOT reproduce step (ii) (`upstream_ok` — every
       configured upstream answering NOERROR; `forward_via` is private and
       has no public wrapper, so the daemon must probe its own upstream
       list directly, and must probe EVERY entry because `forward` has no
       failover) and does NOT reproduce step (iii)(c). **Schedule those
       two separately**, or a machine whose upstreams have all died reads
       green forever: the canary is short-circuited before forward and
       never touches an upstream.
     - `counters()` deltas are what rule out an impostor, because a
       matching signature alone can be forged. The canary bumps
       `canary_probes` for REAL client queries too, not only the
       self-test's synthetic path, so a delta proves our process served a
       canary in that window. Treat it as strong corroboration, not proof
       of provenance for one datagram: the counter carries no per-probe
       identity, and under UDP overload a probe is shed before it is
       counted, so a loaded-but-healthy proxy yields delta 0. Require
       signature AND delta together, and act only on SUSTAINED failure.
     On sustained failure apply
     `on_proxy_failure` policy (`fallback` = NRPT secondary upstream,
     monitored fail-open; `remove_rule` = monitored fail-closed);
     foreign-rule diff → alert; clean removal on orderly shutdown;
     stale-rule cleanup by GUID on next start.
  5. **The 10 ways the listener stops with the rule alive** (crash,
     kill -9, service stop, service disable, uninstall-gone-wrong,
     boot-time port conflict, upgrade replace, bluescreen, user renames
     install dir, defender quarantines binary) — each maps to exactly
     one of layers 1–4; anything that skips all four leaves a rule
     pointing at a dead port, which is why layer 3 is not optional.

- **Tampering:** NRPT rules need only admin — same bar as disabling the
  service. Watchdog diffs effective NRPT rules vs expected; foreign or
  missing rules → alert + re-assert. GPO presence → surface "web
  protection ineffective (GPO NRPT present)" in status, don't
  silently degrade.
- **Blocked-domain bypass via direct-IP or DoH:** accepted residual
  (§1). Roadmap: firewall rules for known public DoH resolver IPs
  (opt-in), SNI heuristics if a driver ever lands.
- **Upstream response forgery / cache poisoning:** the proxy validates
  every upstream response before accepting or caching it: QR set,
  **transaction ID matches a per-query ID generated upstream-side (the
  client's ID is never forwarded verbatim)** and the question
  section echoes the query (qname compared ASCII-case-insensitively per
  RFC 4343 — home CPE forwarders normalize case and byte-exactness
  breaks behind them — qtype/qclass exact). Upstream queries are
  rebuilt CLEAN: fresh txid, RD=1, the question only, zeroed AN/NS
  counts. EXACTLY TWO client-controlled bits leave the machine (round-3
  L01): the CD bit in the header (RFC 4035 §3.1.6), and — only when the
  client itself sent an OPT — ONE self-constructed OPT record carrying
  the client's clamped UDP size and DO bit, with empty rdata. No client
  OPT PAYLOAD is ever relayed: no ECS, no cookies, no options. ECS in
  particular would otherwise steer an answer we then cache machine-wide.
  AD is cleared on every response we emit, in the other direction,
  because we validate nothing. Together with per-query ephemeral sockets and
  `connect()` source filtering this restores the standard resolver
  defense-in-depth; an invalid response is dropped, never cached. The
  UDP receive loop tolerates stray/invalid datagrams within the
  exchange deadline (only the deadline gives up).
  The upstream ID is a keyed PRF (SipHash-1-3 over a counter, key from
  the OS CSPRNG via `RandomState`) — **not** a CSPRNG, and this document
  must not call it "random". An earlier revision did, over a Weyl
  counter through an invertible xorshift seeded with
  `nanos ^ pid.rotate_left(32)`; because `rotate_left(32)` left the low
  32 seed bits as wall-clock nanoseconds alone, two observed IDs plus
  the pid recovered the full state by brute force in 22.7 ms and
  predicted every subsequent ID. The property claimed here is only that
  the sequence is not derivable from observed outputs. Note also that
  the second entropy source a resolver normally leans on — ephemeral
  source-port randomness — is weak on Windows, so the ID carries more
  weight here than the textbook analysis assumes.
- **Oversized answers vs UDP clients:** an answer fetched via the TCP
  fallback can be up to 65535 bytes; replaying it whole to a UDP client
  yields a datagram the client OS drops (WSAEMSGSIZE) with TC clear —
  a hard failure with no retry signal, sticky for the cache lifetime,
  triggered by ordinary traffic with no attacker. The proxy therefore
  serves any UDP answer over the payload limit as an RFC 2181-style
  TRUNCATED response (TC set, question only, zeroed answer counts) so
  the client retries over TCP. The payload limit is the CLIENT's own
  EDNS0-advertised size clamped to [512, 4096]; a client that sent no OPT
  is treated as 512 (RFC 1035). Only an answer exceeding THAT limit is
  truncated (round 3, A1) — which is what keeps ordinary 513–4096-byte
  answers off the bounded TCP pool instead of routing every one of them
  through it. The full answer is cached and served to TCP clients.
- **Cache poisoning via upstream:** we are a forwarding resolver — we
  do NOT do DNSSEC validation in v1; upstream choice inherits the
  operator's trust. Documented; DoH upstream option is a v2 item.
- **Availability:** TCP clients get a SEPARATE, smaller permit pool
  from UDP with a per-connection total-lifetime cap (not just an idle
  timeout) — 256 idle loopback connections dribbling bytes must not be
  able to starve all DNS (and thereby force the fail-open path, which
  doubles as an on-demand filter bypass). The cap bounds EVERY socket
  operation on the connection, reads AND writes (a pipelining client
  that never reads would otherwise park `write_all` on a full kernel
  send buffer and hold its permit forever — reproduced: probes still
  blocked at 2× the promised cap).
- **Log privacy:** query logs are sensitive (browsing history).
  Retention-capped, daemon-local, surfaced only via authenticated IPC
  (same tiering as scan history), never in the unauthenticated tier.

## 6. Config schema (daemon TOML)

```toml
[web_protection]
enabled = false                 # default off until proven on-box
listen = "127.0.0.1:53"         # NRPT queries port 53 — no port syntax exists
upstream = "system"             # or ["1.1.1.1", "9.9.9.9"]
on_proxy_failure = "fallback"   # or "remove_rule"
block_response = "nxdomain"     # or "zero_ip"
allowlist = []                  # exact hosts; leading "." = suffix rule
extra_blocklists = []           # file paths / source ids (hosts format = exact rules;
                                # domain lists take a per-source exact|suffix policy — §4)
log_queries = false             # full query log off by default (privacy)
```

IPC: `webprotection.status` (AuthenticatedRead: enabled, rule present,
proxy healthy, counts, upstream in use), `webprotection.set_enabled`
(PrivilegedMutation, challenge-gated), `webprotection.block_add` /
`.block_remove` / `.allow_add` (PrivilegedMutation),
`webprotection.test` (AuthenticatedAction: the FOUR-step check against
`127.0.0.1:53`, reported step by step; acceptance = all four green. The
60-second operator acceptance test). **It is a RE-IMPLEMENTATION of the
four steps, not a call into `Proxy::self_test`** — `run` takes `self` by
value so no `&Proxy` survives it, and self_test's private serving loop
must never race the real one. Steps (i), (iii) and (iv) are reproducible
from the handles the daemon captured before `run` (§5 layer 4); step (ii)
has NO dnsguard API (`forward_via` is private), so the daemon probes its
own configured upstream list directly, and must probe EVERY entry because
`forward` has no failover.
- (i) canary decided Block by the engine.
- (ii) live `health_check_name` NOERROR from EVERY configured upstream.
- (iii) canary returns the LOCAL SIGNATURE over UDP — txid echoed +
  NOERROR + AA=1 + ANCOUNT=1 + A `0.0.0.0`, all five — and
  `health_check_name` is both decided Allow and resolves positively
  through the listener.
- (iv) canary returns the local signature over TCP.

**The signature, not NXDOMAIN, is the acceptance signal.** An earlier
revision specified "canary → NXDOMAIN through the listener"; that is
vacuous — `.invalid` has no root delegation, so any stock resolver
NXDOMAINs it (RFC 6761 §6.4 makes that a SHOULD; measured on a box with
no Sentinella installed and zero NRPT rules). An implementation of this
endpoint that accepts NXDOMAIN re-introduces that hole at the IPC layer.

**Counter caveat for the implementer:** only the CANARY probe is
counter-clean. It moves `canary_probes` and never `queries`/`blocked`,
even on the live serving path. The `health_check_name` probe is NOT: run
against the live listener it legitimately increments `queries` plus
`forwarded`/`cache_hits` and emits a query-log event, because the
`synthetic` marking exists only inside `Proxy::self_test`'s private loop,
which cannot run while the proxy is serving. Assert on `canary_probes`
only, and tolerate concurrent user traffic.

## 7. Test plan

- Filter engine: precedence, suffix/exact, case, trailing dots, empty
  list = allow-all, hosts-format parser edge cases (comments, inline
  comments, `0.0.0.0` vs `127.0.0.1` vs `::`, whitespace, CRLF,
  1M-line file bounded-time load).
- DNS wire: query parse/build roundtrip; malformed packets (truncated
  header, count lies, compression-pointer loops, oversized); no panics
  on arbitrary bytes (seeded sweeps that provably reach the name
  parser — a sweep that never reaches it is evidence of nothing);
  dot-in-label encodings (cache-key injectivity).
- **Hostile-response validation:** wrong txid dropped; QR-unset
  dropped; mismatched question dropped; no invalid response is ever
  cached; fuzz sweeps reach the name parser (assert with coverage
  markers, not iteration counts).
- Filter semantics: hosts entries are exact (a `0.0.0.0 local` line
  does NOT touch `.local`); explicit `.suffix` rules only via the
  leading-dot marker; allowlist bare labels cannot disable the canary.
- Proxy behavior with a fake loopback upstream: blocked → NXDOMAIN
  shape; allowed → forwarded byte-faithfully; upstream timeout →
  SERVFAIL, not hang; cache hit/miss/TTL expiry; negative caching;
  bounded in-flight (N+1 concurrent queries → shedding, not unbounded
  tasks — and the shed test must ALSO assert healthy queries still
  forward, since a fully broken proxy also emits SERVFAIL); TCP pool
  exhaustion does not starve UDP (the test must PROVE exhaustion —
  small configured pools, the dedicated `tcp_pool_full` counter
  moving — and verify UDP forward+block while TCP permits are gone,
  plus that the pool-full TCP client is answered SERVFAIL, never a
  bare reset). Note the precise boundary: UDP answers within the
  client's negotiated payload size (EDNS0-aware) never touch the TCP
  pool; only an oversized answer truncates onto TCP, and there the
  retry is fail-safe.
- **TCP hard-cap write path:** a pipelining client that never reads
  (enough queued large answers to fill kernel buffers) must still be
  killed at `tcp_max_lifetime` — kill counter moves, freed permit
  serves a fresh client. This test is verified to FAIL on the
  pre-fix code (unbounded `write_all`), as is the starvation test
  against a merged-pool shape.
- **Oversized answers:** a ~60KB answer fetched via TCP fallback is
  cached whole; UDP clients get TC=1, ≤512 bytes, question intact,
  zeroed answer counts; TCP clients get the full answer; one upstream
  fetch total. Verified to FAIL pre-fix (oversized datagram, TC clear).
- **Clean upstream queries:** a client query carrying EDNS0 OPT + ECS
  is forwarded with the client's option payload STRIPPED — the only
  OPT that leaves the machine is self-constructed (clamped UDP size +
  the client's DO bit, empty rdata; round-3 L01 decision: DO/CD are
  relayed, AD is cleared on every response, ECS never is); the cached
  answer is keyed on the question plus DO/CD posture (a different ECS
  hits the same entry). Verified to FAIL pre-fix (verbatim client
  packet upstream).
- **Case-insensitive question echo:** a case-normalizing upstream
  (lowercased qname echo) is accepted; a real letter change is still
  dropped. Verified to FAIL pre-fix (byte-exact echo → SERVFAIL).
- **Stray-datagram tolerance:** garbage / wrong-txid datagrams before
  the real answer do not kill the exchange. Verified to FAIL pre-fix
  (single recv → SERVFAIL).
- **Self-test / health:** `self_test` green against a fake upstream;
  empty upstream list refused at bind; dead upstream →
  `upstream_ok=false` AND `filter_ok=false` (step (iii)(c) requires a
  POSITIVE resolution through the listener, which a dead upstream cannot
  produce) with `engine_ok` still green and `detail` naming which
  sub-checks failed; ONE dead
  upstream out of two → `upstream_ok=false` (no failover exists, so a
  head-only probe would have called this green); `block_response =
  "zero_ip"` **crossed with** a filter that blocks `health_check_name` →
  `filter_ok=false` (the two axes must be tested together: a zero-IP
  block answer is NOERROR with an A record, so a green report here means
  the gate cannot see a machine-wide blackhole); TCP listener dead →
  `tcp_ok=false` while the UDP steps stay green.
- **Wire-length vs presentation-length normalization:** a wire-legal
  name whose ESCAPED form exceeds 253 chars (61×0x00 label) is still
  decided (blocked via its suffix rule, never fail-open None);
  wire-illegal names (label > 63, name > 255 wire bytes) are rejected.
  Verified to FAIL pre-fix (escaped-string measurement → Allow).
- NRPT lifecycle (opt-in elevated `#[ignore]` tests): add → effective
  (`Get-DnsClientNrptPolicy -Effective`), flush, blocked domain
  NXDOMAINs through the SYSTEM resolver (the real end-to-end), proxy
  kill → fallback behavior, shutdown → rule gone, **boot reconciler
  removes the rule when the daemon is absent**, port-53 conflict →
  enable refused with no rule installed. 10-minute operator
  acceptance: `webprotection.test` + browser to a blocklisted test
  domain.
- Sentinel test domain: include one always-blocked canary
  (`webguard-test.sentinella.invalid`) so acceptance doesn't depend on
  a live blocklist.

## 8. v2+ roadmap (recorded, not built)

DoH-resolver IP firewall rules (opt-in); punycode/homoglyph heuristics
on newly-seen domains; domain reputation feed integration (ARGUS/IOC
domain intel); DNS-Client ETW → per-process block enforcement signals
(e.g. alert when a non-browser process resolves a blocked domain via a
non-system resolver); SNI/IP-layer blocking if a driver ever ships;
GUI surface (status card, block/allow editors, per-domain decision
log); installer/MSI registration of the NRPT lifecycle.

# Web Protection — Platform Design (v1: DNS-layer filtering)

Status: design registered; `dnsguard` crate implemented including the
round-2 adversarial hardening (hard TCP cap on reads AND writes,
RFC 2181 truncation for oversized UDP answers, clean upstream queries,
case-insensitive echo + stray-datagram tolerance, wire-length
normalization, 3-step self-test, empty-upstream refusal — all covered
by tests verified to fail on the pre-fix code). Daemon/NRPT wiring and
installer lifecycle remain the integration round. Scope: "lightweight
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

## 5. Threat model & failure modes

- **Proxy dies → whole-machine DNS outage** (the catch-all makes us a
  single point of failure). This is THE hazard of the design — an AV
  that breaks DNS is worse than an AV that misses malware — so the
  lifecycle is specified here, before integration, not after:

  1. **Bind before rule.** The proxy binds `127.0.0.1:53` (UDP+TCP) and
     passes a THREE-STEP self-test BEFORE any NRPT rule is installed
     (`Proxy::self_test`, implemented): (i) the filter engine decides
     the always-blocked canary as Block — the canary NXDOMAINs on ANY
     box (`.invalid` is reserved), so only a local engine decision
     proves the plumbing is ours and not a box where we were never
     installed; (ii) a LIVE query for a real resolvable name
     (`health_check_name`, default `example.com`) forwarded to a
     configured upstream returns NOERROR; (iii) the canary queried
     through the listener returns NXDOMAIN. Bind failure (port
     conflict — something else owns 53) or any failed step → refuse to
     enable, loud error, no rule. Binding with an EMPTY upstream list
     is refused outright: a resolver with no upstream is a lie (it
     would pass bind while SERVFAILing every real query).
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
     RULE first (and rule removal must succeed or the uninstall aborts
     loudly), THEN the task, then the binaries. The reverse order
     destroys the only out-of-process remover first; any interruption
     between steps would strand a catch-all rule with no listener, no
     reconciler, and no product to clean it up. (The MSI has no
     CustomAction for this today — wiring it is installer work for the
     integration round.)
  4. **Runtime watchdog (in-daemon, layered under 1–3, never instead
     of):** the 3-step self-test every N s, probed against the PUBLIC
     socket `127.0.0.1:53` — NOT `proxy.local_addr()`: a health check
     aimed at the address the proxy CHOSE validates the wrong thing;
     the DNS Client uses port 53. On sustained failure apply
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
  rebuilt CLEAN: fresh txid, RD=1, the question only, zeroed counts,
  NO additional records and no EDNS0 — client-controlled bytes (flag
  games, ECS, OPT payloads) never leave the machine, and ECS in
  particular would otherwise steer an answer we then cache
  machine-wide. Together with per-query ephemeral sockets and
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
  the client retries over TCP. v1 treats every UDP client as 512 bytes
  (we strip EDNS0 from forwarded queries, so no client UDP size is ever
  negotiated — documented limitation); the full answer is cached and
  served to TCP clients.
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
extra_blocklists = []           # file paths / source ids (hosts format = exact rules)
log_queries = false             # full query log off by default (privacy)
```

IPC: `webprotection.status` (AuthenticatedRead: enabled, rule present,
proxy healthy, counts, upstream in use), `webprotection.set_enabled`
(PrivilegedMutation, challenge-gated), `webprotection.block_add` /
`.block_remove` / `.allow_add` (PrivilegedMutation),
`webprotection.test` (AuthenticatedAction: runs the 3-step self-test
against `127.0.0.1:53` — canary decided Block by the engine, live
`health_check_name` query NOERROR from an upstream, canary NXDOMAIN
through the listener — and reports each step; acceptance = all three
green. The 60-second operator acceptance test).

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
  small configured pools, a fresh TCP probe refused — and verify UDP
  forward+block while TCP permits are gone).
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
  is forwarded with ARCOUNT=0 and no OPT; the cached answer is keyed
  on the question only (a different ECS hits the same entry). Verified
  to FAIL pre-fix (verbatim client packet upstream).
- **Case-insensitive question echo:** a case-normalizing upstream
  (lowercased qname echo) is accepted; a real letter change is still
  dropped. Verified to FAIL pre-fix (byte-exact echo → SERVFAIL).
- **Stray-datagram tolerance:** garbage / wrong-txid datagrams before
  the real answer do not kill the exchange. Verified to FAIL pre-fix
  (single recv → SERVFAIL).
- **Self-test / health:** `self_test` green against a fake upstream;
  empty upstream list refused at bind; dead upstream →
  `upstream_ok=false` with engine/filter steps still green.
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

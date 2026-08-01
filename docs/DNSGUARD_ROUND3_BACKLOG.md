# dnsguard — round-3 review backlog (handoff)

**Base commit:** `f0f9be8` (`dnsguard: fix 3 round-3 HIGH findings`)
**Source:** adversarial review of `4b10313`, 20 agents over 5 surfaces, each
finding independently attacked by a skeptic instructed to refute it.
**Status of that review:** 6 confirmed, 9 refuted, 18 unverified.

Nothing in dnsguard is shipped: `enabled = false`, and no NRPT code exists
anywhere in the repo. Everything below is pre-integration. The next commit is
the sentinelld wiring, so the findings that matter most are the ones the
wiring will assume and that do not hold.

---

## What is already done — do not re-fix

The three HIGH findings were fixed in `f0f9be8`:

1. **TCP hard lifetime cap** — `read_budget` was computed once and shared by
   the length-prefix read and the body read, so a client that landed the
   second prefix byte just under the deadline started a fresh full-length
   body wait (measured 1.99x, and 6.99x with a slow upstream chained through
   an unbounded `handle_query`). Every await now re-derives its budget from
   the deadline. `tcp_lifetime_kills` moved to a single exit point so it can
   no longer report a successful cap kill for a connection that outlived the
   cap.
2. **Upstream txid** — was a Weyl counter through an invertible xorshift
   seeded `nanos ^ pid.rotate_left(32)`; the rotate left the low 32 seed bits
   as wall-clock nanoseconds alone, and two observed IDs plus the pid
   recovered the state in 22.7 ms. Now a keyed PRF (SipHash-1-3 over a
   counter, key from the OS CSPRNG via `RandomState`), still dependency-free.
3. **`self_test()` single-upstream blindness** — step (ii) probed only the
   round-robin head and `forward` has no failover, so `[live, dead]` reported
   all-green with an empty detail. `forward` is now split over `forward_via`;
   the health check probes every configured upstream, and
   `upstreams_healthy` / `upstreams_total` are on the report.

Fixes 1 and 3 are revert-verified (revert -> named test fails -> re-apply ->
green). Fix 2 is **not** revert-verified and the commit says so: the defect
was cryptographic strength, not behaviour, so no unit test fails against the
old construction.

**Line numbers below cite `4b10313`.** `f0f9be8` shifted `proxy.rs`
substantially (`tcp_conn`, `self_test`, `forward`/`forward_via`,
`UpstreamTxids`). Re-anchor by symbol name, not by line.

---

## Ground rules for this round

These are not style preferences. Every one of them is a failure this project
has actually shipped, and each has recurred in more than one round.

1. **A confident false assertion in a comment or doc is a defect in itself.**
   One such sentence previously enabled a CWE-59 privilege escalation. Last
   round, "HARD cap ... no matter how active it is" hid an unbounded write
   path for a full release cycle.
2. **A test must be able to fail.** For every test you write or touch, ask:
   would a deliberately broken implementation also pass this? Two tests
   certifying the round-1 TCP fix passed unchanged on pre-fix code. Prove it
   by revert-check: revert the fix, watch the named test fail, re-apply.
3. **Check by identity, not by name/string.**
4. **Fix the data, not one sink.** When you fix a path, grep for its
   siblings; several findings below are exactly this shape.
5. **Narrowing is not closing.** Removing the demonstrated instance while
   leaving the class open is how findings return one round later wearing a
   different hat.

Also: if a finding below is **wrong**, say so with evidence and leave it
unfixed. A refutation on the record is worth as much as a fix. Nine findings
were refuted this round and they are not in this document precisely so nobody
re-litigates them.

---

# Section A — confirmed MEDIUM (3)

These survived an adversarial skeptic who tried to refute them and reproduced
the chain from source. Severities are the **skeptic's corrected** values, all
downgraded from HIGH. Reproduce before fixing; the reproductions are cited.

### A1. Truncation coupled ordinary traffic to a 32-permit, squattable, non-fail-safe TCP pool

**Where:** `proxy.rs` — the UDP truncation branch (`resp.len() >
wire::MAX_UDP_PAYLOAD`), `DEFAULT_TCP_MAX_CONNECTIONS = 32`, the accept-loop
exhaustion path (`try_acquire_owned` -> bare `drop(stream)`).

**What happens:** before `4b10313` a 945-byte answer reached a UDP client in
one datagram. Revert-checked: with only the truncation hunk removed, the probe
prints `PRE-FIX3: udp answer len=945 tc=false rcode=0` — no client TCP at all.
At HEAD the same answer becomes a 29-byte TC=1 and the client is *ordered*
onto the TCP listener. That listener has 32 permits and exhaustion is not
fail-safe: it bumps `shed` and drops the socket, so the client gets RST/EOF —
never SERVFAIL, never a retryable answer, on the path we just sent it to.

Reproduced three ways:
- 32 zero-byte connections from one unprivileged process: UDP still returns
  TC=1/NOERROR while the mandated TCP retry dies with os error 10054.
- **No attacker:** 32 clients that each issue one real query and keep the
  connection open (RFC 7766 says clients SHOULD reuse) fill the pool. The 33rd
  resolution of the same name fails, while small names keep resolving cleanly
  over UDP — so nothing *looks* broken.
- Sustained squat: one process, 96 connect loops, each completing a cheap
  query per idle window, produced 20/20 probe failures across ~7x the idle
  timeout.

**Honest scope** (the skeptic's downgrade, worth reading before you size the
fix): recovery is immediate once the squatter exits, and a leaked-but-idle
squat self-heals in ~9.8 s via the idle timeout — this is **not**
reboot-surviving. The polite-client variant self-heals in ~10 s too; only a
deliberate sub-idle-timeout keepalive sustains it. And the pre-fix behaviour
was *worse* for classic 512-byte-buffer stubs: unconditional WSAEMSGSIZE, no
attacker needed. Truncation was a net improvement that introduced a coupling.

**Two now-false statements this created**, both of which a maintainer would
rely on: `tests/proxy_loopback.rs` "UDP — the machine's actual DNS path — is
completely unaffected", and `WEB_PROTECTION_DESIGN.md` "verify UDP
forward+block while TCP permits are gone". Both were true before the
truncation fix and were invalidated by it in the same commit.

**Direction:** break the coupling, not the demonstration. (a) Truncate against
the client's advertised EDNS payload size — see L01, the size is already in
the packet — so ordinary 513–4096-byte answers stay on UDP and never touch the
pool. (b) Make pool exhaustion fail-safe: answer SERVFAIL instead of
`drop(stream)`. (c) Per-source accounting so one peer cannot take all 32.
(d) Fix both false statements and add a test asserting a >512-byte name still
resolves while the pool is saturated.

### A2. One process starves DNS-over-TCP machine-wide, and the health surface stays green

**Where:** the single process-wide `tcp_semaphore`, `try_acquire_owned` then
`drop(stream)` with no queue / no per-source cap / no fairness; `self_test`
steps (ii) and (iii) are both UDP-only.

**What happens:** when the pool is full the permit goes to whoever reconnects
fastest. Measured at 1/10-scaled production ratios (pool 8, idle 1 s, lifetime
6 s): **12 perfectly well-behaved clients reduced a legitimate client to 2
answers out of 268 attempts over 15 s — 0.7%.** `tcp_lifetime_kills = 16`:
the cap fires and the hogs simply re-win the freed permit. End-to-end with an
upstream that always truncates, a TC-honouring client got 49/49 UDP answers
and **0/49 successful TCP retries**.

Throughout, `self_test()` reports green — there is no TCP probe anywhere, and
the design doc's runtime watchdog is defined as those same three UDP steps.
TCP-pool exhaustion is folded into the shared `shed` counter, so the daemon
cannot even distinguish it.

Note `f0f9be8` changed the recycling dynamics slightly (the cap now actually
fires at its configured value instead of ~2x). It does **not** fix this: the
reconnect spinner still wins the freed permit.

**Direction:** per-source-address cap plus a small bounded FIFO wait instead
of drop-on-full; a 4th self-test step that resolves through the **TCP**
listener; a dedicated `tcp_pool_full` counter separate from `shed`. Consider
raising `DEFAULT_TCP_MAX_CONNECTIONS` now that truncation routes every
>512-byte answer through TCP.

### A3. `block_response = "zero_ip"` makes `self_test()` permanently red

**Where:** step (iii) hard-codes `== wire::RCODE_NXDOMAIN`;
`build_zero_ip_response` answers NOERROR with a 0.0.0.0 A record;
`block_response = "nxdomain" # or "zero_ip"` is documented and supported.

**What happens:** flip the supported knob and `filter_ok` is false forever.
Measured: `SelfTestReport { engine_ok: true, upstream_ok: true, filter_ok:
false, detail: "canary through listener did not return NXDOMAIN; " }` — while
in the same test the running proxy answered a real canary query correctly.
Blocking works perfectly; the gate says it doesn't.

Consequences, and this is why it is here rather than in Section B: the design
says any failed step means refuse to enable, so choosing `zero_ip` means web
protection can never be turned on. Worse, the design reuses the same 3-step
test as the **runtime watchdog** with "on sustained failure apply
`on_proxy_failure`" — a wiring that calls `report.ok()` there sees permanent
failure and fires `remove_rule` (filtering silently off) or `fallback` (NRPT
secondary = unfiltered DNS), machine-wide, on a 100%-healthy proxy. **This is
what the next commit hits the first time anyone flips a supported config
knob.**

**Direction:** step (iii) must assert what the *configured* block response
is — match on `state.config.block_response`. Better, assert a property that
holds under both policies and that an upstream answer cannot satisfy (see
L07/L12): AA=1 on locally-synthesized block answers, or a `counters.blocked`
delta of exactly 1 across the probe.

---

# Section B — unverified (18)

**Nobody attacked these.** They come from the attack pass only; the verify
budget went to the higher-severity items. Treat each as a hypothesis: confirm
it from source before you change anything, and push back on the ones that are
wrong. Severities are the finder's own, uncalibrated.

**7 of these are MEDIUM, not LOW** — L01, L07, L08, L11, L12, L13, L14.

## Wire / protocol correctness

**L01 (MEDIUM) — DO and CD are stripped while the upstream's AD bit is relayed
verbatim.** `build_upstream_query` emits `flags = FLAG_RD` only, question
only, no OPT. Reproduced: client sends CD=1 plus EDNS0 DO=1; upstream sees
`flags=0x0100 arcount=0`; upstream answers AD=1; client receives `flags=0x81a0`
— AD set. So a client asking for DNSSEC gets a silently unsigned answer
(classic downgrade), a client setting CD=1 cannot self-validate, and the AD=1
it does get is a lie — we validated nothing and accepted the packet on txid +
question echo over plaintext UDP. Since the proxy is on 127.0.0.1 it is
exactly the "secure channel" a stub is entitled to trust AD from.
*Direction:* pick one and state it — either clear AD on everything we emit and
document that DNSSEC is unavailable in v1, or forward DO and CD (header/OPT
flag bits, not ECS — forwarding them does not reintroduce the client-steering
problem) and relay RRSIGs, which also means honouring the client's EDNS size.
Do not leave the current mix.

**L02 (LOW) — `build_truncated_response` hardcodes RCODE=NOERROR.** Reproduced:
upstream returns a 948-byte NXDOMAIN, cached under `negative_ttl`. TCP client
gets `len=948 rcode=3`; UDP client gets `len=32 rcode=0` with TC set. A client
that treats TC=1/NOERROR/ANCOUNT=0 as NODATA rather than retrying records
"exists, no records" for a name that does not exist, for the full 60 s
negative-cache window. Self-inflicted: the rcode is in hand at the call site.
*Direction:* pass the answer's rcode in. The existing unit test only asserts
`flags & 0x000F == 0`, so it would pass on any hardcoded-NOERROR
implementation — failure shape #2, fix the test too.

**L03 (LOW) — the truncation fallback fails OPEN to the oversized response.**
`build_truncated_response(&bytes).unwrap_or(resp)`. Traced as currently
unreachable and could not be triggered, so this is a latent shape, not a live
bug — but `unwrap_or(the thing we are protecting against)` is the wrong
default for exactly this fix, and any future change that makes the builder
fallible for another reason turns it back into the original HIGH.
*Direction:* fall back to SERVFAIL or drop; never to the oversized response.

**L04 (LOW) — the rebuilt upstream query silently rewrites RD and OPCODE, and
the blocked path disagrees.** Reproduced: an RD=0 client (`+norecurse`) gets
its query forwarded with RD forced on and receives `flags=0x8180` — we tell
the client it asked for recursion when it did not (RFC 1035 4.1.1 says RD is
copied into the response). An opcode=2 client is forwarded as opcode 0 and
gets opcode 0 back, which a conforming client discards — yet the *same* query
when **blocked** comes back with opcode=2 preserved, because
`build_error_response` and `build_zero_ip_response` both mask the opcode
through. *Direction:* reject `opcode != 0` with NOTIMP before forwarding or
cache lookup; for RD either copy the client's value or rewrite it back on the
response. Whatever you pick, make the forwarded and blocked paths agree.

## Health / self-test

**L07 (MEDIUM) — step (iii) still cannot tell "our block fired" from "the
upstream said NXDOMAIN".** This is the vacuity commit `4b10313` row 7 claims
to have removed. The canary is under RFC 2606 `.invalid`; step (iii) accepts
on rcode alone — no AA, no ancount, no locality check. Reproduced with
`FilterEngine::default()` (zero rules — models a blocklist load that failed)
and an upstream that NXDOMAINs like any real resolver: `{ engine_ok: false,
upstream_ok: false, filter_ok: TRUE }` **and the canary was leaked upstream**
(2 hits). Then that upstream NXDOMAIN is cached and served for 60 s.
*Direction:* make the block answer self-identifying (AA=1 on locally
synthesized answers) and require rcode==NXDOMAIN AND AA==1 AND ancount==0, or
assert a `counters.blocked` delta no upstream can fake. Also gate step (iii)
so a cached answer cannot satisfy it. Pairs with A3 and L12 — fix them as one
change.

**L08 (MEDIUM) — a self-referential upstream is accepted and amplifies.**
`bind()` validates only `is_empty()`. Reproduced: `listen == upstreams[0]`
binds fine; with `max_in_flight=64`, **one** client query produced 65 internal
queries and 1 shed, client SERVFAIL in 26 ms. At the production default of 256
that is ~257 internal queries and ~256 ephemeral sockets per client query,
saturating the in-flight pool instantly. Reachable: adapter DNS discovery
returns whatever the interface is configured with, and 127.0.0.1 is the normal
adapter DNS on any box that has run dnscrypt-proxy, Acrylic, Pi-hole-on-host,
or a prior Sentinella. Second half: `upstreams` lives in `Arc<State>` with no
mutator, so the doc's "re-read on network-change events" is not expressible.
*Direction:* reject any upstream equal to the listen address, and loopback
upstreams on the listen port generally. Add an `upstreams` mutator
(`ArcSwap<Vec<SocketAddr>>` + `Proxy::set_upstreams`) validated the same way —
the wiring needs it regardless.

**L05 / L09 (LOW, same root) — `health_check_name`'s doc comment is false.**
It says "Must NOT be a name the filter could block". No such constraint
exists: step (ii) calls `forward`/`forward_via` directly and never reaches
`decide`. Reproduced: with `example.com` (the default) on the blocklist,
`self_test()` returned all-green with an empty detail and the upstream still
saw the query. The comment encodes the author's belief that step (ii)
traverses the serving path — it does not, and nothing in `self_test` proves a
*resolvable* name resolves through the listener. L05 adds that
`health_check_name` is re-encoded by `build_query`, which is escape-unaware,
so an operator name containing an escape silently probes a different name.
*Direction:* delete the sentence or make it true. Replace with what is
load-bearing: "step (ii) validates upstream reachability only; it does NOT
prove the listener can resolve anything." Validate `health_check_name` at
bind (reject empty/root/unencodable/backslash-bearing).

**L10 (LOW) — `self_test()` writes synthetic traffic into user-facing
counters.** Measured: `{queries:0, blocked:0}` -> `{queries:1, blocked:1}`.
The GUI/IPC "domains blocked" figure includes canary probes the user never
made, and the DecisionHook receives a Blocked event for a query no client
issued — a query-log correctness problem as well as a cosmetic one. Harmless
at one probe per start; becomes a visible lie the moment the wiring runs the
health check on a timer, which the design asks for. **Note `f0f9be8` made this
slightly worse**: step (ii) now probes every upstream instead of one.
*Direction:* snapshot and restore, or route the probe through a path flagged
synthetic that skips the counters and the hook.

## Filter / blocklists

**L13 (MEDIUM) — the escaping fix quadrupled the worst-case memory of the
"bounded" load.** The 253-byte presentation cap was replaced by a 255-wire-
octet bound, which is correct for the fail-open bug it fixed but silently
removed any bound on the string actually stored. Measured: one rule at 1003
presentation chars for 255 wire octets — a 3.96x loosening — and 20,000 such
lines load with `truncated: false`. The only remaining budget is
`MAX_HOSTS_LINES`, a *line* cap, and the comment next to it still promises
predictable memory. *Direction:* add a byte budget to
`load_hosts_with_limit`, reported in `HostsLoadStats` and honoured as honestly
as `truncated`; update the comment to the real bound.

**L14 (MEDIUM) — no shipped blocklist source can express a suffix rule.**
Settling the question round 2 asked: not addressed in code, not in the doc,
not acknowledged — `4b10313` left §4 byte-identical. The doc still says suffix
rules need a leading dot and still names StevenBlack/hosts and the URLhaus
domain list as the sources. Neither format emits a leading dot, so 100% of
rules are exact-host. Measured: a URLhaus-format load gives `rules_added: 0,
lines_skipped: 6` and returns Ok, and `decide(evil-c2.example) = Allow`.
Subdomain-wildcarding C2 — the normal shape — is unblocked. *Direction:*
either add a plain-domain-list loader with a per-source exact/suffix policy
flag, or **at minimum** state the consequence in §4 next to the source list.
The Pi-hole precedent cited there is accurate for hosts files, but Pi-hole
ships regex/wildcard lists alongside them; we currently have no reachable path
to a suffix rule at all.

**L16 (LOW) — the documented `allowlist = [".evil.example"]` config surface
has no public API that accepts it.** The leading-dot marker is stripped only
inside the private `parse_hosts_line`. Every public adder runs the raw string
through `normalize_name`, which rejects a leading dot as an empty label.
Measured: `add_allow`, `add_allow_exact`, `add_block` all return `false` for
`.evil.example`; rule count 0. The wiring will read `allowlist` from TOML and
call `add_allow_exact` per the doc's wording, and `false` here means
"malformed", which is easy to log as a warning and move on — the operator's
allowlist silently vanishes. *Direction:* expose `add_allow_rule` /
`add_block_rule` sharing one implementation with `parse_hosts_line`, and make
the daemon treat `false` as a loud config error.

**L15 (LOW) — `normalize_name`'s absolute invariant is false for the root
name.** The comment says a wire-legal name *always* normalizes and `None` is
reserved for operator input mistakes. The root name is a counterexample:
`parse_question_name` returns `""` for a root-label-only question, which is
wire-legal (root NS priming looks exactly like this), and `decide` fails open
with no counter and no log. Blast radius today is nil — there is nothing to
block at the root. The hazard is the sentence: the wiring is invited to trust
"a `None` on a query name is impossible". *Direction:* weaken the sentence to
the truth, and add a counter on the fail-open branch so the next Block→Allow
regression in this class is visible instead of silent.

**L17 (LOW) — `MAX_NAME_LEN` is now a public constant that enforces nothing.**
The escaping fix removed its only non-test use; it remains `pub`, named as a
limit, with a doc comment whose qualifier makes it sound narrower rather than
dead. The next commit adds `webprotection.block_add` / `.allow_add` as
privileged IPC endpoints needing input validation, and the obvious constant to
reach for is exactly this one — `if name.len() > MAX_NAME_LEN { reject }` at
the IPC boundary re-creates the escape-expansion bug at a new layer.
*Direction:* delete it, or rename to `MAX_PLAIN_PRESENTATION_LEN` and mark it
informational-only.

**L18 (LOW) — two observability gaps.** (a) `parse_hosts_line` counts a line
as skipped only when the *whole* line produced zero rules, so a multi-host
line with some malformed hosts reports full success. Measured:
`0.0.0.0 good.example a..bad .suffix.example` gives `rules_added: 2,
lines_skipped: 0` — one of three dropped, nothing says so. This contradicts
the principle the same file states for the line cap: "stop ingesting but
report honestly — silently truncating a blocklist would hide protection gaps."
(b) is the counter half of L10. *Direction:* add `hosts_rejected` to
`HostsLoadStats` and warn when non-zero.

## Tests

**L06 (LOW) — the starvation test's proof-of-premise assertion can silently
skip.** `if let Ok(mut stream) = TcpStream::connect(...) { ... assert!(...,
"TCP pool must be exhausted") }` — the assertion that the pool is actually
saturated, which is the entire point of the rewrite, runs only if the probe
connect succeeds. If the listen backlog is exhausted or connect is refused
under load, the block is skipped without a word and the test degrades to
"UDP still works", which any pool sizing satisfies. It did not trigger on this
box — the assertion ran, and the test correctly failed when the pools were
merged — but it is an unguarded silent-skip in the one assertion establishing
the premise. *Direction:* hoist the connect out and match on it explicitly
(`Err` == refused == exhausted, fine), or assert on a counter instead.

## Design doc

**L11 (MEDIUM) — rule-removal failure has no retry, no registry fallback, and
no boot-time backstop.** §5.3 specifies only "rule removal must succeed or the
uninstall aborts loudly". That is the entire failure-case specification, for
the one direction that breaks machines. The doc supplies its own missing
fallback two pages earlier and never connects them: it gives the exact
registry location and says direct writes are an option — stated for the *add*
path only, never for removal. Triggers where the cmdlet is unavailable or
fails: Server Core / Nano without the DnsClient module, PowerShell in
ConstrainedLanguage mode, GPO override, access denied. And "abort loudly" is a
dead end users route around destructively — the user deletes the folder, and
now the rule is live with no reconciler and no product. *Direction:* specify
the removal ladder: (1) `Remove-DnsClientNrptRule -GUID`; (2) on failure,
direct delete of our GUID subkey + `Clear-DnsClientCache`; (3) on failure,
**leave the reconciler task and binaries in place**, mark the uninstall
blocked, and let the boot reconciler retry. Never let the abort path destroy
the remover. State the behaviour when a GPO NRPT policy is present.

**L12 (MEDIUM) — the acceptance canary is still vacuous.** Commit row 7 claims
adding step (i) fixed it. Step (i) is a socket-free in-process HashSet lookup
— it proves nothing about *who* is serving the address. Step (iii) remains "a
`.invalid` name returns NXDOMAIN from address X", which every resolver on
earth satisfies. Verified on this box with no Sentinella installed and
`Get-DnsClientNrptRule` count 0: `nslookup webguard-test.sentinella.invalid`
-> "Non-existent domain". The composite proves "our engine has the rule" AND
"something answered NXDOMAIN" — never "our proxy is what the DNS Client
reaches". The vacuity was relocated, not removed. *Direction:* make the
acceptance signal one no stock resolver can produce — answer the canary with
`ZeroIp` unconditionally, so "canary -> 0.0.0.0 at 127.0.0.1:53" positively
identifies our listener — and require a *positive* resolution in the same
probe through the listener, so a proxy that blocks the canary but SERVFAILs
everything else fails. Pairs with A3 and L07.

---

## Suggested order

1. **A3 + L07 + L12 together.** They are one change to what step (iii)
   asserts, and A3 is the one the wiring trips over on day one.
2. **L08.** The wiring needs `set_upstreams` anyway, and the self-referential
   check belongs in the same edit.
3. **A1 + A2 + L01 together.** Honouring the client's EDNS size is the fix
   that decouples truncation from the TCP pool, which is most of A1; the
   fairness and fail-safe work in A2 is what remains. L01's AD/DO/CD decision
   has to be made before the EDNS work, not after.
4. **The doc items — L11, L14.** Cheap, and L11 is the one that determines
   whether a failed uninstall bricks a machine.
5. **Everything else**, in any order.

`L03`, `L15`, `L17` are latent-shape items with no live trigger. They are
worth doing because each one is aimed squarely at the next commit, but do not
let them displace the list above.

//! Domain filter engine: allowlist/blocklist with exact-host and suffix
//! matching, plus a hosts-file-format loader.
//!
//! Semantics (design doc §4):
//! - precedence: allowlist beats blocklist, always (an operator must be able
//!   to un-break a false positive without editing third-party lists);
//! - rule kinds are explicit: hosts-format entries (`0.0.0.0 host`) are
//!   EXACT-host rules (Pi-hole semantics — the entry blocks that host, not
//!   its subtree; a `0.0.0.0 local` line must never blackhole `.local`).
//!   Suffix rules exist only via an explicit leading-dot marker
//!   (`.evil.example`) in user-supplied lists, the `add_allow` /
//!   `add_block` API used by the daemon's IPC layer, the marker-aware
//!   `add_allow_rule` / `add_block_rule` config entry points, or a
//!   plain-domain-list load with a per-source suffix policy (§4);
//! - a suffix rule `evil.example` matches `evil.example` itself and any
//!   subdomain (`a.b.evil.example`) but never a superstring
//!   (`notevil.example`);
//! - an exact rule matches only the host itself;
//! - query names arrive RFC 4343-escaped from the wire layer (a `.` inside
//!   a label appears as `\.`); suffix cuts happen only at UNescaped dots,
//!   so the single label `microsoft.com` (`microsoft\.com`) can never
//!   suffix-match the two-label rule `microsoft.com`.

use std::collections::HashSet;
use std::io::{self, BufRead, Read};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::wire;

/// Always-blocked sentinel domain (design doc §7): lets operator acceptance
/// tests verify the pipeline end to end without depending on a live
/// blocklist. `.invalid` is reserved by RFC 2606, so it can never collide
/// with a real name.
pub const CANARY_DOMAIN: &str = "webguard-test.sentinella.invalid";

/// INFORMATIONAL ONLY — enforces nothing. Maximum length of a *plain*
/// presentation-form DNS name per RFC 1035 (without the trailing dot).
/// The authoritative validation in [`FilterEngine::normalize_name`] is
/// done in WIRE units (labels ≤ 63 octets, total ≤ 255 wire bytes,
/// computed on the UNescaped bytes), because the escaped presentation
/// form is up to 4× longer than the wire name it represents. Do NOT use
/// this constant to validate input (e.g. `if name.len() > ... { reject }`
/// at an IPC boundary): that re-creates the escape-expansion fail-open
/// bug at a new layer — wire-legal names can be far longer than this.
pub const MAX_PLAIN_PRESENTATION_LEN: usize = 253;

/// Hard cap on hosts-file lines ingested in one load. WHY: blocklists are
/// attacker-influenceable downloads. This is ONE of three budgets —
/// lines, input bytes ([`MAX_HOSTS_BYTES`]) and rules
/// ([`MAX_HOSTS_RULES`]) — and it is the weakest of them: a single hosts
/// line may carry dozens of hostnames, so a line cap alone bounds neither
/// memory nor load time. Measured: 684k lines produced 43.8M rules, 2.36
/// GB resident, and 144.6 s of blocking single-threaded load. The rule cap
/// is what makes those two quantities predictable.
pub const MAX_HOSTS_LINES: u64 = 2_000_000;

/// Hard cap on INPUT bytes ingested in one load (line bytes including the
/// newline). 256 MiB comfortably fits the largest legitimate lists
/// (2M lines × ~40 average bytes ≈ 80 MiB).
///
/// This bounds the INPUT and nothing else. It does NOT bound the rules'
/// memory: `normalize_name` returns an owned lowercased `String` per rule
/// (not a borrowed substring of the input), which costs a 24-byte header
/// inside the hashbrown table plus its own heap block plus load-factor
/// slack. MEASURED at this budget with the worst LEGAL shape — many short
/// hostnames per hosts line, which the loader explicitly supports — 256
/// MiB of input produced 43.8M rules and **2.36 GB resident / 2.91 GB
/// peak**, i.e. 9.2x/11.4x the byte budget. An earlier revision of this
/// comment claimed the opposite ("substrings of the input, so this also
/// bounds the rules' memory"); it was wrong by an order of magnitude.
/// [`MAX_HOSTS_RULES`] is the cap that actually binds memory.
pub const MAX_HOSTS_BYTES: u64 = 256 * 1024 * 1024;

/// Hard cap on RULES ingested in one load — the budget that actually
/// bounds memory, because memory is proportional to rules, not to input
/// bytes.
///
/// WHY a third cap: the line cap is defeated by multi-host lines (one
/// hosts line may carry dozens of hostnames, each becoming a rule), and
/// the byte cap prices input, not storage. Measured worst legal shape:
/// 684k lines / 256 MiB of input yielded 43.8M rules — 22x more rules
/// than lines and 44x the design's own stated ceiling for a blocklist
/// (10^4–10^6 domains, design §4). 4M is comfortably above every real
/// list and caps the hostile case at roughly 250 MB of rule storage.
pub const MAX_HOSTS_RULES: u64 = 4_000_000;

/// Which list a rule belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    Allow,
    Block,
}

/// Default rule kind for the unmarked entries of a plain domain list
/// (one domain per line, e.g. the URLhaus domain list). The policy is a
/// property of the SOURCE, declared in config — never of the data.
///
/// `Suffix` is the correct choice for C2/malware-domain feeds, where
/// subdomain wildcarding is the normal shape (an exact-only load of such
/// a feed leaves `anything.evil-c2.example` unblocked). It is
/// FALSE-POSITIVE-PRONE for generic lists: one bad or stale entry
/// blackholes the entry's whole subtree. Default to `Exact` unless the
/// source is a dedicated malware-domain feed. An explicit leading-dot
/// marker in the data always requests a suffix rule regardless of policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainListPolicy {
    Exact,
    Suffix,
}

/// What an UNMARKED token means for a given caller. The leading-dot
/// marker always overrides it; this is only the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleKind {
    Exact,
    Suffix,
}

impl From<DomainListPolicy> for RuleKind {
    fn from(p: DomainListPolicy) -> Self {
        match p {
            DomainListPolicy::Exact => RuleKind::Exact,
            DomainListPolicy::Suffix => RuleKind::Suffix,
        }
    }
}

/// Filter decision for a query name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
}

/// In-memory rule sets. Exact rules live in their own sets so an exact hit
/// is a single lookup; suffix rules are matched by walking label boundaries,
/// which is O(labels) hash lookups per query and needs no separate index.
#[derive(Debug, Default)]
pub struct FilterEngine {
    allow_exact: HashSet<String>,
    allow_suffix: HashSet<String>,
    block_exact: HashSet<String>,
    block_suffix: HashSet<String>,
    /// Query names `decide` could not normalize and therefore failed OPEN
    /// on. Reachable from the wire (the root name is wire-legal — see
    /// [`normalize_name`](Self::normalize_name)), so this must be VISIBLE,
    /// not silent: a future Block→Allow regression in normalization shows
    /// up here instead of passing unnoticed.
    unnormalizable_queries: AtomicU64,
}

impl FilterEngine {
    /// New engine containing only the always-blocked canary domain.
    pub fn new() -> Self {
        let mut engine = Self::default();
        // WHY exact (design doc §4/§7): the canary must not be disabled by
        // a bare-label allowlist entry. With exact semantics, allowlisting
        // `invalid` or `sentinella.invalid` cannot match it — only an
        // exact allow of the canary itself (or an explicit leading-dot
        // suffix rule on a parent) overrides it.
        engine.block_exact.insert(CANARY_DOMAIN.to_string());
        engine
    }

    /// Normalize a presentation-form domain name for matching: strip
    /// trailing dots, lowercase ASCII, reject empty names, empty labels,
    /// and non-ASCII input.
    ///
    /// Escape-aware (RFC 4343): `\` followed by any byte is a literal
    /// escaped character within a label; label boundaries are UNescaped
    /// dots only. An escape at the very end of the name is malformed and
    /// rejected. This is what keeps the single wire label `microsoft.com`
    /// (presented as `microsoft\.com`) from matching the two-label rule
    /// `microsoft.com`.
    ///
    /// Length validation is done in WIRE units on the UNescaped bytes —
    /// labels ≤ 63 octets, total name ≤ 255 wire bytes — never against
    /// the escaped presentation string. WHY: escaping inflates one wire
    /// octet to up to 4 presentation chars (`\DDD`), so measuring the
    /// escaped string against 253 rejects names that are perfectly legal
    /// on the wire (a 61×0x00 label escapes to 244 chars); rejecting a
    /// wire-legal name here used to make `decide` fail OPEN and let a
    /// blocked suffix through. The escaped string is for matching only.
    ///
    /// Returns `None` for anything that cannot be a WIRE-LEGAL DNS name —
    /// with ONE wire-legal exception: the root name. A root-label-only
    /// question is legal on the wire (root NS priming looks exactly like
    /// this) and arrives here as `""`, which this function rejects.
    /// Every OTHER wire-legal name normalizes (never `None`); apart from
    /// the root, `None` is reserved for names no wire packet could carry
    /// (operator/list input mistakes). `decide` fails open on `None` and
    /// counts it in [`unnormalizable_query_count`](Self::unnormalizable_query_count),
    /// so the exception is observable rather than silent.
    pub fn normalize_name(name: &str) -> Option<String> {
        // Strip one trailing root dot — but only an UNescaped one: `foo\.`
        // is a label ending in a dot, not a rooted name.
        let bytes = name.as_bytes();
        let mut end = bytes.len();
        if end > 0 && bytes[end - 1] == b'.' {
            let mut backslashes = 0usize;
            let mut i = end - 1;
            while i > 0 && bytes[i - 1] == b'\\' {
                backslashes += 1;
                i -= 1;
            }
            if backslashes.is_multiple_of(2) {
                end -= 1;
            }
        }
        let trimmed = &name[..end];
        if trimmed.is_empty() || !trimmed.is_ascii() {
            return None;
        }
        // Wire-format accounting on UNescaped octets. Escape forms per
        // RFC 4343 (and what the wire layer emits): `\DDD` (backslash +
        // exactly three decimal digits) or `\X` (backslash + one char) —
        // both are exactly ONE wire octet; an unescaped `.` is a label
        // boundary. Root label costs 1 byte; every label costs
        // 1 (length) + octets.
        let bytes = trimmed.as_bytes();
        let mut wire_len = 1usize;
        let mut label_octets = 0usize;
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => {
                    let is_decimal_escape = i + 3 < bytes.len()
                        && bytes[i + 1].is_ascii_digit()
                        && bytes[i + 2].is_ascii_digit()
                        && bytes[i + 3].is_ascii_digit();
                    i += if is_decimal_escape { 4 } else { 2 };
                    label_octets += 1;
                }
                b'.' => {
                    if label_octets == 0 {
                        return None; // empty label
                    }
                    if label_octets > wire::MAX_LABEL_LEN {
                        return None; // overlong label
                    }
                    wire_len += 1 + label_octets;
                    if wire_len > wire::MAX_NAME_WIRE_LEN {
                        return None; // overlong name
                    }
                    label_octets = 0;
                    i += 1;
                }
                _ => {
                    label_octets += 1;
                    i += 1;
                }
            }
        }
        if i > bytes.len() || label_octets == 0 {
            // Dangling escape at end of name, or trailing empty label.
            return None;
        }
        if label_octets > wire::MAX_LABEL_LEN {
            return None;
        }
        wire_len += 1 + label_octets;
        if wire_len > wire::MAX_NAME_WIRE_LEN {
            return None;
        }
        Some(trimmed.to_ascii_lowercase())
    }

    /// Add an allowlist suffix rule (matches the host and its subdomains).
    /// Returns `false` if the name failed normalization.
    pub fn add_allow(&mut self, name: &str) -> bool {
        match Self::normalize_name(name) {
            Some(n) => {
                self.allow_suffix.insert(n);
                true
            }
            None => false,
        }
    }

    /// Add an allowlist exact-host rule (matches only the host itself).
    pub fn add_allow_exact(&mut self, name: &str) -> bool {
        match Self::normalize_name(name) {
            Some(n) => {
                self.allow_exact.insert(n);
                true
            }
            None => false,
        }
    }

    /// Add a blocklist suffix rule (matches the host and its subdomains).
    pub fn add_block(&mut self, name: &str) -> bool {
        match Self::normalize_name(name) {
            Some(n) => {
                self.block_suffix.insert(n);
                true
            }
            None => false,
        }
    }

    /// Add a blocklist exact-host rule (matches only the host itself).
    pub fn add_block_exact(&mut self, name: &str) -> bool {
        match Self::normalize_name(name) {
            Some(n) => {
                self.block_exact.insert(n);
                true
            }
            None => false,
        }
    }

    /// Decide a query name. Unnormalizable names are allowed (forwarded
    /// upstream); the wire layer, not the filter, is responsible for
    /// rejecting malformed packets. The fail-open branch is COUNTED
    /// ([`unnormalizable_query_count`](Self::unnormalizable_query_count)):
    /// the root name reaches it legitimately, and any OTHER name reaching
    /// it is a Block→Allow regression that must be visible, not silent.
    pub fn decide(&self, qname: &str) -> Decision {
        let Some(name) = Self::normalize_name(qname) else {
            self.unnormalizable_queries.fetch_add(1, Ordering::Relaxed);
            return Decision::Allow;
        };
        // WHY this order: allowlist wins unconditionally. Within each list,
        // exact rules are consulted before suffix rules so a specific
        // exception (`allow_exact`) always beats a broad rule.
        if self.allow_exact.contains(&name) || suffix_match(&self.allow_suffix, &name) {
            return Decision::Allow;
        }
        if self.block_exact.contains(&name) || suffix_match(&self.block_suffix, &name) {
            return Decision::Block;
        }
        Decision::Allow
    }

    /// Number of rules across all lists (diagnostics/IPC status).
    pub fn rule_count(&self) -> usize {
        self.allow_exact.len()
            + self.allow_suffix.len()
            + self.block_exact.len()
            + self.block_suffix.len()
    }

    /// Query names `decide` failed open on because they did not normalize
    /// (the wire-legal root name, or a normalization regression).
    pub fn unnormalizable_query_count(&self) -> u64 {
        self.unnormalizable_queries.load(Ordering::Relaxed)
    }

    /// Add one rule expressed in the USER/CONFIG surface syntax: a bare
    /// name is an exact-host rule, a leading-dot name (`.evil.example`)
    /// is a suffix rule. This is THE shared implementation of the
    /// leading-dot marker — the hosts loader, the domain-list loader, and
    /// the daemon's config/IPC path all go through it, so the marker
    /// means exactly one thing everywhere.
    ///
    /// Returns `false` when the name failed normalization. `false` from
    /// config input is a LOUD CONFIG ERROR (the operator's rule vanished)
    /// — the daemon must surface it as such, never log-and-continue.
    fn add_rule(&mut self, kind: ListKind, token: &str, default: RuleKind) -> bool {
        // An explicit leading dot ALWAYS requests a suffix rule; without
        // one the source's policy decides. Folding the per-source default
        // in here is what lets the domain-list loader share this function
        // instead of reimplementing the marker — see the doc above.
        let (name, suffix) = match token.strip_prefix('.') {
            Some(rest) => (rest, true),
            None => (token, default == RuleKind::Suffix),
        };
        match (kind, suffix) {
            (ListKind::Allow, true) => self.add_allow(name),
            (ListKind::Allow, false) => self.add_allow_exact(name),
            (ListKind::Block, true) => self.add_block(name),
            (ListKind::Block, false) => self.add_block_exact(name),
        }
    }

    /// Add one allowlist rule in config syntax (bare = exact, leading dot
    /// = suffix). This is the entry point for the TOML `allowlist` — a
    /// plain `add_allow_exact` call on `".evil.example"` would reject the
    /// marker as an empty label and the rule would silently vanish.
    /// `false` = malformed config value; treat as a loud config error.
    pub fn add_allow_rule(&mut self, token: &str) -> bool {
        self.add_rule(ListKind::Allow, token, RuleKind::Exact)
    }

    /// Add one blocklist rule in config syntax — see
    /// [`add_allow_rule`](Self::add_allow_rule).
    pub fn add_block_rule(&mut self, token: &str) -> bool {
        self.add_rule(ListKind::Block, token, RuleKind::Exact)
    }

    /// Load a hosts-format file into the given list with the default line
    /// cap ([`MAX_HOSTS_LINES`]). Accepted line shape:
    /// `<ip> <host> [<host>...] [# comment]` where `<ip>` is any literal
    /// that parses as an IP (`0.0.0.0`, `127.0.0.1`, `::`, ...). Blank
    /// lines, full-line `#` comments, and lines without a valid leading IP
    /// are skipped. Multiple hostnames on one line each become a rule.
    ///
    /// Rule kinds (design doc §4 — Pi-hole semantics): each host becomes an
    /// EXACT-host rule (the entry blocks that host only, never its
    /// subtree — a `127.0.0.1 local` preamble line must not blackhole
    /// `.local`). The one exception is the explicit suffix marker: a host
    /// written with a leading dot (`.evil.example`) becomes a suffix rule
    /// matching the host and all subdomains.
    ///
    /// Runs in O(RULES), not O(lines) — one hash insert per hostname, and
    /// a hosts line may carry many. Measured: 684k lines carrying 43.8M
    /// rules took 144.6 s of blocking single-threaded load, so "a 10⁶-line
    /// list loads in seconds" (an earlier revision of this sentence) holds
    /// only for one-host-per-line input. Bounded by ALL THREE of
    /// [`MAX_HOSTS_LINES`], [`MAX_HOSTS_BYTES`] and [`MAX_HOSTS_RULES`];
    /// the rule cap is the one that bounds memory and load time.
    pub fn load_hosts<R: BufRead>(&mut self, kind: ListKind, reader: R) -> io::Result<HostsLoadStats> {
        self.load_hosts_with_limit(kind, reader, MAX_HOSTS_LINES, MAX_HOSTS_BYTES, MAX_HOSTS_RULES)
    }

    /// Like [`load_hosts`](Self::load_hosts) with explicit caps (exposed
    /// so tests can exercise truncation without a 2M-line fixture). The
    /// byte budget counts INPUT bytes (including newlines) and bounds only
    /// those; rules are owned lowercased `String`s, not substrings of the
    /// input, so rule memory is bounded by the rule cap instead — see
    /// [`MAX_HOSTS_BYTES`] for the measured factor.
    pub fn load_hosts_with_limit<R: BufRead>(
        &mut self,
        kind: ListKind,
        reader: R,
        max_lines: u64,
        max_bytes: u64,
        max_rules: u64,
    ) -> io::Result<HostsLoadStats> {
        self.ingest_lines(reader, max_lines, max_bytes, max_rules, |engine, line, room| {
            engine.parse_hosts_line(kind, line, room)
        })
    }

    /// Load a plain domain list (one domain per line, `#` comments, blank
    /// lines — e.g. the URLhaus domain list) into the given list with the
    /// default caps. Unlike the hosts loader there is no leading IP token
    /// and no multi-host lines; a line with interior whitespace is
    /// malformed and counted in `hosts_rejected`.
    ///
    /// `policy` is a property of the SOURCE (declared in config), not of
    /// the data — see [`DomainListPolicy`] for the exact/suffix trade-off.
    pub fn load_domain_list<R: BufRead>(
        &mut self,
        kind: ListKind,
        reader: R,
        policy: DomainListPolicy,
    ) -> io::Result<HostsLoadStats> {
        self.load_domain_list_with_limit(
            kind,
            reader,
            policy,
            MAX_HOSTS_LINES,
            MAX_HOSTS_BYTES,
            MAX_HOSTS_RULES,
        )
    }

    /// Like [`load_domain_list`](Self::load_domain_list) with explicit
    /// caps (test hook, same rationale as [`load_hosts_with_limit`](Self::load_hosts_with_limit)).
    pub fn load_domain_list_with_limit<R: BufRead>(
        &mut self,
        kind: ListKind,
        reader: R,
        policy: DomainListPolicy,
        max_lines: u64,
        max_bytes: u64,
        max_rules: u64,
    ) -> io::Result<HostsLoadStats> {
        self.ingest_lines(reader, max_lines, max_bytes, max_rules, |engine, line, _room| {
            engine.parse_domain_list_line(kind, line, policy)
        })
    }

    /// Shared ingest loop for both list formats: enforces the line and
    /// byte budgets and reports honestly — `truncated` when a budget cut
    /// the input short, `hosts_rejected` when individual entries were
    /// malformed. Silently truncating or silently dropping entries would
    /// hide protection gaps.
    fn ingest_lines<R: BufRead>(
        &mut self,
        reader: R,
        max_lines: u64,
        max_bytes: u64,
        max_rules: u64,
        mut parse: impl FnMut(&mut Self, &str, u64) -> (u64, u64),
    ) -> io::Result<HostsLoadStats> {
        let mut stats = HostsLoadStats::default();
        // BOUND THE SOURCE, not just the accounting (round-3 closure
        // review). `reader.lines()` allocates a whole line into a `String`
        // BEFORE control returns here, so a budget checked afterwards
        // bounds what is COUNTED and never what is ALLOCATED: a
        // newline-free 64 MiB body — a broken CDN response, an HTML error
        // page, a gzip served as text/plain — was materialized in full
        // under a 1024-byte budget, and then reported `bytes_read: 0`.
        //
        // `take` makes the cap physical. The most one line can now cost is
        // `max_bytes + 1`, and that extra byte is exactly what lets us tell
        // "the input ended at the budget" from "there was more" without
        // reading the more.
        let mut limited = reader.take(max_bytes.saturating_add(1));
        for line in limited.by_ref().lines() {
            let line = line?;
            // +1 for the newline the line iterator stripped.
            let line_bytes = line.len() as u64 + 1;
            if stats.lines_read >= max_lines || stats.bytes_read + line_bytes > max_bytes {
                stats.truncated = true;
                break;
            }
            stats.lines_read += 1;
            stats.bytes_read += line_bytes;
            let (added, rejected) = parse(self, &line, max_rules.saturating_sub(stats.rules_added));
            stats.rules_added += added;
            // RULE budget (round-3 closure review, U09). Memory is
            // proportional to RULES, not to input bytes or lines: one hosts
            // line may carry dozens of hostnames, so neither of the other
            // two caps binds. Checked AFTER the line so a line is never
            // half-ingested, and reported through the same `truncated` flag.
            if stats.rules_added >= max_rules {
                stats.truncated = true;
                stats.hosts_rejected += rejected;
                if added == 0 {
                    stats.lines_skipped += 1;
                }
                break;
            }
            stats.hosts_rejected += rejected;
            if added == 0 {
                stats.lines_skipped += 1;
            }
        }
        // The source had at least `max_bytes + 1` bytes, so `take` cut it
        // and the last line we saw may be a fragment. Report honestly even
        // when the per-line accounting happened to land exactly on the
        // budget — silently truncating a blocklist hides protection gaps,
        // which is the principle this loader states for the line cap.
        if limited.limit() == 0 {
            stats.truncated = true;
        }
        if stats.truncated {
            tracing::warn!(
                max_lines,
                max_bytes,
                lines_read = stats.lines_read,
                bytes_read = stats.bytes_read,
                rules_added = stats.rules_added,
                "blocklist exceeded a load budget; remaining input ignored"
            );
        }
        if stats.hosts_rejected != 0 {
            tracing::warn!(
                hosts_rejected = stats.hosts_rejected,
                rules_added = stats.rules_added,
                "blocklist contained malformed entries that were dropped"
            );
        }
        Ok(stats)
    }

    /// Parse one hosts line; returns `(rules added, hosts rejected)`.
    fn parse_hosts_line(&mut self, kind: ListKind, line: &str, room: u64) -> (u64, u64) {
        // Strip inline comments first: everything from '#' onward is dead.
        let body = match line.find('#') {
            Some(i) => &line[..i],
            None => line,
        };
        let mut tokens = body.split_whitespace();
        let Some(ip) = tokens.next() else {
            return (0, 0);
        };
        // The first token must be an IP literal; this rejects plain
        // domain-list lines and garbage alike.
        if ip.parse::<IpAddr>().is_err() {
            return (0, 0);
        }
        let mut added = 0u64;
        let mut rejected = 0u64;
        for host in tokens {
            // The rule budget binds WITHIN the line, not just between
            // lines: one hosts line may carry millions of hostnames (line
            // length is bounded only by the byte budget), so a
            // between-lines check alone would let a single line blow past
            // the cap by an unbounded amount.
            if added >= room {
                break;
            }
            // Hosts entries are EXACT rules (Pi-hole semantics); only the
            // explicit leading-dot marker requests a suffix rule.
            if self.add_rule(kind, host, RuleKind::Exact) {
                added += 1;
            } else {
                rejected += 1;
            }
        }
        (added, rejected)
    }

    /// Parse one domain-list line; returns `(rules added, hosts rejected)`.
    fn parse_domain_list_line(
        &mut self,
        kind: ListKind,
        line: &str,
        policy: DomainListPolicy,
    ) -> (u64, u64) {
        let body = match line.find('#') {
            Some(i) => &line[..i],
            None => line,
        };
        let mut tokens = body.split_whitespace();
        let Some(token) = tokens.next() else {
            return (0, 0); // blank or comment-only line
        };
        if tokens.next().is_some() {
            // Not one-domain-per-line: refuse to guess which token is the
            // domain (a space is a WIRE-LEGAL label octet, so normalizing
            // the whole line would silently store garbage).
            return (0, 1);
        }
        // ONE implementation of the marker (round-3 closure review, U11):
        // this used to be a 12-line inline copy that could drift from
        // `add_rule`, while the doc on `add_rule` claimed every caller
        // went through it.
        let ok = self.add_rule(kind, token, RuleKind::from(policy));
        if ok { (1, 0) } else { (0, 1) }
    }
}

/// Does `name` or any of its parent suffixes appear in `set`? Cuts happen
/// only at UNescaped dots — this is what keeps `evil.example` from matching
/// `notevil.example`, and the escaped single label `microsoft\.com` from
/// matching the two-label rule `microsoft.com`.
fn suffix_match(set: &HashSet<String>, name: &str) -> bool {
    if set.contains(name) {
        return true;
    }
    let bytes = name.as_bytes();
    let mut escaped = false;
    for (i, &byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
        } else if byte == b'.' && set.contains(&name[i + 1..]) {
            return true;
        }
    }
    false
}

/// Load statistics for one list ingest (hosts format or domain list).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HostsLoadStats {
    pub lines_read: u64,
    /// Input bytes ingested (including newlines); bounded by the byte
    /// budget — together with `lines_read` this makes the memory of a
    /// load predictable regardless of what a source serves.
    pub bytes_read: u64,
    pub rules_added: u64,
    pub lines_skipped: u64,
    /// Individual host ENTRIES rejected as malformed, whether or not
    /// their line produced any rule. This and `lines_skipped` are counted
    /// independently and DO overlap: `lines_skipped` counts LINES that
    /// yielded no rule (including blank and comment lines), so a line on
    /// which every entry is malformed is counted in both — and for
    /// one-domain-per-line input that is always the case. An earlier
    /// revision of this comment claimed the line is NOT in
    /// `lines_skipped`; it is. Non-zero means part of a list silently did
    /// not become protection — the loader warns when this moves.
    pub hosts_rejected: u64,
    /// True when the input exceeded a budget (line cap or byte budget)
    /// and was cut short.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REGRESSION (U09). Memory is proportional to RULES, and neither the
    /// line cap nor the byte cap binds them: ONE hosts line may carry
    /// dozens of hostnames. Measured at the real budget, 256 MiB of input
    /// produced 43.8M rules and 2.36 GB resident under a comment claiming
    /// the byte budget bounded rule memory "to well under this figure".
    ///
    /// Asserts the PROPERTY, so a byte-or-line-only implementation fails:
    /// the rule cap binds while the other two are wide open.
    #[test]
    fn rule_budget_binds_what_line_and_byte_caps_cannot() {
        const RULES: u64 = 50;
        // 20 lines x 64 hosts = 1280 candidate rules from only 20 lines.
        let mut input = String::new();
        for line in 0..20u32 {
            input.push_str("0.0.0.0");
            for host in 0..64u32 {
                input.push_str(&format!(" h{line}x{host}.example"));
            }
            input.push('\n');
        }
        let mut engine = FilterEngine::new();
        let stats = engine
            .load_hosts_with_limit(
                ListKind::Block,
                io::BufReader::new(input.as_bytes()),
                u64::MAX, // line cap wide open
                u64::MAX, // byte cap wide open
                RULES,
            )
            .expect("load");
        assert!(
            stats.rules_added <= RULES,
            "rule cap did not bind: {stats:?}"
        );
        assert!(stats.truncated, "hitting the rule cap must be reported: {stats:?}");
        assert!(
            stats.lines_read < 20,
            "the cap must stop mid-list, not after it: {stats:?}"
        );
    }

    /// REGRESSION (U11). `add_rule`'s doc claimed to be THE shared
    /// implementation of the leading-dot marker while the domain-list
    /// loader carried its own 12-line copy that could drift. The three
    /// entry points must agree on what the marker means.
    #[test]
    fn leading_dot_marker_means_the_same_thing_on_every_entry_point() {
        // (a) config/IPC surface
        let mut cfg = FilterEngine::new();
        assert!(cfg.add_block_rule(".evil.example"));
        assert_eq!(cfg.decide("sub.evil.example"), Decision::Block, "config: suffix");
        let mut cfg_exact = FilterEngine::new();
        assert!(cfg_exact.add_block_rule("evil.example"));
        assert_eq!(
            cfg_exact.decide("sub.evil.example"),
            Decision::Allow,
            "config: bare token is EXACT"
        );

        // (b) hosts loader
        let mut hosts = FilterEngine::new();
        hosts
            .load_hosts(ListKind::Block, io::BufReader::new("0.0.0.0 .evil.example
".as_bytes()))
            .expect("load");
        assert_eq!(hosts.decide("sub.evil.example"), Decision::Block, "hosts: suffix");

        // (c) domain list, Exact policy — the marker still overrides it
        let mut dl = FilterEngine::new();
        dl.load_domain_list(
            ListKind::Block,
            io::BufReader::new(".evil.example
".as_bytes()),
            DomainListPolicy::Exact,
        )
        .expect("load");
        assert_eq!(
            dl.decide("sub.evil.example"),
            Decision::Block,
            "domain list: an explicit marker beats an Exact source policy"
        );

        // (d) domain list, Suffix policy — an UNMARKED token follows it
        let mut dl2 = FilterEngine::new();
        dl2.load_domain_list(
            ListKind::Block,
            io::BufReader::new("evil.example
".as_bytes()),
            DomainListPolicy::Suffix,
        )
        .expect("load");
        assert_eq!(
            dl2.decide("sub.evil.example"),
            Decision::Block,
            "domain list: an unmarked token follows the source policy"
        );
    }

    /// A `BufRead` that records how many bytes were actually taken from the
    /// SOURCE, so a memory-budget claim can be measured rather than
    /// asserted.
    struct Counting<R> {
        inner: R,
        consumed: std::sync::Arc<AtomicU64>,
    }

    impl<R: Read> Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.consumed.fetch_add(n as u64, Ordering::SeqCst);
            Ok(n)
        }
    }

    impl<R: BufRead> BufRead for Counting<R> {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            self.inner.fill_buf()
        }
        fn consume(&mut self, amt: usize) {
            self.consumed.fetch_add(amt as u64, Ordering::SeqCst);
            self.inner.consume(amt);
        }
    }

    /// REGRESSION (round-3 closure review, finding 4). `MAX_HOSTS_BYTES`
    /// bounded what was ACCOUNTED, never what was ALLOCATED:
    /// `reader.lines()` materializes a whole line into a `String` before
    /// control returns to the budget check, so a newline-free body — a
    /// broken CDN response, an HTML error page, a gzip served as
    /// text/plain — was pulled in full under any budget, and then reported
    /// `bytes_read: 0`, failing the honest-reporting promise in the same
    /// breath.
    ///
    /// Revert-checked: without the `take`, `consumed` is the whole 8 MiB.
    #[test]
    fn byte_budget_bounds_what_is_allocated_not_just_what_is_counted() {
        const BUDGET: u64 = 1024;
        // One line, no newline anywhere — the pathological shape.
        let hostile = vec![b'a'; 8 * 1024 * 1024];
        let consumed = std::sync::Arc::new(AtomicU64::new(0));
        let reader = Counting {
            inner: io::Cursor::new(hostile),
            consumed: std::sync::Arc::clone(&consumed),
        };

        let mut engine = FilterEngine::new();
        let stats = engine
            .load_hosts_with_limit(ListKind::Block, reader, u64::MAX, BUDGET, u64::MAX)
            .expect("load must not error");

        let pulled = consumed.load(Ordering::SeqCst);
        assert!(
            pulled <= BUDGET + 1,
            "pulled {pulled} bytes from the source under a {BUDGET}-byte budget"
        );
        assert!(
            stats.truncated,
            "hitting the budget must be reported, not silent: {stats:?}"
        );
        assert_eq!(stats.rules_added, 0, "no rule can come from a cut fragment");
    }

    fn engine_with_block(rules: &[&str]) -> FilterEngine {
        let mut engine = FilterEngine::new();
        for rule in rules {
            assert!(engine.add_block(rule), "test rule must normalize: {rule}");
        }
        engine
    }

    fn load(engine: &mut FilterEngine, kind: ListKind, input: &str) -> HostsLoadStats {
        engine
            .load_hosts(kind, io::BufReader::new(input.as_bytes()))
            .expect("in-memory load cannot fail")
    }

    #[test]
    fn empty_engine_allows_all() {
        let engine = FilterEngine::new();
        assert_eq!(engine.decide("example.com"), Decision::Allow);
        assert_eq!(engine.decide("anything.at.all.example.org"), Decision::Allow);
    }

    #[test]
    fn canary_is_blocked_with_empty_blocklist() {
        let engine = FilterEngine::new();
        assert_eq!(engine.decide(CANARY_DOMAIN), Decision::Block);
        // The canary is an EXACT rule (design doc §4/§7): its subdomains
        // are not covered — and cannot be covered accidentally, which is
        // the point (see canary_survives_bare_label_allowlist).
        assert_eq!(engine.decide("sub.webguard-test.sentinella.invalid"), Decision::Allow);
    }

    #[test]
    fn canary_survives_bare_label_allowlist() {
        let mut engine = FilterEngine::new();
        // Exact allowlist entries on parent/bare labels cannot reach the
        // canary — this is what keeps a `0.0.0.0 invalid`-style line in an
        // allowlist from silently disabling the acceptance-test domain.
        assert!(engine.add_allow_exact("invalid"));
        assert!(engine.add_allow_exact("sentinella.invalid"));
        assert_eq!(engine.decide(CANARY_DOMAIN), Decision::Block);
        // Documented escape hatch: an exact allow of the canary itself DOES
        // override (allowlist always wins for the exact host).
        assert!(engine.add_allow_exact(CANARY_DOMAIN));
        assert_eq!(engine.decide(CANARY_DOMAIN), Decision::Allow);
    }

    #[test]
    fn hosts_entries_are_exact_rules_not_suffix() {
        // Regression: routing every hosts token to suffix rules made
        // `127.0.0.1 local` blackhole the whole `.local` namespace (AD,
        // GPO, mDNS) and `0.0.0.0 com` would blackhole `.com`.
        let mut engine = FilterEngine::new();
        let stats = load(&mut engine, ListKind::Block, "0.0.0.0 local\n127.0.0.1 com\n");
        assert_eq!(stats.rules_added, 2);
        assert_eq!(engine.decide("local"), Decision::Block, "the host itself is blocked");
        assert_eq!(engine.decide("com"), Decision::Block, "the host itself is blocked");
        assert_eq!(engine.decide("foo.local"), Decision::Allow, "subtree untouched");
        assert_eq!(engine.decide("corp.example.local"), Decision::Allow);
        assert_eq!(engine.decide("anything.com"), Decision::Allow, ".com survives");
    }

    #[test]
    fn leading_dot_marker_creates_suffix_rule() {
        let mut engine = FilterEngine::new();
        let stats = load(
            &mut engine,
            ListKind::Block,
            "0.0.0.0 .evil.example\n0.0.0.0 exact-only.example\n",
        );
        assert_eq!(stats.rules_added, 2);
        assert_eq!(engine.decide("evil.example"), Decision::Block);
        assert_eq!(engine.decide("a.b.evil.example"), Decision::Block);
        assert_eq!(engine.decide("notevil.example"), Decision::Allow);
        assert_eq!(engine.decide("exact-only.example"), Decision::Block);
        assert_eq!(engine.decide("sub.exact-only.example"), Decision::Allow);
    }

    #[test]
    fn escaped_dot_in_label_never_matches_two_label_rule() {
        // The wire decoder presents the single label "microsoft.com" as
        // `microsoft\.com`. Suffix cuts happen at UNescaped dots only, so
        // it must match neither the two-label rule `microsoft.com` nor the
        // suffix rule `com`-under-`soft.com` style parents.
        let mut engine = FilterEngine::new();
        assert!(engine.add_block("microsoft.com"));
        assert!(engine.add_block("soft.com"));
        assert_eq!(engine.decide("microsoft.com"), Decision::Block);
        assert_eq!(engine.decide("www.microsoft.com"), Decision::Block);
        assert_eq!(engine.decide("microsoft\\.com"), Decision::Allow, "hostile single label");
        assert_eq!(engine.decide("micro\\.soft.com"), Decision::Allow, "escaped dot is no boundary");
        // Escaped form still normalizes (it is a valid presentation name).
        assert!(FilterEngine::normalize_name("microsoft\\.com").is_some());
        // Dangling escape is malformed → unnormalizable → fail-open Allow.
        assert_eq!(FilterEngine::normalize_name("dangling\\"), None);
    }

    #[test]
    fn allowlist_beats_blocklist_same_host() {
        let mut engine = engine_with_block(&["evil.example"]);
        assert_eq!(engine.decide("evil.example"), Decision::Block);
        engine.add_allow("evil.example");
        assert_eq!(engine.decide("evil.example"), Decision::Allow);
    }

    #[test]
    fn allowlist_exact_beats_blocklist_suffix_parent() {
        let mut engine = engine_with_block(&["example.com"]);
        engine.add_allow_exact("good.example.com");
        assert_eq!(engine.decide("good.example.com"), Decision::Allow);
        assert_eq!(engine.decide("bad.example.com"), Decision::Block);
    }

    #[test]
    fn suffix_rule_matches_host_and_subdomains_but_not_superstrings() {
        let engine = engine_with_block(&["evil.example"]);
        assert_eq!(engine.decide("evil.example"), Decision::Block);
        assert_eq!(engine.decide("a.b.evil.example"), Decision::Block);
        // The critical case: superstring shares no label boundary.
        assert_eq!(engine.decide("notevil.example"), Decision::Allow);
        assert_eq!(engine.decide("evil.example.evil.com"), Decision::Allow);
        assert_eq!(engine.decide("evilexample.com"), Decision::Allow);
    }

    #[test]
    fn exact_rule_matches_only_the_host() {
        let mut engine = FilterEngine::new();
        assert!(engine.add_block_exact("exact.example"));
        assert_eq!(engine.decide("exact.example"), Decision::Block);
        assert_eq!(engine.decide("sub.exact.example"), Decision::Allow);
    }

    #[test]
    fn matching_is_ascii_case_insensitive() {
        let mut engine = FilterEngine::new();
        assert!(engine.add_block("Evil.Example"));
        assert_eq!(engine.decide("EVIL.EXAMPLE"), Decision::Block);
        assert_eq!(engine.decide("eViL.eXaMpLe"), Decision::Block);
    }

    #[test]
    fn trailing_dot_is_stripped() {
        let engine = engine_with_block(&["evil.example"]);
        assert_eq!(engine.decide("evil.example."), Decision::Block);
        assert_eq!(engine.decide("a.evil.example."), Decision::Block);
    }

    #[test]
    fn normalization_rejects_empty_and_wire_illegal_names() {
        assert_eq!(FilterEngine::normalize_name(""), None);
        assert_eq!(FilterEngine::normalize_name("."), None);
        assert_eq!(FilterEngine::normalize_name("a..b"), None);
        // Validation is in WIRE units (labels ≤ 63, total ≤ 255), not
        // against the presentation length: a 253-char single label is
        // wire-ILLEGAL (label > 63) even though it fits 253 presentation
        // chars — the pre-fix code accepted it.
        let overlong_label = "a".repeat(MAX_PLAIN_PRESENTATION_LEN);
        assert_eq!(FilterEngine::normalize_name(&overlong_label), None);
        // Wire-legal at the limit: 63/63/63/61 octet labels = 255 wire
        // bytes exactly (252 presentation chars).
        let at_limit = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert!(FilterEngine::normalize_name(&at_limit).is_some());
        // One octet over: 4×63 labels = 257 wire bytes.
        let overlong_name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        );
        assert_eq!(FilterEngine::normalize_name(&overlong_name), None);
        let engine = FilterEngine::new();
        assert_eq!(engine.decide(&overlong_name), Decision::Allow);
    }

    #[test]
    fn wire_legal_escaped_name_past_253_presentation_chars_still_decides() {
        // Regression (Block→Allow fail-open): a label of 61 × 0x00 octets
        // is WIRE-LEGAL (≤ 63) but escapes to 244 presentation chars
        // (`\000` × 61); with a suffix the escaped string passes 253
        // chars, and measuring THAT string against 253 made normalize
        // return None → decide → Allow, defeating the suffix block.
        let escaped_label = "\\000".repeat(61);
        let name = format!("{escaped_label}.c2.example");
        assert!(name.len() > MAX_PLAIN_PRESENTATION_LEN, "escaped form exceeds 253 chars");
        // Every NON-ROOT wire-legal name normalizes — never None.
        let normalized = FilterEngine::normalize_name(&name)
            .expect("wire-legal name must normalize");
        assert_eq!(normalized, name);
        // …and the suffix rule decides it: Block, not fail-open Allow.
        let engine = engine_with_block(&["c2.example"]);
        assert_eq!(engine.decide(&name), Decision::Block);
    }

    #[test]
    fn hosts_parser_full_line_and_inline_comments() {
        let mut engine = FilterEngine::new();
        let stats = load(
            &mut engine,
            ListKind::Block,
            "# full-line comment\n0.0.0.0 bad.example # inline comment\n#0.0.0.0 not-a-rule.example\n",
        );
        assert_eq!(stats.rules_added, 1);
        assert_eq!(stats.lines_skipped, 2);
        assert_eq!(engine.decide("bad.example"), Decision::Block);
        assert_eq!(engine.decide("not-a-rule.example"), Decision::Allow);
    }

    #[test]
    fn hosts_parser_all_ip_forms_whitespace_crlf_and_blanks() {
        let mut engine = FilterEngine::new();
        let input = "0.0.0.0 zero.example\r\n127.0.0.1 loop.example\n:: v6.example\n   0.0.0.0\t\tspaced.example   \r\n\n\r\n";
        let stats = load(&mut engine, ListKind::Block, input);
        assert_eq!(stats.rules_added, 4);
        for name in ["zero.example", "loop.example", "v6.example", "spaced.example"] {
            assert_eq!(engine.decide(name), Decision::Block, "{name}");
        }
    }

    #[test]
    fn hosts_parser_multi_host_lines_add_each() {
        let mut engine = FilterEngine::new();
        let stats = load(&mut engine, ListKind::Block, "0.0.0.0 a.example b.example c.example\n");
        assert_eq!(stats.rules_added, 3);
        assert_eq!(engine.decide("b.example"), Decision::Block);
    }

    #[test]
    fn hosts_parser_skips_lines_without_ip_and_bad_hosts() {
        let mut engine = FilterEngine::new();
        let stats = load(
            &mut engine,
            ListKind::Allow,
            "just-a-domain.example\nnot.an.ip host.example\n0.0.0.0 a..broken\n",
        );
        assert_eq!(stats.rules_added, 0);
        assert_eq!(stats.lines_skipped, 3);
    }

    #[test]
    fn hosts_loader_respects_line_cap() {
        let mut engine = FilterEngine::new();
        let input = "0.0.0.0 a.example\n0.0.0.0 b.example\n0.0.0.0 c.example\n";
        let stats = engine
            .load_hosts_with_limit(ListKind::Block, io::BufReader::new(input.as_bytes()), 2, u64::MAX, u64::MAX)
            .expect("load");
        assert!(stats.truncated);
        assert_eq!(stats.lines_read, 2);
        assert_eq!(stats.rules_added, 2);
        assert_eq!(engine.decide("c.example"), Decision::Allow);
    }

    #[test]
    fn million_line_load_is_linear_time() {
        // 10⁶ lines must load in seconds, i.e. the loader must not be
        // quadratic. Generous ceiling: catches accidental O(n²) by orders of
        // magnitude without being flaky on slow CI.
        let mut input = String::with_capacity(24 * 1_000_000);
        for i in 0..1_000_000u32 {
            input.push_str(&format!("0.0.0.0 d{i}.example\n"));
        }
        let mut engine = FilterEngine::new();
        let start = std::time::Instant::now();
        let stats = load(&mut engine, ListKind::Block, &input);
        let elapsed = start.elapsed();
        assert_eq!(stats.rules_added, 1_000_000);
        assert!(!stats.truncated);
        assert!(
            elapsed < std::time::Duration::from_secs(60),
            "1M-line load took {elapsed:?} — likely quadratic"
        );
        assert_eq!(engine.decide("d999999.example"), Decision::Block);
    }

    // ---------------------------------------------------------------
    // Round 3, Grupo 3: L13 (byte budget), L14 (domain-list loader),
    // L15 (root-name counter), L16 (config rule API), L18a (rejected
    // host accounting).
    // ---------------------------------------------------------------

    #[test]
    fn hosts_loader_respects_byte_budget() {
        // L13: a line cap alone does not bound memory — escaping inflates
        // one stored wire octet to up to 4 presentation chars, so 2M
        // maximal lines were gigabytes loading with truncated:false.
        // Revert-check: remove the byte-budget comparison in
        // `ingest_lines` and this loads all three lines, failing
        // `assert!(stats.truncated)`.
        // Wire-LEGAL but long: 63/63/63/50-octet labels (244 wire bytes,
        // 242 presentation chars) — the byte budget, not normalization,
        // must be what stops the load.
        let long_name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(50)
        );
        let input = format!(
            "0.0.0.0 first.example\n0.0.0.0 {long_name}\n0.0.0.0 third.example\n"
        );
        let input_bytes = input.len() as u64;
        let mut engine = FilterEngine::new();
        // Budget fits the first two lines but not the third.
        let stats = engine
            .load_hosts_with_limit(
                ListKind::Block,
                io::BufReader::new(input.as_bytes()),
                u64::MAX,
                input_bytes - 20,
                u64::MAX,
            )
            .expect("load");
        assert!(stats.truncated, "byte budget cut the input short");
        assert_eq!(stats.rules_added, 2);
        assert!(stats.bytes_read <= input_bytes - 20, "budget honoured: {stats:?}");
        assert!(stats.bytes_read > 0, "bytes ingested are reported");
        assert_eq!(engine.decide("first.example"), Decision::Block);
        assert_eq!(engine.decide("third.example"), Decision::Allow, "never ingested");
    }

    #[test]
    fn byte_budget_binds_what_line_cap_alone_cannot() {
        // The measured L13 shape: maximal escaped names (~4 presentation
        // chars per wire octet). With only the line cap these all load;
        // a byte budget stops them. Uses the default MAX_HOSTS_BYTES as
        // an upper sanity bound on what "predictable memory" means.
        let escaped = "\\000".repeat(61); // 61 wire octets, 244 chars
        let line = format!("0.0.0.0 {escaped}.c2.example\n");
        let mut input = String::new();
        for _ in 0..20_000 {
            input.push_str(&line);
        }
        let mut engine = FilterEngine::new();
        let stats = engine
            .load_hosts_with_limit(
                ListKind::Block,
                io::BufReader::new(input.as_bytes()),
                u64::MAX, // line cap out of the way: bytes are the binder
                1024 * 1024,
                u64::MAX,
            )
            .expect("load");
        assert!(stats.truncated);
        assert!(stats.bytes_read <= 1024 * 1024);
        assert!(stats.rules_added < 20_000, "cut short by bytes, not lines");
    }

    #[test]
    fn domain_list_suffix_policy_covers_c2_wildcards() {
        // L14: the URLhaus domain list is one domain per line with no
        // leading-dot marker, so through the hosts loader it produced
        // rules_added:0 — and even parsed as exact rules it could never
        // cover subdomain-wildcarding C2, the normal shape. The suffix
        // policy (a property of the SOURCE) closes that.
        let urlhaus_like = "# URLhaus-style domain list\n\
                            evil-c2.example\n\
                            malware-drop.example # active since 2024\n\
                            \n\
                            a..broken\n";
        let mut engine = FilterEngine::new();
        let stats = engine
            .load_domain_list(
                ListKind::Block,
                io::BufReader::new(urlhaus_like.as_bytes()),
                DomainListPolicy::Suffix,
            )
            .expect("load");
        assert_eq!(stats.rules_added, 2);
        assert_eq!(stats.hosts_rejected, 1, "the malformed line is reported");
        assert_eq!(engine.decide("evil-c2.example"), Decision::Block);
        assert_eq!(
            engine.decide("anything.evil-c2.example"),
            Decision::Block,
            "wildcarded C2 subdomains are covered"
        );
        assert_eq!(engine.decide("notevil-c2.example"), Decision::Allow);
        // Same data through the hosts loader adds nothing — the old
        // measured behaviour, kept as a guard against format drift.
        let mut hosts_engine = FilterEngine::new();
        let hosts_stats = load(&mut hosts_engine, ListKind::Block, urlhaus_like);
        assert_eq!(hosts_stats.rules_added, 0);
    }

    #[test]
    fn domain_list_exact_policy_is_the_fp_safe_default() {
        // Suffix-by-source is correct for C2 feeds but FP-prone for
        // generic lists: Exact must leave subtrees alone.
        let mut engine = FilterEngine::new();
        let stats = engine
            .load_domain_list(
                ListKind::Block,
                io::BufReader::new(b"evil.example\n".as_slice()),
                DomainListPolicy::Exact,
            )
            .expect("load");
        assert_eq!(stats.rules_added, 1);
        assert_eq!(engine.decide("evil.example"), Decision::Block);
        assert_eq!(engine.decide("sub.evil.example"), Decision::Allow, "exact policy");
        // The explicit leading-dot marker overrides the policy default.
        let mut marked = FilterEngine::new();
        marked
            .load_domain_list(
                ListKind::Block,
                io::BufReader::new(b".evil.example\n".as_slice()),
                DomainListPolicy::Exact,
            )
            .expect("load");
        assert_eq!(marked.decide("sub.evil.example"), Decision::Block, "marker wins");
        // Interior whitespace is not a domain — never silently stored.
        let mut spaced = FilterEngine::new();
        let spaced_stats = spaced
            .load_domain_list(
                ListKind::Block,
                io::BufReader::new(b"evil.example extra-token\n".as_slice()),
                DomainListPolicy::Exact,
            )
            .expect("load");
        assert_eq!(spaced_stats.rules_added, 0);
        assert_eq!(spaced_stats.hosts_rejected, 1);
    }

    #[test]
    fn config_rule_api_understands_the_leading_dot_marker() {
        // L16: before this API the marker was understood only inside the
        // private hosts parser; the public adders rejected `.evil.example`
        // (empty label), so an allowlist read from TOML vanished silently.
        let mut engine = FilterEngine::new();
        assert!(engine.add_allow_rule(".evil.example"), "suffix marker accepted");
        assert!(engine.add_allow_rule("plain.example"), "bare name = exact rule");
        assert_eq!(engine.decide("deep.evil.example"), Decision::Allow, "suffix allow");
        engine.add_block("other.example");
        assert_eq!(engine.decide("other.example"), Decision::Block);
        assert!(engine.add_block_rule(".c2.example"));
        assert_eq!(engine.decide("x.c2.example"), Decision::Block, "suffix block");
        assert_eq!(engine.decide("c2.example"), Decision::Block);
        // Garbage returns false — tratable como config error ruidoso.
        assert!(!engine.add_allow_rule("a..broken"));
        assert!(!engine.add_block_rule("."));
    }

    #[test]
    fn root_name_fails_open_but_counted() {
        // L15: the root name is wire-legal (root NS priming), arrives as
        // "", does not normalize, and decide fails OPEN — now counted, so
        // a Block→Allow regression in this class is visible, not silent.
        // Revert-check: delete the fetch_add in `decide` and the counter
        // stays 0, failing the assertion.
        let engine = FilterEngine::new();
        assert_eq!(engine.decide(""), Decision::Allow, "root name fails open");
        assert_eq!(engine.decide("."), Decision::Allow, "rooted root fails open");
        assert_eq!(
            engine.unnormalizable_query_count(),
            2,
            "the fail-open branch is counted, not silent"
        );
        // Normal traffic does not move the counter.
        assert_eq!(engine.decide("example.com"), Decision::Allow);
        assert_eq!(engine.unnormalizable_query_count(), 2);
    }

    #[test]
    fn malformed_hosts_on_a_multi_host_line_are_counted() {
        // L18a: the measured line — one of three hosts dropped while the
        // line reported full success (rules_added:2, lines_skipped:0).
        // hosts_rejected makes the partial failure visible.
        // Revert-check: stop accumulating `rejected` in parse_hosts_line
        // and hosts_rejected stays 0, failing the assertion.
        let mut engine = FilterEngine::new();
        let stats = load(
            &mut engine,
            ListKind::Block,
            "0.0.0.0 good.example a..bad .suffix.example\n",
        );
        assert_eq!(stats.rules_added, 2);
        assert_eq!(stats.lines_skipped, 0, "the line produced rules");
        assert_eq!(stats.hosts_rejected, 1, "the dropped host is reported");
        assert_eq!(engine.decide("good.example"), Decision::Block);
        assert_eq!(engine.decide("x.suffix.example"), Decision::Block);
    }
}

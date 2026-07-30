//! Domain filter engine: allowlist/blocklist with exact-host and suffix
//! matching, plus a hosts-file-format loader.
//!
//! Semantics (design doc §4):
//! - precedence: allowlist beats blocklist, always (an operator must be able
//!   to un-break a false positive without editing third-party lists);
//! - a suffix rule `evil.example` matches `evil.example` itself and any
//!   subdomain (`a.b.evil.example`) but never a superstring
//!   (`notevil.example`);
//! - an exact rule matches only the host itself.

use std::collections::HashSet;
use std::io::{self, BufRead};
use std::net::IpAddr;

/// Always-blocked sentinel domain (design doc §7): lets operator acceptance
/// tests verify the pipeline end to end without depending on a live
/// blocklist. `.invalid` is reserved by RFC 2606, so it can never collide
/// with a real name.
pub const CANARY_DOMAIN: &str = "webguard-test.sentinella.invalid";

/// Maximum DNS name length per RFC 1035 (presentation form, without the
/// trailing dot).
pub const MAX_NAME_LEN: usize = 253;

/// Hard cap on hosts-file lines ingested in one load. WHY: blocklists are
/// attacker-influenceable downloads; a bounded load keeps memory and load
/// time predictable regardless of what a source serves.
pub const MAX_HOSTS_LINES: u64 = 2_000_000;

/// Which list a rule belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    Allow,
    Block,
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
}

impl FilterEngine {
    /// New engine containing only the always-blocked canary domain.
    pub fn new() -> Self {
        let mut engine = Self::default();
        engine.block_suffix.insert(CANARY_DOMAIN.to_string());
        engine
    }

    /// Normalize a presentation-form domain name for matching: strip
    /// trailing dots, lowercase ASCII, reject empty names, empty labels,
    /// non-ASCII input, and names over 253 bytes.
    ///
    /// Returns `None` for anything that cannot be a valid DNS name; callers
    /// treat that as "no rule can match" (fail-open to the upstream), never
    /// as a block decision based on garbage.
    pub fn normalize_name(name: &str) -> Option<String> {
        let trimmed = name.trim_end_matches('.');
        if trimmed.is_empty() || trimmed.len() > MAX_NAME_LEN {
            return None;
        }
        if !trimmed.is_ascii() {
            return None;
        }
        if trimmed.split('.').any(|label| label.is_empty()) {
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
    /// rejecting malformed packets.
    pub fn decide(&self, qname: &str) -> Decision {
        let Some(name) = Self::normalize_name(qname) else {
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

    /// Load a hosts-format file into the given list with the default line
    /// cap ([`MAX_HOSTS_LINES`]). Accepted line shape:
    /// `<ip> <host> [<host>...] [# comment]` where `<ip>` is any literal
    /// that parses as an IP (`0.0.0.0`, `127.0.0.1`, `::`, ...). Blank
    /// lines, full-line `#` comments, and lines without a valid leading IP
    /// are skipped. Multiple hostnames on one line each become a rule.
    ///
    /// Runs in O(lines): one pass, hash inserts only — no per-line rescans,
    /// so a 10⁶-line list loads in seconds.
    pub fn load_hosts<R: BufRead>(&mut self, kind: ListKind, reader: R) -> io::Result<HostsLoadStats> {
        self.load_hosts_with_limit(kind, reader, MAX_HOSTS_LINES)
    }

    /// Like [`load_hosts`](Self::load_hosts) with an explicit line cap
    /// (exposed so tests can exercise truncation without a 2M-line fixture).
    pub fn load_hosts_with_limit<R: BufRead>(
        &mut self,
        kind: ListKind,
        reader: R,
        max_lines: u64,
    ) -> io::Result<HostsLoadStats> {
        let mut stats = HostsLoadStats::default();
        for line in reader.lines() {
            let line = line?;
            if stats.lines_read >= max_lines {
                // WHY: stop ingesting but report honestly — silently
                // truncating a blocklist would hide protection gaps.
                stats.truncated = true;
                break;
            }
            stats.lines_read += 1;
            let added = self.parse_hosts_line(kind, &line);
            if added == 0 {
                stats.lines_skipped += 1;
            } else {
                stats.rules_added += added;
            }
        }
        if stats.truncated {
            tracing::warn!(
                max_lines,
                rules_added = stats.rules_added,
                "hosts file exceeded line cap; remaining lines ignored"
            );
        }
        Ok(stats)
    }

    /// Parse one hosts line; returns the number of rules added.
    fn parse_hosts_line(&mut self, kind: ListKind, line: &str) -> u64 {
        // Strip inline comments first: everything from '#' onward is dead.
        let body = match line.find('#') {
            Some(i) => &line[..i],
            None => line,
        };
        let mut tokens = body.split_whitespace();
        let Some(ip) = tokens.next() else {
            return 0;
        };
        // The first token must be an IP literal; this rejects plain
        // domain-list lines and garbage alike.
        if ip.parse::<IpAddr>().is_err() {
            return 0;
        }
        let mut added = 0u64;
        for host in tokens {
            let ok = match kind {
                ListKind::Allow => self.add_allow(host),
                ListKind::Block => self.add_block(host),
            };
            if ok {
                added += 1;
            }
        }
        added
    }
}

/// Does `name` or any of its parent suffixes (cut at label boundaries)
/// appear in `set`? This is what keeps `evil.example` from matching
/// `notevil.example`: cuts only happen after a dot.
fn suffix_match(set: &HashSet<String>, name: &str) -> bool {
    if set.contains(name) {
        return true;
    }
    for (i, byte) in name.bytes().enumerate() {
        if byte == b'.' && set.contains(&name[i + 1..]) {
            return true;
        }
    }
    false
}

/// Load statistics for one hosts-file ingest.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HostsLoadStats {
    pub lines_read: u64,
    pub rules_added: u64,
    pub lines_skipped: u64,
    /// True when the input exceeded the line cap and was cut short.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(engine.decide("sub.webguard-test.sentinella.invalid"), Decision::Block);
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
    fn normalization_rejects_empty_and_overlong_names() {
        assert_eq!(FilterEngine::normalize_name(""), None);
        assert_eq!(FilterEngine::normalize_name("."), None);
        assert_eq!(FilterEngine::normalize_name("a..b"), None);
        let overlong = format!("{}.example", "a".repeat(MAX_NAME_LEN));
        assert_eq!(FilterEngine::normalize_name(&overlong), None);
        let at_limit = "a".repeat(MAX_NAME_LEN);
        assert!(FilterEngine::normalize_name(&at_limit).is_some());
        let engine = FilterEngine::new();
        assert_eq!(engine.decide(&overlong), Decision::Allow);
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
            .load_hosts_with_limit(ListKind::Block, io::BufReader::new(input.as_bytes()), 2)
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
}

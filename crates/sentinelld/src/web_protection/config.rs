//! `[web_protection]` configuration.
//!
//! POLARITY WARNING, read before changing anything here. Every other
//! config section in this crate has the property that turning a field OFF
//! is the harm — an attacker disabling realtime protection, say. This
//! section is the opposite: **turning it ON when the proxy cannot serve is
//! the harm, and turning it OFF is the emergency fix.** A DNS proxy the
//! machine has been pointed at, which is not answering, is a machine with
//! no name resolution at all. Design principle, from the review that
//! produced this module: *under any uncertainty the system must degrade to
//! "no filtering", never to "no DNS".*
//!
//! That is why `validate` here does NOT follow the crate's usual
//! clamp-and-warn convention. Resetting a malformed `listen` to a
//! plausible default (the pattern used by `update_mirror`,
//! `clamav_isolation`, `sandbox.mode` and friends) would leave the section
//! looking configured and let a later commit install an NRPT rule on the
//! strength of it. Invalid input FORCES `enabled = false`, following the
//! one existing precedent that does the same — developer mode without a
//! provisioned password.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tracing::warn;

/// What the proxy answers for a blocked name.
///
/// Mirrors `dnsguard::proxy::BlockResponse`; kept as a string in TOML so
/// the config surface does not depend on the crate's enum layout.
pub const BLOCK_RESPONSE_NXDOMAIN: &str = "nxdomain";
pub const BLOCK_RESPONSE_ZERO_IP: &str = "zero_ip";

/// What happens when the proxy stops answering while a rule is live.
/// Consumed by the reconciler work (commit C), declared here so the config
/// surface is complete and a user's setting is never silently dropped.
pub const ON_FAILURE_REMOVE_RULE: &str = "remove_rule";
pub const ON_FAILURE_FALLBACK: &str = "fallback";

/// Upstream source: `"system"` means discover from the active adapters.
pub const UPSTREAM_SYSTEM: &str = "system";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebProtectionConfig {
    /// USER INTENT — not a statement about the world.
    ///
    /// This is deliberately NOT the same thing as "an NRPT rule is
    /// installed". The two are tracked separately because they come apart
    /// constantly and in normal operation: while the daemon is starting,
    /// after a failed self-test, after a crash, during an upgrade, during
    /// an MSI rollback. Deriving either from the other is how a machine
    /// ends up believing it is protected while its DNS is broken, or the
    /// reverse. The runtime fact lives in
    /// [`super::status::WebProtectionStatus::nrpt_installed`] and is read
    /// from the system, never from this field.
    pub enabled: bool,

    /// Address the proxy listens on. Production MUST be `127.0.0.1:53`:
    /// NRPT `NameServers` carries no port syntax, so the Windows DNS
    /// Client always queries 53. A non-53 port is accepted here only
    /// because the integration tests need an ephemeral one, and it is
    /// refused in combination with `enabled` — see [`Self::validate`].
    pub listen: String,

    /// `"system"` to discover from active adapters, or explicit
    /// `IP:port` entries. An empty list with `listen`-relative discovery
    /// failing is a hard disable: a resolver with no upstream is a lie.
    pub upstreams: Vec<String>,

    /// `"nxdomain"` (default) or `"zero_ip"`.
    pub block_response: String,

    /// `"remove_rule"` (fail closed: filtering off, DNS restored) or
    /// `"fallback"` (fail open: unfiltered DNS via the NRPT secondary).
    /// Default is `remove_rule`, matching the degrade-to-no-filtering
    /// principle above.
    pub on_proxy_failure: String,

    /// Name the self-test resolves to prove the serving path works.
    /// MUST be a name you never intend to block: the self-test requires
    /// the engine to decide it `Allow`, because a `zero_ip` block answer
    /// is NOERROR-with-an-A-record and is otherwise indistinguishable
    /// from a real resolution.
    pub health_check_name: String,

    /// Extra blocklist files to load at startup, beyond the built-in
    /// canary. Each entry is `path` or `path|suffix` — the per-source
    /// exact/suffix policy is a property of the SOURCE, never of the data
    /// (design §4), and `suffix` is correct only for dedicated
    /// malware-domain feeds.
    pub blocklists: Vec<String>,

    /// Allowlist entries in config syntax: a bare name is an exact-host
    /// rule, a leading dot (`.example.com`) is a suffix rule.
    pub allowlist: Vec<String>,

    /// Record per-query decisions for the authenticated IPC surface.
    /// Off by default — this is browsing history.
    pub log_queries: bool,
}

impl Default for WebProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:53".into(),
            upstreams: vec![UPSTREAM_SYSTEM.into()],
            block_response: BLOCK_RESPONSE_NXDOMAIN.into(),
            on_proxy_failure: ON_FAILURE_REMOVE_RULE.into(),
            health_check_name: "example.com".into(),
            blocklists: Vec::new(),
            allowlist: Vec::new(),
            log_queries: false,
        }
    }
}

impl WebProtectionConfig {
    /// Validate, forcing `enabled = false` on anything malformed.
    ///
    /// Every branch that disables says WHY at `warn!` level, because the
    /// user's visible symptom is "I turned it on and nothing happened" and
    /// the log is the only place that distinguishes the causes.
    pub fn validate(&mut self) {
        // Non-enabling fields are clamped as usual; only the ones that
        // could produce a live-but-wrong proxy force a disable.
        if !matches!(
            self.block_response.as_str(),
            BLOCK_RESPONSE_NXDOMAIN | BLOCK_RESPONSE_ZERO_IP
        ) {
            warn!(
                value = %self.block_response,
                "web_protection.block_response invalid — using nxdomain"
            );
            self.block_response = BLOCK_RESPONSE_NXDOMAIN.into();
        }
        if !matches!(
            self.on_proxy_failure.as_str(),
            ON_FAILURE_REMOVE_RULE | ON_FAILURE_FALLBACK
        ) {
            warn!(
                value = %self.on_proxy_failure,
                "web_protection.on_proxy_failure invalid — using remove_rule"
            );
            self.on_proxy_failure = ON_FAILURE_REMOVE_RULE.into();
        }

        if !self.enabled {
            return;
        }

        // From here down, every failure DISABLES rather than substitutes.
        if let Err(reason) = self.check_enablable() {
            warn!(%reason, "web_protection.enabled=true but the config cannot serve — disabling");
            self.enabled = false;
        }
    }

    /// The conditions under which `enabled = true` can be honoured.
    /// Split out so it is testable without going through `warn!`.
    fn check_enablable(&self) -> Result<(), String> {
        let addr: SocketAddr = self
            .listen
            .parse()
            .map_err(|_| format!("listen {:?} is not a valid IP:port", self.listen))?;
        if !addr.ip().is_loopback() {
            // A non-loopback listener turns the AV into an open resolver
            // for the whole network.
            return Err(format!("listen {addr} is not a loopback address"));
        }
        // Port 0 means "pick one", which cannot be reached through NRPT
        // (no port syntax) and would let a later commit install a rule
        // pointing at 53 while we listen somewhere else entirely.
        if addr.port() == 0 {
            return Err("listen port 0 cannot be reached through NRPT".into());
        }

        if self.upstreams.is_empty() {
            return Err("upstreams is empty — a resolver with no upstream is a lie".into());
        }
        for u in &self.upstreams {
            if u == UPSTREAM_SYSTEM {
                continue;
            }
            let up: SocketAddr = u
                .parse()
                .map_err(|_| format!("upstream {u:?} is not a valid IP:port"))?;
            // Self-reference is an infinite loop that saturates the
            // in-flight pool on the first query. dnsguard refuses it at
            // bind too; catching it here gives a better message and keeps
            // the daemon from starting a proxy it knows is broken.
            if up == addr {
                return Err(format!("upstream {up} is the listen address"));
            }
        }

        if self.health_check_name.trim().is_empty() {
            return Err("health_check_name is empty".into());
        }
        if self.health_check_name.contains('\\') {
            // dnsguard's query builder is escape-unaware, so a backslash
            // would silently probe a different name than configured.
            return Err(format!(
                "health_check_name {:?} contains a backslash escape",
                self.health_check_name
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> WebProtectionConfig {
        WebProtectionConfig {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn default_is_off_and_survives_validation() {
        let mut c = WebProtectionConfig::default();
        c.validate();
        assert!(!c.enabled);
        assert_eq!(c.listen, "127.0.0.1:53");
        assert_eq!(c.upstreams, vec![UPSTREAM_SYSTEM.to_string()]);
    }

    #[test]
    fn a_valid_enabled_config_stays_enabled() {
        let mut c = enabled();
        c.validate();
        assert!(c.enabled, "a valid config must not be disabled");
    }

    /// The whole point of this module: malformed input must DISABLE, not
    /// be substituted into something that looks configured. The crate's
    /// usual convention would turn each of these into a working-looking
    /// proxy that a later commit would install an NRPT rule for.
    #[test]
    fn malformed_input_disables_rather_than_substituting() {
        let cases: &[(&str, fn(&mut WebProtectionConfig))] = &[
            ("garbage listen", |c| c.listen = "not-an-address".into()),
            ("non-loopback listen", |c| c.listen = "0.0.0.0:53".into()),
            ("port 0", |c| c.listen = "127.0.0.1:0".into()),
            ("empty upstreams", |c| c.upstreams.clear()),
            ("garbage upstream", |c| c.upstreams = vec!["1.1.1.1".into()]),
            ("self-referential upstream", |c| {
                c.upstreams = vec!["127.0.0.1:53".into()]
            }),
            ("empty health name", |c| c.health_check_name = "  ".into()),
            ("escaped health name", |c| {
                c.health_check_name = "ex\\ample.com".into()
            }),
        ];
        for (name, mutate) in cases {
            let mut c = enabled();
            mutate(&mut c);
            c.validate();
            assert!(!c.enabled, "{name}: must force enabled=false");
            // And it must NOT have been silently rewritten into something
            // that would pass a second validate().
            let before = c.clone();
            c.validate();
            assert!(!c.enabled, "{name}: must stay disabled");
            assert_eq!(before.listen, c.listen, "{name}: no silent substitution");
        }
    }

    /// `system` is the default upstream and must not be mistaken for a
    /// malformed address.
    #[test]
    fn system_upstream_is_not_an_address() {
        let mut c = enabled();
        c.upstreams = vec![UPSTREAM_SYSTEM.into(), "9.9.9.9:53".into()];
        c.validate();
        assert!(c.enabled);
    }

    /// Enum-ish fields DO follow the crate's clamp convention: they cannot
    /// produce a live-but-wrong proxy, only a differently-shaped answer.
    #[test]
    fn enum_fields_clamp_without_disabling() {
        let mut c = enabled();
        c.block_response = "explode".into();
        c.on_proxy_failure = "panic".into();
        c.validate();
        assert!(c.enabled, "an unknown enum value must not disable the feature");
        assert_eq!(c.block_response, BLOCK_RESPONSE_NXDOMAIN);
        assert_eq!(c.on_proxy_failure, ON_FAILURE_REMOVE_RULE);
    }
}

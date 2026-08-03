//! The status surface: what web protection actually IS right now, as
//! opposed to what the user asked for.

use serde::{Deserialize, Serialize};

/// Why the proxy is not serving, when it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyState {
    /// `enabled = false`, or the config failed validation and was forced
    /// off. Nothing is running and nothing is meant to be.
    Disabled,
    /// Enabled, but the listener could not bind — most often because
    /// something else already owns `127.0.0.1:53`.
    BindFailed,
    /// Bound, but the four-step self-test did not pass. The proxy is NOT
    /// serving: we do not run a listener we could not prove works,
    /// because a later commit would install a rule on the strength of it.
    SelfTestFailed,
    /// Bound, self-tested, serving.
    Serving,
}

/// A point-in-time answer to "what is web protection doing?".
///
/// Reports INTENT and FACT as separate fields on purpose. A caller that
/// wants to know whether the machine's DNS is currently going through us
/// must read `nrpt_installed`; a caller that wants to know what the user
/// asked for reads `enabled`. Rendering only one of them is how a UI ends
/// up claiming protection that is not there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebProtectionStatus {
    /// User intent, straight from config.
    pub enabled: bool,
    /// Whether an NRPT rule of ours is present on the system RIGHT NOW,
    /// discovered rather than inferred. `None` means we could not tell —
    /// which is NOT the same as `Some(false)` and must never be rendered
    /// as "not installed".
    pub nrpt_installed: Option<bool>,
    /// What the listener is doing.
    pub state: ProxyState,
    /// Address actually bound, when serving.
    pub listen: Option<String>,
    /// Upstreams currently in force (after discovery).
    pub upstreams: Vec<String>,
    /// Healthy upstreams over total, from the last self-test.
    pub upstreams_healthy: usize,
    pub upstreams_total: usize,
    /// Rules loaded into the filter engine.
    pub rules_loaded: u64,
    /// Human-readable detail for a failed state; empty when serving.
    pub detail: String,
    /// Counters, when serving.
    pub queries: u64,
    pub blocked: u64,
    pub cache_hits: u64,
    pub upstream_errors: u64,
}

impl WebProtectionStatus {
    /// The status of a daemon where web protection is off. `nrpt_installed`
    /// is `None` rather than `Some(false)`: with no NRPT code in this
    /// commit we genuinely do not know, and claiming otherwise would be
    /// the kind of confident-but-false statement this project keeps
    /// getting bitten by.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            nrpt_installed: None,
            state: ProxyState::Disabled,
            listen: None,
            upstreams: Vec::new(),
            upstreams_healthy: 0,
            upstreams_total: 0,
            rules_loaded: 0,
            detail: String::new(),
            queries: 0,
            blocked: 0,
            cache_hits: 0,
            upstream_errors: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The status must survive the IPC round trip: it is returned as JSON
    /// and the GUI reads the two states separately. A rename here without
    /// a GUI change shows up as a silently missing field, so the shape is
    /// pinned.
    #[test]
    fn status_serializes_with_both_states_distinguishable() {
        let s = WebProtectionStatus::disabled();
        let v = serde_json::to_value(&s).expect("status must serialize");
        assert_eq!(v["enabled"], serde_json::json!(false));
        // null, NOT false — "we do not know" is a third value and the UI
        // must be able to tell it from "not installed".
        assert!(
            v["nrpt_installed"].is_null(),
            "unknown NRPT state must serialize as null, got {}",
            v["nrpt_installed"]
        );
        assert_eq!(v["state"], serde_json::json!("disabled"));
        for k in [
            "listen",
            "upstreams",
            "upstreams_healthy",
            "upstreams_total",
            "rules_loaded",
            "detail",
            "queries",
            "blocked",
            "cache_hits",
            "upstream_errors",
        ] {
            assert!(v.get(k).is_some(), "status is missing field {k}");
        }
    }

    #[test]
    fn disabled_status_does_not_claim_to_know_about_nrpt() {
        let s = WebProtectionStatus::disabled();
        assert!(!s.enabled);
        assert_eq!(s.state, ProxyState::Disabled);
        assert_eq!(
            s.nrpt_installed, None,
            "unknown must not be reported as not-installed"
        );
    }
}

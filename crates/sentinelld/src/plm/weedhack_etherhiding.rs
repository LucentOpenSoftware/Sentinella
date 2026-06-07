//! WeedHack EtherHiding correlator.
//!
//! ## What is EtherHiding?
//!
//! Instead of a hardcoded C2 URL — which is trivial to extract, block, and
//! sinkhole — WeedHack reads the current C2 IP from a smart-contract
//! storage slot on the Ethereum mainnet. The malware calls the contract's
//! `getRPCUrl()` view function via JSON-RPC (`eth_call`) against any
//! public Ethereum RPC endpoint. The operator updates the slot whenever a
//! C2 is taken down. Reading on-chain state is free for the malware and
//! infrastructure-resilient for the operator.
//!
//! The function selector — the first 4 bytes of `keccak256("getRPCUrl()")`
//! — is **`0xce6d41de`**. This selector appears in the JSON-RPC request
//! `data` field as a literal hex string. It is the smoking gun.
//!
//! Source: 0xresetti reverse-engineering writeup, corroborated by McAfee
//! Labs network telemetry.
//!
//! ## What we detect
//!
//! A JSON-RPC POST request where ALL of the following are true:
//!
//! 1. Destination host is a known public Ethereum mainnet RPC endpoint
//!    (Infura, Alchemy, Cloudflare, Ankr, public-node, llama, 1RPC).
//! 2. Request body contains the literal hex string `0xce6d41de`.
//! 3. Source process is `javaw.exe` or `java.exe`.
//!
//! All three together is a no-false-positive fingerprint: legitimate
//! Java code does not call this contract, and the selector is too
//! specific to appear by accident in an unrelated payload.
//!
//! ## Why not relax condition 3?
//!
//! The selector + Eth-RPC host is *suspicious* even from a non-Java
//! caller (could be malware staging on a different runtime), but the
//! signal becomes generic enough that legitimate research tooling using
//! the same view function on a coincidentally-named contract would
//! trip it. We keep the Java gate to maintain zero-FP.

#![allow(dead_code)]

use super::weedhack_runtime::WeedHackSignal;

/// Public Ethereum mainnet RPC endpoints abused by WeedHack EtherHiding.
/// These are the popular free-tier nodes; the operator picks one at runtime.
/// Hostnames are checked case-insensitively as substrings of the URL.
const ETH_RPC_HOSTS: &[&str] = &[
    "mainnet.infura.io",
    "eth-mainnet.g.alchemy.com",
    "cloudflare-eth.com",
    "rpc.ankr.com/eth",
    "ethereum-rpc.publicnode.com",
    "eth.llamarpc.com",
    "1rpc.io/eth",
    // QuickNode and Chainstack offer subdomain endpoints; match the
    // distinctive substrings only.
    ".quiknode.pro",
    ".chainstack.com",
];

/// The WeedHack `getRPCUrl()` function selector — first 4 bytes of the
/// keccak256 hash of the function signature, written as it appears in
/// the JSON-RPC `data` parameter.
const WEEDHACK_SELECTOR: &str = "0xce6d41de";

/// A captured outbound HTTP event — supplied by the ETW network probe or
/// a future sandbox harness. Field shapes match what the Microsoft-Windows-
/// WinINet / WinHTTP / DNS ETW providers expose.
#[derive(Debug, Clone)]
pub struct EtherHidingEvent {
    /// Full request URL including scheme and host.
    pub url: String,
    /// HTTP method (we only care about POST).
    pub method: String,
    /// Raw request body — typically a JSON-RPC payload.
    pub body: String,
    /// PID of the connecting process.
    pub source_pid: u32,
    /// Image file name (not full path) of the connecting process.
    pub source_image_name: String,
}

/// Evaluate one network event and decide whether it matches the
/// WeedHack EtherHiding C2-lookup fingerprint.
///
/// Returns `Some(WeedHackSignal::EtherHidingFromJava)` on a confirmed
/// match, `None` otherwise. The caller routes the signal through the
/// same finding-emission path used by chain-based detections.
pub fn evaluate(event: &EtherHidingEvent) -> Option<WeedHackSignal> {
    if !event.method.eq_ignore_ascii_case("POST") {
        return None;
    }

    let url_lower = event.url.to_ascii_lowercase();
    if !ETH_RPC_HOSTS.iter().any(|h| url_lower.contains(h)) {
        return None;
    }

    let body_lower = event.body.to_ascii_lowercase();
    if !body_lower.contains(WEEDHACK_SELECTOR) {
        return None;
    }

    let image_lower = event.source_image_name.to_ascii_lowercase();
    if image_lower != "javaw.exe" && image_lower != "java.exe" {
        return None;
    }

    Some(WeedHackSignal::EtherHidingFromJava)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn javaw_event(url: &str, body: &str) -> EtherHidingEvent {
        EtherHidingEvent {
            url: url.into(),
            method: "POST".into(),
            body: body.into(),
            source_pid: 4242,
            source_image_name: "javaw.exe".into(),
        }
    }

    const WH_BODY: &str = r#"{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xabcd...","data":"0xce6d41de"},"latest"],"id":1}"#;

    #[test]
    fn confirmed_etherhiding_call_fires() {
        let ev = javaw_event("https://mainnet.infura.io/v3/PROJECT_ID", WH_BODY);
        assert_eq!(evaluate(&ev), Some(WeedHackSignal::EtherHidingFromJava));
    }

    #[test]
    fn alchemy_endpoint_also_fires() {
        let ev = javaw_event(
            "https://eth-mainnet.g.alchemy.com/v2/SOME_KEY",
            WH_BODY,
        );
        assert_eq!(evaluate(&ev), Some(WeedHackSignal::EtherHidingFromJava));
    }

    #[test]
    fn cloudflare_eth_endpoint_fires() {
        let ev = javaw_event("https://cloudflare-eth.com/", WH_BODY);
        assert_eq!(evaluate(&ev), Some(WeedHackSignal::EtherHidingFromJava));
    }

    #[test]
    fn quiknode_subdomain_fires() {
        let ev = javaw_event(
            "https://misty-blue.quiknode.pro/abc123/",
            WH_BODY,
        );
        assert_eq!(evaluate(&ev), Some(WeedHackSignal::EtherHidingFromJava));
    }

    #[test]
    fn correct_host_wrong_selector_does_not_fire() {
        // Legit dapp making a different contract call.
        let body = r#"{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x...","data":"0x70a08231"}]}"#;
        let ev = javaw_event("https://mainnet.infura.io/v3/X", body);
        assert!(evaluate(&ev).is_none());
    }

    #[test]
    fn correct_selector_wrong_host_does_not_fire() {
        // Selector in body but POSTed to operator-controlled host —
        // probably a different malware family. Out of scope for this
        // correlator (the JAR layer catches that case).
        let ev = javaw_event("https://attacker.example/api", WH_BODY);
        assert!(evaluate(&ev).is_none());
    }

    #[test]
    fn correct_selector_correct_host_but_not_java_does_not_fire() {
        // A pentester running ethers.js from Node — same call shape,
        // not WeedHack. Keep FP at zero.
        let mut ev = javaw_event("https://mainnet.infura.io/v3/X", WH_BODY);
        ev.source_image_name = "node.exe".into();
        assert!(evaluate(&ev).is_none());
    }

    #[test]
    fn get_request_does_not_fire() {
        // EtherHiding requires a POST; GETs to RPC are health checks.
        let mut ev = javaw_event("https://mainnet.infura.io/v3/X", WH_BODY);
        ev.method = "GET".into();
        assert!(evaluate(&ev).is_none());
    }

    #[test]
    fn case_insensitive_method_and_url() {
        let mut ev = javaw_event("HTTPS://Mainnet.Infura.IO/v3/X", WH_BODY);
        ev.method = "post".into();
        assert_eq!(evaluate(&ev), Some(WeedHackSignal::EtherHidingFromJava));
    }

    #[test]
    fn weight_clears_chain_cap() {
        let ev = javaw_event("https://mainnet.infura.io/v3/X", WH_BODY);
        let sig = evaluate(&ev).unwrap();
        assert!(
            sig.weight() >= 50,
            "EtherHiding signal must score in the kill-on-sight band"
        );
    }
}

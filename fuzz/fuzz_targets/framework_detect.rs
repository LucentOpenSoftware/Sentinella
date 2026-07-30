//! Fuzz target: installer-framework detection dispatch on arbitrary bytes.
//!
//! Drives `argus::layers::framework::detect` — the full dispatch path:
//! bounded PE header parsing, then the NSIS / Inno Setup / WiX Burn
//! structural detectors, then the legacy WeakHint fallback, all funnelling
//! through the centralized `FrameworkDetection::build` invariant.
//!
//! Oracles (any violation = bug):
//! - no panic, on any byte string;
//! - `mitigation_safe()` ⇒ confidence >= Corroborated AND at least one
//!   structural evidence item (THE centralized invariant);
//! - `FrameworkKind::Unknown` ⇒ Confidence::Unknown and never safe.
//!
//! Run (Linux/WSL2 — see fuzz/README.md):
//!   cargo +nightly fuzz run framework_detect -- -max_total_time=900
//! Seed corpus: fuzz/corpus/framework_detect/ (deterministic; regenerate
//! with `python fuzz/tools/gen_framework_corpus.py`).
//! No-cargo-fuzz replay: `cargo test -p argus --test installer_spoofing
//! seed_corpus_replays_cleanly`.

#![no_main]

use argus::layers::framework::{Confidence, FrameworkKind, detect};
use libfuzzer_sys::fuzz_target;

fn check(data: &[u8], path: &str) {
    let d = detect(data, path);
    if d.mitigation_safe() {
        assert!(
            d.confidence() >= Confidence::Corroborated,
            "mitigation_safe below Corroborated: {:?}",
            d.confidence()
        );
        assert!(
            d.evidence().iter().any(|e| e.source.is_structural()),
            "mitigation_safe without structural evidence"
        );
    }
    if d.kind() == FrameworkKind::Unknown {
        assert_eq!(d.confidence(), Confidence::Unknown);
        assert!(!d.mitigation_safe());
    }
}

fuzz_target!(|data: &[u8]| {
    // Cap input size (detectors are bounded, but keep RSS sane).
    if data.len() > 4 * 1024 * 1024 {
        return;
    }

    // Pass 1: bytes as-is.
    check(data, "fuzz.exe");

    // Pass 2: MZ-forced — reach the PE dispatch branch more often.
    if data.len() >= 2 {
        let mut pe = data.to_vec();
        pe[0] = b'M';
        pe[1] = b'Z';
        check(&pe, "fuzz_setup.exe");
    }

    // Pass 3: MSI-extension path for OLE2-magic inputs.
    check(data, "fuzz.msi");
});

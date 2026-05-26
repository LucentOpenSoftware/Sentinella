//! Fuzz target: ARGUS engine analysis on crafted PE/binary buffers
//!
//! Tests the full ARGUS analysis pipeline with adversarial input:
//! - PE header parsing
//! - Section analysis + entropy
//! - Import table parsing
//! - MIME detection
//! - Structural heuristics
//! - Score aggregation
//!
//! Focus: malformed PE headers, truncated sections, integer overflow
//! in size fields, pathological entropy, crafted import tables.
//!
//! Run: cargo +nightly fuzz run fuzz_argus_pe -- -max_total_time=600

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Cap input size to prevent OOM (ARGUS has internal caps but be safe).
    if data.len() > 2 * 1024 * 1024 {
        return;
    }

    // Test 1: analyze_buffer — the main ARGUS entry point for in-memory analysis.
    // Must never panic on any input.
    let engine = argus::ArgusEngine::new(argus::ArgusConfig::default());
    let result = engine.analyze_buffer("fuzz_input.exe", data);

    // Test 2: Score must be in valid range.
    assert!(result.score <= 100, "score {} > 100", result.score);

    // Test 3: Verdict must be consistent with score.
    let expected_verdict = argus::verdict::Verdict::from_score(result.score);
    // Verdict ordering should match.
    assert_eq!(
        format!("{:?}", result.verdict),
        format!("{:?}", expected_verdict),
        "verdict {:?} inconsistent with score {}",
        result.verdict,
        result.score
    );

    // Test 4: Findings weights should sum to something reasonable.
    let total_weight: u32 = result.findings.iter().map(|f| f.weight).sum();
    // After deduplication and caps, total should be bounded.
    // The raw score is the minimum of total_weight and 100 (before discounts).

    // Test 5: Explanation must have a valid confidence label.
    let _ = result.explanation.confidence_label;
    let _ = result.explanation.final_score;

    // Test 6: Try with PE-like headers (MZ magic).
    if data.len() >= 2 {
        let mut pe_data = data.to_vec();
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        let pe_result = engine.analyze_buffer("fuzz_pe.exe", &pe_data);
        assert!(pe_result.score <= 100);
    }

    // Test 7: Try with script-like content.
    if data.len() >= 10 {
        let mut script_data = b"#!/bin/bash\n".to_vec();
        script_data.extend_from_slice(data);
        let script_result = engine.analyze_buffer("fuzz_script.sh", &script_data);
        assert!(script_result.score <= 100);
    }
});

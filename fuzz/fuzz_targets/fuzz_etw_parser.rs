//! Fuzz target: ETW event data parser
//!
//! Tests extract_image_from_event() with adversarial event payloads.
//! Focus: OOB reads, invalid UTF-16, missing null terminators,
//! oversized paths, truncated structures.
//!
//! Run: cargo +nightly fuzz run fuzz_etw_parser -- -max_total_time=600
//!
//! NOTE: extract_image_from_event is defined in sentinelld (Windows-only).
//! This harness reimplements the parsing logic for cross-platform fuzzing.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// Reimplementation of extract_image_from_event for fuzzing.
/// Must match the logic in plm/etw_intake.rs.
fn extract_image_from_event(data: &[u8]) -> Option<String> {
    if data.len() < 60 { return None; }

    for offset in (40..data.len().saturating_sub(8)).step_by(2) {
        if offset + 4 > data.len() { break; }
        let ch = data[offset];
        let ch_hi = data[offset + 1];
        let colon = data[offset + 2];
        let colon_hi = data[offset + 3];

        if ch_hi == 0 && colon == 0x3A && colon_hi == 0 && ch.is_ascii_alphabetic() && ch >= b'C' {
            let path_start = offset;
            let mut path_end = path_start;
            while path_end + 1 < data.len() {
                let lo = data[path_end];
                let hi = data[path_end + 1];
                if lo == 0 && hi == 0 { break; }
                path_end += 2;
            }
            if path_end > path_start + 4 {
                let wide: Vec<u16> = data[path_start..path_end]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&wide);
                if s.contains('\\') && s.len() > 3 {
                    return Some(s);
                }
            }
        }
    }

    None
}

fuzz_target!(|data: &[u8]| {
    // Test 1: Never panics on any input.
    let result = extract_image_from_event(data);

    // Test 2: If a path is returned, it must be valid UTF-8 (already guaranteed by String).
    if let Some(ref path) = result {
        assert!(path.len() > 3);
        assert!(path.contains('\\'));
    }

    // Test 3: Empty and tiny inputs don't panic.
    let _ = extract_image_from_event(&[]);
    let _ = extract_image_from_event(&[0u8; 1]);
    let _ = extract_image_from_event(&[0u8; 59]);
    let _ = extract_image_from_event(&[0u8; 60]);

    // Test 4: All-zero data doesn't panic.
    let _ = extract_image_from_event(&[0u8; 1024]);

    // Test 5: Data full of drive-letter patterns doesn't cause infinite loop.
    // C:\  in UTF-16LE = [0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00]
    let mut pattern_data = vec![0u8; 200];
    for i in (40..180).step_by(6) {
        if i + 5 < pattern_data.len() {
            pattern_data[i] = 0x43;     // 'C'
            pattern_data[i+1] = 0x00;
            pattern_data[i+2] = 0x3A;   // ':'
            pattern_data[i+3] = 0x00;
            pattern_data[i+4] = 0x5C;   // '\'
            pattern_data[i+5] = 0x00;
        }
    }
    let _ = extract_image_from_event(&pattern_data);
});

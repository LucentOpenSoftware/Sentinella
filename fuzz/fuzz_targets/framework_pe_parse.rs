//! Fuzz target: bounded PE header parsing (`framework::pe::parse`).
//!
//! Drives the total header parser directly (this is why the `pe` module is
//! `pub` — see the WHY note in `layers/framework/mod.rs`): DOS/PE/COFF/
//! optional headers, the section table, raw-range clamping, overlay extent
//! computation, all under checked arithmetic.
//!
//! Oracles (any violation = bug):
//! - no panic, on any byte string;
//! - on `Some(pe)`: `overlay_start <= len`, `overlay_len == len -
//!   overlay_start`, `sections.len() <= MAX_SECTIONS`, `headers_end <=
//!   len`, and the overlay never begins inside a (clamped) section range;
//! - `SectionInfo::raw_range` results are always sliceable.
//!
//! Run (Linux/WSL2 — see fuzz/README.md):
//!   cargo +nightly fuzz run framework_pe_parse -- -max_total_time=900
//! Seed corpus: fuzz/corpus/framework_pe_parse/ (same PE fixtures as
//! framework_detect; regenerate with `python fuzz/tools/gen_framework_corpus.py`).

#![no_main]

use argus::layers::framework::pe;
use libfuzzer_sys::fuzz_target;

fn check(data: &[u8]) {
    let Some(info) = pe::parse(data) else {
        return; // rejection is the fail-closed happy path
    };
    let len = data.len() as u64;
    assert!(info.sections.len() <= pe::MAX_SECTIONS as usize);
    assert!(info.headers_end <= len, "headers past EOF");
    assert!(info.overlay_start <= len, "overlay starts past EOF");
    assert_eq!(info.overlay_len, len - info.overlay_start);
    for s in &info.sections {
        if s.raw_size == 0 {
            continue;
        }
        let clamped_end = (u64::from(s.raw_ptr) + u64::from(s.raw_size)).min(len);
        assert!(
            info.overlay_start >= clamped_end,
            "overlay begins inside section '{}'",
            s.name
        );
        if let Some(range) = s.raw_range(data.len()) {
            // Must always be sliceable — this is the raw_range contract.
            let _ = &data[range];
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 4 * 1024 * 1024 {
        return;
    }
    check(data);
    if data.len() >= 2 {
        let mut pe = data.to_vec();
        pe[0] = b'M';
        pe[1] = b'Z';
        check(&pe);
    }
});

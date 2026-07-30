//! Fuzz target: ETW `EVENT_TRACE_PROPERTIES` buffer layout computation.
//!
//! Drives `sentinella_common::etw_props::compute_layout` — the pure,
//! cross-platform size/offset arithmetic behind the aligned ETW storage
//! (the fix for the misaligned-`Vec<u8>` UB class). Input decoding matches
//! the seed generator and the replay test: four u64 LE fields from the
//! first 32 bytes — struct_size, logger units, logfile units
//! (u64::MAX = None), extra slack bytes.
//!
//! Oracles (any violation = bug):
//! - no panic, on any parameters (checked arithmetic everywhere);
//! - on `Ok(layout)`: offsets and total agree exactly with the inputs and
//!   `total_size <= u32::MAX` (Wnode.BufferSize is a u32).
//!
//! Run (Linux/WSL2 — see fuzz/README.md):
//!   cargo +nightly fuzz run etw_props_layout -- -max_total_time=600
//! Seed corpus: fuzz/corpus/etw_props_layout/ (regenerate with
//! `python fuzz/tools/gen_framework_corpus.py`).
//! No-cargo-fuzz replay: `cargo test -p sentinella-common
//! etw_props::tests::seed_corpus_replays_cleanly`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinella_common::etw_props::compute_layout;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let u64_at = |i: usize| u64::from_le_bytes(data[i * 8..i * 8 + 8].try_into().unwrap());
    let as_usize = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
    let struct_size = as_usize(u64_at(0));
    let logger_units = as_usize(u64_at(1));
    let logfile_units = match u64_at(2) {
        u64::MAX => None,
        v => Some(as_usize(v)),
    };
    let extra = as_usize(u64_at(3));

    let Ok(l) = compute_layout(struct_size, logger_units, logfile_units, extra) else {
        return; // rejection is the fail-closed happy path
    };
    let logger_bytes = logger_units * 2 + 2;
    let logfile_bytes = logfile_units.map(|u| u * 2 + 2).unwrap_or(0);
    assert_eq!(l.logger_name_offset as usize, struct_size);
    assert_eq!(l.total_size, struct_size + logger_bytes + logfile_bytes + extra);
    assert!(l.total_size <= u32::MAX as usize, "BufferSize is a u32");
});

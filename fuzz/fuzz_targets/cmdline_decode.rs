//! Fuzz target: PLM command-line `UNICODE_STRING` decoding.
//!
//! Drives `parse_unicode_string_payload` + `decode_command_line_units`
//! from `crates/sentinelld/src/plm/cmdline.rs` — the bounded parser for
//! attacker-controlled process command lines (NtQueryInformationProcess
//! ProcessCommandLineInformation responses).
//!
//! ## WHY a `#[path]` include (honest limitation)
//!
//! sentinelld is a binary-only crate (`[[bin]]`, no lib target), so this
//! separate fuzz crate cannot link against it. Adding a lib target to a
//! SYSTEM-service binary just for fuzzing was judged the worse trade;
//! instead this target `#[path]`-includes the parser's source file
//! VERBATIM — the fuzzed code is byte-identical to production, not a
//! copy. The file's only non-std imports are `serde`/`serde_json`
//! (declared in this project); its `cfg(windows)` backend compiles out on
//! non-Windows fuzz hosts, leaving exactly the pure parsing surface.
//! If sentinelld ever gains a lib target, switch to a path dependency.
//!
//! ## Rebase convention
//!
//! The parser requires the payload pointer to be an ABSOLUTE address
//! inside the buffer — something a byte string cannot carry. The harness
//! interprets the pointer field as a RELATIVE offset and rebases it
//! (`ptr = buf.as_ptr() + (rel % len)`), keeping every validation branch
//! reachable from bytes alone. The corpus generator and the replay test
//! in cmdline.rs use the identical convention.
//!
//! Oracles: no panic on any byte string; a `Present` result never exceeds
//! the structural cap, is non-empty, and contains no NUL.
//!
//! Run (Linux/WSL2 — see fuzz/README.md):
//!   cargo +nightly fuzz run cmdline_decode -- -max_total_time=600
//! Note: cargo-fuzz itself does not run on Windows MSVC; on Windows this
//! target's coverage is provided by the replay test
//! (`cargo test -p sentinelld plm::cmdline::tests::seed_corpus_replays_cleanly`)
//! and the seeded sweeps in cmdline.rs.
//! Seed corpus: fuzz/corpus/cmdline_decode/ (regenerate with
//! `python fuzz/tools/gen_framework_corpus.py`).

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/sentinelld/src/plm/cmdline.rs"]
mod cmdline;

use cmdline::{CommandLineState, MAX_COMMAND_LINE_UTF16_UNITS};

/// Rebase the pointer field per the convention in the module docs.
fn rebase_pointer(buf: &mut [u8]) {
    let ptr_size = std::mem::size_of::<usize>();
    if buf.len() < 2 * ptr_size {
        return;
    }
    let mut rel_bytes = [0u8; 8];
    rel_bytes[..ptr_size].copy_from_slice(&buf[ptr_size..2 * ptr_size]);
    let rel = usize::from_le_bytes(rel_bytes) % buf.len();
    let abs = buf.as_ptr() as usize + rel;
    buf[ptr_size..2 * ptr_size].copy_from_slice(&abs.to_le_bytes()[..ptr_size]);
}

fn assert_state_invariants(state: &CommandLineState) {
    if let CommandLineState::Present(s) = state {
        assert!(s.encode_utf16().count() <= MAX_COMMAND_LINE_UTF16_UNITS);
        assert!(!s.is_empty());
        assert!(!s.contains('\0'));
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 128 * 1024 {
        return;
    }

    // Pass 1: raw buffer with rebased pointer through the full parser.
    let mut buf = data.to_vec();
    rebase_pointer(&mut buf);
    assert_state_invariants(&cmdline::parse_unicode_string_payload(&buf));

    // Pass 2: the bytes as raw UTF-16 units through the decoder directly.
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_state_invariants(&cmdline::decode_command_line_units(&units));
});

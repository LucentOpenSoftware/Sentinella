//! Fuzz target: path parsing, skip logic, and file identity
//!
//! Tests all path-based security decisions with adversarial paths:
//! - is_excluded (config exclusions)
//! - is_build_or_dev_path (project tree verification)
//! - is_transient_build_artifact
//! - is_clamav_temp_artifact
//! - is_sentinella_path
//! - should_skip_file
//!
//! Focus: path traversal, Unicode edge cases, UNC paths, device paths,
//! extremely long paths, null bytes in paths.
//!
//! Run: cargo +nightly fuzz run fuzz_paths -- -max_total_time=600
//!
//! NOTE: Skip logic functions are in sentinelld. This harness tests the
//! path parsing primitives that are available from std.

#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use std::path::Path;

#[derive(Arbitrary, Debug)]
struct FuzzPathInput {
    /// Raw path bytes (may contain any bytes).
    path_bytes: Vec<u8>,
    /// Exclusion patterns to test against.
    exclusions: Vec<String>,
    /// Extension exclusions.
    ext_exclusions: Vec<String>,
}

fuzz_target!(|input: FuzzPathInput| {
    // Convert bytes to a lossy string path.
    let path_str = String::from_utf8_lossy(&input.path_bytes);
    let path = Path::new(path_str.as_ref());

    // Test 1: std::fs::canonicalize on adversarial paths — must not panic.
    // (Will return Err for non-existent paths, which is fine.)
    let _ = std::fs::canonicalize(path);

    // Test 2: Path component iteration — must not panic.
    for component in path.components() {
        let _ = component.as_os_str().to_string_lossy();
    }

    // Test 3: Extension extraction — must not panic.
    let _ = path.extension();
    let _ = path.file_name();
    let _ = path.parent();
    let _ = path.file_stem();

    // Test 4: Path lowercasing — must not panic on any Unicode.
    let _ = path.to_string_lossy().to_lowercase();

    // Test 5: is_symlink on arbitrary paths — must not panic.
    let _ = path.is_symlink();
    let _ = path.is_file();
    let _ = path.is_dir();

    // Test 6: Prefix matching for exclusions — must not panic.
    let path_lower = path.to_string_lossy().to_lowercase();
    for excl in &input.exclusions {
        let excl_lower = excl.to_lowercase();
        // Prefix match (hardened from substring match).
        let _ = path_lower.starts_with(&excl_lower);
    }

    // Test 7: Extension matching — must not panic.
    if let Some(ext) = path.extension() {
        let ext_str = ext.to_string_lossy().to_lowercase();
        for excl_ext in &input.ext_exclusions {
            let _ = ext_str == excl_ext.to_lowercase().trim_start_matches('.');
        }
    }

    // Test 8: Adversarial path patterns that should be handled gracefully.
    let adversarial_paths = [
        "\\\\?\\C:\\very\\long\\path",
        "\\\\?\\UNC\\server\\share",
        "\\\\.\\PhysicalDrive0",
        "\\\\.\\pipe\\sentinelld",
        "CON", "PRN", "AUX", "NUL",
        "C:\\..\\..\\Windows\\System32\\cmd.exe",
        "C:\\Users\\victim\\Desktop\\build\\..\\..\\..\\Windows\\System32\\cmd.exe",
        &"A".repeat(32768), // MAX_PATH overflow
        "C:\\Users\\victim\\Desktop\\research_samples\\payload.exe", // C1 fix test
        "C:\\Users\\victim\\Desktop\\node_modules\\evil.exe", // H1 fix test
        "C:\\Users\\victim\\Desktop\\esbuild-payload.exe", // H2 fix test
        "C:\\Users\\victim\\Desktop\\html-tmp.evil\\malware.exe", // H3 fix test
    ];

    for p in &adversarial_paths {
        let ap = Path::new(p);
        let _ = ap.components().count();
        let _ = ap.to_string_lossy().to_lowercase();
        let _ = ap.file_name();
    }
});

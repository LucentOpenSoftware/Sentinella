//! Fuzz target: IPC JSON-RPC frame parsing
//!
//! Tests the JSON-RPC frame decoding and method dispatch with adversarial input.
//! The IPC protocol uses a 4-byte length prefix + JSON body.
//!
//! Focus: malformed JSON, extremely large frames, missing fields,
//! type confusion, unexpected method names, injection in string fields.
//!
//! Run: cargo +nightly fuzz run fuzz_ipc_frame -- -max_total_time=600
//!
//! NOTE: Full dispatch requires AppState, which can't be created in a
//! fuzz harness. This tests the JSON parsing + validation layer only.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: serde_json::from_slice on arbitrary bytes — must not panic.
    let parsed: Result<serde_json::Value, _> = serde_json::from_slice(data);

    if let Ok(val) = parsed {
        // Test 2: Extract JSON-RPC fields — must handle missing/wrong types.
        let _ = val.get("method").and_then(|v| v.as_str());
        let _ = val.get("id").and_then(|v| v.as_u64());
        let _ = val.get("params");
        let _ = val.get("auth").and_then(|v| v.as_str());

        // Test 3: Nested object access — must not panic.
        if let Some(params) = val.get("params") {
            let _ = params.get("target").and_then(|v| v.as_str());
            let _ = params.get("type").and_then(|v| v.as_str());
            let _ = params.get("path").and_then(|v| v.as_str());
            let _ = params.get("hash").and_then(|v| v.as_str());
            let _ = params.get("reason").and_then(|v| v.as_str());

            // Test 4: Array access — must not panic.
            if let Some(arr) = params.as_array() {
                for item in arr {
                    let _ = item.as_str();
                    let _ = item.as_u64();
                }
            }
        }

        // Test 5: Method name validation — must handle any string.
        if let Some(method) = val.get("method").and_then(|v| v.as_str()) {
            // Simulate dispatch table lookup.
            let _known = matches!(method,
                "engine.status" | "scan.start" | "scan.cancel" | "scan.status"
                | "quarantine.list" | "quarantine.restore" | "quarantine.delete"
                | "settings.set" | "settings.get"
                | "update.start" | "update.status"
                | "health" | "runtime.status" | "trust.status"
            );
        }

        // Test 6: Serialize back — round-trip must not panic.
        let _ = serde_json::to_string(&val);
        let _ = serde_json::to_vec(&val);
    }

    // Test 7: Frame length parsing (4-byte big-endian prefix).
    if data.len() >= 4 {
        let frame_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        // Sanity: reject frames > 16 MiB (matches IPC MAX_FRAME_SIZE).
        let _valid = frame_len <= 16 * 1024 * 1024;

        // Parse the body after the header.
        if data.len() > 4 && frame_len <= data.len() - 4 {
            let body = &data[4..4 + frame_len.min(data.len() - 4)];
            let _: Result<serde_json::Value, _> = serde_json::from_slice(body);
        }
    }

    // Test 8: Extremely nested JSON — must not stack overflow.
    // serde_json has a recursion limit, but test it.
    let deep_json = "{".repeat(128) + &"}".repeat(128);
    let _: Result<serde_json::Value, _> = serde_json::from_str(&deep_json);
});

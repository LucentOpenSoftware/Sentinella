//! libclamav FFI bridge.
//!
//! In the current scaffold, this is a stub. Once vcpkg dependencies
//! are installed and libclamav builds on Windows, this module will
//! contain the safe Rust wrapper around `cl_engine_*`, `cl_scan*`,
//! and `cl_load`.

// Re-export proto types so the rest of the daemon can use them
// without importing the proto crate directly for engine types.
#[allow(unused_imports)]
pub use sentinella_ipc_proto::engine::{EngineState, EngineStatus, ReloadResult};

// TODO: Engine struct with FFI integration.

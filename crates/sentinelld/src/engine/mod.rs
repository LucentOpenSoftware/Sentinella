//! ClamAV engine module.
//!
//! - `bindings.rs`: Raw C FFI type definitions.
//! - `clamav.rs`: Safe Rust wrapper that loads libclamav.dll at runtime.

pub mod bindings;
pub mod clamav;

pub use clamav::ClamEngine;

//! Analysis layers — each module implements a specific detection capability.
//!
//! Every layer receives file data and returns zero or more [`Finding`]s.
//! The engine orchestrates layers and aggregates their results.

pub mod authenticode;
pub mod context;
pub mod file_deception;
pub mod ioc;
pub mod mime;
pub mod packer;
pub mod patterns;
pub mod pe_heuristics;
pub mod reputation;
pub mod script;
pub mod trusted_cache;
pub mod yara;

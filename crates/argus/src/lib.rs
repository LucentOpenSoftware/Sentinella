//! # ARGUS Heuristics Engine
//!
//! Sentinella's layered suspicion and correlation engine.
//!
//! ARGUS does not guess. ARGUS correlates.
//!
//! ## Architecture
//!
//! ARGUS runs files through a series of analysis layers, each producing
//! weighted findings. The score aggregator combines all findings into a
//! final verdict with full explainability — every point of suspicion
//! includes a human-readable reason.
//!
//! ## Layers
//!
//! - **Layer 0**: ClamAV signatures (external, via daemon)
//! - **Layer 1**: MIME / magic validation
//! - **Layer 2**: PE/ELF structural heuristics
//! - **Layer 3**: Packer/protector detection
//! - **Layer 4**: Script analysis (JS, PowerShell, batch)
//! - **Layer 5**: Specialty pattern detection (stealers, fake docs, etc.)
//! - **Layer 6**: IOC and reputation correlation
//! - **Layer 7**: Score aggregation and explainable verdicts

pub mod budget;
pub mod correlation;
pub mod engine;
pub mod layers;
pub mod verdict;

pub use engine::{ArgusConfig, ArgusEngine, ArgusStats, ENGINE_VERSION};
pub use verdict::{ArgusVerdict, Finding, Severity, Verdict, VerdictExplanation};

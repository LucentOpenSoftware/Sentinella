//! TRRX — Scan target collection and policies.
//!
//! Centralizes target enumeration for Full Disk Scan, Startup Scan,
//! and Quick Scan. Each provider collects paths, the deduplicator
//! ensures no path is scanned twice.

pub mod dedup;
pub mod full_disk;
pub mod startup;

use std::path::PathBuf;

/// Config for target collection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct TargetConfig {
    pub startup_scan_enabled: bool,
    pub startup_scan_on_boot: bool,
    pub startup_recent_days: u32,
    pub full_scan_fixed_drives: bool,
    pub full_scan_max_depth: u32,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            startup_scan_enabled: false,
            startup_scan_on_boot: false,
            startup_recent_days: 7,
            full_scan_fixed_drives: true,
            full_scan_max_depth: 15,
        }
    }
}

/// Trait for scan target providers.
pub trait TargetProvider {
    #[allow(dead_code)]
    fn name(&self) -> &str;
    fn collect(&self, config: &TargetConfig) -> Vec<PathBuf>;
}

/// Quick scan targets — existing 3-directory approach.
#[allow(dead_code)]
pub struct QuickScanTargets;

impl TargetProvider for QuickScanTargets {
    fn name(&self) -> &str {
        "quick"
    }

    fn collect(&self, _config: &TargetConfig) -> Vec<PathBuf> {
        let home = std::env::var("USERPROFILE").unwrap_or_default();
        let temp =
            std::env::var("TEMP").unwrap_or_else(|_| format!("{home}\\AppData\\Local\\Temp"));

        [
            format!("{home}\\Downloads"),
            format!("{home}\\Desktop"),
            temp,
        ]
        .into_iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_scan_targets_exist() {
        let targets = QuickScanTargets.collect(&TargetConfig::default());
        // At least one of Downloads/Desktop/Temp should exist.
        assert!(
            !targets.is_empty(),
            "Quick scan should find at least one target directory"
        );
    }

    #[test]
    fn config_defaults_sane() {
        let cfg = TargetConfig::default();
        assert!(!cfg.startup_scan_enabled);
        assert!(cfg.full_scan_fixed_drives);
        assert_eq!(cfg.startup_recent_days, 7);
        assert_eq!(cfg.full_scan_max_depth, 15);
    }
}

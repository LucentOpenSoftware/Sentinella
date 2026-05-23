//! Full disk scan target provider.
//! Enumerates all fixed drives on Windows.

use super::{TargetConfig, TargetProvider};
use std::path::PathBuf;

pub struct FullDiskTargets;

impl TargetProvider for FullDiskTargets {
    fn name(&self) -> &str {
        "full_disk"
    }

    fn collect(&self, config: &TargetConfig) -> Vec<PathBuf> {
        if !config.full_scan_fixed_drives {
            return vec![];
        }

        let mut drives = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Check drive letters A-Z for fixed drives.
            for letter in b'C'..=b'Z' {
                let path = format!("{}:\\", letter as char);
                let pb = PathBuf::from(&path);
                if pb.exists() && is_fixed_drive(&path) {
                    drives.push(pb);
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Unix: scan root.
            let root = PathBuf::from("/");
            if root.exists() {
                drives.push(root);
            }
        }

        drives
    }
}

/// Check if a drive is a fixed local disk (not removable, not network).
#[cfg(target_os = "windows")]
fn is_fixed_drive(root: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = OsStr::new(root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // GetDriveTypeW: 3 = DRIVE_FIXED
    let drive_type = unsafe {
        windows::Win32::Storage::FileSystem::GetDriveTypeW(windows::core::PCWSTR(wide.as_ptr()))
    };
    drive_type == 3 // DRIVE_FIXED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_disk_finds_c_drive() {
        let targets = FullDiskTargets.collect(&TargetConfig::default());
        let has_c = targets
            .iter()
            .any(|p| p.to_string_lossy().to_uppercase().starts_with("C:\\"));
        assert!(has_c, "Full disk scan should find C: drive");
    }

    #[test]
    fn full_disk_disabled_returns_empty() {
        let mut cfg = TargetConfig::default();
        cfg.full_scan_fixed_drives = false;
        let targets = FullDiskTargets.collect(&cfg);
        assert!(targets.is_empty());
    }
}

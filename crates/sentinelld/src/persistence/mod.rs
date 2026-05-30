//! Persistence Intelligence — ASTRA contextual scoring for autorun locations.
//!
//! Files found at persistence locations (Run keys, Startup folder, Scheduled
//! Tasks, Services) receive contextual score amplification. A file scored
//! 30/100 in Downloads is unusual. The same file in a Run key is suspicious.
//!
//! This is NOT direct maliciousness detection. It is contextual weighting
//! that feeds into the ARGUS convergence model.

#![allow(dead_code)]

use std::path::Path;

/// Persistence location type — where the file was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceType {
    /// Registry Run / RunOnce key.
    RunKey,
    /// User Startup folder.
    StartupFolder,
    /// Scheduled Task.
    ScheduledTask,
    /// Windows Service.
    Service,
    /// Image File Execution Options (debugger hijack).
    Ifeo,
    /// AppInit_DLLs (DLL injection point).
    AppInitDlls,
    /// COM hijack (InProcServer32 replacement).
    ComHijack,
    /// WMI event subscription persistence.
    WmiPersistence,
    /// ADS on a persistence-related file.
    AdsPersistence,
}

impl PersistenceType {
    /// Contextual weight boost for this persistence type.
    /// Higher = more suspicious when found at this location.
    pub fn context_weight(&self) -> u32 {
        match self {
            Self::RunKey => 8,
            Self::StartupFolder => 8,
            Self::ScheduledTask => 10,
            Self::Service => 12,
            Self::Ifeo => 15,
            Self::AppInitDlls => 15,
            Self::ComHijack => 12,
            Self::WmiPersistence => 14,
            Self::AdsPersistence => 10,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::RunKey => "Registry Run key",
            Self::StartupFolder => "Startup folder",
            Self::ScheduledTask => "Scheduled task",
            Self::Service => "Windows service",
            Self::Ifeo => "Image File Execution Options",
            Self::AppInitDlls => "AppInit_DLLs",
            Self::ComHijack => "COM object hijack",
            Self::WmiPersistence => "WMI event subscription",
            Self::AdsPersistence => "ADS on persistence path",
        }
    }
}

/// Check if a file path is at a known persistence location.
/// Returns the persistence type and contextual weight if found.
pub fn check_persistence_context(path: &Path) -> Option<PersistenceType> {
    let p = path.to_string_lossy().to_lowercase();

    // Startup folder.
    if p.contains("\\start menu\\programs\\startup\\") {
        return Some(PersistenceType::StartupFolder);
    }

    // Common autorun-adjacent paths.
    if p.contains("\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup") {
        return Some(PersistenceType::StartupFolder);
    }

    // Task scheduler XML files.
    if p.contains("\\system32\\tasks\\") || p.contains("\\syswow64\\tasks\\") {
        return Some(PersistenceType::ScheduledTask);
    }

    // Service binaries in System32 — DISABLED. Previously flagged every
    // .dll/.sys in \system32\ as PersistenceType::Service worth +12 weight,
    // including legitimate kernel32.dll, ntdll.dll, user32.dll, etc. This
    // boosted ARGUS scores for every scan touching System32 — massive FP
    // cascade. To re-enable safely, would need either (a) cross-reference
    // against actual SCM service binary registry, or (b) Authenticode
    // trust-anchor check filtering Microsoft-signed binaries. Until then,
    // service persistence is detected only via the ScheduledTask + Run-key
    // + StartupFolder paths above which are far more specific.

    // IFEO registry-related paths (binaries targeted by IFEO).
    // This is detected at scan time when we correlate with registry data.

    None
}

/// Create an ARGUS finding for persistence context.
pub fn persistence_finding(
    persistence_type: PersistenceType,
    path: &Path,
    is_unsigned: bool,
) -> argus::Finding {
    let base_weight = persistence_type.context_weight();
    // Unsigned files at persistence locations are more suspicious.
    let weight = if is_unsigned {
        base_weight + 5
    } else {
        base_weight
    };

    let severity = if weight >= 15 {
        argus::verdict::Severity::High
    } else if weight >= 10 {
        argus::verdict::Severity::Medium
    } else {
        argus::verdict::Severity::Low
    };

    let unsigned_note = if is_unsigned { " (unsigned)" } else { "" };

    argus::Finding {
        layer: argus::verdict::Layer::Persistence,
        severity,
        weight,
        description: format!(
            "File located at {} persistence point{}",
            persistence_type.label(),
            unsigned_note,
        ),
        technical_detail: Some(path.to_string_lossy().to_string()),
    }
}

/// Check if a file path matches known Run key target patterns.
/// Used during startup scan to boost scores for autorun entries.
pub fn is_run_key_target(path: &Path, run_key_paths: &[std::path::PathBuf]) -> bool {
    run_key_paths.iter().any(|rk| {
        let rk_lower = rk.to_string_lossy().to_lowercase();
        let p_lower = path.to_string_lossy().to_lowercase();
        rk_lower == p_lower
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn startup_folder_detected() {
        let path = PathBuf::from(
            r"C:\Users\test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe",
        );
        assert_eq!(
            check_persistence_context(&path),
            Some(PersistenceType::StartupFolder)
        );
    }

    #[test]
    fn normal_downloads_not_persistence() {
        let path = PathBuf::from(r"C:\Users\test\Downloads\setup.exe");
        assert_eq!(check_persistence_context(&path), None);
    }

    #[test]
    fn scheduled_task_detected() {
        let path = PathBuf::from(r"C:\Windows\System32\Tasks\MyUpdate");
        assert_eq!(
            check_persistence_context(&path),
            Some(PersistenceType::ScheduledTask)
        );
    }

    #[test]
    fn persistence_weight_ordering() {
        assert!(PersistenceType::Ifeo.context_weight() > PersistenceType::RunKey.context_weight());
        assert!(
            PersistenceType::Service.context_weight()
                > PersistenceType::StartupFolder.context_weight()
        );
    }

    #[test]
    fn unsigned_boost() {
        let path = PathBuf::from(
            r"C:\Users\test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\app.exe",
        );
        let signed = persistence_finding(PersistenceType::StartupFolder, &path, false);
        let unsigned = persistence_finding(PersistenceType::StartupFolder, &path, true);
        assert!(unsigned.weight > signed.weight);
    }

    #[test]
    fn run_key_matching() {
        let targets = vec![PathBuf::from(r"C:\Program Files\MyApp\updater.exe")];
        let path = PathBuf::from(r"C:\Program Files\MyApp\updater.exe");
        assert!(is_run_key_target(&path, &targets));

        let other = PathBuf::from(r"C:\Users\test\Downloads\setup.exe");
        assert!(!is_run_key_target(&other, &targets));
    }
}

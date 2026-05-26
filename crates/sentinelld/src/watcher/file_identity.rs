//! FileIdentity — stable file identity snapshot for TOCTOU race prevention.
//!
//! Captures a canonical snapshot of a file at event intake time, then
//! revalidates before scan and quarantine to ensure the same file object
//! is being operated on.
//!
//! Prevents symlink/junction/reparse attacks where an attacker swaps a
//! normal file for a symlink between watcher validation and scan/quarantine.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// File identity snapshot — captured at watcher event intake.
#[derive(Debug, Clone)]
pub struct FileIdentity {
    /// Original path from watcher event.
    pub original_path: PathBuf,
    /// Canonical (resolved) path at capture time.
    pub canonical_path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// Last modified time (unix timestamp, seconds).
    pub modified_secs: u64,
    /// Whether the path was a reparse point at capture time.
    pub is_reparse: bool,
    /// Windows file index (volume_serial:index_high:index_low) if available.
    #[cfg(target_os = "windows")]
    pub file_index: Option<(u32, u32, u32)>,
}

/// Why a revalidation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMismatch {
    /// File no longer exists.
    FileGone,
    /// Canonical path changed (symlink/junction swap).
    CanonicalPathChanged,
    /// File became a reparse point (was normal file).
    BecameReparsePoint,
    /// File size changed (content replaced).
    SizeChanged,
    /// File modified time changed.
    ModifiedTimeChanged,
    /// Windows file index changed (different file object).
    #[cfg(target_os = "windows")]
    FileIndexChanged,
    /// Path escaped watched root.
    EscapedWatchRoot,
    /// Metadata read failed.
    MetadataError,
}

impl std::fmt::Display for IdentityMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileGone => write!(f, "file_gone"),
            Self::CanonicalPathChanged => write!(f, "canonical_path_changed"),
            Self::BecameReparsePoint => write!(f, "became_reparse_point"),
            Self::SizeChanged => write!(f, "size_changed"),
            Self::ModifiedTimeChanged => write!(f, "modified_time_changed"),
            #[cfg(target_os = "windows")]
            Self::FileIndexChanged => write!(f, "file_index_changed"),
            Self::EscapedWatchRoot => write!(f, "escaped_watch_root"),
            Self::MetadataError => write!(f, "metadata_error"),
        }
    }
}

/// Race prevention diagnostics counters.
pub struct RaceDiagnostics {
    pub race_skipped: AtomicU64,
    pub reparse_rejected: AtomicU64,
    pub identity_changed: AtomicU64,
    pub quarantine_race_prevented: AtomicU64,
    pub parent_rescans_scheduled: AtomicU64,
}

impl RaceDiagnostics {
    pub fn new() -> Self {
        Self {
            race_skipped: AtomicU64::new(0),
            reparse_rejected: AtomicU64::new(0),
            identity_changed: AtomicU64::new(0),
            quarantine_race_prevented: AtomicU64::new(0),
            parent_rescans_scheduled: AtomicU64::new(0),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "race_skipped": self.race_skipped.load(Ordering::Relaxed),
            "reparse_rejected": self.reparse_rejected.load(Ordering::Relaxed),
            "identity_changed": self.identity_changed.load(Ordering::Relaxed),
            "quarantine_race_prevented": self.quarantine_race_prevented.load(Ordering::Relaxed),
            "parent_rescans_scheduled": self.parent_rescans_scheduled.load(Ordering::Relaxed),
        })
    }
}

impl FileIdentity {
    /// Capture a file identity snapshot. Returns None if the file is a reparse
    /// point, doesn't exist, or can't be canonicalized.
    pub fn capture(path: &Path) -> Option<Self> {
        // Reject reparse points immediately at capture time.
        if is_reparse_point(path) {
            return None;
        }

        let canonical = match std::fs::canonicalize(path) {
            Ok(c) => c,
            Err(_) => return None,
        };

        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return None,
        };

        let modified_secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        #[cfg(target_os = "windows")]
        let file_index = get_file_index(path);

        Some(Self {
            original_path: path.to_path_buf(),
            canonical_path: canonical,
            size: meta.len(),
            modified_secs,
            is_reparse: false, // Already rejected reparse above.
            #[cfg(target_os = "windows")]
            file_index,
        })
    }

    /// Revalidate file identity before scan or quarantine.
    /// Returns Ok(()) if identity matches, Err(mismatch_reason) if changed.
    pub fn revalidate(&self, watched_roots: &[PathBuf]) -> Result<(), IdentityMismatch> {
        // 1. File must still exist.
        if !self.original_path.exists() {
            return Err(IdentityMismatch::FileGone);
        }

        // 2. Must not have become a reparse point.
        if is_reparse_point(&self.original_path) {
            return Err(IdentityMismatch::BecameReparsePoint);
        }

        // 3. Canonical path must match.
        let current_canonical = std::fs::canonicalize(&self.original_path)
            .map_err(|_| IdentityMismatch::MetadataError)?;
        if current_canonical != self.canonical_path {
            return Err(IdentityMismatch::CanonicalPathChanged);
        }

        // 4. Canonical path must be under a watched root.
        // Normalize: strip \\?\ prefix (Windows canonicalize adds it).
        let canonical_str = current_canonical.to_string_lossy().to_lowercase();
        let canonical_lower = canonical_str
            .strip_prefix("\\\\?\\")
            .unwrap_or(&canonical_str);
        let in_watched_root = watched_roots.iter().any(|root| {
            let root_str = root.to_string_lossy().to_lowercase();
            let root_lower = root_str.strip_prefix("\\\\?\\").unwrap_or(&root_str);
            canonical_lower.starts_with(root_lower)
        });
        if !in_watched_root {
            return Err(IdentityMismatch::EscapedWatchRoot);
        }

        // 5. Read current metadata.
        let meta =
            std::fs::metadata(&self.original_path).map_err(|_| IdentityMismatch::MetadataError)?;

        // 6. Size must match (content replacement check).
        if meta.len() != self.size {
            return Err(IdentityMismatch::SizeChanged);
        }

        // 7. Modified time must match.
        let current_modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if current_modified != self.modified_secs {
            return Err(IdentityMismatch::ModifiedTimeChanged);
        }

        // 8. Windows: file index must match (different file object check).
        #[cfg(target_os = "windows")]
        {
            if let Some(captured_idx) = self.file_index {
                if let Some(current_idx) = get_file_index(&self.original_path) {
                    if captured_idx != current_idx {
                        return Err(IdentityMismatch::FileIndexChanged);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Check if a path is a reparse point (symlink, junction, mount point).
///
/// On Windows, uses file attributes to detect ALL reparse point types,
/// not just symlinks (unlike `Path::is_symlink()` which may miss junctions).
#[cfg(target_os = "windows")]
pub fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;

    // FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    // Use symlink_metadata to NOT follow the link.
    match std::fs::symlink_metadata(path) {
        Ok(meta) => (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0,
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_reparse_point(path: &Path) -> bool {
    path.is_symlink()
}

/// Get Windows file index (volume serial + file index).
/// Returns (volume_serial, index_high, index_low).
#[cfg(target_os = "windows")]
fn get_file_index(path: &Path) -> Option<(u32, u32, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;
    use windows::Win32::Storage::FileSystem::GetFileInformationByHandle;

    let file = std::fs::File::open(path).ok()?;
    let handle = windows::Win32::Foundation::HANDLE(file.as_raw_handle() as _);

    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        if GetFileInformationByHandle(handle, &mut info).is_ok() {
            Some((
                info.dwVolumeSerialNumber,
                info.nFileIndexHigh,
                info.nFileIndexLow,
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn capture_normal_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let id = FileIdentity::capture(&file_path);
        assert!(id.is_some(), "should capture normal file");
        let id = id.unwrap();
        assert_eq!(id.size, 5);
        assert!(!id.is_reparse);
    }

    #[test]
    fn capture_nonexistent_returns_none() {
        let id = FileIdentity::capture(Path::new("nonexistent_file_12345.txt"));
        assert!(id.is_none());
    }

    #[test]
    fn revalidate_unchanged_file_passes() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("stable.txt");
        std::fs::write(&file_path, "stable content").unwrap();

        let id = FileIdentity::capture(&file_path).unwrap();
        // Use canonicalized root to match canonical path format.
        let roots = vec![std::fs::canonicalize(dir.path()).unwrap()];
        assert!(id.revalidate(&roots).is_ok());
    }

    #[test]
    fn revalidate_deleted_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("deleted.txt");
        std::fs::write(&file_path, "will be deleted").unwrap();

        let id = FileIdentity::capture(&file_path).unwrap();
        std::fs::remove_file(&file_path).unwrap();

        let roots = vec![dir.path().to_path_buf()];
        assert_eq!(id.revalidate(&roots), Err(IdentityMismatch::FileGone));
    }

    #[test]
    fn revalidate_size_changed_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("growing.txt");
        std::fs::write(&file_path, "short").unwrap();

        let id = FileIdentity::capture(&file_path).unwrap();

        // Modify file content (changes size).
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file_path)
            .unwrap();
        f.write_all(b"this is much longer content now").unwrap();
        drop(f);

        let roots = vec![dir.path().to_path_buf()];
        let result = id.revalidate(&roots);
        assert!(result.is_err(), "should fail: size changed");
    }

    #[test]
    fn revalidate_outside_watched_root_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("orphan.txt");
        std::fs::write(&file_path, "orphan").unwrap();

        let id = FileIdentity::capture(&file_path).unwrap();

        // Use a different root that doesn't contain the file.
        let fake_root = PathBuf::from("C:\\NonexistentRoot");
        let result = id.revalidate(&[fake_root]);
        assert_eq!(result.is_err(), true);
    }

    // Note: symlink/junction tests require Windows admin privileges or Developer Mode.
    // They are documented here but may not run in CI.
    #[test]
    #[cfg(target_os = "windows")]
    fn capture_reparse_point_returns_none() {
        // Creating symlinks requires either admin or Developer Mode.
        // This test documents expected behavior but may be skipped.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.txt");
        let link = dir.path().join("link.txt");
        std::fs::write(&target, "real").unwrap();

        // Try to create symlink — may fail without admin.
        if std::os::windows::fs::symlink_file(&target, &link).is_ok() {
            let id = FileIdentity::capture(&link);
            assert!(id.is_none(), "reparse points should be rejected at capture");
        }
    }
}

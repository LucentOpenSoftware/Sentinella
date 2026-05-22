//! Real-time file system watcher abstraction.
//!
//! Defines the `Watcher` trait and platform-specific implementations.
//! v1 ships `UserModePostFacto` only.
//!
//! All types are `#[allow(dead_code)]` during scaffolding — they
//! define the interface that platform backends will implement.

use std::path::PathBuf;

/// Events emitted by the watcher.
#[allow(dead_code)]
pub struct FileEvent {
    pub path: PathBuf,
    pub kind: FileEventKind,
    pub timestamp: std::time::SystemTime,
}

#[allow(dead_code)]
pub enum FileEventKind {
    Created,
    Modified,
    Renamed { from: PathBuf },
}

/// What kind of protection the watcher offers.
#[allow(dead_code)]
pub enum WatcherMode {
    /// Post-facto: file detected after write. Cannot block.
    UserModePostFacto,
    /// Pre-access blocking via kernel driver. v2+.
    KernelPreAccess,
}

/// Trait that all platform watcher backends implement.
#[allow(dead_code)]
pub trait Watcher: Send + Sync {
    fn start(&mut self, roots: &[PathBuf]) -> anyhow::Result<()>;
    fn stop(&mut self) -> anyhow::Result<()>;
    fn mode(&self) -> WatcherMode;
}

// TODO: platform implementations:
//   - windows_readdir.rs  (ReadDirectoryChangesW)
//   - windows_usn.rs      (USN Journal)
//   - linux_fanotify.rs   (wraps clamonacc)
//   - macos_fsevents.rs   (deferred)

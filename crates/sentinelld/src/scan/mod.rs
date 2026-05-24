//! Scan utilities — exclusion checking, file classification, scan cache, ADS.

pub mod ads;
pub mod cache;

use std::path::Path;

/// Directories skipped ONLY during quick scans (triage mode).
/// Full scans and user-selected folder scans scan everything.
const QUICK_SCAN_SKIP_DIRS: &[&str] = &[
    // Build artifacts — can contain hundreds of thousands of files.
    "target", // Rust/Cargo
    "build",  // Generic build output
    "dist",   // Frontend builds
    "out",    // Generic output
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".fingerprint",
    "incremental",
    ".cargo",
    ".rustup",
    ".npm",
    ".pnpm-store",
    ".nuget",
    ".gradle",
    ".m2",
    // IDE/editor caches.
    ".vs",
    ".vscode",
    ".idea",
    // OS caches.
    "$recycle.bin",
    "system volume information",
    // Large data dirs.
    "appdata",
    "programdata",
];

/// Check if a file path should be excluded from scanning.
pub fn is_excluded(path: &Path, excluded_paths: &[String], excluded_extensions: &[String]) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();

    // Check path exclusions.
    for excl in excluded_paths {
        let excl_lower = excl.to_lowercase();
        if path_str.starts_with(&excl_lower) || path_str.contains(&excl_lower) {
            return true;
        }
    }

    // Check extension exclusions.
    if let Some(ext) = path.extension() {
        let ext_str = ext.to_string_lossy().to_lowercase();
        for excl_ext in excluded_extensions {
            if ext_str == excl_ext.to_lowercase().trim_start_matches('.') {
                return true;
            }
        }
    }

    false
}

/// Check if a directory should be skipped during recursive file collection.
///
/// When `quick_scan` is true (triage mode), skips build artifacts, package
/// caches, and version control directories for speed. Full scans and
/// user-selected folder scans pass `quick_scan = false` to scan everything.
///
/// ClamAV extraction temp directories are ALWAYS skipped regardless of mode
/// to prevent infinite scan-extract-scan feedback loops.
pub fn should_skip_dir(path: &Path, quick_scan: bool) -> bool {
    // ALWAYS skip ClamAV extraction temp directories.
    // These are ephemeral artifacts, not user files. Scanning them creates
    // an infinite loop: scan → ClamAV extracts → collect_files picks up
    // extracted content → scan → ClamAV extracts again → ...
    if let Some(name) = path.file_name() {
        let name_lower = name.to_string_lossy().to_lowercase();
        if name_lower.starts_with("html-tmp.")
            || name_lower.starts_with("pdf-tmp.")
            || name_lower.starts_with("ole2-tmp.")
            || name_lower.starts_with("ooxml-tmp.")
            || name_lower.starts_with("swf-tmp.")
        {
            return true;
        }
    }

    if !quick_scan {
        return false; // Full/folder scans never skip user directories.
    }

    if let Some(name) = path.file_name() {
        let name_lower = name.to_string_lossy().to_lowercase();

        for &skip in QUICK_SCAN_SKIP_DIRS {
            if name_lower == skip.to_lowercase() {
                return true;
            }
        }
    }

    false
}

/// Check if path is within Sentinella's own directories.
/// Prevents self-detection false positives.
///
/// Uses the daemon's own exe location as anchor — NOT substring matching
/// on "sentinella" which could be exploited by malware placing files in
/// a directory named "sentinella".
pub fn is_sentinella_path(path: &Path) -> bool {
    // Anchor: daemon's own directory.
    static DAEMON_DIR: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    let daemon_dir = DAEMON_DIR.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    });

    if let Some(exe_dir) = daemon_dir {
        let exe_dir_str = exe_dir.to_string_lossy().to_lowercase();
        let p = path.to_string_lossy().to_lowercase();

        // Files under the daemon's own directory tree.
        if p.starts_with(&exe_dir_str) {
            return true;
        }

        // Sentinella project directory (dev mode — exe is in target/debug or target/release).
        if exe_dir_str.contains("target\\debug")
            || exe_dir_str.contains("target/debug")
            || exe_dir_str.contains("target\\release")
            || exe_dir_str.contains("target/release")
        {
            // In dev mode, exclude the project root and all build artifacts.
            // ancestors: nth(0)=self, nth(1)=target, nth(2)=sentinella project root
            if let Some(project_root) = exe_dir.ancestors().nth(2) {
                let root_str = project_root.to_string_lossy().to_lowercase();
                if p.starts_with(&root_str) {
                    let relative = &p[root_str.len()..];
                    // Core project dirs — never scan own build artifacts.
                    if relative.starts_with("\\runtime\\") || relative.starts_with("/runtime/")
                        || relative.starts_with("\\target\\") || relative.starts_with("/target/")
                        || relative.starts_with("\\crates\\") || relative.starts_with("/crates/")
                        // GUI sub-project (gui/src-tauri/target/...)
                        || relative.starts_with("\\gui\\") || relative.starts_with("/gui/")
                    {
                        return true;
                    }
                }
            }
        }
    }

    // Sentinella binaries by name (fallback).
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name == "sentinelld.exe" || name == "sentinella.exe" {
        return true;
    }

    // Research samples — never auto-scanned by watcher (manual only).
    let p = path.to_string_lossy().to_lowercase();
    if p.contains("research_samples") {
        return true;
    }

    // Sentinel quarantine/runtime dirs (installed mode).
    if p.contains("sentinella\\quarantine")
        || p.contains("sentinella/quarantine")
        || p.contains("sentinella\\signatures")
        || p.contains("sentinella/signatures")
        || p.contains("sentinella\\logs")
        || p.contains("sentinella/logs")
    {
        return true;
    }

    // ClamAV dedicated temp directory (runtime/clamav_tmp).
    if p.contains("\\clamav_tmp\\") || p.contains("/clamav_tmp/") {
        return true;
    }

    false
}

/// Directories that are always build/dev artifacts — watcher + idle scanner skip.
const BUILD_DEV_DIRS: &[&str] = &[
    "target",       // Rust
    "node_modules", // Node
    ".git",         // Git
    "dist",         // Bundler output
    "build",        // CMake / generic
    ".next",        // Next.js
    ".vite",        // Vite cache
    ".cargo",       // Cargo home cache
    ".rustup",      // Rust toolchains
    ".npm",         // npm cache
    ".pnpm-store",  // pnpm store
    "__pycache__",  // Python
    ".fingerprint", // Rust incremental
    "incremental",  // Rust incremental
    ".gradle",      // Gradle
    ".m2",          // Maven
    ".nuget",       // .NET
    "release",      // Release staging (under project)
];

/// Check if path passes through a build/dev directory.
/// Returns true if any path component matches BUILD_DEV_DIRS.
pub fn is_build_or_dev_path(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    for &dir in BUILD_DEV_DIRS {
        let sep_dir = format!("\\{dir}\\");
        let sep_dir_fwd = format!("/{dir}/");
        if p.contains(&sep_dir) || p.contains(&sep_dir_fwd) {
            return true;
        }
    }
    false
}

/// Check if a file should be skipped (system files, temp locks, etc.).
pub fn should_skip_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Skip common system/temp files that change frequently.
    let skip_names = [
        "thumbs.db",
        "desktop.ini",
        ".ds_store",
        "pagefile.sys",
        "swapfile.sys",
        "hiberfil.sys",
    ];

    if skip_names.iter().any(|&s| name == s) {
        return true;
    }

    // Skip lock files and partial downloads.
    if name.ends_with(".lock")
        || name.ends_with(".tmp")
        || name.ends_with(".crdownload")
        || name.ends_with(".part")
    {
        return true;
    }

    // Skip ClamAV temp extraction artifacts.
    // ClamAV extracts HTML/PDF/archive content into %TEMP% when scanning.
    // Scanning these back creates an infinite feedback loop:
    //   scan file → ClamAV extracts to temp → scan picks up extracted file → repeat.
    if is_clamav_temp_artifact(path) {
        return true;
    }

    false
}

/// Check if a path is a ClamAV temporary extraction artifact.
///
/// ClamAV creates temp directories/files when scanning compound files:
///   - `html-tmp.<hash>/javascript`   (HTML script extraction)
///   - `pdf-tmp.<hash>/pdf obj N N`   (PDF object extraction)
///   - `ole2-tmp.<hash>/...`          (OLE2/Office extraction)
///   - `clamav-<hash>.tmp`            (generic temp files)
///
/// These MUST be skipped by all scan paths to prevent infinite loops
/// where ClamAV scans its own extraction output.
pub fn is_clamav_temp_artifact(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();

    // ClamAV extraction temp directories.
    if p.contains("\\html-tmp.")
        || p.contains("/html-tmp.")
        || p.contains("\\pdf-tmp.")
        || p.contains("/pdf-tmp.")
        || p.contains("\\ole2-tmp.")
        || p.contains("/ole2-tmp.")
        || p.contains("\\ooxml-tmp.")
        || p.contains("/ooxml-tmp.")
        || p.contains("\\swf-tmp.")
        || p.contains("/swf-tmp.")
    {
        return true;
    }

    // ClamAV generic temp files (clamav-<hash>.tmp).
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name.starts_with("clamav-") {
        return true;
    }

    false
}

/// Check if a path is a transient build/dev tool artifact.
///
/// Build tools (esbuild, webpack, tsc, cargo, msbuild) create and delete
/// temporary files rapidly in %TEMP% and project directories. Scanning these
/// files causes contention: the watcher opens the file for scanning while
/// the build tool tries to delete/rename it, causing "access denied" build
/// failures.
///
/// These are ALWAYS skipped by the watcher. Manual scans still cover them.
pub fn is_transient_build_artifact(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // esbuild temp files (esbuild-<hash> in %TEMP%).
    if name.starts_with("esbuild-") || name.starts_with("esbuild_") {
        return true;
    }

    // Vite/Rollup temp files.
    if name.starts_with("vite-") || name.starts_with("rollup-") {
        return true;
    }

    // TypeScript compiler temp files.
    if name.starts_with("tsc-") || name.starts_with("tsserver-") {
        return true;
    }

    // Cargo/rustc incremental compilation artifacts in temp.
    if name.starts_with("rustc") && (name.ends_with(".o") || name.ends_with(".rcgu")) {
        return true;
    }

    // MSBuild/Visual Studio temp.
    if name.starts_with("msbuild") || name.starts_with("vctmp") {
        return true;
    }

    // npm/pnpm staging files.
    if p.contains("\\.staging\\") || p.contains("\\pnpm-") || p.contains("\\_cacache\\") {
        return true;
    }

    // Go compiler temp.
    if name.starts_with("go-build") || name.starts_with("go-link") {
        return true;
    }

    // Python/pip temp.
    if name.starts_with("pip-") && (name.contains("install") || name.contains("build")) {
        return true;
    }

    // Webpack hot-update files.
    if name.ends_with(".hot-update.js") || name.ends_with(".hot-update.json") {
        return true;
    }

    // Generic: files in AppData\Local\Temp with hex hash names (32+ chars, no extension).
    // These are typically build tool intermediates.
    if p.contains("\\temp\\") || p.contains("\\tmp\\") {
        if name.len() >= 32
            && !name.contains('.')
            && name.chars().all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_')
        {
            return true;
        }
    }

    false
}

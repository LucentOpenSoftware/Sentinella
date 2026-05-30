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

/// System-managed pseudo directories skipped in every scan profile.
///
/// They contain tombstoned or privileged artifacts that can pin in-process
/// scanners and prevent cancellation from completing.
const ALWAYS_SKIP_SYSTEM_DIRS: &[&str] = &["$recycle.bin", "system volume information"];

/// Check if a file path should be excluded from scanning.
pub fn is_excluded(path: &Path, excluded_paths: &[String], excluded_extensions: &[String]) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();

    // Check path exclusions.
    // R4-LETHAL-2: previous version used raw `starts_with` with no path
    // boundary. Excluding "C:\Users\Me" would also exclude "C:\Users\Mexico\"
    // and "C:\Users\MeOwner\..." — an attacker (or a typo) could trick a
    // user into excluding a benign-looking prefix and unlock scanning of
    // an unrelated sibling directory whose name shares that prefix.
    //
    // Fix: enforce that after the prefix match, the next char must be a
    // path separator (or end-of-string for exact match), so that
    // "C:\Users\Me\..." matches but "C:\Users\Mexico\..." does NOT.
    for excl in excluded_paths {
        let mut excl_lower = excl.to_lowercase();
        // Normalize: strip trailing separators so the boundary check below
        // works uniformly whether the user wrote "C:\Users\Me" or
        // "C:\Users\Me\".
        while excl_lower.ends_with('\\') || excl_lower.ends_with('/') {
            excl_lower.pop();
        }
        if excl_lower.is_empty() {
            continue;
        }
        if path_str.starts_with(&excl_lower) {
            let rest = &path_str[excl_lower.len()..];
            if rest.is_empty() || rest.starts_with('\\') || rest.starts_with('/') {
                return true;
            }
            // Prefix matched but next char is not a separator — e.g.
            // excl="c:\\users\\me", path="c:\\users\\mexico\\..." — NOT a match.
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

/// True if `path` is a reparse point — a symlink OR an NTFS junction /
/// mount point. `Path::is_symlink()` only flags true symlinks (reparse tag
/// `IO_REPARSE_TAG_SYMLINK`), NOT junctions (`IO_REPARSE_TAG_MOUNT_POINT`), so
/// directory walkers that guard with `is_symlink` alone can still be lured into
/// traversing a junction into an unintended tree (loops, scope-creep into
/// another user's profile under SYSTEM). Recursive walkers should guard with
/// THIS instead. Uses `symlink_metadata` so it inspects the link, not the
/// target; returns false on any stat error (treat as a normal entry).
pub fn is_reparse_point(path: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        std::fs::symlink_metadata(path)
            .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        path.is_symlink()
    }
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
        if ALWAYS_SKIP_SYSTEM_DIRS
            .iter()
            .any(|skip| name_lower == *skip)
        {
            return true;
        }
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

    // C1 fix: removed global "research_samples" substring bypass.
    // Previously, ANY path containing "research_samples" was skipped.
    // Now, only Sentinella's own installed directories are skipped.

    // Sentinel quarantine/runtime dirs — only under Sentinella's own install tree.
    // R9-LETHAL pattern: anchor to the daemon's data root (PathManager), NOT
    // CWD. CWD drift would silently invalidate this guard → AV scans its own
    // signatures/quarantine recursively → storm + self-quarantine risk.
    {
        let daemon_lower = crate::paths::paths().root().to_string_lossy().to_lowercase();
        let p = path.to_string_lossy().to_lowercase();
        if !daemon_lower.is_empty() && p.starts_with(&daemon_lower) {
            // Inside daemon directory — skip runtime artifacts.
            if p.contains("\\quarantine\\")
                || p.contains("/quarantine/")
                || p.contains("\\signatures\\")
                || p.contains("/signatures/")
                || p.contains("\\logs\\")
                || p.contains("/logs/")
                || p.contains("\\clamav_tmp\\")
                || p.contains("/clamav_tmp/")
            {
                return true;
            }
        }
    }

    // Installed mode: ProgramData\Sentinella paths.
    let p = path.to_string_lossy().to_lowercase();
    if p.contains("\\programdata\\sentinella\\quarantine")
        || p.contains("\\programdata\\sentinella\\signatures")
        || p.contains("\\programdata\\sentinella\\logs")
        || p.contains("\\programdata\\sentinella\\clamav_tmp")
    {
        return true;
    }

    false
}

/// Build/dev directory names — only skipped when inside a verified project tree.
/// H1 fix: previously skipped globally (any `\build\` anywhere → bypass).
/// Now requires a project marker file in an ancestor directory.
const BUILD_DEV_DIRS: &[&str] = &[
    "target",       // Rust
    "node_modules", // Node
    "dist",         // Bundler output
    "build",        // CMake / generic
    ".next",        // Next.js
    ".vite",        // Vite cache
    "__pycache__",  // Python
    ".fingerprint", // Rust incremental
    "incremental",  // Rust incremental
    ".gradle",      // Gradle
    ".m2",          // Maven
    ".nuget",       // .NET
                    // Removed: "release" — too common in non-dev contexts.
                    // Removed: ".git" — not a build artifact dir, and can contain hooks.
];

/// Dotfiles/caches that are safe to skip unconditionally (always hidden, never user content).
const ALWAYS_SKIP_DIRS: &[&str] = &[
    ".cargo",      // Cargo home cache
    ".rustup",     // Rust toolchains
    ".npm",        // npm cache
    ".pnpm-store", // pnpm store
];

/// Project marker files — if any exist in an ancestor directory,
/// the path is considered inside a verified development workspace.
const PROJECT_MARKERS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "go.mod",
    "pyproject.toml",
    "setup.py",
    "CMakeLists.txt",
    "Makefile",
    "build.gradle",
    "pom.xml",
    ".sln",
    ".csproj",
];

/// Check if path passes through a build/dev directory.
///
/// H1 fix: DOMAIN-CONSTRAINED. Only skips if:
/// 1. Path contains a build dir component, AND
/// 2. An ancestor directory contains a project marker file (Cargo.toml, package.json, etc.)
///
/// Unconditionally safe dirs (.cargo, .rustup, .npm) are always skipped.
pub fn is_build_or_dev_path(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();

    // Always-safe hidden caches — no project verification needed.
    for &dir in ALWAYS_SKIP_DIRS {
        let sep_dir = format!("\\{dir}\\");
        let sep_dir_fwd = format!("/{dir}/");
        if p.contains(&sep_dir) || p.contains(&sep_dir_fwd) {
            return true;
        }
    }

    // Build dirs require project tree verification.
    let mut found_build_dir = false;
    for &dir in BUILD_DEV_DIRS {
        let sep_dir = format!("\\{dir}\\");
        let sep_dir_fwd = format!("/{dir}/");
        if p.contains(&sep_dir) || p.contains(&sep_dir_fwd) {
            found_build_dir = true;
            break;
        }
    }

    if !found_build_dir {
        return false;
    }

    // Walk ancestors looking for a project marker.
    let mut ancestor = path.parent();
    let mut depth = 0;
    while let Some(dir) = ancestor {
        if depth > 10 {
            break;
        } // Don't walk too far up.
        for &marker in PROJECT_MARKERS {
            if dir.join(marker).exists() {
                return true; // Verified project tree.
            }
        }
        ancestor = dir.parent();
        depth += 1;
    }

    false // Build dir found but NO project marker → not a real dev workspace.
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
/// H3 fix: DOMAIN-CONSTRAINED. ClamAV temp patterns only recognized inside
/// temp directories or ClamAV's dedicated temp dir. Previously, creating
/// `html-tmp.evil` anywhere on the filesystem bypassed all scanning.
///
/// ClamAV creates temp directories/files when scanning compound files:
///   - `html-tmp.<hash>/javascript`   (HTML script extraction)
///   - `pdf-tmp.<hash>/pdf obj N N`   (PDF object extraction)
///   - `ole2-tmp.<hash>/...`          (OLE2/Office extraction)
///   - `clamav-<hash>.tmp`            (generic temp files)
pub fn is_clamav_temp_artifact(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();

    // H3 domain check: must be inside a temp directory.
    let in_temp = p.contains("\\temp\\")
        || p.contains("\\tmp\\")
        || p.contains("/temp/")
        || p.contains("/tmp/")
        || p.contains("\\clamav_tmp\\")
        || p.contains("/clamav_tmp/");

    if !in_temp {
        return false;
    }

    // ClamAV extraction temp directory patterns (component-level check).
    for component in path.components() {
        let c = component.as_os_str().to_string_lossy().to_lowercase();
        if c.starts_with("html-tmp.")
            || c.starts_with("pdf-tmp.")
            || c.starts_with("ole2-tmp.")
            || c.starts_with("ooxml-tmp.")
            || c.starts_with("swf-tmp.")
        {
            return true;
        }
    }

    // ClamAV generic temp files.
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
/// H2 fix: DOMAIN-CONSTRAINED. Build tool artifacts are only skipped when:
/// 1. The file is inside a temp directory (%TEMP%, %TMP%, AppData\Local\Temp), OR
/// 2. The file is inside a verified project tree (has project marker ancestor).
///
/// Previously, `esbuild-*` or `msbuild*` filenames were skipped ANYWHERE,
/// allowing trivial bypass by renaming malware.
pub fn is_transient_build_artifact(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Domain check: is this file in a temp directory or verified project?
    let in_temp = p.contains("\\temp\\")
        || p.contains("\\tmp\\")
        || p.contains("/temp/")
        || p.contains("/tmp/");
    let in_project = is_build_or_dev_path(path); // Already verified project tree.

    if !in_temp && !in_project {
        return false; // H2 fix: outside safe domains, never skip by name alone.
    }

    // Build tool temp files — only valid inside temp or project dirs.
    if name.starts_with("esbuild-") || name.starts_with("esbuild_") {
        return true;
    }
    if name.starts_with("vite-") || name.starts_with("rollup-") {
        return true;
    }
    if name.starts_with("tsc-") || name.starts_with("tsserver-") {
        return true;
    }
    if name.starts_with("rustc") && (name.ends_with(".o") || name.ends_with(".rcgu")) {
        return true;
    }
    if name.starts_with("msbuild") || name.starts_with("vctmp") {
        return true;
    }
    if name.starts_with("go-build") || name.starts_with("go-link") {
        return true;
    }
    if name.starts_with("pip-") && (name.contains("install") || name.contains("build")) {
        return true;
    }
    if name.ends_with(".hot-update.js") || name.ends_with(".hot-update.json") {
        return true;
    }

    // npm/pnpm staging — substring-based but requires temp/project context.
    if p.contains("\\.staging\\") || p.contains("\\pnpm-") || p.contains("\\_cacache\\") {
        return true;
    }

    // Generic hex-hash temp files — only in actual temp directories.
    if in_temp
        && name.len() >= 32
        && !name.contains('.')
        && name
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_')
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_reparse_point_negatives() {
        // A real (non-reparse) directory and a regular file are not reparse
        // points; a nonexistent path is false (no panic). Junction/symlink
        // positives need privileged setup, so they're covered by manual/field
        // testing — this locks the safe negatives + no-panic contract.
        let dir = std::env::temp_dir();
        assert!(!is_reparse_point(&dir), "temp dir must not be a reparse point");
        assert!(!is_reparse_point(Path::new(
            "C:\\__sentinella_nonexistent_reparse_probe__"
        )));

        let f = dir.join("sentinella_reparse_probe.txt");
        std::fs::write(&f, b"x").unwrap();
        assert!(!is_reparse_point(&f), "regular file must not be a reparse point");
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn r4_lethal2_exclusion_boundary_no_prefix_collision() {
        // Exclusion of "C:\Users\Me" must NOT exclude "C:\Users\Mexico\..."
        // or "C:\Users\MeOwner\..." — prefix-only match was the bug.
        let excl = vec!["C:\\Users\\Me".to_string()];
        let exts: Vec<String> = vec![];

        // Legit exclusion target.
        assert!(
            is_excluded(Path::new("C:\\Users\\Me\\Downloads\\evil.exe"), &excl, &exts),
            "real Me\\... path should be excluded"
        );
        // Path that previously was falsely excluded due to prefix collision.
        assert!(
            !is_excluded(
                Path::new("C:\\Users\\Mexico\\Downloads\\evil.exe"),
                &excl,
                &exts
            ),
            "BUG: Mexico\\... falsely excluded by Me prefix"
        );
        assert!(
            !is_excluded(
                Path::new("C:\\Users\\MeOwner\\file.exe"),
                &excl,
                &exts
            ),
            "BUG: MeOwner\\... falsely excluded by Me prefix"
        );
    }

    #[test]
    fn r4_lethal2_exclusion_exact_match_works() {
        // Exclusion exactly equal to the path (without trailing separator)
        // should still match.
        let excl = vec!["C:\\Temp\\sandbox".to_string()];
        let exts: Vec<String> = vec![];
        assert!(is_excluded(Path::new("C:\\Temp\\sandbox"), &excl, &exts));
        assert!(is_excluded(
            Path::new("C:\\Temp\\sandbox\\file.bin"),
            &excl,
            &exts
        ));
    }

    #[test]
    fn r4_lethal2_trailing_separator_normalized() {
        // Both "C:\Foo" and "C:\Foo\" should behave identically.
        let a = vec!["C:\\Foo".to_string()];
        let b = vec!["C:\\Foo\\".to_string()];
        let exts: Vec<String> = vec![];
        for excl in [&a, &b] {
            assert!(is_excluded(Path::new("C:\\Foo\\bar.exe"), excl, &exts));
            assert!(!is_excluded(Path::new("C:\\FooBar\\bar.exe"), excl, &exts));
        }
    }
}

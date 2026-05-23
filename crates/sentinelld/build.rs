/// Build script for sentinelld.
///
/// On Windows, embeds the Sentinella icon and version info into the
/// executable so it shows correctly in Task Manager, Explorer, etc.

fn main() {
    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("sentinelld.ico");
        res.set("ProductName", "Sentinella Antivirus Suite");
        res.set(
            "FileDescription",
            "Sentinella Daemon — ARGUS Heuristics Engine",
        );
        res.set("CompanyName", "Lucent Open Software");
        res.set("InternalName", "sentinelld");
        res.set("OriginalFilename", "sentinelld.exe");
        res.set(
            "LegalCopyright",
            "Copyright (c) 2024-2026 Lucent Open Software. GPLv2.",
        );
        res.set("FileVersion", env!("CARGO_PKG_VERSION"));
        res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=Failed to embed Windows resources: {e}");
            // Non-fatal — the daemon works fine without an icon.
        }
    }
}

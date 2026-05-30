//! Sentinella Dev Console — internal tool for the Sentinella developer
//! center. NOT distributed in the public installer.
//!
//! Capabilities:
//!   * Detect an installed SentinellaDaemon service + read its
//!     `health` / config snapshot.
//!   * Provision / revoke Developer Mode (writes the SHA-256 password
//!     hash to `<ProgramData>\Sentinella\config\sentinelld.toml` with
//!     atomic write + service restart).
//!   * Spawn the `argusd benchmark --json` hardware-parity tool and
//!     render Performance Index / throughput / latency / SIMD flags.
//!
//! Built as a single-binary native GUI via `eframe`+`egui`. No webview,
//! no extra runtime.

// On Windows: hide the console window for the dev tool itself. The
// commands it spawns (sc, argusd) already use CREATE_NO_WINDOW.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod benchmark;
mod daemon;
mod ipc;
mod provision;
mod tab_benchmark;
mod tab_setup;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 540.0])
            .with_min_inner_size([560.0, 380.0])
            .with_title("Sentinella Dev Console"),
        ..Default::default()
    };
    eframe::run_native(
        "Sentinella Dev Console",
        native_options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}

//! Top-level egui app: tab routing + shared state.

use crate::benchmark::BenchmarkOutcome;
use crate::daemon::DaemonSnapshot;
use crate::provision::DeveloperSnapshot;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Setup,
    Benchmark,
}

/// Long-running work (service restart, benchmark) is moved to background
/// threads so the UI stays responsive. They post status into these slots.
#[derive(Debug, Default)]
pub struct AsyncSlots {
    pub setup_busy: bool,
    pub setup_log: Vec<String>,
    pub benchmark_busy: bool,
    pub benchmark_log: Vec<String>,
    pub benchmark_result: Option<BenchmarkOutcome>,
    pub benchmark_raw_json: Option<String>,
}

pub struct App {
    pub tab: Tab,
    pub daemon: DaemonSnapshot,
    pub dev_snapshot: Option<DeveloperSnapshot>,
    pub last_refresh: chrono::DateTime<chrono::Utc>,

    // Setup tab inputs.
    pub setup_password: String,
    pub setup_password_confirm: String,
    pub setup_show_hash: bool,

    // Benchmark tab inputs.
    pub bench_passes: u32,
    pub bench_dir: String,

    pub slots: Arc<Mutex<AsyncSlots>>,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let daemon = DaemonSnapshot::collect();
        let dev_snapshot = crate::provision::read_developer_snapshot(&daemon.config_path).ok();
        Self {
            tab: Tab::Setup,
            daemon,
            dev_snapshot,
            last_refresh: chrono::Utc::now(),
            setup_password: String::new(),
            setup_password_confirm: String::new(),
            setup_show_hash: false,
            bench_passes: 3,
            bench_dir: String::new(),
            slots: Arc::new(Mutex::new(AsyncSlots::default())),
        }
    }

    pub fn refresh_state(&mut self) {
        self.daemon = DaemonSnapshot::collect();
        self.dev_snapshot =
            crate::provision::read_developer_snapshot(&self.daemon.config_path).ok();
        self.last_refresh = chrono::Utc::now();
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Repaint while async work is in flight so the log fills in real time.
        let busy = {
            let s = self.slots.lock().unwrap();
            s.setup_busy || s.benchmark_busy
        };
        if busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Sentinella Dev Console");
                ui.add_space(16.0);
                ui.selectable_value(&mut self.tab, Tab::Setup, "Setup");
                ui.selectable_value(&mut self.tab, Tab::Benchmark, "Benchmark");
                ui.add_space(16.0);
                if ui.button("⟳ Refresh").clicked() {
                    self.refresh_state();
                }
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(if self.daemon.service_running {
                    "🟢 daemon running"
                } else if self.daemon.service_present {
                    "🟡 daemon installed, stopped"
                } else {
                    "🔴 daemon not installed"
                });
                if let Some(v) = &self.daemon.version {
                    ui.separator();
                    ui.label(format!("v{v}"));
                }
                if let Some(u) = self.daemon.uptime_secs {
                    ui.separator();
                    ui.label(format!("uptime {}s", u));
                }
                if !crate::daemon::is_elevated() {
                    ui.separator();
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 140, 60),
                        "⚠ NOT elevated — service ops will fail. Restart as Admin.",
                    );
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Setup => crate::tab_setup::draw(ui, self),
            Tab::Benchmark => crate::tab_benchmark::draw(ui, self),
        });
    }
}

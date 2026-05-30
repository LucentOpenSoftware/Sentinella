//! Benchmark tab — runs `argusd.exe benchmark --json` and renders the report.

use crate::app::App;
use crate::benchmark::{self, BenchmarkOutcome};

pub fn draw(ui: &mut egui::Ui, app: &mut App) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.label(format!(
            "argusd: {}",
            app.daemon
                .argusd_path
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(not found — install Sentinella first)".into())
        ));
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Passes:");
            ui.add(egui::DragValue::new(&mut app.bench_passes).range(1..=10));
            ui.label("(timed; one warm-up runs first)");
        });
        ui.horizontal(|ui| {
            ui.label("Corpus dir (optional):");
            ui.add(egui::TextEdit::singleline(&mut app.bench_dir).hint_text("leave empty for deterministic safe corpus"));
        });

        ui.add_space(8.0);

        let busy = is_busy(app);
        let can_run = app.daemon.argusd_path.is_some() && !busy;

        if ui
            .add_enabled(can_run, egui::Button::new(if busy { "Running…" } else { "▶ Run benchmark" }))
            .clicked()
        {
            spawn_benchmark(app);
        }

        ui.add_space(12.0);
        ui.separator();
        ui.heading("Result");

        let (result, raw) = {
            let s = app.slots.lock().unwrap();
            (s.benchmark_result.clone(), s.benchmark_raw_json.clone())
        };
        match result {
            None => {
                ui.label("(no run yet)");
            }
            Some(BenchmarkOutcome::Failed { stderr, exit }) => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 80, 80),
                    format!("argusd exited with {exit:?}"),
                );
                ui.label("stderr:");
                ui.monospace(stderr);
            }
            Some(BenchmarkOutcome::Ok(r)) => {
                egui::Grid::new("bench_result").striped(true).show(ui, |ui| {
                    ui.label("Engine version:");
                    ui.label(&r.engine_version);
                    ui.end_row();
                    ui.label("Passes:");
                    ui.label(r.passes.to_string());
                    ui.end_row();
                    ui.label("Corpus:");
                    ui.label(format!(
                        "{} files / {:.2} MB",
                        r.corpus_files,
                        r.corpus_bytes as f64 / (1024.0 * 1024.0)
                    ));
                    ui.end_row();
                    ui.label("Throughput:");
                    ui.label(format!(
                        "{:.1} files/sec · {:.1} MB/sec",
                        r.files_per_sec, r.mb_per_sec
                    ));
                    ui.end_row();
                    ui.label("Latency (per file):");
                    ui.label(format!(
                        "p50 {} µs · p95 {} µs · max {} µs · mean {} µs",
                        r.p50_us, r.p95_us, r.max_us, r.mean_us
                    ));
                    ui.end_row();
                    ui.label("Performance Index:");
                    ui.colored_label(
                        if r.performance_index >= 100.0 {
                            egui::Color32::from_rgb(80, 200, 120)
                        } else if r.performance_index >= 50.0 {
                            egui::Color32::from_rgb(220, 190, 80)
                        } else {
                            egui::Color32::from_rgb(220, 100, 80)
                        },
                        format!("{:.1}", r.performance_index),
                    );
                    ui.end_row();
                    ui.label("CPU cores:");
                    ui.label(r.logical_cores.to_string());
                    ui.end_row();
                    ui.label("SIMD:");
                    ui.label(if r.simd.is_empty() {
                        "—".into()
                    } else {
                        r.simd.join(", ")
                    });
                    ui.end_row();
                });

                if !r.extra.is_empty() {
                    ui.collapsing("Extra fields (raw)", |ui| {
                        ui.monospace(
                            serde_json::to_string_pretty(&r.extra).unwrap_or_default(),
                        );
                    });
                }
            }
        }

        if let Some(raw) = raw {
            ui.add_space(8.0);
            if ui.button("Save raw JSON…").clicked() {
                save_raw_to_temp(&raw);
            }
        }

        ui.add_space(12.0);
        ui.separator();
        ui.heading("Log");
        let log_text = {
            let s = app.slots.lock().unwrap();
            s.benchmark_log.join("\n")
        };
        egui::ScrollArea::vertical()
            .max_height(160.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.monospace(if log_text.is_empty() { "—" } else { &log_text });
            });
    });
}

fn is_busy(app: &App) -> bool {
    let s = app.slots.lock().unwrap();
    s.benchmark_busy
}

fn spawn_benchmark(app: &mut App) {
    let Some(argusd) = app.daemon.argusd_path.clone() else { return };
    let passes = app.bench_passes;
    let dir = if app.bench_dir.trim().is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(app.bench_dir.trim()))
    };
    let slots = app.slots.clone();
    {
        let mut s = slots.lock().unwrap();
        s.benchmark_busy = true;
        s.benchmark_result = None;
        s.benchmark_raw_json = None;
        s.benchmark_log.push(stamp(&format!(
            "spawning {} benchmark --passes {passes}",
            argusd.display()
        )));
    }
    std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let out = benchmark::run_benchmark(&argusd, passes, dir.as_deref());
        let elapsed = start.elapsed();
        let mut s = slots.lock().unwrap();
        match out {
            Ok(outcome) => {
                s.benchmark_log
                    .push(stamp(&format!("✓ finished in {:.1}s", elapsed.as_secs_f64())));
                if let BenchmarkOutcome::Ok(ref r) = outcome {
                    s.benchmark_raw_json =
                        Some(serde_json::to_string_pretty(r).unwrap_or_default());
                }
                s.benchmark_result = Some(outcome);
            }
            Err(e) => {
                s.benchmark_log.push(stamp(&format!("✖ {e}")));
            }
        }
        s.benchmark_busy = false;
    });
}

fn save_raw_to_temp(raw: &str) {
    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let path = std::env::temp_dir().join(format!("sentinella-bench-{ts}.json"));
    if let Err(e) = std::fs::write(&path, raw) {
        eprintln!("failed to write {}: {e}", path.display());
    } else {
        // Best-effort open in Explorer.
        let _ = std::process::Command::new("explorer").arg(&path).spawn();
    }
}

fn stamp(line: &str) -> String {
    format!(
        "[{}] {line}",
        chrono::Utc::now().format("%H:%M:%S")
    )
}

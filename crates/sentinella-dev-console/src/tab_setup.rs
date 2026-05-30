//! Setup tab — Developer Mode provisioning + live state mirror.

use crate::app::App;
use crate::daemon;
use crate::provision::{self, DeveloperPatchOwned};

pub fn draw(ui: &mut egui::Ui, app: &mut App) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.label(format!("Config: {}", app.daemon.config_path.display()));
        ui.separator();

        if let Some(snap) = &app.dev_snapshot {
            egui::Grid::new("dev_state").striped(true).show(ui, |ui| {
                ui.label("Password provisioned:");
                ui.label(if snap.has_password { "✅ yes" } else { "❌ no" });
                ui.end_row();
                ui.label("Developer mode enabled:");
                ui.label(if snap.enabled { "✅ yes" } else { "❌ no" });
                ui.end_row();
                ui.label("Telemetry enabled:");
                ui.label(if snap.telemetry_enabled { "✅ yes" } else { "❌ no" });
                ui.end_row();
            });
        } else {
            ui.colored_label(
                egui::Color32::YELLOW,
                "could not read config — daemon may not be installed yet",
            );
        }

        ui.add_space(12.0);
        ui.separator();
        ui.heading("Provision password");

        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut app.setup_password).password(!app.setup_show_hash));
        });
        ui.horizontal(|ui| {
            ui.label("Confirm: ");
            ui.add(egui::TextEdit::singleline(&mut app.setup_password_confirm).password(!app.setup_show_hash));
        });
        ui.checkbox(&mut app.setup_show_hash, "show password + hash preview");

        let matches = !app.setup_password.is_empty()
            && app.setup_password == app.setup_password_confirm;
        let hash = if app.setup_password.is_empty() {
            String::new()
        } else {
            provision::sha256_hex(&app.setup_password)
        };

        if app.setup_show_hash && !hash.is_empty() {
            ui.label(format!("SHA-256: {hash}"));
        }
        if !app.setup_password.is_empty() && !matches {
            ui.colored_label(egui::Color32::from_rgb(220, 140, 60), "passwords do not match");
        }

        ui.add_space(8.0);

        let mut clicked_provision = false;
        let mut clicked_disable = false;
        let mut clicked_enable_existing = false;
        let mut clicked_revoke = false;

        ui.horizontal(|ui| {
            let provision_enabled = matches && !is_busy(app);
            if ui
                .add_enabled(provision_enabled, egui::Button::new("Provision + enable"))
                .on_hover_text("Writes password hash, sets enabled=true, telemetry=true, restarts daemon")
                .clicked()
            {
                clicked_provision = true;
            }
            if ui
                .add_enabled(
                    app.dev_snapshot.as_ref().map(|s| s.has_password).unwrap_or(false) && !is_busy(app),
                    egui::Button::new("Enable (existing pwd)"),
                )
                .clicked()
            {
                clicked_enable_existing = true;
            }
            if ui
                .add_enabled(
                    app.dev_snapshot.as_ref().map(|s| s.enabled).unwrap_or(false) && !is_busy(app),
                    egui::Button::new("Disable"),
                )
                .clicked()
            {
                clicked_disable = true;
            }
            if ui
                .add_enabled(!is_busy(app), egui::Button::new("Revoke password"))
                .on_hover_text("Clears password hash AND disables developer mode. Cannot be undone without re-provisioning.")
                .clicked()
            {
                clicked_revoke = true;
            }
        });

        if clicked_provision {
            spawn_apply(
                app,
                DeveloperPatchOwned {
                    set_password_hash: Some(hash.clone()),
                    enabled: Some(true),
                    telemetry_enabled: Some(true),
                },
                "provisioned password + enabled developer mode",
            );
            app.setup_password.clear();
            app.setup_password_confirm.clear();
        }
        if clicked_enable_existing {
            spawn_apply(
                app,
                DeveloperPatchOwned {
                    set_password_hash: None,
                    enabled: Some(true),
                    telemetry_enabled: None,
                },
                "developer mode enabled",
            );
        }
        if clicked_disable {
            spawn_apply(
                app,
                DeveloperPatchOwned {
                    set_password_hash: None,
                    enabled: Some(false),
                    telemetry_enabled: None,
                },
                "developer mode disabled",
            );
        }
        if clicked_revoke {
            spawn_apply(
                app,
                DeveloperPatchOwned {
                    set_password_hash: Some(String::new()),
                    enabled: Some(false),
                    telemetry_enabled: None,
                },
                "password revoked",
            );
            app.setup_password.clear();
            app.setup_password_confirm.clear();
        }

        ui.add_space(12.0);
        ui.separator();
        ui.heading("Log");
        let log_text = {
            let slots = app.slots.lock().unwrap();
            slots.setup_log.join("\n")
        };
        egui::ScrollArea::vertical()
            .max_height(200.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.monospace(if log_text.is_empty() { "—" } else { &log_text });
            });
    });
}

fn is_busy(app: &App) -> bool {
    let s = app.slots.lock().unwrap();
    s.setup_busy
}

fn spawn_apply(app: &mut App, patch: DeveloperPatchOwned, success_msg: &'static str) {
    let path = app.daemon.config_path.clone();
    let slots = app.slots.clone();
    {
        let mut s = slots.lock().unwrap();
        s.setup_busy = true;
        s.setup_log.push(stamp("applying patch…"));
    }
    std::thread::spawn(move || {
        let push = |line: String| {
            let mut s = slots.lock().unwrap();
            s.setup_log.push(stamp(&line));
            // Cap the log so a long-running session doesn't grow without bound.
            if s.setup_log.len() > 200 {
                let extra = s.setup_log.len() - 200;
                s.setup_log.drain(0..extra);
            }
        };

        match provision::patch_developer_section(&path, &patch) {
            Ok(new_toml) => match provision::atomic_write(&path, &new_toml) {
                Ok(()) => push(format!("wrote {}", path.display())),
                Err(e) => {
                    push(format!("✖ atomic_write failed: {e}"));
                    slots.lock().unwrap().setup_busy = false;
                    return;
                }
            },
            Err(e) => {
                push(format!("✖ patch failed: {e}"));
                slots.lock().unwrap().setup_busy = false;
                return;
            }
        }
        push("restarting SentinellaDaemon…".into());
        match daemon::restart_service() {
            Ok(_) => push(format!("✓ {success_msg}")),
            Err(e) => push(format!("✖ service restart failed: {e}")),
        }
        slots.lock().unwrap().setup_busy = false;
    });
}

fn stamp(line: &str) -> String {
    format!(
        "[{}] {line}",
        chrono::Utc::now().format("%H:%M:%S")
    )
}

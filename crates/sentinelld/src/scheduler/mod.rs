//! Scheduler — automated scans, signature updates, quarantine cleanup.
//!
//! Runs in a dedicated thread, checks every 60 seconds for due tasks.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tracing::{debug, info, warn};

pub struct Scheduler {
    running: Arc<AtomicBool>,
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl Scheduler {
    pub fn start(state: Arc<crate::ipc::AppState>) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&running);
        let thread = std::thread::spawn(move || scheduler_loop(state, r));
        info!("scheduler started");
        Self {
            running,
            _thread: Some(thread),
        }
    }

    #[allow(dead_code)]
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

fn scheduler_loop(state: Arc<crate::ipc::AppState>, running: Arc<AtomicBool>) {
    let mut last_scan_day: Option<u32> = None;
    let mut last_cleanup_day: Option<u32> = None;
    let mut last_update_hour: Option<(u32, u32)> = None; // (day, hour)

    while running.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_secs(60));
        if !running.load(Ordering::Relaxed) {
            break;
        }

        let now = chrono::Local::now();
        let hour = now.format("%H").to_string().parse::<u32>().unwrap_or(0);
        let day = now.format("%j").to_string().parse::<u32>().unwrap_or(0);

        // ── Auto-update signatures (every N hours) ─────────────
        let config = crate::config::Config::load(None).unwrap_or_default();
        if config.auto_update {
            let interval = config.update_interval_hours.max(1);
            let should_update = match last_update_hour {
                Some((d, h)) => {
                    if d != day {
                        true
                    } else {
                        hour >= h + interval
                    }
                }
                None => hour % interval == 0, // Run on interval boundaries
            };

            if should_update {
                last_update_hour = Some((day, hour));
                debug!("scheduler: auto-update triggered");
                let result = state.start_update();
                let ok = result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                if ok {
                    info!("scheduler: auto-update started in background");
                } else {
                    let err = result
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    warn!(err, "scheduler: auto-update failed to start");
                }
            }
        }

        // ── Scheduled scan ──────────────────────────────────────
        if config.scheduled_scan_enabled
            && hour == config.scheduled_scan_hour
            && last_scan_day != Some(day)
        {
            last_scan_day = Some(day);
            let status = state.scan_status();
            if !status.running {
                let scan_type = &config.scheduled_scan_type;
                info!(scan_type, hour, "scheduler: scheduled scan");
                state.log_activity(
                    "info",
                    "scheduler",
                    &format!("Scheduled {} scan started", scan_type),
                    &format!("{:02}:00", config.scheduled_scan_hour),
                    None,
                );
                let _ = state.start_scan(scan_type, None);
            }
        }

        // ── Ecosystem lifecycle maintenance ────────────────────
        // Runs every cycle: transitions Active→Cooling→Expired, prunes expired.
        state.ecosystem.expire();

        // ── Working set residency management ──────────────────
        // Trims working set after quiet periods to keep Task Manager
        // appearance lightweight. Respects active scans and cooldown.
        state.check_residency_trim();

        // ── Quarantine retention cleanup at 4 AM ───────────────
        if hour == 4 && last_cleanup_day != Some(day) {
            last_cleanup_day = Some(day);
            let retention_secs: i64 = config.quarantine_retention_days as i64 * 86400;
            let cutoff = chrono::Utc::now().timestamp() - retention_secs;
            let items = state.quarantine_list();
            let mut cleaned = 0u32;
            for item in &items {
                if item.quarantined_at < cutoff {
                    if state.quarantine_delete(&item.quarantine_id).is_ok() {
                        cleaned += 1;
                    }
                }
            }
            if cleaned > 0 {
                info!(cleaned, "scheduler: quarantine cleanup");
                state.log_activity(
                    "info",
                    "scheduler",
                    &format!("Removed {cleaned} expired quarantine items"),
                    "",
                    None,
                );
            }
        }
    }

    info!("scheduler stopped");
}

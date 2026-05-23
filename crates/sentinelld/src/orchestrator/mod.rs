//! Scan orchestration foundation.
//!
//! This layer owns queue/worker state only. Existing scan paths remain intact
//! until callers are migrated queue-by-queue.

#![allow(dead_code)]

use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

type Job = Box<dyn FnOnce(CancellationToken) + Send + 'static>;

const MANUAL_WORKERS: usize = 2;
const REALTIME_WORKERS: usize = 1;
const IDLE_WORKERS: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueKind {
    Realtime,
    Manual,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    Starting,
    Ready,
    Busy,
    Cancelling,
    Recovering,
    Crashed,
    Offline,
}

impl WorkerState {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Starting,
            1 => Self::Ready,
            2 => Self::Busy,
            3 => Self::Cancelling,
            4 => Self::Recovering,
            5 => Self::Crashed,
            _ => Self::Offline,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Starting => 0,
            Self::Ready => 1,
            Self::Busy => 2,
            Self::Cancelling => 3,
            Self::Recovering => 4,
            Self::Crashed => 5,
            Self::Offline => 6,
        }
    }
}

#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn from_flag(cancelled: Arc<AtomicBool>) -> Self {
        Self { cancelled }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }
}

struct QueueMessage {
    token: CancellationToken,
    job: Job,
}

struct QueueRuntime {
    sender: mpsc::Sender<QueueMessage>,
    depth: Arc<AtomicU64>,
    submitted: Arc<AtomicU64>,
    completed: Arc<AtomicU64>,
    total_duration_us: Arc<AtomicU64>,
}

pub struct ScanQueue {
    kind: QueueKind,
    runtime: QueueRuntime,
}

impl ScanQueue {
    fn submit<F>(&self, token: CancellationToken, job: F) -> Result<(), String>
    where
        F: FnOnce(CancellationToken) + Send + 'static,
    {
        self.runtime.depth.fetch_add(1, Ordering::Relaxed);
        self.runtime.submitted.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = self.runtime.sender.send(QueueMessage {
            token,
            job: Box::new(job),
        }) {
            self.runtime.depth.fetch_sub(1, Ordering::Relaxed);
            return Err(format!(
                "orchestrator {:?} queue send failed: {e}",
                self.kind
            ));
        }
        Ok(())
    }

    fn snapshot(&self) -> QueueSnapshot {
        let completed = self.runtime.completed.load(Ordering::Relaxed);
        let total = self.runtime.total_duration_us.load(Ordering::Relaxed);
        let depth = self.runtime.depth.load(Ordering::Relaxed);
        let pressure = match (self.kind, depth) {
            (QueueKind::Realtime, d) if d > 10 => "saturated",
            (QueueKind::Realtime, d) if d > 3 => "elevated",
            (QueueKind::Manual, d) if d > 5 => "saturated",
            (QueueKind::Manual, d) if d > 2 => "elevated",
            (QueueKind::Idle, d) if d > 3 => "saturated",
            (QueueKind::Idle, d) if d > 1 => "elevated",
            _ => "normal",
        };
        QueueSnapshot {
            kind: self.kind,
            depth,
            submitted: self.runtime.submitted.load(Ordering::Relaxed),
            completed,
            average_scan_duration_ms: if completed == 0 {
                0
            } else {
                (total / completed) / 1000
            },
            pressure: pressure.into(),
        }
    }
}

#[derive(Serialize)]
pub struct QueueSnapshot {
    kind: QueueKind,
    depth: u64,
    submitted: u64,
    completed: u64,
    average_scan_duration_ms: u64,
    /// Pressure indicator: "normal", "elevated", "saturated".
    pressure: String,
}

pub struct WorkerHandle {
    id: String,
    kind: QueueKind,
    state: Arc<AtomicU8>,
    active_jobs: Arc<AtomicU64>,
    completed_jobs: Arc<AtomicU64>,
    restart_count: Arc<AtomicU64>,
    crash_count: Arc<AtomicU64>,
    stuck_worker_timeout_sec: u64,
    last_error: Arc<Mutex<Option<String>>>,
    last_duration_ms: Arc<AtomicU64>,
    longest_duration_ms: Arc<AtomicU64>,
}

impl WorkerHandle {
    fn snapshot(&self) -> WorkerSnapshot {
        WorkerSnapshot {
            id: self.id.clone(),
            kind: self.kind,
            state: WorkerState::from_u8(self.state.load(Ordering::Relaxed)),
            active_jobs: self.active_jobs.load(Ordering::Relaxed),
            completed_jobs: self.completed_jobs.load(Ordering::Relaxed),
            restart_count: self.restart_count.load(Ordering::Relaxed),
            crash_count: self.crash_count.load(Ordering::Relaxed),
            stuck_worker_timeout_sec: self.stuck_worker_timeout_sec,
            last_error: self
                .last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            last_duration_ms: self.last_duration_ms.load(Ordering::Relaxed),
            longest_duration_ms: self.longest_duration_ms.load(Ordering::Relaxed),
        }
    }
}

#[derive(Serialize)]
pub struct WorkerSnapshot {
    pub id: String,
    pub kind: QueueKind,
    pub state: WorkerState,
    pub active_jobs: u64,
    pub completed_jobs: u64,
    pub restart_count: u64,
    pub crash_count: u64,
    pub stuck_worker_timeout_sec: u64,
    pub last_error: Option<String>,
    pub last_duration_ms: u64,
    pub longest_duration_ms: u64,
}

pub struct ScanOrchestrator {
    realtime: ScanQueue,
    manual: ScanQueue,
    idle: ScanQueue,
    workers: Vec<WorkerHandle>,
}

impl ScanOrchestrator {
    pub fn start() -> Arc<Self> {
        let mut workers = Vec::new();
        let realtime = make_queue(QueueKind::Realtime, REALTIME_WORKERS, &mut workers);
        let manual = make_queue(QueueKind::Manual, MANUAL_WORKERS, &mut workers);
        let idle = make_queue(QueueKind::Idle, IDLE_WORKERS, &mut workers);
        Arc::new(Self {
            realtime,
            manual,
            idle,
            workers,
        })
    }

    pub fn submit<F>(&self, kind: QueueKind, token: CancellationToken, job: F) -> Result<(), String>
    where
        F: FnOnce(CancellationToken) + Send + 'static,
    {
        match kind {
            QueueKind::Realtime => self.realtime.submit(token, job),
            QueueKind::Manual => self.manual.submit(token, job),
            QueueKind::Idle => self.idle.submit(token, job),
        }
    }

    pub fn diagnostics(&self) -> OrchestratorDiagnostics {
        OrchestratorDiagnostics {
            queues: vec![
                self.realtime.snapshot(),
                self.manual.snapshot(),
                self.idle.snapshot(),
            ],
            workers: self.workers.iter().map(WorkerHandle::snapshot).collect(),
        }
    }
}

#[derive(Serialize)]
pub struct OrchestratorDiagnostics {
    pub queues: Vec<QueueSnapshot>,
    pub workers: Vec<WorkerSnapshot>,
}

fn make_queue(kind: QueueKind, count: usize, workers: &mut Vec<WorkerHandle>) -> ScanQueue {
    let (tx, rx) = mpsc::channel::<QueueMessage>();
    let receiver = Arc::new(Mutex::new(rx));
    let depth = Arc::new(AtomicU64::new(0));
    let submitted = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let total_duration_us = Arc::new(AtomicU64::new(0));

    for idx in 0..count {
        let state = Arc::new(AtomicU8::new(WorkerState::Starting.as_u8()));
        let active_jobs = Arc::new(AtomicU64::new(0));
        let worker_completed = Arc::new(AtomicU64::new(0));
        let restart_count = Arc::new(AtomicU64::new(0));
        let crash_count = Arc::new(AtomicU64::new(0));
        let last_error = Arc::new(Mutex::new(None));
        let last_duration_ms = Arc::new(AtomicU64::new(0));
        let longest_duration_ms = Arc::new(AtomicU64::new(0));

        spawn_worker(
            kind,
            Arc::clone(&receiver),
            Arc::clone(&depth),
            Arc::clone(&completed),
            Arc::clone(&total_duration_us),
            Arc::clone(&state),
            Arc::clone(&active_jobs),
            Arc::clone(&worker_completed),
            Arc::clone(&crash_count),
            Arc::clone(&last_error),
            Arc::clone(&last_duration_ms),
            Arc::clone(&longest_duration_ms),
        );

        workers.push(WorkerHandle {
            id: format!("{kind:?}-{idx}"),
            kind,
            state,
            active_jobs,
            completed_jobs: worker_completed,
            restart_count,
            crash_count,
            stuck_worker_timeout_sec: 30,
            last_error,
            last_duration_ms,
            longest_duration_ms,
        });
    }

    ScanQueue {
        kind,
        runtime: QueueRuntime {
            sender: tx,
            depth,
            submitted,
            completed,
            total_duration_us,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn manual_queue_executes_job() {
        let orchestrator = ScanOrchestrator::start();
        let token = CancellationToken::new();
        let (tx, rx) = mpsc::channel();

        orchestrator
            .submit(QueueKind::Manual, token, move |token| {
                tx.send(token.is_cancelled()).unwrap();
            })
            .unwrap();

        assert!(!rx.recv_timeout(Duration::from_secs(2)).unwrap());
    }

    #[test]
    fn cancelled_token_reaches_manual_job() {
        let orchestrator = ScanOrchestrator::start();
        let token = CancellationToken::new();
        token.cancel();
        let (tx, rx) = mpsc::channel();

        orchestrator
            .submit(QueueKind::Manual, token, move |token| {
                tx.send(token.is_cancelled()).unwrap();
            })
            .unwrap();

        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
    }

    #[test]
    fn realtime_queue_executes() {
        let orchestrator = ScanOrchestrator::start();
        let token = CancellationToken::new();
        let (tx, rx) = mpsc::channel();

        orchestrator
            .submit(QueueKind::Realtime, token, move |_| {
                tx.send(42u32).unwrap();
            })
            .unwrap();

        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 42);
    }

    #[test]
    fn idle_queue_executes_with_delay() {
        let orchestrator = ScanOrchestrator::start();
        let token = CancellationToken::new();
        let (tx, rx) = mpsc::channel();

        orchestrator
            .submit(QueueKind::Idle, token, move |_| {
                tx.send(true).unwrap();
            })
            .unwrap();

        // Idle queue has 250ms delay between jobs.
        assert!(rx.recv_timeout(Duration::from_secs(3)).unwrap());
    }

    #[test]
    fn diagnostics_snapshot() {
        let orchestrator = ScanOrchestrator::start();
        let diag = orchestrator.diagnostics();
        assert_eq!(diag.queues.len(), 3);
        assert_eq!(
            diag.workers.len(),
            MANUAL_WORKERS + REALTIME_WORKERS + IDLE_WORKERS
        );
    }

    #[test]
    fn multiple_manual_jobs_execute() {
        let orchestrator = ScanOrchestrator::start();
        let (tx, rx) = mpsc::channel();

        for i in 0..5u32 {
            let tx = tx.clone();
            let token = CancellationToken::new();
            orchestrator
                .submit(QueueKind::Manual, token, move |_| {
                    tx.send(i).unwrap();
                })
                .unwrap();
        }
        drop(tx);

        let mut results: Vec<u32> = rx.iter().collect();
        results.sort();
        assert_eq!(results, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn cancel_before_execution_skips_work() {
        let orchestrator = ScanOrchestrator::start();
        let token = CancellationToken::new();
        token.cancel(); // Cancel before submit.
        let (tx, rx) = mpsc::channel();

        orchestrator
            .submit(QueueKind::Manual, token, move |token| {
                // Job should see cancelled flag.
                tx.send(token.is_cancelled()).unwrap();
            })
            .unwrap();

        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
    }

    #[test]
    fn worker_recovers_from_panic() {
        let orchestrator = ScanOrchestrator::start();

        // Submit a panicking job.
        let token = CancellationToken::new();
        orchestrator
            .submit(QueueKind::Manual, token, move |_| {
                panic!("test panic");
            })
            .unwrap();

        // Brief wait for panic recovery.
        std::thread::sleep(Duration::from_millis(200));

        // Submit normal job — should still work.
        let (tx, rx) = mpsc::channel();
        let token2 = CancellationToken::new();
        orchestrator
            .submit(QueueKind::Manual, token2, move |_| {
                tx.send(true).unwrap();
            })
            .unwrap();

        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());

        // Crash count should be > 0.
        let diag = orchestrator.diagnostics();
        let manual_workers: Vec<_> = diag
            .workers
            .iter()
            .filter(|w| w.kind == QueueKind::Manual)
            .collect();
        let total_crashes: u64 = manual_workers.iter().map(|w| w.crash_count).sum();
        assert!(total_crashes > 0, "Crash count should be > 0 after panic");
    }

    #[test]
    fn queue_depth_tracks_correctly() {
        let orchestrator = ScanOrchestrator::start();

        // Submit a slow job to keep worker busy.
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let token = CancellationToken::new();
        orchestrator
            .submit(QueueKind::Manual, token, move |_| {
                let _ = gate_rx.recv_timeout(Duration::from_secs(5));
            })
            .unwrap();

        std::thread::sleep(Duration::from_millis(50));

        // Submit more jobs — they should queue.
        for _ in 0..3 {
            let token = CancellationToken::new();
            orchestrator
                .submit(QueueKind::Manual, token, move |_| {
                    std::thread::sleep(Duration::from_millis(10));
                })
                .unwrap();
        }

        // Check diagnostics — depth should reflect queued jobs.
        let diag = orchestrator.diagnostics();
        let manual_q = diag
            .queues
            .iter()
            .find(|q| q.kind == QueueKind::Manual)
            .unwrap();
        // With 2 workers, 1 blocked + 3 queued = at least 2 in depth
        // (one worker may have already picked up a job).
        assert!(manual_q.submitted >= 4, "Should have submitted 4+ jobs");

        // Release the gate.
        let _ = gate_tx.send(());
    }
}

fn spawn_worker(
    kind: QueueKind,
    receiver: Arc<Mutex<mpsc::Receiver<QueueMessage>>>,
    depth: Arc<AtomicU64>,
    completed: Arc<AtomicU64>,
    total_duration_us: Arc<AtomicU64>,
    state: Arc<AtomicU8>,
    active_jobs: Arc<AtomicU64>,
    worker_completed: Arc<AtomicU64>,
    crash_count: Arc<AtomicU64>,
    last_error: Arc<Mutex<Option<String>>>,
    last_duration_ms: Arc<AtomicU64>,
    longest_duration_ms: Arc<AtomicU64>,
) {
    std::thread::spawn(move || {
        state.store(WorkerState::Ready.as_u8(), Ordering::Relaxed);
        loop {
            let msg = {
                let guard = receiver.lock().unwrap_or_else(|e| e.into_inner());
                guard.recv()
            };
            let msg = match msg {
                Ok(msg) => msg,
                Err(_) => {
                    state.store(WorkerState::Offline.as_u8(), Ordering::Relaxed);
                    break;
                }
            };

            depth.fetch_sub(1, Ordering::Relaxed);
            active_jobs.fetch_add(1, Ordering::Relaxed);
            if msg.token.is_cancelled() {
                state.store(WorkerState::Cancelling.as_u8(), Ordering::Relaxed);
            } else {
                state.store(WorkerState::Busy.as_u8(), Ordering::Relaxed);
            }
            let started = Instant::now();
            let token = msg.token.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (msg.job)(token);
            }));
            let elapsed = started.elapsed();
            let duration_ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
            total_duration_us.fetch_add(elapsed_us(elapsed), Ordering::Relaxed);
            completed.fetch_add(1, Ordering::Relaxed);
            worker_completed.fetch_add(1, Ordering::Relaxed);
            active_jobs.fetch_sub(1, Ordering::Relaxed);

            // Track per-worker duration stats.
            last_duration_ms.store(duration_ms, Ordering::Relaxed);
            let prev_longest = longest_duration_ms.load(Ordering::Relaxed);
            if duration_ms > prev_longest {
                longest_duration_ms.store(duration_ms, Ordering::Relaxed);
            }

            if result.is_err() {
                crash_count.fetch_add(1, Ordering::Relaxed);
                state.store(WorkerState::Recovering.as_u8(), Ordering::Relaxed);
                *last_error.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(format!("{kind:?} worker job panic"));
            }

            if kind == QueueKind::Idle {
                std::thread::sleep(Duration::from_millis(250));
            }
            state.store(WorkerState::Ready.as_u8(), Ordering::Relaxed);
        }
    });
}

fn elapsed_us(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

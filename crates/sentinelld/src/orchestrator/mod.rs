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

/// Audit fix D: process-wide cap on concurrently-leaked stuck worker
/// threads. A worker hung inside a native ClamAV call cannot be
/// force-killed in safe Rust, so a respawn leaks the old thread until it
/// unblocks. Without a cap, sustained malformed input could spawn
/// unbounded threads. Past this many live leaks the watchdog stops
/// respawning (the pool degrades but the process is not thread-bombed).
static LEAKED_WORKERS: AtomicU64 = AtomicU64::new(0);
const MAX_LEAKED_WORKERS: u64 = 16;

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
        // Bug R3-7: previously unbounded — pathological submitter could OOM
        // the daemon with millions of pending Job closures (each Box<dyn>).
        // Cap per-queue depth at MAX_QUEUE_DEPTH; new submissions during
        // saturation get rejected so the caller learns to back off.
        const MAX_QUEUE_DEPTH: u64 = 1024;
        // Race fix: the previous `load + check + fetch_add` is a check-then-act
        // race — N concurrent submitters all see `current < cap` and each
        // fetch_add, so the queue can overshoot the cap by N. The whole point
        // of the cap is to bound memory under load; an attacker (or runaway
        // watcher) could push past it. Reserve a slot via fetch_add FIRST and
        // give it back if we were over.
        let prev = self.runtime.depth.fetch_add(1, Ordering::Relaxed);
        if prev >= MAX_QUEUE_DEPTH {
            self.runtime.depth.fetch_sub(1, Ordering::Relaxed);
            return Err(format!(
                "orchestrator {:?} queue saturated ({} pending) — rejecting submission",
                self.kind, prev
            ));
        }
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

/// Everything a worker thread needs to run — clonable so the watchdog can
/// respawn a replacement worker on the SAME queue when one gets stuck.
#[derive(Clone)]
struct WorkerCtx {
    id: String,
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
    /// Cancellation token of the job currently running (None when idle).
    /// The watchdog fires this on timeout for cooperative cancellation.
    current_token: Arc<Mutex<Option<CancellationToken>>>,
    /// Epoch-millis when the current job started; 0 = idle. Watchdog reads
    /// this to detect a worker stuck on a single job.
    job_started_ms: Arc<AtomicU64>,
    restart_count: Arc<AtomicU64>,
    stuck_worker_timeout_sec: u64,
    /// Bumped by the watchdog each time it respawns this logical worker.
    /// A running thread captures its value at spawn; if it later observes a
    /// higher generation it knows a replacement exists and self-retires
    /// (prevents two consumers on the same receiver). NOT derivable from the
    /// shared `state` field, which the replacement resets to Ready.
    generation: Arc<AtomicU64>,
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
    /// Shared with the running worker; used by the watchdog.
    current_token: Arc<Mutex<Option<CancellationToken>>>,
    job_started_ms: Arc<AtomicU64>,
    /// Full respawn context for the watchdog.
    ctx: WorkerCtx,
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
        // Audit fix B: 30s falsely killed legitimate large-archive scans.
        // With MAXSCANSIZE=400MB / MAXFILES=5000 / MAXRECURSION=10 a deep
        // nested archive can legitimately run for minutes. 300s is well
        // past any honest scan but still catches a true infinite hang.
        Self::start_with_stuck_timeout(300, Duration::from_secs(5))
    }

    /// Construct with a custom stuck-worker timeout + watchdog poll interval.
    /// Production uses 30s timeout / 5s poll; tests use small values.
    fn start_with_stuck_timeout(stuck_secs: u64, poll: Duration) -> Arc<Self> {
        let mut workers = Vec::new();
        let realtime = make_queue(QueueKind::Realtime, REALTIME_WORKERS, stuck_secs, &mut workers);
        let manual = make_queue(QueueKind::Manual, MANUAL_WORKERS, stuck_secs, &mut workers);
        let idle = make_queue(QueueKind::Idle, IDLE_WORKERS, stuck_secs, &mut workers);

        // Watchdog: detect workers stuck on a single job (e.g. ClamAV
        // looping on a malformed archive) and recover the queue.
        let watchdog_ctxs: Vec<WorkerCtx> = workers.iter().map(|w| w.ctx.clone()).collect();
        spawn_watchdog(watchdog_ctxs, poll);

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

fn make_queue(
    kind: QueueKind,
    count: usize,
    stuck_secs: u64,
    workers: &mut Vec<WorkerHandle>,
) -> ScanQueue {
    let (tx, rx) = mpsc::channel::<QueueMessage>();
    let receiver = Arc::new(Mutex::new(rx));
    let depth = Arc::new(AtomicU64::new(0));
    let submitted = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let total_duration_us = Arc::new(AtomicU64::new(0));

    for idx in 0..count {
        let ctx = WorkerCtx {
            id: format!("{kind:?}-{idx}"),
            kind,
            receiver: Arc::clone(&receiver),
            depth: Arc::clone(&depth),
            completed: Arc::clone(&completed),
            total_duration_us: Arc::clone(&total_duration_us),
            state: Arc::new(AtomicU8::new(WorkerState::Starting.as_u8())),
            active_jobs: Arc::new(AtomicU64::new(0)),
            worker_completed: Arc::new(AtomicU64::new(0)),
            crash_count: Arc::new(AtomicU64::new(0)),
            last_error: Arc::new(Mutex::new(None)),
            last_duration_ms: Arc::new(AtomicU64::new(0)),
            longest_duration_ms: Arc::new(AtomicU64::new(0)),
            current_token: Arc::new(Mutex::new(None)),
            job_started_ms: Arc::new(AtomicU64::new(0)),
            restart_count: Arc::new(AtomicU64::new(0)),
            stuck_worker_timeout_sec: stuck_secs,
            generation: Arc::new(AtomicU64::new(0)),
        };

        spawn_worker(ctx.clone());

        workers.push(WorkerHandle {
            id: ctx.id.clone(),
            kind,
            state: Arc::clone(&ctx.state),
            active_jobs: Arc::clone(&ctx.active_jobs),
            completed_jobs: Arc::clone(&ctx.worker_completed),
            restart_count: Arc::clone(&ctx.restart_count),
            crash_count: Arc::clone(&ctx.crash_count),
            stuck_worker_timeout_sec: ctx.stuck_worker_timeout_sec,
            last_error: Arc::clone(&ctx.last_error),
            last_duration_ms: Arc::clone(&ctx.last_duration_ms),
            longest_duration_ms: Arc::clone(&ctx.longest_duration_ms),
            current_token: Arc::clone(&ctx.current_token),
            job_started_ms: Arc::clone(&ctx.job_started_ms),
            ctx,
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
    fn watchdog_respawns_stuck_worker_and_drains_queue() {
        // 1s stuck timeout, 200ms poll. One realtime worker.
        let orchestrator = ScanOrchestrator::start_with_stuck_timeout(1, Duration::from_millis(200));

        // Submit a job that ignores the cancel token and blocks ~4s — this
        // wedges the single realtime worker, simulating a native ClamAV hang.
        let token = CancellationToken::new();
        orchestrator
            .submit(QueueKind::Realtime, token, move |_tok| {
                std::thread::sleep(Duration::from_secs(4));
            })
            .unwrap();

        // Give the watchdog time to detect + respawn (>1s + a poll).
        std::thread::sleep(Duration::from_millis(1600));

        // The queue must NOT be permanently starved: a new realtime job
        // should run on the replacement worker even though the original is
        // still blocked.
        let (tx, rx) = mpsc::channel();
        let token2 = CancellationToken::new();
        orchestrator
            .submit(QueueKind::Realtime, token2, move |_| {
                tx.send(true).unwrap();
            })
            .unwrap();
        assert!(
            rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            "replacement worker should drain the queue while original is stuck"
        );

        // restart_count for realtime should be >= 1.
        let diag = orchestrator.diagnostics();
        let rt_restarts: u64 = diag
            .workers
            .iter()
            .filter(|w| w.kind == QueueKind::Realtime)
            .map(|w| w.restart_count)
            .sum();
        assert!(rt_restarts >= 1, "watchdog should have respawned the stuck worker");
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

/// Monotonic millisecond clock for stuck-worker detection.
///
/// Audit fix A: previously used wall-clock `SystemTime`, so an NTP
/// correction or VM resume that jumped the clock forward >timeout would
/// falsely kill a live scan, and a backward jump would hide a real hang.
/// `Instant` is monotonic and immune to wall-clock changes.
fn monotonic_ms() -> u64 {
    use std::sync::OnceLock;
    static BASE: OnceLock<Instant> = OnceLock::new();
    let base = BASE.get_or_init(Instant::now);
    base.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn spawn_worker(ctx: WorkerCtx) {
    std::thread::spawn(move || {
        // Capture our generation. If the watchdog later respawns this
        // logical worker (bumping the generation), we self-retire so two
        // threads never consume the same receiver concurrently.
        let my_generation = ctx.generation.load(Ordering::SeqCst);
        ctx.state.store(WorkerState::Ready.as_u8(), Ordering::Relaxed);
        loop {
            // If a replacement has been spawned for us, retire before
            // grabbing another job. We were a leaked stuck thread that
            // unblocked between jobs — release our leak-budget slot.
            if ctx.generation.load(Ordering::SeqCst) != my_generation {
                LEAKED_WORKERS.fetch_sub(1, Ordering::SeqCst);
                break;
            }
            let msg = {
                let guard = ctx.receiver.lock().unwrap_or_else(|e| e.into_inner());
                guard.recv()
            };
            let msg = match msg {
                Ok(msg) => msg,
                Err(_) => {
                    ctx.state.store(WorkerState::Offline.as_u8(), Ordering::Relaxed);
                    break;
                }
            };

            ctx.depth.fetch_sub(1, Ordering::Relaxed);
            ctx.active_jobs.fetch_add(1, Ordering::Relaxed);
            if msg.token.is_cancelled() {
                ctx.state.store(WorkerState::Cancelling.as_u8(), Ordering::Relaxed);
            } else {
                ctx.state.store(WorkerState::Busy.as_u8(), Ordering::Relaxed);
            }

            // Publish current job for the watchdog BEFORE running it.
            let token = msg.token.clone();
            *ctx.current_token.lock().unwrap_or_else(|e| e.into_inner()) = Some(token.clone());
            // job_started_ms must be the LAST thing set (the watchdog uses
            // it as the "armed" signal), and non-zero. Monotonic clock.
            ctx.job_started_ms
                .store(monotonic_ms().max(1), Ordering::SeqCst);

            let started = Instant::now();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (msg.job)(token);
            }));

            // Disarm watchdog FIRST so a long post-processing tail is not
            // mistaken for a stuck job.
            ctx.job_started_ms.store(0, Ordering::SeqCst);
            *ctx.current_token.lock().unwrap_or_else(|e| e.into_inner()) = None;

            let elapsed = started.elapsed();
            let duration_ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
            ctx.total_duration_us
                .fetch_add(elapsed_us(elapsed), Ordering::Relaxed);
            ctx.completed.fetch_add(1, Ordering::Relaxed);
            ctx.worker_completed.fetch_add(1, Ordering::Relaxed);
            ctx.active_jobs.fetch_sub(1, Ordering::Relaxed);

            ctx.last_duration_ms.store(duration_ms, Ordering::Relaxed);
            ctx.longest_duration_ms
                .fetch_max(duration_ms, Ordering::Relaxed);

            if result.is_err() {
                ctx.crash_count.fetch_add(1, Ordering::Relaxed);
                ctx.state.store(WorkerState::Recovering.as_u8(), Ordering::Relaxed);
                *ctx.last_error.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(format!("{:?} worker job panic", ctx.kind));
            }

            if ctx.kind == QueueKind::Idle {
                std::thread::sleep(Duration::from_millis(250));
            }

            // If the watchdog respawned us while we were stuck, retire this
            // now-extra consumer thread instead of looping back to recv().
            // Do NOT touch `state` here — it is shared with the replacement
            // worker, which owns it now. Release our leak-budget slot.
            if ctx.generation.load(Ordering::SeqCst) != my_generation {
                LEAKED_WORKERS.fetch_sub(1, Ordering::SeqCst);
                break;
            }
            ctx.state.store(WorkerState::Ready.as_u8(), Ordering::Relaxed);
        }
    });
}

/// Watchdog: scan workers periodically; if one has been on the same job
/// past its stuck timeout, fire the job's cancel token (cooperative) and
/// spawn a replacement worker so the queue keeps draining. The stuck
/// thread is leaked until its native call returns, then it self-retires.
fn spawn_watchdog(ctxs: Vec<WorkerCtx>, poll: Duration) {
    if ctxs.is_empty() {
        return;
    }
    std::thread::Builder::new()
        .name("orch-watchdog".into())
        .spawn(move || {
            use std::collections::HashMap;
            // Last job-start timestamp we already acted on, per worker id —
            // prevents respawning repeatedly for the same stuck job.
            let mut acted: HashMap<String, u64> = HashMap::new();

            loop {
                std::thread::sleep(poll);

                for ctx in &ctxs {
                    let started = ctx.job_started_ms.load(Ordering::SeqCst);
                    if started == 0 {
                        continue; // idle
                    }
                    let now = monotonic_ms();
                    // Monotonic clock — `now >= started` always; saturating
                    // sub is belt-and-suspenders.
                    let elapsed_ms = now.saturating_sub(started);
                    let limit_ms = ctx.stuck_worker_timeout_sec.saturating_mul(1000);
                    if elapsed_ms < limit_ms {
                        continue;
                    }
                    // Already handled this exact job instance?
                    if acted.get(&ctx.id) == Some(&started) {
                        continue;
                    }

                    // Audit fix C: close the TOCTOU window. Between the read
                    // above and now the worker may have finished (disarmed).
                    // Re-read; if it changed, the worker is NOT stuck — skip.
                    if ctx.job_started_ms.load(Ordering::SeqCst) != started {
                        continue;
                    }

                    // Audit fix D: bound leaked threads. A worker stuck in a
                    // native call cannot be force-killed; we leak it until it
                    // returns. Under a sustained malformed-input attack that
                    // could spawn unbounded threads. Cap concurrent leaks;
                    // past the cap we stop respawning (queue degrades but the
                    // process is not thread-bombed).
                    if LEAKED_WORKERS.load(Ordering::SeqCst) >= MAX_LEAKED_WORKERS {
                        tracing::error!(
                            worker = ctx.id.as_str(),
                            "orchestrator watchdog: leaked-worker budget exhausted — NOT respawning (pool degraded)"
                        );
                        // Still record so we don't spin on this one each tick.
                        acted.insert(ctx.id.clone(), started);
                        continue;
                    }

                    acted.insert(ctx.id.clone(), started);

                    tracing::error!(
                        worker = ctx.id.as_str(),
                        elapsed_ms,
                        limit_ms,
                        "orchestrator watchdog: worker stuck — cancelling + respawning"
                    );

                    // Cooperative cancel (works for scan jobs that poll the token).
                    if let Some(tok) = ctx
                        .current_token
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_ref()
                    {
                        tok.cancel();
                    }

                    ctx.state.store(WorkerState::Crashed.as_u8(), Ordering::SeqCst);
                    ctx.restart_count.fetch_add(1, Ordering::Relaxed);
                    *ctx.last_error.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(format!("worker stuck >{}s — respawned", ctx.stuck_worker_timeout_sec));

                    // Account the soon-to-be-leaked stuck thread, then bump
                    // generation BEFORE respawn so it self-retires (and
                    // decrements the leak counter) once it unblocks.
                    LEAKED_WORKERS.fetch_add(1, Ordering::SeqCst);
                    ctx.generation.fetch_add(1, Ordering::SeqCst);
                    spawn_worker(ctx.clone());
                }

                // Prune `acted` entries for workers that have since gone idle
                // so a future stuck job on the same worker id is detected.
                acted.retain(|id, ts| {
                    ctxs.iter()
                        .find(|c| &c.id == id)
                        .map(|c| c.job_started_ms.load(Ordering::SeqCst) == *ts)
                        .unwrap_or(false)
                });
            }
        })
        .ok();
}

fn elapsed_us(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

//! ETW layout validation probe — diagnostic binary for Sentinella.
//!
//! Validates ETW consumer struct layouts and callback mechanisms safely,
//! completely isolated from sandboxd. If this binary crashes, sandboxd
//! is unaffected.
//!
//! Run with: `cargo run -p etw_probe` (requires admin for ETW session).
//!
//! Truthfulness contract (F-1/C-1): this probe exists to DETECT the
//! "session starts but delivers zero events" failure mode — the bug where
//! `StartTraceW` succeeds while the kernel ignores `EnableFlags` because
//! the session is not a system logger ("EnableFlags is only valid for
//! system loggers" — EVENT_TRACE_PROPERTIES, MS Learn). A previous
//! version printed `StartTraceW: SUCCESS` and then `Events received: 0`
//! with no verdict — a diagnostic blind to the bug it exists to probe.
//! The probe now uses the corrected production architecture (private
//! system-logger session: EVENT_TRACE_SYSTEM_LOGGER_MODE + private
//! Wnode.Guid), generates its own process activity, and prints an
//! explicit PASS/FAIL verdict with remediation guidance.
//!
//! Exit codes: 0 = PASS (events flowed), 1 = FAIL (session started but
//! delivered zero events — the C-1 signature), 2 = INCONCLUSIVE (session
//! or consumer could not be started, e.g. not elevated).

fn main() {
    #[cfg(not(target_os = "windows"))]
    {
        println!("ETW probe is Windows-only");
        std::process::exit(0);
    }

    #[cfg(target_os = "windows")]
    {
        std::process::exit(windows_probe::run());
    }
}

#[cfg(target_os = "windows")]
mod windows_probe {
    use std::mem::size_of;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use windows::Win32::System::Diagnostics::Etw::*;
    use windows::core::PCWSTR;

    use sentinella_common::etw_props::EventTracePropsStorage;

    // ═══════════════════════════════════════════════════════════════
    //  Session config — mirrors the corrected production architecture
    //  (sandboxd::etw_config / sentinelld etw_intake F-1 fix).
    //
    //  DEDUP FLAG (orchestrator): these constants duplicate
    //  `crates/sandboxd/src/etw_config.rs` (bin crates cannot share code).
    //  The shared builder belongs in sentinella_common::etw_props; until
    //  then, keep the three call sites bit-identical.
    // ═══════════════════════════════════════════════════════════════

    /// EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE.
    /// Without SYSTEM_LOGGER_MODE the kernel ignores EnableFlags and the
    /// session delivers zero events despite StartTraceW succeeding.
    const LOG_FILE_MODE: u32 = 0x0000_0100 | 0x0200_0000;
    /// WNODE_FLAG_TRACED_GUID.
    const WNODE_FLAGS: u32 = 0x0002_0000;
    /// EVENT_TRACE_FLAG_PROCESS — the probe only needs process events;
    /// it generates its own process activity to provoke them.
    const ENABLE_FLAGS: u32 = 0x0000_0001;
    /// Fixed private session GUID for the probe (`GUID::from_u128` byte
    /// order: {5a9c3e17-2d48-4f6b-b1a4-7e3c8d2f5b09}). MUST NOT be
    /// SystemTraceControlGuid (StartTraceW would fail with
    /// ERROR_INVALID_PARAMETER for a privately-named session) and must
    /// stay distinct from sentinelld's and sandboxd's session GUIDs —
    /// there are only 8 system-logger slots on Win8+.
    const SESSION_GUID_U128: u128 = 0x5a9c3e17_2d48_4f6b_b1a4_7e3c8d2f5b09;

    // ═══════════════════════════════════════════════════════════════
    //  Drop guard — ensures StopTraceW is called even on panic
    // ═══════════════════════════════════════════════════════════════

    struct SessionGuard {
        handle: CONTROLTRACE_HANDLE,
        session_name_wide: Vec<u16>,
        active: bool,
    }

    impl SessionGuard {
        fn new(handle: CONTROLTRACE_HANDLE, session_name_wide: Vec<u16>) -> Self {
            Self {
                handle,
                session_name_wide,
                active: true,
            }
        }

        fn stop(&mut self) {
            if !self.active {
                return;
            }
            self.active = false;
            // Aligned storage via the shared helper (was a local Vec<u64>
            // `aligned_props_storage`). Stop-by-handle needs no name
            // content; BufferSize + LoggerNameOffset are constructor-set.
            let mut stop_buf = match EventTracePropsStorage::with_extra("", None, 256) {
                Ok(s) => s,
                Err(e) => {
                    println!("  [cleanup] stop props layout failed: {e}");
                    return;
                }
            };
            let result = unsafe {
                ControlTraceW(
                    self.handle,
                    PCWSTR::null(),
                    stop_buf.props_mut(),
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            println!("  StopTraceW result: {}", result.0);
        }
    }

    impl Drop for SessionGuard {
        fn drop(&mut self) {
            if self.active {
                println!("[cleanup] Drop guard stopping stale session...");
                self.stop();
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  Main probe entry point
    // ═══════════════════════════════════════════════════════════════

    pub fn run() -> i32 {
        println!("=== Sentinella ETW Probe ===\n");
        println!("Purpose: DETECT the 'session starts but delivers zero events'");
        println!("failure mode (F-1/C-1). StartTraceW success alone means nothing.\n");

        // Global timeout: exit after 5 seconds max.
        let start = Instant::now();
        let timeout = Duration::from_secs(5);

        // (a) Print struct sizes for validation.
        print_struct_sizes();

        if start.elapsed() >= timeout {
            println!("\n[timeout] 5 seconds elapsed, exiting.");
            return 2;
        }

        // (b) Try StartTraceW as a private system-logger session.
        let session_result = try_start_trace();

        if start.elapsed() >= timeout {
            println!("\n[timeout] 5 seconds elapsed, exiting.");
            return 2;
        }

        // (c) + (d) OpenTraceW consumer + generated activity + verdict.
        match session_result {
            Some(mut guard) => {
                let events = try_open_trace(&guard, start, timeout);
                // Always clean up.
                guard.stop();

                println!("\n=== ETW Probe Complete ===");
                match events {
                    Some(n) if n > 0 => {
                        println!(
                            "VERDICT: PASS — system-logger session delivered {n} events \
                             under generated process activity."
                        );
                        0
                    }
                    Some(_) => {
                        // The exact failure mode this probe exists for.
                        println!(
                            "VERDICT: FAIL — session started but delivered 0 events \
                             under generated process activity."
                        );
                        println!("  Likely cause: session is NOT a system logger — check that");
                        println!("  LogFileMode includes EVENT_TRACE_SYSTEM_LOGGER_MODE and");
                        println!("  Wnode.Guid is a private (non-SystemTraceControlGuid) GUID.");
                        println!("  Kernel EnableFlags are ignored otherwise (EVENT_TRACE_PROPERTIES,");
                        println!("  MS Learn) — StartTraceW success is NOT evidence of a working session.");
                        1
                    }
                    None => {
                        println!(
                            "VERDICT: INCONCLUSIVE — consumer could not be opened; \
                             event flow untested."
                        );
                        2
                    }
                }
            }
            None => {
                println!("\n[skip] No active session — skipping OpenTraceW test.");
                println!("\n=== ETW Probe Complete ===");
                println!(
                    "VERDICT: INCONCLUSIVE — session did not start (run elevated?)."
                );
                2
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  (a) Struct size validation
    // ═══════════════════════════════════════════════════════════════

    fn print_struct_sizes() {
        println!("--- Struct Sizes ---");
        println!(
            "  EVENT_TRACE_PROPERTIES:  {} bytes",
            size_of::<EVENT_TRACE_PROPERTIES>()
        );
        println!(
            "  CONTROLTRACE_HANDLE:     {} bytes",
            size_of::<CONTROLTRACE_HANDLE>()
        );
        println!(
            "  EVENT_TRACE_FLAG:        {} bytes",
            size_of::<EVENT_TRACE_FLAG>()
        );
        println!(
            "  WNODE_HEADER:            {} bytes",
            size_of::<WNODE_HEADER>()
        );
        println!(
            "  EVENT_RECORD:            {} bytes",
            size_of::<EVENT_RECORD>()
        );
        println!(
            "  EVENT_HEADER:            {} bytes",
            size_of::<EVENT_HEADER>()
        );
        println!(
            "  EVENT_DESCRIPTOR:        {} bytes",
            size_of::<EVENT_DESCRIPTOR>()
        );

        // Consumer-side structs (require Win32_System_Time feature).
        println!(
            "  EVENT_TRACE_LOGFILEW:    {} bytes",
            size_of::<EVENT_TRACE_LOGFILEW>()
        );
        println!(
            "  EVENT_TRACE:             {} bytes",
            size_of::<EVENT_TRACE>()
        );
        println!(
            "  TRACE_LOGFILE_HEADER:    {} bytes",
            size_of::<TRACE_LOGFILE_HEADER>()
        );
        println!(
            "  PROCESSTRACE_HANDLE:     {} bytes",
            size_of::<PROCESSTRACE_HANDLE>()
        );

        println!();
    }

    // ═══════════════════════════════════════════════════════════════
    //  (b) StartTraceW as a private system-logger session
    // ═══════════════════════════════════════════════════════════════

    /// Fill the session-semantic fields of a fresh props buffer from the
    /// probe's config constants. Buffer layout (offsets, names,
    /// BufferSize) is owned by EventTracePropsStorage.
    fn apply_session_config(props: &mut EVENT_TRACE_PROPERTIES) {
        props.Wnode.ClientContext = 1; // QPC timestamps
        props.Wnode.Flags = WNODE_FLAGS;
        props.Wnode.Guid = windows::core::GUID::from_u128(SESSION_GUID_U128);
        props.LogFileMode = LOG_FILE_MODE;
        props.EnableFlags = EVENT_TRACE_FLAG(ENABLE_FLAGS);
    }

    fn try_start_trace() -> Option<SessionGuard> {
        println!("--- StartTraceW Test (private system-logger session) ---");

        let session_name = format!("SentinellaProbe_{}", std::process::id());
        let session_name_wide: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Report the exact config under test — the verdict below is only
        // meaningful against these bits.
        println!("  Session name: {session_name}");
        println!(
            "  LogFileMode:  0x{LOG_FILE_MODE:08x} (REAL_TIME 0x100 | SYSTEM_LOGGER_MODE 0x02000000)"
        );
        println!("  Wnode.Flags:  0x{WNODE_FLAGS:08x} (WNODE_FLAG_TRACED_GUID)");
        println!("  Wnode.Guid:   {{5a9c3e17-2d48-4f6b-b1a4-7e3c8d2f5b09}} (private, fixed)");
        println!("  EnableFlags:  0x{ENABLE_FLAGS:08x} (EVENT_TRACE_FLAG_PROCESS)");

        // Aligned EVENT_TRACE_PROPERTIES storage via the shared helper —
        // sets Wnode.BufferSize, LoggerNameOffset and writes the
        // terminated UTF-16 session name into the buffer.
        let mut props_storage = match EventTracePropsStorage::with_extra(&session_name, None, 256)
        {
            Ok(s) => s,
            Err(e) => {
                println!("  ETW props layout failed: {e}");
                return None;
            }
        };
        apply_session_config(props_storage.props_mut());

        let mut session_handle = CONTROLTRACE_HANDLE::default();

        let result = unsafe {
            StartTraceW(
                &mut session_handle,
                PCWSTR(session_name_wide.as_ptr()),
                props_storage.props_mut(),
            )
        };

        match result.0 {
            0 => {
                // NOTE: success here is NOT the verdict — the old probe
                // stopped here. Events must actually flow (see below).
                println!("  StartTraceW: SUCCESS (handle={:?}) — not yet a PASS", session_handle);
                println!();
                Some(SessionGuard::new(session_handle, session_name_wide))
            }
            5 => {
                // ERROR_ACCESS_DENIED
                println!("  StartTraceW: ERROR_ACCESS_DENIED (5)");
                println!("  Need admin — run as Administrator to test ETW sessions.");
                println!();
                None
            }
            183 => {
                // ERROR_ALREADY_EXISTS — stop stale session and retry.
                println!("  StartTraceW: ERROR_ALREADY_EXISTS (183) — stopping stale session...");
                stop_stale_session(&session_name_wide);

                // Rebuild props buffer for retry — identical config.
                let mut retry_storage =
                    match EventTracePropsStorage::with_extra(&session_name, None, 256) {
                        Ok(s) => s,
                        Err(e) => {
                            println!("  ETW props layout failed: {e}");
                            return None;
                        }
                    };
                apply_session_config(retry_storage.props_mut());

                let retry = unsafe {
                    StartTraceW(
                        &mut session_handle,
                        PCWSTR(session_name_wide.as_ptr()),
                        retry_storage.props_mut(),
                    )
                };

                if retry.0 == 0 {
                    println!("  StartTraceW retry: SUCCESS (handle={:?}) — not yet a PASS", session_handle);
                    println!();
                    Some(SessionGuard::new(session_handle, session_name_wide))
                } else {
                    println!("  StartTraceW retry: FAILED (error={})", retry.0);
                    println!();
                    None
                }
            }
            1450 => {
                // ERROR_NO_SYSTEM_RESOURCES — all 8 system-logger slots in
                // use (2 reserved). Not a config bug.
                println!("  StartTraceW: ERROR_NO_SYSTEM_RESOURCES (1450)");
                println!("  All system-logger slots are in use — stop other kernel");
                println!("  trace sessions (logman query -ets) and retry.");
                println!();
                None
            }
            other => {
                println!("  StartTraceW: FAILED (error={other})");
                println!();
                None
            }
        }
    }

    fn stop_stale_session(session_name_wide: &[u16]) {
        let mut stop_buf = match EventTracePropsStorage::with_extra("", None, 256) {
            Ok(s) => s,
            Err(e) => {
                println!("  Stale stop props layout failed: {e}");
                return;
            }
        };

        let result = unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(session_name_wide.as_ptr()),
                stop_buf.props_mut(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        println!("  Stale session stop result: {}", result.0);
    }

    // ═══════════════════════════════════════════════════════════════
    //  (c) + (d) OpenTraceW consumer test with generated activity
    // ═══════════════════════════════════════════════════════════════

    /// Global event counter for the callback.
    static EVENT_COUNT: AtomicU64 = AtomicU64::new(0);

    /// Bare extern "system" callback — ETW callbacks cannot capture closures.
    unsafe extern "system" fn probe_callback(event: *mut EVENT_RECORD) {
        if event.is_null() {
            return;
        }
        let e = unsafe { &*event };
        let count = EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
        // Print first 5 events for visibility.
        if count < 5 {
            println!(
                "  EVENT: provider={:?} pid={} opcode={}",
                e.EventHeader.ProviderId,
                e.EventHeader.ProcessId,
                e.EventHeader.EventDescriptor.Opcode,
            );
        }
    }

    /// Returns the number of events received, or None if the consumer
    /// could not be opened (verdict: inconclusive).
    fn try_open_trace(guard: &SessionGuard, start: Instant, timeout: Duration) -> Option<u64> {
        println!("--- OpenTraceW Consumer Test ---");
        println!(
            "  OpenTraceW available in windows crate: YES (Win32_System_Time feature enabled)"
        );

        // Reset counters.
        EVENT_COUNT.store(0, Ordering::Relaxed);

        // Build EVENT_TRACE_LOGFILEW for real-time consumption.
        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        logfile.LoggerName = windows::core::PWSTR(guard.session_name_wide.as_ptr() as *mut u16);

        // Anonymous1 is a union: { LogFileMode, ProcessTraceMode }.
        // PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
        // PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
        logfile.Anonymous1.ProcessTraceMode = 0x0000_0100 | 0x1000_0000;

        // Anonymous2 is a union: { EventCallback, EventRecordCallback }.
        logfile.Anonymous2.EventRecordCallback = Some(probe_callback);

        println!(
            "  EVENT_TRACE_LOGFILEW size (actual): {} bytes",
            size_of::<EVENT_TRACE_LOGFILEW>()
        );

        let trace_handle = unsafe { OpenTraceW(&mut logfile) };

        // INVALID_PROCESSTRACE_HANDLE check.
        if trace_handle.Value == u64::MAX {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            println!("  OpenTraceW: FAILED (GetLastError={})", err.0,);
            println!("  Could not open trace for real-time consumption.");
            return None;
        }

        println!("  OpenTraceW: SUCCESS (handle={})", trace_handle.Value);

        // Spawn a thread to call ProcessTrace (it blocks until session stops).
        let process_handle = trace_handle;
        let consumer_thread = std::thread::spawn(move || {
            let handles = [process_handle];
            let result = unsafe { ProcessTrace(&handles, None, None) };
            println!("  ProcessTrace returned: {}", result.0);
        });

        // Run for up to 3 seconds (or until global timeout), GENERATING
        // our own kernel activity the whole time: without known-good
        // activity, "0 events" is ambiguous (quiet system vs dead
        // session). Spawning short-lived children guarantees process
        // events on any healthy system-logger session.
        let consume_duration = Duration::from_secs(3);
        let consume_start = Instant::now();
        let activity_thread = std::thread::spawn(move || {
            let mut spawned: u32 = 0;
            while consume_start.elapsed() < consume_duration {
                match std::process::Command::new("cmd.exe")
                    .args(["/c", "exit", "0"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                {
                    Ok(mut c) => {
                        spawned += 1;
                        let _ = c.wait();
                    }
                    // cmd.exe always exists on Windows; failure here is
                    // bizarre but must not panic the probe — the verdict
                    // just becomes less reliable.
                    Err(_) => break,
                }
            }
            spawned
        });

        while start.elapsed() < timeout {
            std::thread::sleep(Duration::from_millis(100));
        }
        let spawned = activity_thread.join().unwrap_or(0);
        println!("  Activity generated: {spawned} child processes spawned by the probe");

        let events = EVENT_COUNT.load(Ordering::Relaxed);
        println!("  Events received: {events}");

        // Close the trace handle to unblock ProcessTrace.
        let close_result = unsafe { CloseTrace(trace_handle) };
        println!("  CloseTrace result: {}", close_result.0);

        // Wait for the consumer thread — blocks until the CloseTrace above
        // unblocks ProcessTrace (no timeout; CloseTrace guarantees the exit).
        let _ = consumer_thread.join();
        println!("  Consumer thread joined.");

        Some(events)
    }
}

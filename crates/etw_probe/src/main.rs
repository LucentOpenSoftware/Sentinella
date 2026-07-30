//! ETW layout validation probe — diagnostic binary for Sentinella.
//!
//! Validates ETW consumer struct layouts and callback mechanisms safely,
//! completely isolated from sandboxd. If this binary crashes, sandboxd
//! is unaffected.
//!
//! Run with: `cargo run -p etw_probe` (requires admin for ETW session).

fn main() {
    #[cfg(not(target_os = "windows"))]
    {
        println!("ETW probe is Windows-only");
        std::process::exit(0);
    }

    #[cfg(target_os = "windows")]
    {
        windows_probe::run();
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

    pub fn run() {
        println!("=== Sentinella ETW Probe ===\n");

        // Global timeout: exit after 5 seconds max.
        let start = Instant::now();
        let timeout = Duration::from_secs(5);

        // (a) Print struct sizes for validation.
        print_struct_sizes();

        if start.elapsed() >= timeout {
            println!("\n[timeout] 5 seconds elapsed, exiting.");
            return;
        }

        // (b) Try StartTraceW with kernel PROCESS flag.
        let session_result = try_start_trace();

        if start.elapsed() >= timeout {
            println!("\n[timeout] 5 seconds elapsed, exiting.");
            return;
        }

        // (c) + (d) Try OpenTraceW consumer API.
        match session_result {
            Some(mut guard) => {
                try_open_trace(&guard, start, timeout);
                // Always clean up.
                guard.stop();
            }
            None => {
                println!("\n[skip] No active session — skipping OpenTraceW test.");
            }
        }

        println!("\n=== ETW Probe Complete ===");
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
    //  (b) StartTraceW with kernel PROCESS flag
    // ═══════════════════════════════════════════════════════════════

    fn try_start_trace() -> Option<SessionGuard> {
        println!("--- StartTraceW Test ---");

        let session_name = format!("SentinellaProbe_{}", std::process::id());
        let session_name_wide: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        println!("  Session name: {session_name}");

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
        let props = props_storage.props_mut();

        props.Wnode.ClientContext = 1; // QPC timestamps
        props.Wnode.Flags = 0x0002_0000; // WNODE_FLAG_TRACED_GUID
        props.LogFileMode = 0x0000_0100; // EVENT_TRACE_REAL_TIME_MODE

        // Enable PROCESS events.
        props.EnableFlags = EVENT_TRACE_FLAG(0x0000_0001); // EVENT_TRACE_FLAG_PROCESS

        let mut session_handle = CONTROLTRACE_HANDLE::default();

        let result = unsafe {
            StartTraceW(
                &mut session_handle,
                PCWSTR(session_name_wide.as_ptr()),
                props,
            )
        };

        match result.0 {
            0 => {
                println!("  StartTraceW: SUCCESS (handle={:?})", session_handle);
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

                // Rebuild props buffer for retry.
                let mut retry_storage =
                    match EventTracePropsStorage::with_extra(&session_name, None, 256) {
                        Ok(s) => s,
                        Err(e) => {
                            println!("  ETW props layout failed: {e}");
                            return None;
                        }
                    };
                let retry_props = retry_storage.props_mut();
                retry_props.Wnode.ClientContext = 1;
                retry_props.Wnode.Flags = 0x0002_0000;
                retry_props.LogFileMode = 0x0000_0100;
                retry_props.EnableFlags = EVENT_TRACE_FLAG(0x0000_0001);

                let retry = unsafe {
                    StartTraceW(
                        &mut session_handle,
                        PCWSTR(session_name_wide.as_ptr()),
                        retry_props,
                    )
                };

                if retry.0 == 0 {
                    println!("  StartTraceW retry: SUCCESS (handle={:?})", session_handle);
                    println!();
                    Some(SessionGuard::new(session_handle, session_name_wide))
                } else {
                    println!("  StartTraceW retry: FAILED (error={})", retry.0);
                    println!();
                    None
                }
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
    //  (c) + (d) OpenTraceW consumer test with callback
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

    fn try_open_trace(guard: &SessionGuard, start: Instant, timeout: Duration) {
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
            return;
        }

        println!("  OpenTraceW: SUCCESS (handle={})", trace_handle.Value);

        // Spawn a thread to call ProcessTrace (it blocks until session stops).
        let process_handle = trace_handle;
        let consumer_thread = std::thread::spawn(move || {
            let handles = [process_handle];
            let result = unsafe { ProcessTrace(&handles, None, None) };
            println!("  ProcessTrace returned: {}", result.0);
        });

        // Run for up to 3 seconds (or until global timeout).
        let consume_duration = Duration::from_secs(3);
        let consume_start = Instant::now();
        while consume_start.elapsed() < consume_duration && start.elapsed() < timeout {
            std::thread::sleep(Duration::from_millis(100));
        }

        println!("  Events received: {}", EVENT_COUNT.load(Ordering::Relaxed));

        // Close the trace handle to unblock ProcessTrace.
        let close_result = unsafe { CloseTrace(trace_handle) };
        println!("  CloseTrace result: {}", close_result.0);

        // Wait for the consumer thread — blocks until the CloseTrace above
        // unblocks ProcessTrace (no timeout; CloseTrace guarantees the exit).
        let _ = consumer_thread.join();
        println!("  Consumer thread joined.");
    }
}

//! ETW adapter interfaces for WeedHack runtime detection.
//!
//! This module defines the **minimum event surface** the WeedHack
//! detectors need from Windows ETW. It contains only:
//!
//!   * Plain-data event types that ETW callers populate.
//!   * Trait-based source interfaces detectors / the campaign tracker
//!     consume.
//!
//! It deliberately contains **no ETW implementation** — implementing
//! these traits against real ETW providers is the job of a future intake
//! module (separately reviewable and testable). The traits exist now so
//! that:
//!
//!   1. Detector logic stays decoupled from Windows-only ETW types,
//!   2. Test harnesses can substitute trivial in-memory queues,
//!   3. The eventual ETW intake author knows **exactly** which provider,
//!      event ID, and field set each detector needs.
//!
//! ## Provider mapping
//!
//! | Trait                    | Provider                                  | Event(s) / Filter                            |
//! |--------------------------|-------------------------------------------|----------------------------------------------|
//! | `ProcessCreateSource`    | `Microsoft-Windows-Kernel-Process`        | event-id 1 (ProcessStart)                    |
//! | `ImageLoadSource`        | `Microsoft-Windows-Kernel-Process`        | event-id 5 (ImageLoad); browser-image filter |
//! | `FileReadSource`         | `Microsoft-Windows-Kernel-FileIO`         | event-id 14 (FileRead) — wallet-path filter  |
//! | `HttpRequestSource`      | `Microsoft-Windows-WinINet` + WinHTTP     | request-send w/ body capture; eth-rpc filter |
//!
//! ## Required filtering at the source side
//!
//! ETW is high-volume. Each source MUST filter at the provider/session
//! level (event-IDs, image-path masks, file-path prefix masks) before
//! handing events to the detectors. The detectors are the **final**
//! filter — not the only filter. Sane filtering keeps steady-state cost
//! bounded:
//!
//!   * `FileReadSource`: drop reads whose path doesn't match any
//!     wallet/credential prefix (`\\User Data\\`, `\\.minecraft\\`,
//!     `\\Local Extension Settings\\`, `\\Exodus\\`, `\\Telegram*\\`,
//!     `\\discord*\\`, `\\Mozilla\\Firefox\\Profiles\\`, etc.).
//!   * `ImageLoadSource`: only emit events whose target image is a known
//!     browser (`chrome|msedge|brave|firefox|opera|vivaldi|yandex`).
//!   * `HttpRequestSource`: only emit POSTs whose URL contains a known
//!     Ethereum-RPC host substring.
//!   * `ProcessCreateSource`: no filter — full process tree is needed.

#![allow(dead_code)]

// Re-export the detector event types so downstream code has a single
// well-defined import path for everything ETW-shaped.
pub use super::weedhack_browser_injection::ImageLoadEvent;
pub use super::weedhack_etherhiding::EtherHidingEvent as HttpRequestEvent;

/// One ProcessStart from `Microsoft-Windows-Kernel-Process` (event-id 1).
///
/// Mirrors what the existing PLM `etw_intake` already captures into
/// `LineageGraph`. Listed here for completeness; consumers normally use
/// `LineageGraph` directly rather than this struct.
#[derive(Debug, Clone)]
pub struct ProcessCreateEvent {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_name: String,
    pub image_path: String,
    pub command_line: Option<String>,
    /// Unix timestamp (seconds). Required for correlation windows and
    /// PID-reuse disambiguation across all consumers.
    pub timestamp_unix: i64,
}

/// One `Microsoft-Windows-Kernel-FileIO` read for a candidate wallet /
/// credential / session store. The provider session is expected to have
/// already filtered out unrelated reads (see "Required filtering" above).
#[derive(Debug, Clone)]
pub struct FileReadEvent {
    /// PID of the reader.
    pub pid: u32,
    /// Image file name of the reader.
    pub image_name: String,
    /// Full path of the file that was read.
    pub path: String,
    /// Unix timestamp the read began.
    pub timestamp_unix: i64,
}

/// Source of process-create events.
///
/// Implementations: a Windows ETW-backed source for production, a queue-
/// backed source for tests.
pub trait ProcessCreateSource: Send {
    /// Drain currently-queued events into `out`. Returns the number of
    /// events drained. Non-blocking — empty queue returns 0.
    fn drain(&mut self, out: &mut Vec<ProcessCreateEvent>) -> usize;
}

/// Source of pre-filtered image-load events targeting browser processes.
pub trait ImageLoadSource: Send {
    fn drain(&mut self, out: &mut Vec<ImageLoadEvent>) -> usize;
}

/// Source of pre-filtered file-read events for wallet / credential paths.
pub trait FileReadSource: Send {
    fn drain(&mut self, out: &mut Vec<FileReadEvent>) -> usize;
}

/// Source of pre-filtered HTTP-request events to known Ethereum-RPC hosts.
pub trait HttpRequestSource: Send {
    fn drain(&mut self, out: &mut Vec<HttpRequestEvent>) -> usize;
}

// ─────────────────────────────────────────────────────────────────────
//  In-memory test sources — used by campaign tracker tests so the
//  contract above is exercised without ETW.
// ─────────────────────────────────────────────────────────────────────

/// In-memory queue-backed source. Generic over event type — used to
/// implement every `*Source` trait via blanket impls. Pushing events is
/// `O(1)` and draining is `O(n)` over queued items.
#[derive(Default)]
pub struct InMemorySource<E> {
    queue: std::collections::VecDeque<E>,
}

impl<E> InMemorySource<E> {
    pub fn new() -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
        }
    }
    pub fn push(&mut self, event: E) {
        self.queue.push_back(event);
    }
    pub fn len(&self) -> usize {
        self.queue.len()
    }
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl ProcessCreateSource for InMemorySource<ProcessCreateEvent> {
    fn drain(&mut self, out: &mut Vec<ProcessCreateEvent>) -> usize {
        let n = self.queue.len();
        out.extend(self.queue.drain(..));
        n
    }
}

impl ImageLoadSource for InMemorySource<ImageLoadEvent> {
    fn drain(&mut self, out: &mut Vec<ImageLoadEvent>) -> usize {
        let n = self.queue.len();
        out.extend(self.queue.drain(..));
        n
    }
}

impl FileReadSource for InMemorySource<FileReadEvent> {
    fn drain(&mut self, out: &mut Vec<FileReadEvent>) -> usize {
        let n = self.queue.len();
        out.extend(self.queue.drain(..));
        n
    }
}

impl HttpRequestSource for InMemorySource<HttpRequestEvent> {
    fn drain(&mut self, out: &mut Vec<HttpRequestEvent>) -> usize {
        let n = self.queue.len();
        out.extend(self.queue.drain(..));
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_process_create_round_trip() {
        let mut src = InMemorySource::<ProcessCreateEvent>::new();
        src.push(ProcessCreateEvent {
            pid: 1,
            parent_pid: 0,
            image_name: "explorer.exe".into(),
            image_path: "C:\\Windows\\explorer.exe".into(),
            command_line: None,
            timestamp_unix: 1700_000_000,
        });
        let mut sink = Vec::new();
        let n = ProcessCreateSource::drain(&mut src, &mut sink);
        assert_eq!(n, 1);
        assert_eq!(sink.len(), 1);
        // Draining again yields nothing.
        assert_eq!(ProcessCreateSource::drain(&mut src, &mut sink), 0);
    }

    #[test]
    fn in_memory_file_read_round_trip() {
        let mut src = InMemorySource::<FileReadEvent>::new();
        src.push(FileReadEvent {
            pid: 100,
            image_name: "javaw.exe".into(),
            path: "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
                .into(),
            timestamp_unix: 1700_000_001,
        });
        let mut sink = Vec::new();
        let n = FileReadSource::drain(&mut src, &mut sink);
        assert_eq!(n, 1);
        assert_eq!(sink[0].pid, 100);
    }
}

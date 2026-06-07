//! WeedHack wallet/credential bulk-harvest detector.
//!
//! ## Attack pattern
//!
//! Stage 2 (Elevator.jar) iterates a known list of browser and wallet
//! credential paths and reads each in turn. McAfee documented 36 browser
//! profiles + 56 web-wallet extensions + 12 desktop wallets — all within
//! a few seconds of process start. Legitimate Java code does not touch
//! ANY of these, much less three of them inside a short window.
//!
//! ## What we detect
//!
//! This module maintains per-PID sliding-window state: when a single
//! `javaw.exe` PID reads ≥ `THRESHOLD` distinct paths from the curated
//! wallet/credential list within `WINDOW`, we emit
//! `WeedHackSignal::WalletHarvestBurst` exactly once for that PID
//! (subsequent reads on the same PID after the signal are ignored — the
//! finding will already have fired and the process should be killed).
//!
//! ## Design choices
//!
//! - **Per-PID state, not global.** Two unrelated processes each reading
//!   one wallet path each is NOT a harvest.
//! - **Path normalization.** We match by *canonical-path-key* (e.g. all
//!   Chromium `Login Data` reads collapse to the key `chromium:login`)
//!   so reading the same store from different OS-localized paths counts
//!   as one entry, not three.
//! - **Distinct paths required.** Re-reading the same Login Data file
//!   five times does not raise the count — the stealer's tell is the
//!   *breadth* of paths.
//! - **One-shot per PID.** After firing we mark the PID as triggered and
//!   ignore subsequent reads to avoid finding spam.
//! - **Bounded memory.** Maximum of `MAX_TRACKED_PIDS` concurrent PIDs;
//!   oldest dropped on overflow. Per-PID state expires after `WINDOW`.

#![allow(dead_code)]

use super::weedhack_runtime::WeedHackSignal;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Number of distinct wallet keys within the window required to fire.
const THRESHOLD: usize = 3;
/// Time window for the burst detection.
const WINDOW: Duration = Duration::from_secs(10);
/// Hard cap on concurrent PIDs we track.
const MAX_TRACKED_PIDS: usize = 256;

/// Per-PID accumulator.
#[derive(Debug)]
struct PidState {
    /// When the FIRST wallet-path read for this PID was observed.
    started_at: Instant,
    /// Distinct canonical wallet keys read so far.
    seen_keys: HashSet<&'static str>,
    /// Once the threshold fires we suppress further reads.
    fired: bool,
}

impl PidState {
    fn new(now: Instant) -> Self {
        Self {
            started_at: now,
            seen_keys: HashSet::new(),
            fired: false,
        }
    }
}

/// Stateful wallet-harvest detector. Thread-safe via internal Mutex.
pub struct WalletHarvestDetector {
    state: Mutex<HashMap<u32, PidState>>,
}

impl Default for WalletHarvestDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletHarvestDetector {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Observe a file-read event from `pid` (process image `image_name`,
    /// file path `path`). Returns `Some(WeedHackSignal::WalletHarvestBurst)`
    /// the FIRST time the threshold is crossed for this PID, and `None`
    /// otherwise.
    pub fn observe_file_read(
        &self,
        pid: u32,
        image_name: &str,
        path: &str,
    ) -> Option<WeedHackSignal> {
        if !is_javaw(image_name) {
            return None;
        }
        let key = match canonical_key(path) {
            Some(k) => k,
            None => return None,
        };
        let now = Instant::now();

        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Lightweight eviction: drop stale PID entries past their window.
        map.retain(|_, s| now.duration_since(s.started_at) < WINDOW.saturating_mul(2));

        // Bounded memory: if at cap and this PID isn't already tracked,
        // drop the oldest entry to make room. Detection accuracy degrades
        // gracefully under absurd load instead of leaking memory.
        if map.len() >= MAX_TRACKED_PIDS && !map.contains_key(&pid) {
            if let Some(&oldest_pid) = map
                .iter()
                .min_by_key(|(_, s)| s.started_at)
                .map(|(p, _)| p)
            {
                map.remove(&oldest_pid);
            }
        }

        let entry = map.entry(pid).or_insert_with(|| PidState::new(now));

        // If the window expired for this PID, restart the burst counter.
        if now.duration_since(entry.started_at) >= WINDOW {
            *entry = PidState::new(now);
        }

        if entry.fired {
            return None;
        }

        entry.seen_keys.insert(key);

        if entry.seen_keys.len() >= THRESHOLD {
            entry.fired = true;
            return Some(WeedHackSignal::WalletHarvestBurst);
        }

        None
    }

    /// Number of PIDs currently being tracked. Test/diagnostics only.
    pub fn tracked_pid_count(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

fn is_javaw(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "javaw.exe" || lower == "java.exe"
}

/// Map a filesystem path to a canonical wallet/credential-store key.
///
/// Returns the same `&'static str` key for all paths that point to the
/// same logical store, regardless of OS-localized profile name or
/// drive letter. Returns `None` if the path is not a wallet/credential
/// store of interest — those reads do not advance the burst counter.
fn canonical_key(path: &str) -> Option<&'static str> {
    let p = path.to_ascii_lowercase();

    // ── Chromium-family browser credential stores. Every Chromium fork
    //    keeps these files under `User Data\<Profile>\`. Collapse all of
    //    them — Chrome, Edge, Brave, Opera, Vivaldi, Yandex — to a
    //    single per-store key so the stealer can't game us by reading
    //    each browser's copy and counting them as "different stores".
    if p.contains("\\user data\\") || p.contains("\\user data\\default\\") {
        if p.ends_with("\\login data") || p.ends_with("\\login data for account") {
            return Some("chromium:login-data");
        }
        if p.ends_with("\\cookies") || p.ends_with("\\network\\cookies") {
            return Some("chromium:cookies");
        }
        if p.ends_with("\\web data") {
            return Some("chromium:web-data");
        }
        if p.ends_with("\\history") {
            return Some("chromium:history");
        }
        if p.ends_with("\\local state") {
            return Some("chromium:local-state");
        }
    }

    // Firefox / Gecko credential storage.
    if p.contains("\\mozilla\\firefox\\profiles\\") {
        if p.ends_with("\\logins.json") {
            return Some("firefox:logins");
        }
        if p.ends_with("\\key4.db") {
            return Some("firefox:key4");
        }
        if p.ends_with("\\cookies.sqlite") {
            return Some("firefox:cookies");
        }
    }

    // ── Wallet browser extensions (MetaMask / Phantom / Coinbase / etc.)
    //    All live under Chromium's
    //    `User Data\<Profile>\Local Extension Settings\<EXT_ID>\` —
    //    the EXT_ID identifies the wallet. We list the well-known IDs
    //    from McAfee's catalog and collapse to one key per wallet so
    //    re-reading multiple files inside a single wallet does not
    //    inflate the count.
    if p.contains("\\local extension settings\\") {
        for &(ext_id, key) in WALLET_EXTENSIONS {
            if p.contains(ext_id) {
                return Some(key);
            }
        }
    }

    // ── Desktop wallets.
    if p.contains("\\exodus\\exodus.wallet")
        || p.contains("\\exodus\\.exodus")
        || p.contains("\\exodus\\local storage")
    {
        return Some("desktop-wallet:exodus");
    }
    if p.contains("\\atomic\\local storage") || p.contains("\\atomicwallet") {
        return Some("desktop-wallet:atomic");
    }
    if p.contains("\\electrum\\wallets\\") {
        return Some("desktop-wallet:electrum");
    }
    if p.contains("\\bitcoin\\wallet.dat") {
        return Some("desktop-wallet:bitcoin-core");
    }
    if p.contains("\\ethereum\\keystore\\") {
        return Some("desktop-wallet:ethereum-keystore");
    }
    if p.contains("\\daedalus\\wallets\\") {
        return Some("desktop-wallet:daedalus");
    }

    // ── Discord token storage.
    if p.contains("\\discord\\local storage\\leveldb")
        || p.contains("\\discordcanary\\local storage\\leveldb")
        || p.contains("\\discordptb\\local storage\\leveldb")
    {
        return Some("discord:leveldb");
    }

    // ── Telegram session.
    if p.contains("\\telegram desktop\\tdata\\") {
        return Some("telegram:tdata");
    }

    // ── Steam login token.
    if p.ends_with("\\config\\loginusers.vdf") || p.ends_with("\\config\\config.vdf") {
        return Some("steam:loginusers");
    }

    // ── Minecraft session theft (Stage 1 specifically targets these).
    if p.contains("\\.minecraft\\")
        && (p.ends_with("\\launcher_accounts.json")
            || p.ends_with("\\launcher_profiles.json")
            || p.ends_with("\\usercache.json"))
    {
        return Some("minecraft:session");
    }

    None
}

/// Curated wallet-extension IDs. The full McAfee list is 56 entries;
/// these are the highest-prevalence ones. Adding more is mechanical.
const WALLET_EXTENSIONS: &[(&str, &str)] = &[
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "ext-wallet:metamask"),
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "ext-wallet:phantom"),
    ("hnfanknocfeofbddgcijnmhnfnkdnaad", "ext-wallet:coinbase"),
    ("ejbalbakoplchlghecdalmeeeajnimhm", "ext-wallet:metamask-edge"),
    ("ibnejdfjmmkpcnlpebklmnkoeoihofec", "ext-wallet:tronlink"),
    ("egjidjbpglichdcondbcbdnbeeppgdph", "ext-wallet:trust"),
    ("aeachknmefphepccionboohckonoeemg", "ext-wallet:coin98"),
    ("fnjhmkhhmkbjkkabndcnnogagogbneec", "ext-wallet:ronin"),
    ("bhghoamapcdpbohphigoooaddinpkbai", "ext-wallet:authenticator"),
    ("nphplpgoakhhjchkkhmiggakijnkhfnd", "ext-wallet:ton"),
    ("dmkamcknogkgcdfhhbddcghachkejeap", "ext-wallet:keplr"),
    ("efbglgofoippbgcjepnhiblaibcnclgk", "ext-wallet:martian"),
    ("ibljaomceeegddmcaobcpfbngahnmcfb", "ext-wallet:bitkeep"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_distinct_stores_under_window_fires_once() {
        let det = WalletHarvestDetector::new();
        let pid = 100;
        assert!(
            det.observe_file_read(
                pid,
                "javaw.exe",
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            )
            .is_none()
        );
        assert!(
            det.observe_file_read(
                pid,
                "javaw.exe",
                "C:\\Users\\t\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\000003.ldb",
            )
            .is_none()
        );
        // Third distinct key crosses the threshold.
        let s = det
            .observe_file_read(
                pid,
                "javaw.exe",
                "C:\\Users\\t\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco",
            )
            .expect("third distinct read must fire");
        assert_eq!(s, WeedHackSignal::WalletHarvestBurst);

        // Fourth read on same PID does NOT re-fire.
        assert!(
            det.observe_file_read(
                pid,
                "javaw.exe",
                "C:\\Users\\t\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies",
            )
            .is_none(),
            "same PID must not re-fire after threshold"
        );
    }

    #[test]
    fn three_reads_same_store_do_not_fire() {
        let det = WalletHarvestDetector::new();
        let pid = 200;
        for _ in 0..5 {
            // Same canonical key (chromium:login-data) read repeatedly.
            assert!(
                det.observe_file_read(
                    pid,
                    "javaw.exe",
                    "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
                )
                .is_none()
            );
        }
    }

    #[test]
    fn non_javaw_process_never_fires() {
        // notepad.exe reading three wallet stores in a row is bizarre but
        // not WeedHack — we only watch javaw to bound state and avoid
        // false positives from sysadmin tooling.
        let det = WalletHarvestDetector::new();
        let pid = 300;
        let _ = det.observe_file_read(
            pid,
            "notepad.exe",
            "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        );
        let _ = det.observe_file_read(
            pid,
            "notepad.exe",
            "C:\\Users\\t\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\X.ldb",
        );
        let result = det.observe_file_read(
            pid,
            "notepad.exe",
            "C:\\Users\\t\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed",
        );
        assert!(result.is_none());
    }

    #[test]
    fn two_pids_each_reading_two_stores_do_not_fire() {
        let det = WalletHarvestDetector::new();
        for pid in [100u32, 200] {
            assert!(
                det.observe_file_read(
                    pid,
                    "javaw.exe",
                    "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
                )
                .is_none()
            );
            assert!(
                det.observe_file_read(
                    pid,
                    "javaw.exe",
                    "C:\\Users\\t\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\X.ldb",
                )
                .is_none()
            );
        }
    }

    #[test]
    fn canonical_key_collapses_chromium_forks() {
        // Chrome / Edge / Brave Login Data files all canonicalize to the
        // same key. Reading all three is still "1 store read" — the
        // stealer can't game us by reading each browser separately.
        assert_eq!(
            canonical_key(
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
            ),
            Some("chromium:login-data")
        );
        assert_eq!(
            canonical_key(
                "C:\\Users\\t\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data"
            ),
            Some("chromium:login-data")
        );
        assert_eq!(
            canonical_key(
                "C:\\Users\\t\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"
            ),
            Some("chromium:login-data")
        );
    }

    #[test]
    fn canonical_key_handles_metamask_extension() {
        assert_eq!(
            canonical_key(
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn\\000003.ldb"
            ),
            Some("ext-wallet:metamask")
        );
    }

    #[test]
    fn canonical_key_returns_none_for_unrelated_paths() {
        assert_eq!(canonical_key("C:\\Windows\\System32\\kernel32.dll"), None);
        assert_eq!(canonical_key("C:\\Users\\t\\Documents\\notes.txt"), None);
    }

    #[test]
    fn minecraft_session_counts_as_a_store() {
        // Stage 1 (DonutDupe) targets these explicitly. Treat them as a
        // wallet-equivalent so Stage-1-only behaviour can still fire the
        // harvest signal if combined with other reads (e.g. session +
        // Chrome cookies + Login Data).
        assert_eq!(
            canonical_key(
                "C:\\Users\\t\\AppData\\Roaming\\.minecraft\\launcher_accounts.json"
            ),
            Some("minecraft:session")
        );
    }

    #[test]
    fn bounded_pid_state_under_overflow() {
        let det = WalletHarvestDetector::new();
        // Pump in MAX_TRACKED_PIDS+50 different PIDs — must stay capped.
        for pid in 0..(MAX_TRACKED_PIDS as u32 + 50) {
            let _ = det.observe_file_read(
                pid,
                "javaw.exe",
                "C:\\Users\\t\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            );
        }
        assert!(
            det.tracked_pid_count() <= MAX_TRACKED_PIDS,
            "tracked PID count must stay bounded: got {}",
            det.tracked_pid_count()
        );
    }
}

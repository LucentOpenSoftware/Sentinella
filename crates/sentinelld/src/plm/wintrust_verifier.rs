//! Wave 5: WinTrust-backed `ModuleSignerVerifier` for the WeedHack
//! ImageLoad pipeline.
//!
//! ## Architecture
//!
//! ```text
//!  BrowserImageLoadFilter::process_event
//!         │
//!         │  &dyn ModuleSignerVerifier
//!         v
//!  WinTrustModuleSignerVerifier::verify(path)
//!         │
//!         ├─► cache lookup by (path, size, mtime)  ─┐
//!         │                                          │ hit
//!         │                                         OK── return cached verdict
//!         │ miss                                     │
//!         v                                          │
//!  argus::layers::authenticode::verify_for_signer_verdict(path)
//!         │ AuthenticodeStatus (Trusted/Untrusted/Unknown)
//!         v
//!  cache insert + counter increment ────────────────►
//!         │
//!         v
//!  SignerVerdict back to filter
//! ```
//!
//! ## Why a coarse three-state verdict?
//!
//! The richer `TrustResult` enum lives in argus where it drives score
//! discounts. For the WeedHack browser-injection gate we only need:
//!
//!   * **Trusted** — drop pre-lineage. Known-publisher Authenticode chain.
//!     We do NOT spend lineage walk + tracker work on a legitimate signed
//!     Chrome/Edge/Brave module.
//!   * **Untrusted** — eligible. Unsigned, broken, distrusted, revoked.
//!   * **Unknown** — eligible, but the existing path+lineage gate stays
//!     the authoritative decider. Covers ValidUnknown publishers and
//!     WinTrust API errors.
//!
//! The coarsening is intentional: the WeedHack signal must not depend on
//! Authenticode subtleties beyond "known good publisher → drop". Any
//! other state goes through the same path+lineage check.
//!
//! ## Cache
//!
//! Bounded LRU keyed by `(path, size, mtime)`. Per Wave 5 spec:
//!
//!   * Max entries: 4096.
//!   * Eviction: oldest by `inserted_at` (LRU on insert; counters track).
//!   * TTL: 1 hour — Authenticode status doesn't change on hot files;
//!     a 1h refresh window absorbs corner cases like signing a previously
//!     unsigned file in place.
//!
//! ## Failure handling
//!
//! - Filesystem metadata unavailable (file gone, IO error) → skip cache,
//!   return `Unknown`, increment `verify_errors`.
//! - WinTrust panic — wrapped in `catch_unwind` in the trait impl. Even
//!   though `verify_for_signer_verdict` is documented not to panic, the
//!   defensive guard means a future regression in argus never crashes
//!   the worker thread.

#![allow(dead_code)]

use super::weedhack_image_load::{ModuleSignerVerifier, SignerVerdict};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

// ─────────────────────────────────────────────────────────────────────
//  Tunables
// ─────────────────────────────────────────────────────────────────────

/// Maximum cached entries before LRU eviction kicks in.
pub const MAX_CACHE_ENTRIES: usize = 4096;

/// Entries older than this are re-verified on next lookup. One hour is
/// long enough to absorb burst loads of the same DLL, short enough that
/// an in-place re-sign on a server-deployed binary refreshes within an
/// operator-noticeable window.
pub const CACHE_TTL: Duration = Duration::from_secs(60 * 60);

// ─────────────────────────────────────────────────────────────────────
//  Cache key
// ─────────────────────────────────────────────────────────────────────

/// (path, size, mtime) tuple. PathBuf normalized to the path the
/// ETW callback handed us (no extra canonicalize — that's an extra
/// syscall per lookup). Size + mtime defeat hash collisions across
/// rebuilds of the same file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub path: PathBuf,
    pub size: u64,
    pub mtime_unix: i64,
}

impl CacheKey {
    /// Build a key by hitting the filesystem for size + mtime. Returns
    /// `None` if metadata is unavailable (file gone, permission denied,
    /// etc.) — caller treats that as "skip cache, verify directly".
    pub fn from_path(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        let size = meta.len();
        let mtime_unix = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Some(CacheKey {
            path: path.to_path_buf(),
            size,
            mtime_unix,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Diagnostics
// ─────────────────────────────────────────────────────────────────────

/// Per-verifier counters surfaced under `image_load_etw.signer` in the
/// diagnostics JSON.
pub struct SignerDiagnostics {
    pub trusted: AtomicU64,
    pub untrusted: AtomicU64,
    pub unknown: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub verify_errors: AtomicU64,
    /// LRU evictions over the verifier's lifetime — exposed so an
    /// operator can tell if MAX_CACHE_ENTRIES is too small.
    pub cache_evictions: AtomicU64,
    /// Entries dropped due to TTL during cache lookup.
    pub cache_ttl_expirations: AtomicU64,
}

impl SignerDiagnostics {
    pub fn new() -> Self {
        Self {
            trusted: AtomicU64::new(0),
            untrusted: AtomicU64::new(0),
            unknown: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            verify_errors: AtomicU64::new(0),
            cache_evictions: AtomicU64::new(0),
            cache_ttl_expirations: AtomicU64::new(0),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "trusted": self.trusted.load(Ordering::Relaxed),
            "untrusted": self.untrusted.load(Ordering::Relaxed),
            "unknown": self.unknown.load(Ordering::Relaxed),
            "cache_hits": self.cache_hits.load(Ordering::Relaxed),
            "cache_misses": self.cache_misses.load(Ordering::Relaxed),
            "verify_errors": self.verify_errors.load(Ordering::Relaxed),
            "cache_evictions": self.cache_evictions.load(Ordering::Relaxed),
            "cache_ttl_expirations": self.cache_ttl_expirations.load(Ordering::Relaxed),
            "max_cache_entries": MAX_CACHE_ENTRIES,
            "cache_ttl_secs": CACHE_TTL.as_secs(),
        })
    }
}

impl Default for SignerDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Cache
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    verdict: SignerVerdict,
    inserted_at: Instant,
}

/// Bounded LRU cache. Eviction is "oldest-by-insertion-time" — simpler
/// than touching access timestamps on every read and good enough for
/// the steady-state pattern (mostly idempotent DLL loads).
pub struct SignerCache {
    inner: Mutex<HashMap<CacheKey, CacheEntry>>,
}

impl SignerCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Look up a verdict. Returns None for cache miss (caller verifies)
    /// or expired entry (caller re-verifies; expiration is counted).
    pub fn get(&self, key: &CacheKey, diag: &SignerDiagnostics) -> Option<SignerVerdict> {
        self.get_at(key, diag, Instant::now())
    }

    pub fn get_at(
        &self,
        key: &CacheKey,
        diag: &SignerDiagnostics,
        now: Instant,
    ) -> Option<SignerVerdict> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = map.get(key) {
            if now.duration_since(entry.inserted_at) < CACHE_TTL {
                diag.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.verdict);
            }
            // Expired — remove and treat as miss.
            map.remove(key);
            diag.cache_ttl_expirations.fetch_add(1, Ordering::Relaxed);
        }
        diag.cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert a fresh verdict. Evicts the oldest entry if at cap.
    pub fn put(&self, key: CacheKey, verdict: SignerVerdict, diag: &SignerDiagnostics) {
        self.put_at(key, verdict, diag, Instant::now())
    }

    pub fn put_at(
        &self,
        key: CacheKey,
        verdict: SignerVerdict,
        diag: &SignerDiagnostics,
        now: Instant,
    ) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Light TTL sweep so the size cap stays accurate.
        map.retain(|_, e| now.duration_since(e.inserted_at) < CACHE_TTL);

        if map.len() >= MAX_CACHE_ENTRIES && !map.contains_key(&key) {
            // Evict oldest by inserted_at.
            if let Some(oldest_k) = map
                .iter()
                .min_by_key(|(_, e)| e.inserted_at)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_k);
                diag.cache_evictions.fetch_add(1, Ordering::Relaxed);
            }
        }

        map.insert(
            key,
            CacheEntry {
                verdict,
                inserted_at: now,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn clear(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

impl Default for SignerCache {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Verifier function boundary — pluggable for tests
// ─────────────────────────────────────────────────────────────────────

/// Function signature the verifier delegates to for the actual
/// Authenticode call. Production wires this to
/// `argus::layers::authenticode::verify_for_signer_verdict`; tests
/// substitute closures that return scripted verdicts (including errors).
///
/// We use this indirection — instead of always going through argus —
/// because the Phase 5 spec requires the verifier-error path to be
/// testable without real signed binaries on CI.
pub type AuthenticodeFn =
    dyn Fn(&Path) -> Result<argus::layers::authenticode::AuthenticodeStatus, ()> + Send + Sync;

/// Production wrapper: calls argus and never returns Err.
fn production_authenticode(path: &Path) -> Result<argus::layers::authenticode::AuthenticodeStatus, ()> {
    // The argus function is documented not to panic but we still wrap
    // defensively — a future bug there must not kill the worker thread.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        argus::layers::authenticode::verify_for_signer_verdict(path)
    }));
    result.map_err(|_| ())
}

// ─────────────────────────────────────────────────────────────────────
//  WinTrust-backed verifier — production
// ─────────────────────────────────────────────────────────────────────

/// Production `ModuleSignerVerifier` backed by the WinTrust API via the
/// argus authenticode layer. Caches verdicts by `(path, size, mtime)`
/// to keep ImageLoad burst cost bounded.
pub struct WinTrustModuleSignerVerifier {
    cache: std::sync::Arc<SignerCache>,
    diagnostics: std::sync::Arc<SignerDiagnostics>,
    /// The Authenticode function this verifier delegates to. Production
    /// is a static fn pointer to argus; tests can box a closure.
    authenticode: Box<AuthenticodeFn>,
}

impl WinTrustModuleSignerVerifier {
    /// Production constructor — argus-backed.
    pub fn new() -> Self {
        Self {
            cache: std::sync::Arc::new(SignerCache::new()),
            diagnostics: std::sync::Arc::new(SignerDiagnostics::new()),
            authenticode: Box::new(production_authenticode),
        }
    }

    /// Test/integration constructor with a custom Authenticode delegate.
    /// Used by tests to script Trusted/Untrusted/Unknown/Err verdicts
    /// without real signed binaries.
    pub fn with_authenticode(authenticode: Box<AuthenticodeFn>) -> Self {
        Self {
            cache: std::sync::Arc::new(SignerCache::new()),
            diagnostics: std::sync::Arc::new(SignerDiagnostics::new()),
            authenticode,
        }
    }

    pub fn diagnostics(&self) -> &std::sync::Arc<SignerDiagnostics> {
        &self.diagnostics
    }

    pub fn diagnostics_json(&self) -> serde_json::Value {
        self.diagnostics.to_json()
    }

    pub fn cache(&self) -> &std::sync::Arc<SignerCache> {
        &self.cache
    }

    /// Translate the coarse Authenticode verdict into the
    /// `weedhack_image_load::SignerVerdict` the filter consumes.
    fn translate(
        &self,
        status: argus::layers::authenticode::AuthenticodeStatus,
    ) -> SignerVerdict {
        use argus::layers::authenticode::AuthenticodeStatus;
        match status {
            AuthenticodeStatus::Trusted => SignerVerdict::Trusted,
            AuthenticodeStatus::Untrusted => SignerVerdict::Untrusted,
            AuthenticodeStatus::Unknown => SignerVerdict::Unknown,
        }
    }

    fn bump_verdict_counter(&self, verdict: SignerVerdict) {
        let counter = match verdict {
            SignerVerdict::Trusted => &self.diagnostics.trusted,
            SignerVerdict::Untrusted => &self.diagnostics.untrusted,
            SignerVerdict::Unknown => &self.diagnostics.unknown,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for WinTrustModuleSignerVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleSignerVerifier for WinTrustModuleSignerVerifier {
    fn verify(&self, module_path: &str) -> SignerVerdict {
        let path = Path::new(module_path);

        // Build the cache key. If we can't read metadata (file gone or
        // permission denied), skip the cache entirely and emit Unknown —
        // counted as verify_error since we cannot answer reliably.
        let cache_key = match CacheKey::from_path(path) {
            Some(k) => k,
            None => {
                self.diagnostics.verify_errors.fetch_add(1, Ordering::Relaxed);
                self.bump_verdict_counter(SignerVerdict::Unknown);
                return SignerVerdict::Unknown;
            }
        };

        if let Some(cached) = self.cache.get(&cache_key, &self.diagnostics) {
            self.bump_verdict_counter(cached);
            return cached;
        }

        // Cache miss — call into argus, defensively catch any panic.
        let verdict = match (self.authenticode)(path) {
            Ok(status) => self.translate(status),
            Err(()) => {
                self.diagnostics.verify_errors.fetch_add(1, Ordering::Relaxed);
                SignerVerdict::Unknown
            }
        };

        self.cache.put(cache_key, verdict, &self.diagnostics);
        self.bump_verdict_counter(verdict);
        verdict
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use argus::layers::authenticode::AuthenticodeStatus;
    use std::io::Write;

    /// Helper that creates a small temp file the verifier can metadata-stat
    /// successfully. Returns the absolute path as a String matching what
    /// the ETW callback would hand us.
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(suffix: &str) -> Self {
            // We need a real file so CacheKey::from_path succeeds. Use
            // the OS temp dir + a process-unique name.
            let nano = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir()
                .join(format!("sentinella_wintrust_test_{nano}_{suffix}.bin"));
            let mut f = std::fs::File::create(&p).expect("create temp file");
            f.write_all(b"fake dll bytes").expect("write");
            Self { path: p }
        }

        fn path_str(&self) -> String {
            self.path.to_string_lossy().to_string()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn verifier_returning(status: AuthenticodeStatus) -> WinTrustModuleSignerVerifier {
        WinTrustModuleSignerVerifier::with_authenticode(Box::new(move |_| Ok(status)))
    }

    fn verifier_erroring() -> WinTrustModuleSignerVerifier {
        WinTrustModuleSignerVerifier::with_authenticode(Box::new(|_| Err(())))
    }

    // ── Phase 5 required cases ────────────────────────────────────

    #[test]
    fn trusted_signer_returns_trusted_and_increments_counter() {
        let v = verifier_returning(AuthenticodeStatus::Trusted);
        let f = TempFile::new("trusted");
        assert_eq!(v.verify(&f.path_str()), SignerVerdict::Trusted);
        assert_eq!(v.diagnostics.trusted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unsigned_signer_returns_untrusted() {
        let v = verifier_returning(AuthenticodeStatus::Untrusted);
        let f = TempFile::new("unsigned");
        assert_eq!(v.verify(&f.path_str()), SignerVerdict::Untrusted);
        assert_eq!(v.diagnostics.untrusted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn invalid_signer_returns_untrusted() {
        // Argus translates Invalid → Untrusted (sig present but broken).
        let v = verifier_returning(AuthenticodeStatus::Untrusted);
        let f = TempFile::new("invalid");
        assert_eq!(v.verify(&f.path_str()), SignerVerdict::Untrusted);
    }

    #[test]
    fn unknown_signer_returns_unknown() {
        let v = verifier_returning(AuthenticodeStatus::Unknown);
        let f = TempFile::new("valid_unknown_pub");
        assert_eq!(v.verify(&f.path_str()), SignerVerdict::Unknown);
        assert_eq!(v.diagnostics.unknown.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn verifier_errors_do_not_panic_and_return_unknown() {
        let v = verifier_erroring();
        let f = TempFile::new("error");
        assert_eq!(v.verify(&f.path_str()), SignerVerdict::Unknown);
        assert_eq!(v.diagnostics.verify_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn missing_file_does_not_crash_returns_unknown() {
        let v = verifier_returning(AuthenticodeStatus::Trusted);
        // Path that definitely doesn't exist — metadata read will fail.
        let result = v.verify("C:\\__definitely_missing__\\nope.dll");
        assert_eq!(result, SignerVerdict::Unknown);
        assert!(v.diagnostics.verify_errors.load(Ordering::Relaxed) >= 1);
    }

    // ── Cache behavior ────────────────────────────────────────────

    #[test]
    fn cache_hit_avoids_authenticode_call() {
        use std::sync::atomic::AtomicU64;
        use std::sync::Arc;
        let calls = Arc::new(AtomicU64::new(0));
        let calls_clone = Arc::clone(&calls);
        let v = WinTrustModuleSignerVerifier::with_authenticode(Box::new(move |_| {
            calls_clone.fetch_add(1, Ordering::Relaxed);
            Ok(AuthenticodeStatus::Trusted)
        }));
        let f = TempFile::new("cached");
        let p = f.path_str();

        // First call → miss → calls=1, cache_misses=1.
        assert_eq!(v.verify(&p), SignerVerdict::Trusted);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(v.diagnostics.cache_misses.load(Ordering::Relaxed), 1);
        assert_eq!(v.diagnostics.cache_hits.load(Ordering::Relaxed), 0);

        // Second + third call → hit → calls still 1.
        assert_eq!(v.verify(&p), SignerVerdict::Trusted);
        assert_eq!(v.verify(&p), SignerVerdict::Trusted);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "cache must avoid re-verification"
        );
        assert_eq!(v.diagnostics.cache_hits.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn cache_respects_max_entries_via_lru_eviction() {
        // We bypass the file-touch cache key build by exercising the
        // SignerCache directly. SignerCache::put_at with a small synthetic
        // load of MAX_CACHE_ENTRIES+N keys → cache size stays bounded.
        let cache = SignerCache::new();
        let diag = SignerDiagnostics::new();
        let mut now = Instant::now();
        let total = MAX_CACHE_ENTRIES + 50;
        for i in 0..total {
            let key = CacheKey {
                path: PathBuf::from(format!("C:\\fake\\m{i}.dll")),
                size: i as u64,
                mtime_unix: 1_700_000_000,
            };
            cache.put_at(key, SignerVerdict::Untrusted, &diag, now);
            now += Duration::from_millis(1); // distinct inserted_at per entry
        }
        assert!(
            cache.len() <= MAX_CACHE_ENTRIES,
            "cache size {} exceeded cap {}",
            cache.len(),
            MAX_CACHE_ENTRIES
        );
        assert!(
            diag.cache_evictions.load(Ordering::Relaxed) >= 50,
            "evictions must advance — got {}",
            diag.cache_evictions.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn cache_ttl_expiration_re_verifies() {
        let cache = SignerCache::new();
        let diag = SignerDiagnostics::new();
        let key = CacheKey {
            path: PathBuf::from("C:\\fake.dll"),
            size: 1,
            mtime_unix: 1_700_000_000,
        };
        let t0 = Instant::now();
        cache.put_at(key.clone(), SignerVerdict::Trusted, &diag, t0);
        // Within TTL → hit.
        assert_eq!(
            cache.get_at(&key, &diag, t0 + Duration::from_secs(30 * 60)),
            Some(SignerVerdict::Trusted)
        );
        assert_eq!(diag.cache_hits.load(Ordering::Relaxed), 1);

        // After TTL → miss + ttl_expiration counter advances.
        assert_eq!(
            cache.get_at(&key, &diag, t0 + CACHE_TTL + Duration::from_secs(1)),
            None
        );
        assert_eq!(diag.cache_ttl_expirations.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn diagnostics_json_shape_matches_spec() {
        let v = verifier_returning(AuthenticodeStatus::Trusted);
        let j = v.diagnostics_json();
        for k in [
            "trusted",
            "untrusted",
            "unknown",
            "cache_hits",
            "cache_misses",
            "verify_errors",
            "cache_evictions",
            "cache_ttl_expirations",
            "max_cache_entries",
            "cache_ttl_secs",
        ] {
            assert!(j.get(k).is_some(), "missing diagnostics key: {k}");
        }
    }

    #[test]
    fn cache_key_distinct_on_size_change() {
        // Same path different size → different cache slots. Defeats
        // collision after a rebuild.
        let k1 = CacheKey {
            path: PathBuf::from("C:\\x.dll"),
            size: 100,
            mtime_unix: 1,
        };
        let k2 = CacheKey {
            path: PathBuf::from("C:\\x.dll"),
            size: 200,
            mtime_unix: 1,
        };
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_key_distinct_on_mtime_change() {
        let k1 = CacheKey {
            path: PathBuf::from("C:\\x.dll"),
            size: 100,
            mtime_unix: 1,
        };
        let k2 = CacheKey {
            path: PathBuf::from("C:\\x.dll"),
            size: 100,
            mtime_unix: 2,
        };
        assert_ne!(k1, k2);
    }
}

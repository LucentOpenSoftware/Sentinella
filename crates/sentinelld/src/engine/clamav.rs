//! Safe Rust wrapper around libclamav.
//!
//! Loads libclamav.dll at runtime via `libloading`. The daemon can
//! start without the DLL and report "engine not available" — it won't
//! crash.
//!
//! Thread safety: ClamAV's `cl_scanfile` is thread-safe once the
//! engine is compiled (read-only after `cl_engine_compile`). We wrap
//! the engine pointer in a struct that is Send + Sync.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint, c_ulong};
use std::path::Path;
use std::ptr;

use libloading::Library;
use tracing::{debug, info, warn};

use super::bindings::*;

/// A loaded ClamAV engine ready to scan files.
pub struct ClamEngine {
    _lib: Library, // must outlive the engine pointer
    engine: *mut cl_engine,
    signature_count: u32,

    // Function pointers kept alive for scanning.
    fn_scanfile: FnClScanfile,
    fn_strerror: FnClStrerror,
    fn_engine_free: FnClEngineFree,
}

// SAFETY: cl_engine is thread-safe after cl_engine_compile.
// All scanning functions only read the compiled engine.
unsafe impl Send for ClamEngine {}
unsafe impl Sync for ClamEngine {}

/// Result of scanning a single file.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: String,
    pub infected: bool,
    pub virus_name: Option<String>,
    pub scanned_bytes: u64,
    pub error: Option<String>,
}

impl ClamEngine {
    /// Load libclamav.dll, initialize, load signatures, compile.
    ///
    /// `dll_dir`: directory containing libclamav.dll and its dependencies.
    /// `db_dir`: directory containing .cvd signature files.
    pub fn load(dll_dir: &Path, db_dir: &Path) -> Result<Self, String> {
        // ── Load the DLL ────────────────────────────────
        let dll_path = dll_dir.join("libclamav.dll");
        let lib = unsafe {
            Library::new(&dll_path)
                .map_err(|e| format!("Failed to load {}: {e}", dll_path.display()))?
        };

        // ── Resolve function pointers ───────────────────
        let fn_init: FnClInit;
        let fn_engine_new: FnClEngineNew;
        let fn_engine_free: FnClEngineFree;
        let fn_load: FnClLoad;
        let fn_compile: FnClEngineCompile;
        let fn_scanfile: FnClScanfile;
        let fn_strerror: FnClStrerror;
        let fn_engine_set_str: Option<FnClEngineSetStr>;
        let fn_engine_set_num: Option<FnClEngineSetNum>;

        unsafe {
            fn_init = *lib
                .get::<FnClInit>(b"cl_init\0")
                .map_err(|e| format!("cl_init not found: {e}"))?;
            fn_engine_new = *lib
                .get::<FnClEngineNew>(b"cl_engine_new\0")
                .map_err(|e| format!("cl_engine_new not found: {e}"))?;
            fn_engine_free = *lib
                .get::<FnClEngineFree>(b"cl_engine_free\0")
                .map_err(|e| format!("cl_engine_free not found: {e}"))?;
            fn_load = *lib
                .get::<FnClLoad>(b"cl_load\0")
                .map_err(|e| format!("cl_load not found: {e}"))?;
            fn_compile = *lib
                .get::<FnClEngineCompile>(b"cl_engine_compile\0")
                .map_err(|e| format!("cl_engine_compile not found: {e}"))?;
            fn_scanfile = *lib
                .get::<FnClScanfile>(b"cl_scanfile\0")
                .map_err(|e| format!("cl_scanfile not found: {e}"))?;
            fn_strerror = *lib
                .get::<FnClStrerror>(b"cl_strerror\0")
                .map_err(|e| format!("cl_strerror not found: {e}"))?;
            // Optional — older builds may not export these.
            fn_engine_set_str = lib
                .get::<FnClEngineSetStr>(b"cl_engine_set_str\0")
                .ok()
                .map(|f| *f);
            fn_engine_set_num = lib
                .get::<FnClEngineSetNum>(b"cl_engine_set_num\0")
                .ok()
                .map(|f| *f);
        }

        // ── Initialize ClamAV ───────────────────────────
        let ret = unsafe { fn_init(CL_INIT_DEFAULT) };
        if ret != CL_SUCCESS {
            return Err(format!("cl_init failed: {}", cl_err_str(fn_strerror, ret)));
        }
        info!("ClamAV library initialized");

        // ── Install message callback to route ClamAV logs through tracing ──
        // Suppresses noisy "scanned_bytes exceeds UINT32_MAX" warnings that
        // fire on every scan on Windows (32-bit c_ulong output truncation).
        let fn_set_clcb_msg: Option<FnClSetClcbMsg> = unsafe {
            lib.get::<FnClSetClcbMsg>(b"cl_set_clcb_msg\0")
                .ok()
                .map(|f| *f)
        };
        if let Some(set_cb) = fn_set_clcb_msg {
            unsafe {
                set_cb(Some(clamav_msg_callback));
            }
            debug!("ClamAV message callback installed");
        }

        // ── File-backed mpool residency ──
        // MpoolResidencyManager handles cache lifecycle, versioning, and fallback.
        let mut residency = super::residency::MpoolResidencyManager::new();
        let cache_path = residency.prepare();
        // SAFETY: set_var is unsafe in Rust 2024 due to thread-safety concerns.
        // We call this during single-threaded daemon initialization, before any
        // other threads are spawned. The env var is read by ClamAV in the same
        // thread during cl_engine_new() → mpool_create().
        unsafe {
            std::env::set_var(
                "SENTINELLA_MPOOL_CACHE_PATH",
                cache_path.to_string_lossy().as_ref(),
            );
        }
        debug!(path = %cache_path.display(), "SENTINELLA_MPOOL_CACHE_PATH set");

        // ── Create engine ───────────────────────────────
        let engine = unsafe { fn_engine_new() };
        if engine.is_null() {
            return Err("cl_engine_new returned null".into());
        }
        debug!("Engine instance created");

        // ── Configure engine limits ─────────────────────
        // Dedicated temp directory: prevents ClamAV from polluting %TEMP%
        // and eliminates race conditions when multiple scan threads extract
        // compound files (HTML/PDF/OLE2) simultaneously.
        let clamav_tmp = crate::paths::paths().clamav_tmp();
        let _ = std::fs::create_dir_all(&clamav_tmp);

        if let Some(set_str) = fn_engine_set_str {
            if let Ok(tmp_cstr) = CString::new(clamav_tmp.to_string_lossy().as_ref()) {
                let ret = unsafe { set_str(engine, CL_ENGINE_TMPDIR, tmp_cstr.as_ptr()) };
                if ret == CL_SUCCESS {
                    info!(dir = %clamav_tmp.display(), "ClamAV temp directory set");
                } else {
                    tracing::warn!(
                        "cl_engine_set_str(TMPDIR) failed: {}",
                        cl_err_str(fn_strerror, ret)
                    );
                }
            }
        }

        if let Some(set_num) = fn_engine_set_num {
            // Max scan size per compound file: 400 MB. Limits total extracted
            // content ClamAV will process within a single cl_scanfile call.
            let max_scan: i64 = 400 * 1024 * 1024; // 400 MB
            let ret = unsafe { set_num(engine, CL_ENGINE_MAXSCANSIZE, max_scan) };
            if ret == CL_SUCCESS {
                debug!("ClamAV MAXSCANSIZE set to 400 MB");
            } else {
                tracing::warn!(
                    ret,
                    "cl_engine_set_num(MAXSCANSIZE={}) failed: {}",
                    max_scan,
                    cl_err_str(fn_strerror, ret)
                );
            }

            // Max extracted file size within compound files: 100 MB.
            let max_file: i64 = 100 * 1024 * 1024; // 100 MB
            let ret = unsafe { set_num(engine, CL_ENGINE_MAXFILESIZE, max_file) };
            if ret == CL_SUCCESS {
                debug!("ClamAV MAXFILESIZE set to 100 MB");
            } else {
                tracing::warn!(
                    ret,
                    "cl_engine_set_num(MAXFILESIZE={}) failed: {}",
                    max_file,
                    cl_err_str(fn_strerror, ret)
                );
            }

            // Max archive nesting depth: 10 (default is 17, too deep for zip bombs).
            let max_rec: i64 = 10;
            let ret = unsafe { set_num(engine, CL_ENGINE_MAXRECURSION, max_rec) };
            if ret == CL_SUCCESS {
                debug!("ClamAV MAXRECURSION set to 10");
            } else {
                tracing::warn!(
                    ret,
                    "cl_engine_set_num(MAXRECURSION) failed: {}",
                    cl_err_str(fn_strerror, ret)
                );
            }

            // Max files extracted from a single container: 5000.
            let max_files: i64 = 5000;
            let ret = unsafe { set_num(engine, CL_ENGINE_MAXFILES, max_files) };
            if ret == CL_SUCCESS {
                debug!("ClamAV MAXFILES set to 5000");
            } else {
                tracing::warn!(
                    ret,
                    "cl_engine_set_num(MAXFILES) failed: {}",
                    cl_err_str(fn_strerror, ret)
                );
            }

            info!(
                "ClamAV engine limits configured (MAXSCANSIZE=400MB, MAXFILESIZE=100MB, MAXRECURSION=10, MAXFILES=5000)"
            );
        } else {
            tracing::warn!(
                "cl_engine_set_num not available — engine limits NOT applied, default ClamAV limits in effect"
            );
        }

        // ── Load signature database ─────────────────────
        let db_path = CString::new(db_dir.to_str().ok_or("Invalid DB path")?)
            .map_err(|e| format!("CString error: {e}"))?;

        let mut signo: c_uint = 0;
        let ret = unsafe { fn_load(db_path.as_ptr(), engine, &mut signo, CL_DB_STDOPT_REAL) };
        if ret != CL_SUCCESS {
            unsafe {
                fn_engine_free(engine);
            }
            return Err(format!("cl_load failed: {}", cl_err_str(fn_strerror, ret)));
        }
        info!(
            signatures = signo,
            "Signatures loaded from {}",
            db_dir.display()
        );

        // ── Compile engine ──────────────────────────────
        let compile_start = std::time::Instant::now();
        let ret = unsafe { fn_compile(engine) };
        if ret != CL_SUCCESS {
            unsafe {
                fn_engine_free(engine);
            }
            return Err(format!(
                "cl_engine_compile failed: {}",
                cl_err_str(fn_strerror, ret)
            ));
        }
        let compile_ms = compile_start.elapsed().as_millis();
        info!(compile_ms, "Engine compiled and ready");

        // ── Phase 2A: mpool diagnostics ────────────────────
        // Log memory pool statistics after compile to establish baseline.
        let fn_mpool_getstats: Option<FnMpoolGetstats> = unsafe {
            lib.get::<FnMpoolGetstats>(b"mpool_getstats\0")
                .ok()
                .map(|f| *f)
        };
        if let Some(getstats) = fn_mpool_getstats {
            let mut used: usize = 0;
            let mut total: usize = 0;
            let ret = unsafe { getstats(engine as *const cl_engine, &mut used, &mut total) };
            if ret == 0 {
                let used_mb = used / (1024 * 1024);
                let total_mb = total / (1024 * 1024);
                let efficiency = if total > 0 {
                    (used as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                info!(
                    used_mb,
                    total_mb,
                    used_bytes = used,
                    total_bytes = total,
                    efficiency_pct = format!("{:.1}", efficiency),
                    "ClamAV mpool stats: {}MB used / {}MB mapped ({:.1}% efficiency)",
                    used_mb,
                    total_mb,
                    efficiency
                );

                // Record compile metadata for residency lifecycle.
                // Detect file-backed residency: if cache file exists after compile,
                // the mpool is file-backed. If not, we're using vanilla anonymous pages.
                let cache_exists = cache_path.exists();
                let cache_size_mb = if cache_exists {
                    std::fs::metadata(&cache_path)
                        .map(|m| m.len() / (1024 * 1024))
                        .unwrap_or(0)
                } else {
                    0
                };

                // Phase 2Z: Working set trim after compile.
                // Most mpool pages were just written during compile but won't be
                // read again until a file is scanned. Tell the OS to evict them
                // from the working set — file-backed pages can be re-faulted cheaply.
                #[cfg(target_os = "windows")]
                {
                    use windows::Win32::System::Threading::GetCurrentProcess;

                    let ws_before = {
                        use windows::Win32::System::ProcessStatus::{
                            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
                        };
                        let mut c: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
                        c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                        unsafe {
                            let _ = GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb);
                        }
                        c.WorkingSetSize as u64 / (1024 * 1024)
                    };

                    // EmptyWorkingSet: tells the memory manager to trim ALL pages.
                    // For file-backed pages, this is very cheap — they just get
                    // moved to standby and re-faulted on next access.
                    let trim_result = unsafe {
                        // SetProcessWorkingSetSize with -1, -1 trims the working set.
                        // This is the documented way to empty the working set.
                        use windows::Win32::System::Threading::SetProcessWorkingSetSize;
                        SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX)
                            .is_ok()
                    };

                    let ws_after = {
                        use windows::Win32::System::ProcessStatus::{
                            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
                        };
                        let mut c: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
                        c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                        unsafe {
                            let _ = GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb);
                        }
                        c.WorkingSetSize as u64 / (1024 * 1024)
                    };

                    info!(
                        ws_before_mb = ws_before,
                        ws_after_mb = ws_after,
                        reduction_mb = ws_before.saturating_sub(ws_after),
                        trim_success = trim_result,
                        "Phase 2Z: post-compile working set trim"
                    );
                }

                if !cache_exists {
                    warn!(
                        "ClamAV mpool: file-backed residency NOT active — using anonymous pages. \
                         Private bytes will be ~{} MB instead of ~18 MB. \
                         Install the file-backed DLL to reduce memory pressure.",
                        used_mb
                    );
                } else {
                    info!(
                        cache_mb = cache_size_mb,
                        "ClamAV mpool: file-backed residency ACTIVE — pages are cheaply reclaimable"
                    );
                }

                let source_mgr = super::sources::SignatureSourceManager::new(db_dir);
                let provider_fp = source_mgr.provider_fingerprint();

                residency.record_compile(
                    0, // TODO: read from CVD header
                    0, // TODO: read from CVD header
                    compile_ms as u64,
                    total as u64,
                    0, // region count from ClamAV internals
                    signo,
                    cache_exists,
                    &provider_fp,
                );
                info!(
                    file_backed = cache_exists,
                    cache_mb = if cache_exists {
                        std::fs::metadata(&cache_path)
                            .map(|m| m.len() / (1024 * 1024))
                            .unwrap_or(0)
                    } else {
                        0
                    },
                    private_mb = {
                        #[cfg(target_os = "windows")]
                        {
                            use windows::Win32::System::ProcessStatus::{
                                GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
                            };
                            use windows::Win32::System::Threading::GetCurrentProcess;
                            unsafe {
                                let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
                                c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                                let _ = GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb);
                                c.PagefileUsage as u64 / (1024 * 1024)
                            }
                        }
                        #[cfg(not(target_os = "windows"))]
                        {
                            0u64
                        }
                    },
                    "Residency manager: engine cache recorded"
                );
            }
        }

        Ok(Self {
            _lib: lib,
            engine,
            signature_count: signo,
            fn_scanfile,
            fn_strerror,
            fn_engine_free,
        })
    }

    /// Number of signatures loaded.
    pub fn signature_count(&self) -> u32 {
        self.signature_count
    }

    /// Scan a single file. Returns the scan result.
    /// Does NOT delete, move, or modify the file.
    pub fn scan_file(&self, path: &Path) -> ScanResult {
        let path_str = path.to_string_lossy().to_string();

        let c_path = match CString::new(path_str.clone()) {
            Ok(s) => s,
            Err(e) => {
                return ScanResult {
                    path: path_str,
                    infected: false,
                    virus_name: None,
                    scanned_bytes: 0,
                    error: Some(format!("Invalid path: {e}")),
                };
            }
        };

        let mut virname: *const c_char = ptr::null();
        let mut scanned: c_ulong = 0;
        let mut opts = cl_scan_options {
            general: CL_SCAN_GENERAL_HEURISTICS,
            parse: CL_SCAN_PARSE_DEFAULT,
            heuristic: 0,
            mail: 0,
            dev: 0,
        };

        let ret = unsafe {
            (self.fn_scanfile)(
                c_path.as_ptr(),
                &mut virname,
                &mut scanned,
                self.engine as *const cl_engine,
                &mut opts,
            )
        };

        match ret {
            CL_CLEAN => ScanResult {
                path: path_str,
                infected: false,
                virus_name: None,
                scanned_bytes: scanned as u64 * 1024, // CL_COUNT_PRECISION
                error: None,
            },
            CL_VIRUS => {
                let name = if !virname.is_null() {
                    unsafe { CStr::from_ptr(virname) }
                        .to_string_lossy()
                        .to_string()
                } else {
                    "Unknown".to_string()
                };
                ScanResult {
                    path: path_str,
                    infected: true,
                    virus_name: Some(name),
                    scanned_bytes: scanned as u64 * 1024,
                    error: None,
                }
            }
            _ => ScanResult {
                path: path_str,
                infected: false,
                virus_name: None,
                scanned_bytes: 0,
                error: Some(format!("Scan error: {}", cl_err_str(self.fn_strerror, ret))),
            },
        }
    }
}

impl Drop for ClamEngine {
    fn drop(&mut self) {
        if !self.engine.is_null() {
            debug!("Freeing ClamAV engine");
            unsafe {
                (self.fn_engine_free)(self.engine);
            }
            self.engine = ptr::null_mut();
        }
    }
}

/// Convert a cl_error_t to a string using cl_strerror.
fn cl_err_str(fn_strerror: FnClStrerror, err: cl_error_t) -> String {
    let ptr = unsafe { fn_strerror(err) };
    if ptr.is_null() {
        format!("error code {err}")
    } else {
        unsafe { CStr::from_ptr(ptr) }.to_string_lossy().to_string()
    }
}

/// ClamAV message callback — routes libclamav log output through tracing.
/// Filters out noisy benign warnings (e.g. UINT32_MAX truncation on Windows).
unsafe extern "C" fn clamav_msg_callback(
    severity: c_uint,
    _fullmsg: *const c_char,
    msg: *const c_char,
    _context: *mut std::ffi::c_void,
) {
    if msg.is_null() {
        return;
    }

    let text = unsafe { CStr::from_ptr(msg) }.to_string_lossy();

    // Filter out the benign "scanned_bytes exceeds UINT32_MAX" warning.
    // This fires on every scan on Windows due to c_ulong being 32-bit.
    // The actual MAXSCANSIZE limit is enforced correctly — this is just
    // the output parameter truncation warning, not a real problem.
    if text.contains("UINT32_MAX") {
        return;
    }

    match severity {
        CL_MSG_ERROR => tracing::warn!(target: "clamav", "{}", text),
        CL_MSG_WARN => tracing::debug!(target: "clamav", "{}", text),
        _ => tracing::trace!(target: "clamav", "{}", text),
    }
}

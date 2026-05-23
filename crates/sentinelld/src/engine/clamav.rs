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
use tracing::{debug, info};

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
        let clamav_tmp = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join("runtime")
            .join("clamav_tmp");
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
            // Prevents scanned_bytes u32 overflow on deeply nested archives.
            let max_scan: i64 = 400 * 1024 * 1024; // 400 MB
            let ret = unsafe { set_num(engine, CL_ENGINE_MAXSCANSIZE, max_scan) };
            if ret == CL_SUCCESS {
                debug!("ClamAV max scan size set to 400 MB");
            } else {
                tracing::warn!(
                    "cl_engine_set_num(MAX_SCANSIZE) failed: {}",
                    cl_err_str(fn_strerror, ret)
                );
            }

            // Max extracted file size within compound files: 100 MB.
            let max_file: i64 = 100 * 1024 * 1024; // 100 MB
            let ret = unsafe { set_num(engine, CL_ENGINE_MAXFILESIZE, max_file) };
            if ret == CL_SUCCESS {
                debug!("ClamAV max file size set to 100 MB");
            } else {
                tracing::warn!(
                    "cl_engine_set_num(MAX_FILESIZE) failed: {}",
                    cl_err_str(fn_strerror, ret)
                );
            }
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
        info!("Engine compiled and ready");

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

//! `clamavd` — isolated ClamAV scanner subprocess.
//!
//! Loads libclamav.dll, scans one file, emits JSON result, exits.
//! All ClamAV memory (signatures, engine, buffers) freed on exit.
//! If ClamAV crashes on a malformed file, only this process dies —
//! the daemon survives and respawns a new worker.

use std::ffi::CString;
use std::path::{Path, PathBuf};

use clap::Parser;
use serde::Serialize;

const EXIT_CLEAN: i32 = 0;
const EXIT_INFECTED: i32 = 1;
const EXIT_ERROR: i32 = 3;

#[derive(Parser)]
#[command(name = "clamavd", version, about = "Sentinella ClamAV isolated worker")]
struct Cli {
    /// File to scan.
    path: PathBuf,

    /// Directory containing libclamav.dll.
    #[arg(long)]
    dll_dir: PathBuf,

    /// Directory containing signature databases (.cvd files).
    #[arg(long)]
    db_dir: PathBuf,

    /// Emit JSON output (required for IPC).
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct ScanOutput {
    path: String,
    infected: bool,
    virus_name: Option<String>,
    scanned_bytes: u64,
    error: Option<String>,
    signature_count: u64,
    scan_time_ms: u64,
}

fn main() {
    // Suppress ClamAV stderr noise in worker mode.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if !cli.path.exists() {
        emit_error(&cli, "file not found");
        std::process::exit(EXIT_ERROR);
    }

    let start = std::time::Instant::now();

    // Load ClamAV engine.
    let (engine, sig_count) = match load_clamav(&cli.dll_dir, &cli.db_dir) {
        Ok(v) => v,
        Err(e) => {
            emit_error(&cli, &e);
            std::process::exit(EXIT_ERROR);
        }
    };

    // Scan the file.
    let result = scan_file(&engine, &cli.path);
    let elapsed_ms = start.elapsed().as_millis() as u64;

    let output = ScanOutput {
        path: cli.path.to_string_lossy().to_string(),
        infected: result.infected,
        virus_name: result.virus_name,
        scanned_bytes: result.scanned_bytes,
        error: result.error,
        signature_count: sig_count,
        scan_time_ms: elapsed_ms,
    };

    if cli.json {
        println!("{}", serde_json::to_string(&output).unwrap_or_default());
    } else {
        if output.infected {
            println!(
                "INFECTED: {} — {}",
                output.path,
                output.virus_name.as_deref().unwrap_or("Unknown")
            );
        } else if let Some(ref e) = output.error {
            println!("ERROR: {} — {}", output.path, e);
        } else {
            println!("CLEAN: {}", output.path);
        }
    }

    std::process::exit(if output.infected {
        EXIT_INFECTED
    } else if output.error.is_some() {
        EXIT_ERROR
    } else {
        EXIT_CLEAN
    });
}

/// Restrict DLL search order to System32 + the explicit `dll_dir` only.
/// Excludes CWD and PATH from the search (the actual attack vectors).
/// Best-effort: failure is logged but doesn't abort — defense-in-depth, the
/// caller still uses an absolute path for the top-level Library::new.
#[cfg(target_os = "windows")]
fn harden_dll_search(dll_dir: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::System::LibraryLoader::{
        AddDllDirectory, SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        LOAD_LIBRARY_SEARCH_SYSTEM32, LOAD_LIBRARY_SEARCH_USER_DIRS,
    };
    use windows::core::PCWSTR;

    let flags = LOAD_LIBRARY_SEARCH_SYSTEM32
        | LOAD_LIBRARY_SEARCH_USER_DIRS
        | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;
    let _ = unsafe { SetDefaultDllDirectories(flags) };

    if let Ok(canon) = dll_dir.canonicalize() {
        let wide: Vec<u16> = canon
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let _ = unsafe { AddDllDirectory(PCWSTR(wide.as_ptr())) };
    }
}

#[cfg(not(target_os = "windows"))]
fn harden_dll_search(_dll_dir: &Path) {
    // No equivalent attack surface — dlopen uses RPATH / LD_LIBRARY_PATH which
    // we don't set; not in scope for the v0.1.6 Windows-focused hardening pass.
}

fn emit_error(cli: &Cli, msg: &str) {
    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "path": cli.path.to_string_lossy(),
                "infected": false,
                "virus_name": null,
                "scanned_bytes": 0,
                "error": msg,
                "signature_count": 0,
                "scan_time_ms": 0,
            })
        );
    } else {
        eprintln!("clamavd error: {msg}");
    }
}

// ═══════════════════════════════════════════════════════════════
//  ClamAV FFI — minimal, self-contained
// ═══════════════════════════════════════════════════════════════

struct ClamavEngine {
    _lib: libloading::Library,
    engine: *mut std::ffi::c_void,
    // Function pointers.
    cl_scanfile: unsafe extern "C" fn(
        *const std::ffi::c_char,
        *mut *const std::ffi::c_char,
        *mut u64,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        u32,
    ) -> i32,
    cl_engine_free: unsafe extern "C" fn(*mut std::ffi::c_void) -> i32,
}

impl Drop for ClamavEngine {
    fn drop(&mut self) {
        unsafe {
            (self.cl_engine_free)(self.engine);
        }
    }
}

struct RawScanResult {
    infected: bool,
    virus_name: Option<String>,
    scanned_bytes: u64,
    error: Option<String>,
}

fn load_clamav(dll_dir: &Path, db_dir: &Path) -> Result<(ClamavEngine, u64), String> {
    // ☠️ DLL hijack hardening: BEFORE loading libclamav.dll (which pulls in
    // libssl, libcrypto, zlib, etc. via the system DLL search order), restrict
    // the search to System32 + the explicit dll_dir. Without this, an attacker
    // who can drop e.g. libcrypto-3-x64.dll into CWD / any user-writable PATH
    // entry / next-to-the-exe gets arbitrary code execution in this process —
    // and on the daemon spawn path that is SYSTEM context.
    harden_dll_search(dll_dir);

    let dll_path = dll_dir.join("libclamav.dll");
    let lib = unsafe {
        libloading::Library::new(&dll_path)
            .map_err(|e| format!("Cannot load {}: {e}", dll_path.display()))?
    };

    // Resolve symbols.
    type InitFn = unsafe extern "C" fn(u32) -> i32;
    type NewFn = unsafe extern "C" fn() -> *mut std::ffi::c_void;
    type LoadFn =
        unsafe extern "C" fn(*const std::ffi::c_char, *mut std::ffi::c_void, *mut u32, u32) -> i32;
    type CompileFn = unsafe extern "C" fn(*mut std::ffi::c_void) -> i32;
    type FreeFn = unsafe extern "C" fn(*mut std::ffi::c_void) -> i32;
    type ScanFn = unsafe extern "C" fn(
        *const std::ffi::c_char,
        *mut *const std::ffi::c_char,
        *mut u64,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        u32,
    ) -> i32;

    let cl_init: InitFn = unsafe { *lib.get(b"cl_init\0").map_err(|e| format!("cl_init: {e}"))? };
    let cl_engine_new: NewFn = unsafe {
        *lib.get(b"cl_engine_new\0")
            .map_err(|e| format!("cl_engine_new: {e}"))?
    };
    let cl_load: LoadFn = unsafe { *lib.get(b"cl_load\0").map_err(|e| format!("cl_load: {e}"))? };
    let cl_engine_compile: CompileFn = unsafe {
        *lib.get(b"cl_engine_compile\0")
            .map_err(|e| format!("cl_engine_compile: {e}"))?
    };
    let cl_engine_free: FreeFn = unsafe {
        *lib.get(b"cl_engine_free\0")
            .map_err(|e| format!("cl_engine_free: {e}"))?
    };
    let cl_scanfile: ScanFn = unsafe {
        *lib.get(b"cl_scanfile\0")
            .map_err(|e| format!("cl_scanfile: {e}"))?
    };

    // Initialize.
    let ret = unsafe { cl_init(0) };
    if ret != 0 {
        return Err(format!("cl_init failed: {ret}"));
    }

    let engine = unsafe { cl_engine_new() };
    if engine.is_null() {
        return Err("cl_engine_new returned null".into());
    }

    // Load signatures.
    let db_path =
        CString::new(db_dir.to_string_lossy().as_ref()).map_err(|_| "Invalid db_dir path")?;
    let mut sig_count: u32 = 0;
    let ret = unsafe { cl_load(db_path.as_ptr(), engine, &mut sig_count, 0x1F) }; // CL_DB_STDOPT
    if ret != 0 {
        unsafe {
            cl_engine_free(engine);
        }
        return Err(format!("cl_load failed: {ret}"));
    }

    // Compile.
    let ret = unsafe { cl_engine_compile(engine) };
    if ret != 0 {
        unsafe {
            cl_engine_free(engine);
        }
        return Err(format!("cl_engine_compile failed: {ret}"));
    }

    Ok((
        ClamavEngine {
            _lib: lib,
            engine,
            cl_scanfile,
            cl_engine_free,
        },
        sig_count as u64,
    ))
}

fn scan_file(engine: &ClamavEngine, path: &Path) -> RawScanResult {
    let path_str = match CString::new(path.to_string_lossy().as_ref()) {
        Ok(s) => s,
        Err(_) => {
            return RawScanResult {
                infected: false,
                virus_name: None,
                scanned_bytes: 0,
                error: Some("Invalid file path encoding".into()),
            };
        }
    };

    let mut virus_name_ptr: *const std::ffi::c_char = std::ptr::null();
    let mut scanned: u64 = 0;
    let scan_opts: u32 = 0x0001 | 0x0002 | 0x0004; // CL_SCAN_STDOPT equiv

    let ret = unsafe {
        (engine.cl_scanfile)(
            path_str.as_ptr(),
            &mut virus_name_ptr,
            &mut scanned,
            engine.engine,
            std::ptr::null_mut(),
            scan_opts,
        )
    };

    match ret {
        0 => RawScanResult {
            infected: false,
            virus_name: None,
            scanned_bytes: scanned,
            error: None,
        },
        1 => {
            let name = if !virus_name_ptr.is_null() {
                unsafe {
                    std::ffi::CStr::from_ptr(virus_name_ptr)
                        .to_string_lossy()
                        .to_string()
                }
            } else {
                "Unknown".to_string()
            };
            RawScanResult {
                infected: true,
                virus_name: Some(name),
                scanned_bytes: scanned,
                error: None,
            }
        }
        _ => RawScanResult {
            infected: false,
            virus_name: None,
            scanned_bytes: scanned,
            error: Some(format!("cl_scanfile returned {ret}")),
        },
    }
}

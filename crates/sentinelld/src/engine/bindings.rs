//! Minimal hand-written ClamAV FFI bindings.
//!
//! Only the functions needed for: init → load → compile → scan → free.
//! Generated from `libclamav/clamav.h` in ClamAV 1.6.0.
//!
//! These are loaded at runtime via `libloading` — no link-time dependency
//! on libclamav.dll. The daemon can start and report "engine not available"
//! if the DLL is missing.

#![allow(non_camel_case_types, dead_code)]

use std::os::raw::{c_char, c_int, c_uint, c_ulong};

/// Opaque engine handle.
pub enum cl_engine {}

/// ClamAV error/status codes.
pub type cl_error_t = c_int;

pub const CL_SUCCESS: cl_error_t = 0;
pub const CL_CLEAN: cl_error_t = 0;
pub const CL_VIRUS: cl_error_t = 1;

/// Initialization flags.
pub const CL_INIT_DEFAULT: c_uint = 0;

/// Database loading options.
pub const CL_DB_STDOPT: c_uint = 0x6; // CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE
// Expanded: CL_DB_PHISHING=0x2, CL_DB_PHISHING_URLS=0x8... actually let's use the real value.
// From clamav.h: CL_DB_STDOPT = CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE
//   CL_DB_PHISHING       = 0x2
//   CL_DB_PHISHING_URLS  = 0x8
//   CL_DB_BYTECODE       = 0x2000
// So: 0x2 | 0x8 | 0x2000 = 0x200A
pub const CL_DB_STDOPT_REAL: c_uint = 0x200A;

/// Scan options structure.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct cl_scan_options {
    pub general: u32,
    pub parse: u32,
    pub heuristic: u32,
    pub mail: u32,
    pub dev: u32,
}

// Scan option flags.
pub const CL_SCAN_GENERAL_HEURISTICS: u32 = 0x4;

pub const CL_SCAN_PARSE_ARCHIVE: u32 = 0x1;
pub const CL_SCAN_PARSE_ELF: u32 = 0x2;
pub const CL_SCAN_PARSE_PDF: u32 = 0x4;
pub const CL_SCAN_PARSE_MAIL: u32 = 0x40;
pub const CL_SCAN_PARSE_OLE2: u32 = 0x80;
pub const CL_SCAN_PARSE_HTML: u32 = 0x100;
pub const CL_SCAN_PARSE_PE: u32 = 0x200;

/// Default parse flags: enable all common parsers.
pub const CL_SCAN_PARSE_DEFAULT: u32 = CL_SCAN_PARSE_ARCHIVE
    | CL_SCAN_PARSE_ELF
    | CL_SCAN_PARSE_PDF
    | CL_SCAN_PARSE_MAIL
    | CL_SCAN_PARSE_OLE2
    | CL_SCAN_PARSE_HTML
    | CL_SCAN_PARSE_PE;

/// Function type signatures for libloading.
pub type FnClInit = unsafe extern "C" fn(initoptions: c_uint) -> cl_error_t;

pub type FnClEngineNew = unsafe extern "C" fn() -> *mut cl_engine;

pub type FnClEngineFree = unsafe extern "C" fn(engine: *mut cl_engine) -> cl_error_t;

pub type FnClLoad = unsafe extern "C" fn(
    path: *const c_char,
    engine: *mut cl_engine,
    signo: *mut c_uint,
    dboptions: c_uint,
) -> cl_error_t;

pub type FnClEngineCompile = unsafe extern "C" fn(engine: *mut cl_engine) -> cl_error_t;

pub type FnClScanfile = unsafe extern "C" fn(
    filename: *const c_char,
    virname: *mut *const c_char,
    scanned: *mut c_ulong,
    engine: *const cl_engine,
    scanoptions: *mut cl_scan_options,
) -> cl_error_t;

pub type FnClStrerror = unsafe extern "C" fn(clerror: cl_error_t) -> *const c_char;

/// cl_engine_set_str — set string engine parameter.
pub type FnClEngineSetStr = unsafe extern "C" fn(
    engine: *mut cl_engine,
    field: cl_engine_field,
    val: *const c_char,
) -> cl_error_t;

/// cl_engine_set_num — set numeric engine parameter.
/// ClamAV signature: `int cl_engine_set_num(struct cl_engine *, enum cl_engine_field, long long)`
pub type FnClEngineSetNum =
    unsafe extern "C" fn(engine: *mut cl_engine, field: cl_engine_field, val: i64) -> cl_error_t;

/// Engine configuration fields (from clamav.h enum cl_engine_field).
pub type cl_engine_field = c_uint;

// Field numbers must match clamav.h exactly:
//   0  CL_ENGINE_MAX_SCANSIZE
//   1  CL_ENGINE_MAX_FILESIZE
//   2  CL_ENGINE_MAX_RECURSION
//   3  CL_ENGINE_MAX_FILES
//   13 CL_ENGINE_TMPDIR

/// CL_ENGINE_MAX_SCANSIZE — max data scanned per cl_scanfile call (bytes).
/// Limits compound file extraction depth. Prevents scanned_bytes u32 overflow.
pub const CL_ENGINE_MAXSCANSIZE: cl_engine_field = 0;

/// CL_ENGINE_MAX_FILESIZE — max extracted file size within compound files.
pub const CL_ENGINE_MAXFILESIZE: cl_engine_field = 1;

/// CL_ENGINE_MAX_RECURSION — max archive nesting depth.
pub const CL_ENGINE_MAXRECURSION: cl_engine_field = 2;

/// CL_ENGINE_MAX_FILES — max files extracted from a single container.
pub const CL_ENGINE_MAXFILES: cl_engine_field = 3;

/// CL_ENGINE_TMPDIR — override temp directory for compound file extraction.
pub const CL_ENGINE_TMPDIR: cl_engine_field = 13;

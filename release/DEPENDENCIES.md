# Sentinella Release Dependencies

## ARGUS Worker

- `argusd.exe` is bundled as optional isolated ARGUS worker.
- Worker mode is disabled by default.
- License follows Sentinella GPL-2.0 workspace licensing.

## Core Binaries (Rust, GPL-2.0)
- `sentinelld.exe` — Daemon (ClamAV host + ARGUS engine + IPC server)
- `sentinella.exe` — CLI client
- GUI bundle — Tauri 2.x WebView2 application

## ClamAV Engine (GPL-2.0, Cisco)
- `libclamav.dll` — Core scanning engine
- `libclammspack.dll` — Archive decompression
- `libfreshclam.dll` — Signature update library
- `freshclam.exe` — Signature download tool

**Attribution required**:
> Powered by ClamAV®. ClamAV is a registered trademark of Cisco Systems, Inc.

## vcpkg Dependencies (bundled into ClamAV DLLs)
Built via vcpkg, statically linked into ClamAV:
- OpenSSL (Apache-2.0)
- zlib (zlib license)
- bzip2 (bzip2 license)
- libxml2 (MIT)
- pcre2 (BSD-3-Clause)
- json-c (MIT)
- curl (MIT/curl)
- pthreads-win32 (LGPL)

## Rust Dependencies (compiled into binaries)
- YARA-X v1.16 (BSD-3-Clause) — YARA rule engine
- goblin (MIT) — PE/ELF parser
- infer (MIT) — File type detection
- windows v0.58 (MIT/Apache-2.0) — Win32 API
- sha2/md-5 (MIT/Apache-2.0) — Hashing
- tokio (MIT) — Async runtime
- serde/serde_json (MIT/Apache-2.0) — Serialization
- rusqlite (MIT) — SQLite
- notify (CC0) — Filesystem watching
- aes-gcm (MIT/Apache-2.0) — Quarantine encryption

## TLS Certificates
- `certs/` directory — ClamAV mirror TLS certificates
- Required for freshclam HTTPS downloads

## NOT Bundled (downloaded at runtime)
- ClamAV signature databases (main.cvd, daily.cvd, bytecode.cvd)
- ~260MB total, downloaded by freshclam on first run

## License Summary
| Component | License | Bundled |
|---|---|---|
| Sentinella | GPL-2.0 | Yes |
| ClamAV | GPL-2.0 | Yes (DLLs) |
| YARA-X | BSD-3-Clause | Yes (compiled in) |
| OpenSSL | Apache-2.0 | Yes (in ClamAV) |
| SQLite | Public Domain | Yes (compiled in) |
| Tauri | MIT/Apache-2.0 | Yes (GUI) |
| WebView2 | Microsoft | System component |

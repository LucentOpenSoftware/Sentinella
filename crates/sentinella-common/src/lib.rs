//! Sentinella — shared constants, paths, and version metadata.
//!
//! This crate is intentionally dependency-free so it can be used by
//! the daemon, CLI, GUI backend, and any future tooling without
//! pulling in heavy transitive deps.

/// Product metadata.
pub const PRODUCT_NAME: &str = "Sentinella";
pub const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// IPC transport identifiers.
#[cfg(target_os = "windows")]
pub const IPC_PIPE_NAME: &str = r"\\.\pipe\sentinelld";

#[cfg(not(target_os = "windows"))]
pub const IPC_SOCKET_PATH: &str = "/run/sentinella/sentinelld.sock";

/// Default paths (Windows).
#[cfg(target_os = "windows")]
pub mod paths {
    use std::path::PathBuf;

    pub fn data_dir() -> PathBuf {
        let base = std::env::var("ProgramData")
            .unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(base).join("Sentinella")
    }

    pub fn config_path() -> PathBuf {
        data_dir().join("config.toml")
    }

    pub fn quarantine_dir() -> PathBuf {
        data_dir().join("quarantine")
    }

    pub fn log_dir() -> PathBuf {
        data_dir().join("logs")
    }

    pub fn db_dir() -> PathBuf {
        data_dir().join("signatures")
    }
}

/// Default paths (Linux / macOS).
#[cfg(not(target_os = "windows"))]
pub mod paths {
    use std::path::PathBuf;

    pub fn data_dir() -> PathBuf {
        PathBuf::from("/var/lib/sentinella")
    }

    pub fn config_path() -> PathBuf {
        PathBuf::from("/etc/sentinella/config.toml")
    }

    pub fn quarantine_dir() -> PathBuf {
        data_dir().join("quarantine")
    }

    pub fn log_dir() -> PathBuf {
        PathBuf::from("/var/log/sentinella")
    }

    pub fn db_dir() -> PathBuf {
        data_dir().join("signatures")
    }
}

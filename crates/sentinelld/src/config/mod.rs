//! Configuration loading and management.

use sentinella_ipc_proto::settings::Settings;
use tracing::info;

/// Load configuration from disk, falling back to defaults.
pub fn load(path_override: Option<&str>) -> anyhow::Result<Settings> {
    let path = match path_override {
        Some(p) => std::path::PathBuf::from(p),
        None => sentinella_common::paths::config_path(),
    };

    if path.exists() {
        info!(?path, "loading config from disk");
        let content = std::fs::read_to_string(&path)?;
        // TODO: use toml crate for real config parsing.
        // For now, fall back to defaults.
        let _ = content;
        Ok(Settings::default())
    } else {
        info!(?path, "config file not found, using defaults");
        Ok(Settings::default())
    }
}

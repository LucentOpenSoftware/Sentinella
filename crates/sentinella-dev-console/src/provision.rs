//! Edit the daemon's TOML config to provision (or revoke) Developer Mode.
//!
//! Uses `toml_edit` so we preserve every comment and the user's existing
//! formatting — losing those would be a hostile dev-console.
//!
//! Atomic write pattern mirrors the daemon's own R3-fix in
//! `crates/sentinelld/src/config/mod.rs`: write the new TOML to a `.tmp`
//! sibling, fsync, then rename over the live file.

use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use toml_edit::{value, DocumentMut, Item, Table};

/// Compute the lowercase-hex SHA-256 of a password. Live preview in the UI.
pub fn sha256_hex(password: &str) -> String {
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Apply a developer-section patch to the TOML config at `path`. Creates
/// the [developer] table if missing. Returns the new file contents.
pub fn patch_developer_section(
    path: &Path,
    patch: &DeveloperPatchOwned,
) -> Result<String, String> {
    let existing = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut doc: DocumentMut = existing
        .parse()
        .map_err(|e| format!("parse {}: {e}", path.display()))?;

    let dev = match doc.get_mut("developer") {
        Some(Item::Table(t)) => t,
        _ => {
            doc["developer"] = Item::Table(Table::new());
            doc["developer"].as_table_mut().unwrap()
        }
    };

    if let Some(ref h) = patch.set_password_hash {
        dev["password_sha256"] = value(h.as_str());
    }
    if let Some(en) = patch.enabled {
        dev["enabled"] = value(en);
    }
    if let Some(t) = patch.telemetry_enabled {
        dev["telemetry_enabled"] = value(t);
    }

    Ok(doc.to_string())
}

#[derive(Debug, Clone, Default)]
pub struct DeveloperPatchOwned {
    pub set_password_hash: Option<String>,
    pub enabled: Option<bool>,
    pub telemetry_enabled: Option<bool>,
}

/// Atomic write: `path.tmp` → fsync → rename over `path`.
pub fn atomic_write(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("config path has no parent: {}", path.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("sentinelld.toml")
    ));
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(contents.as_bytes())
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read the current developer section so the UI knows the live state.
#[derive(Debug, Clone, Default)]
pub struct DeveloperSnapshot {
    pub has_password: bool,
    pub enabled: bool,
    pub telemetry_enabled: bool,
}

pub fn read_developer_snapshot(path: &Path) -> Result<DeveloperSnapshot, String> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let doc: DocumentMut = s
        .parse()
        .map_err(|e| format!("parse {}: {e}", path.display()))?;
    let mut snap = DeveloperSnapshot::default();
    if let Some(Item::Table(dev)) = doc.get("developer") {
        if let Some(Item::Value(v)) = dev.get("password_sha256") {
            snap.has_password = v
                .as_str()
                .map(|x| x.trim().len() == 64)
                .unwrap_or(false);
        }
        if let Some(Item::Value(v)) = dev.get("enabled") {
            snap.enabled = v.as_bool().unwrap_or(false);
        }
        if let Some(Item::Value(v)) = dev.get("telemetry_enabled") {
            snap.telemetry_enabled = v.as_bool().unwrap_or(false);
        }
    }
    Ok(snap)
}

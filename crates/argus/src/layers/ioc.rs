//! Layer 6: IOC (Indicator of Compromise) Hash Matching
//!
//! Checks file hashes against a local blocklist of known-malicious
//! SHA-256 hashes. The blocklist is loaded from a simple text file
//! (one hash per line) and stored in a HashSet for O(1) lookups.
//!
//! This is intentionally simple — no cloud lookups, no telemetry.
//! The blocklist can be updated alongside signature updates.

use std::collections::HashSet;
use std::path::Path;
use std::sync::RwLock;

use crate::verdict::{Finding, Layer, Severity};

/// IOC hash database — thread-safe, hot-reloadable.
pub struct IocDatabase {
    /// SHA-256 hashes of known-malicious files (lowercase hex).
    sha256_blocklist: RwLock<HashSet<String>>,
    /// Number of hashes loaded.
    count: std::sync::atomic::AtomicU64,
}

impl IocDatabase {
    /// Create an empty IOC database.
    pub fn new() -> Self {
        Self {
            sha256_blocklist: RwLock::new(HashSet::new()),
            count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Load hashes from a text file (one SHA-256 per line).
    /// Lines starting with '#' are comments. Empty lines are skipped.
    /// Can be called multiple times — each call replaces the previous set.
    pub fn load_from_file(&self, path: &Path) -> Result<u64, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read IOC file {}: {e}", path.display()))?;

        let mut hashes = HashSet::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Accept only valid 64-char hex strings (SHA-256).
            let lower = trimmed.to_lowercase();
            if lower.len() == 64 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
                hashes.insert(lower);
            }
        }

        let count = hashes.len() as u64;
        *self
            .sha256_blocklist
            .write()
            .unwrap_or_else(|e| e.into_inner()) = hashes;
        self.count
            .store(count, std::sync::atomic::Ordering::Relaxed);

        tracing::info!(count, path = %path.display(), "IOC hash database loaded");
        Ok(count)
    }

    /// Add a single hash to the blocklist (e.g., from a detection).
    #[allow(dead_code)]
    pub fn add_hash(&self, sha256: &str) {
        let lower = sha256.to_lowercase();
        if lower.len() == 64 {
            self.sha256_blocklist
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(lower);
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Number of hashes in the blocklist.
    pub fn len(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Check if a file hash is in the blocklist.
    pub fn check(&self, sha256: &str) -> Vec<Finding> {
        let lower = sha256.to_lowercase();
        let blocklist = self
            .sha256_blocklist
            .read()
            .unwrap_or_else(|e| e.into_inner());

        if blocklist.contains(&lower) {
            vec![Finding {
                layer: Layer::IocCorrelation,
                severity: Severity::Critical,
                weight: 90,
                description: "File hash matches a known-malicious indicator of compromise (IOC)."
                    .into(),
                technical_detail: Some(format!(
                    "SHA-256 {} found in IOC blocklist ({} entries)",
                    &lower[..16],
                    blocklist.len()
                )),
            }]
        } else {
            vec![]
        }
    }
}

impl Default for IocDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioc_match() {
        let db = IocDatabase::new();
        db.add_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        let findings = db.check("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].weight, 90);
    }

    #[test]
    fn test_ioc_no_match() {
        let db = IocDatabase::new();
        db.add_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let findings = db.check("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_case_insensitive() {
        let db = IocDatabase::new();
        db.add_hash("AABBCCDD00112233445566778899AABBCCDDEEFF00112233445566778899AABB");

        let findings = db.check("aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb");
        assert_eq!(findings.len(), 1);
    }
}

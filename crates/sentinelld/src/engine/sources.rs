//! SignatureSourceManager — curated intelligence source layering.
//!
//! Architecture:
//!   Core:     Official ClamAV DB (always enabled, required)
//!   Enhanced: ONE selectable provider (optional, advanced mode)
//!
//! Constraint: only ONE enhanced source active at a time.
//! This prevents:
//!   - Uncontrolled memory explosion
//!   - Overlapping noisy signatures / FP stacking
//!   - Unpredictable startup/compile times
//!   - "hobby AV with random lists" perception
//!
//! The user ALWAYS knows:
//!   - Which source is active
//!   - How many signatures it adds
//!   - Estimated footprint impact
//!   - FP risk level
//!   - Update frequency
//!
//! Changing the enhanced source invalidates the mpool cache automatically.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// A signature source provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureProvider {
    /// Unique provider ID.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Short description.
    pub description: String,
    /// Focus area (phishing, macro, enterprise, etc.)
    pub focus: String,
    /// Estimated additional signature count.
    pub estimated_signatures: u64,
    /// Estimated additional mapped footprint in MB.
    pub estimated_footprint_mb: u64,
    /// False positive risk level.
    pub fp_risk: FpRisk,
    /// Update frequency description.
    pub update_frequency: String,
    /// License/attribution requirements.
    pub license: String,
    /// Database file names to download (relative to signatures dir).
    pub db_files: Vec<String>,
    /// Update URL pattern (for freshclam-compatible sources).
    pub update_url: Option<String>,
    /// Whether this provider is currently available.
    pub available: bool,
    /// Provider stability level.
    pub stability: ProviderStability,
    /// Recommendation level.
    pub recommendation: RecommendationLevel,
    /// FP risk explanation (user-facing).
    pub fp_explanation: String,
    /// Intended use case description.
    pub use_case: String,
    /// Provider homepage URL.
    pub homepage: String,
    /// License URL.
    pub license_url: String,
    /// Attribution text (required for display).
    pub attribution: String,
}

/// Provider stability level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStability {
    /// Early stage, may have issues.
    Experimental,
    /// Community-maintained, generally stable.
    Community,
    /// Well-established, production-grade.
    Established,
}

impl ProviderStability {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Experimental => "Experimental",
            Self::Community => "Community",
            Self::Established => "Established",
        }
    }
}

/// Recommendation level — how strongly we suggest this provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationLevel {
    /// Available but not actively recommended.
    Optional,
    /// Suitable for users who understand FP tradeoffs.
    AdvancedUsers,
    /// Actively recommended for most users.
    Recommended,
}

impl RecommendationLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Optional => "Optional",
            Self::AdvancedUsers => "Advanced Users",
            Self::Recommended => "Recommended",
        }
    }
}

/// False positive risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FpRisk {
    /// Low — well-curated, enterprise-grade.
    Low,
    /// Moderate — community-curated, occasional FPs.
    Moderate,
    /// High — aggressive detection, expect FPs.
    High,
}

impl FpRisk {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Moderate => "Moderate",
            Self::High => "High",
        }
    }
}

/// Signature source configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceConfig {
    /// Active enhanced provider ID (None = core only).
    pub enhanced_provider: Option<String>,
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            enhanced_provider: None,
        }
    }
}

/// The signature source manager.
pub struct SignatureSourceManager {
    /// Known providers (built-in registry).
    providers: Vec<SignatureProvider>,
    /// Current configuration.
    config: SourceConfig,
    /// Signatures directory.
    sig_dir: PathBuf,
}

impl SignatureSourceManager {
    /// Create with the built-in provider registry.
    pub fn new(sig_dir: &Path) -> Self {
        Self {
            providers: builtin_providers(),
            config: SourceConfig::default(),
            sig_dir: sig_dir.to_path_buf(),
        }
    }

    /// Load configuration from the daemon config.
    pub fn load_config(&mut self, enhanced_provider: Option<String>) {
        self.config.enhanced_provider = enhanced_provider;
    }

    /// Get the active enhanced provider (if any).
    pub fn active_enhanced(&self) -> Option<&SignatureProvider> {
        self.config
            .enhanced_provider
            .as_ref()
            .and_then(|id| self.providers.iter().find(|p| p.id == *id && p.available))
    }

    /// Get all available providers.
    pub fn available_providers(&self) -> Vec<&SignatureProvider> {
        self.providers.iter().filter(|p| p.available).collect()
    }

    /// Set the active enhanced provider. Returns true if changed.
    /// Changing the provider invalidates the mpool cache.
    pub fn set_enhanced(&mut self, provider_id: Option<&str>) -> bool {
        let new_id = provider_id.map(|s| s.to_string());
        if new_id == self.config.enhanced_provider {
            return false; // No change.
        }

        // Validate provider exists.
        if let Some(ref id) = new_id {
            if !self.providers.iter().any(|p| p.id == *id && p.available) {
                warn!(provider = id.as_str(), "signature source: unknown provider");
                return false;
            }
        }

        let old = self.config.enhanced_provider.take();
        self.config.enhanced_provider = new_id.clone();

        info!(
            old = old.as_deref().unwrap_or("none"),
            new = new_id.as_deref().unwrap_or("none"),
            "signature source: enhanced provider changed — cache invalidation required"
        );

        true // Changed — caller must invalidate mpool cache.
    }

    /// Get all database directories that should be loaded by ClamAV.
    /// Returns: (core_dir, enhanced_files) where enhanced_files are additional
    /// DB files to load alongside the core directory.
    pub fn signature_paths(&self) -> (PathBuf, Vec<PathBuf>) {
        let core = self.sig_dir.clone();
        let enhanced: Vec<PathBuf> = if let Some(provider) = self.active_enhanced() {
            provider
                .db_files
                .iter()
                .map(|f| self.sig_dir.join("enhanced").join(f))
                .filter(|p| p.exists())
                .collect()
        } else {
            vec![]
        };
        (core, enhanced)
    }

    /// Check if enhanced database files are present on disk.
    pub fn enhanced_files_present(&self) -> bool {
        if let Some(provider) = self.active_enhanced() {
            provider
                .db_files
                .iter()
                .any(|f| self.sig_dir.join("enhanced").join(f).exists())
        } else {
            false
        }
    }

    /// Provider fingerprint for cache validation.
    /// Any change in this fingerprint invalidates the mpool cache.
    pub fn provider_fingerprint(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        "core-clamav".hash(&mut hasher);

        if let Some(provider) = self.active_enhanced() {
            provider.id.hash(&mut hasher);
            // Hash the actual files on disk for version tracking.
            for f in &provider.db_files {
                let path = self.sig_dir.join("enhanced").join(f);
                if let Ok(meta) = std::fs::metadata(&path) {
                    meta.len().hash(&mut hasher);
                    if let Ok(mtime) = meta.modified() {
                        if let Ok(d) = mtime.duration_since(std::time::UNIX_EPOCH) {
                            d.as_secs().hash(&mut hasher);
                        }
                    }
                }
            }
        } else {
            "none".hash(&mut hasher);
        }

        format!("{:016x}", hasher.finish())
    }

    /// Diagnostics for GUI/IPC.
    pub fn diagnostics(&self) -> serde_json::Value {
        let active = self.active_enhanced();
        let providers: Vec<serde_json::Value> = self
            .providers
            .iter()
            .filter(|p| p.available)
            .map(|p| {
                let is_active = self.config.enhanced_provider.as_deref() == Some(&p.id);
                serde_json::json!({
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    "focus": p.focus,
                    "estimated_signatures": p.estimated_signatures,
                    "estimated_footprint_mb": p.estimated_footprint_mb,
                    "fp_risk": p.fp_risk.label(),
                    "fp_explanation": p.fp_explanation,
                    "stability": p.stability.label(),
                    "recommendation": p.recommendation.label(),
                    "use_case": p.use_case,
                    "update_frequency": p.update_frequency,
                    "license": p.license,
                    "homepage": p.homepage,
                    "attribution": p.attribution,
                    "active": is_active,
                    "files_present": if is_active { self.enhanced_files_present() } else { false },
                })
            })
            .collect();

        serde_json::json!({
            "core": {
                "name": "Official ClamAV",
                "status": "required",
                "always_enabled": true,
            },
            "enhanced": {
                "active_provider": active.map(|p| p.id.clone()),
                "active_name": active.map(|p| p.name.clone()),
                "active_focus": active.map(|p| p.focus.clone()),
                "active_signatures": active.map(|p| p.estimated_signatures).unwrap_or(0),
                "active_footprint_mb": active.map(|p| p.estimated_footprint_mb).unwrap_or(0),
                "active_fp_risk": active.map(|p| p.fp_risk.label()),
            },
            "available_providers": providers,
            "provider_fingerprint": self.provider_fingerprint(),
        })
    }
}

/// Built-in provider registry.
/// These are well-known ClamAV-compatible signature providers.
fn builtin_providers() -> Vec<SignatureProvider> {
    vec![
        SignatureProvider {
            id: "sanesecurity".into(),
            name: "SaneSecurity".into(),
            description: "Community-curated phishing, scam, and malware signatures".into(),
            focus: "Phishing, scam emails, malware".into(),
            estimated_signatures: 420_000,
            estimated_footprint_mb: 120,
            fp_risk: FpRisk::Moderate,
            update_frequency: "Multiple times daily".into(),
            license: "Free for personal/non-commercial use".into(),
            db_files: vec![
                "sanesecurity.ftm".into(), "junk.ndb".into(), "jurlbl.ndb".into(),
                "phish.ndb".into(), "rogue.hdb".into(), "scam.ndb".into(),
                "sigwhitelist.ign2".into(), "spamimg.hdb".into(), "spamattach.hdb".into(),
                "blurl.ndb".into(), "foxhole_filename.cdb".into(), "foxhole_all.cdb".into(),
                "malwarehash.hsb".into(),
            ],
            update_url: Some("https://mirror.sentinella.dev/sanesecurity/".into()),
            available: true,
            stability: ProviderStability::Community,
            recommendation: RecommendationLevel::AdvancedUsers,
            fp_explanation: "Community-curated rules may flag legitimate bulk email or marketing content. Expect occasional false positives on newsletters and automated notifications.".into(),
            use_case: "Users who receive significant email-borne threats or want broader phishing coverage beyond official ClamAV signatures.".into(),
            homepage: "https://sanesecurity.com".into(),
            license_url: "https://sanesecurity.com/usage/".into(),
            attribution: "SaneSecurity Signatures - https://sanesecurity.com".into(),
        },
        SignatureProvider {
            id: "securiteinfo".into(),
            name: "SecuriteInfo".into(),
            description: "Professional threat intelligence signatures".into(),
            focus: "Malware, exploits, PUA".into(),
            estimated_signatures: 350_000,
            estimated_footprint_mb: 100,
            fp_risk: FpRisk::Low,
            update_frequency: "Daily".into(),
            license: "Free for personal use with registration".into(),
            db_files: vec![
                "securiteinfo.hdb".into(), "securiteinfo.ign2".into(),
                "javascript.ndb".into(), "spam_marketing.ndb".into(),
                "securiteinfohtml.hdb".into(), "securiteinfoascii.hdb".into(),
                "securiteinfopdf.hdb".into(),
            ],
            update_url: None,
            available: true,
            stability: ProviderStability::Established,
            recommendation: RecommendationLevel::Recommended,
            fp_explanation: "Professionally curated with low false positive rate. Suitable for production environments.".into(),
            use_case: "Users who want broader malware and exploit coverage with minimal false positive impact.".into(),
            homepage: "https://www.securiteinfo.com".into(),
            license_url: "https://www.securiteinfo.com/clients/customers/signup".into(),
            attribution: "SecuriteInfo.com - https://www.securiteinfo.com".into(),
        },
        SignatureProvider {
            id: "malwarepatrol".into(),
            name: "MalwarePatrol".into(),
            description: "Real-time malware URL and hash blocklists".into(),
            focus: "Active malware URLs, hashes".into(),
            estimated_signatures: 180_000,
            estimated_footprint_mb: 50,
            fp_risk: FpRisk::Low,
            update_frequency: "Hourly".into(),
            license: "Free community edition available".into(),
            db_files: vec!["malwarepatrol.db".into()],
            update_url: None,
            available: true,
            stability: ProviderStability::Established,
            recommendation: RecommendationLevel::Optional,
            fp_explanation: "Focused on known-bad URLs and hashes. Very low false positive risk.".into(),
            use_case: "Users who want real-time blocking of known malicious URLs and file hashes.".into(),
            homepage: "https://www.malwarepatrol.net".into(),
            license_url: "https://www.malwarepatrol.net/non-commercial-use/".into(),
            attribution: "MalwarePatrol - https://www.malwarepatrol.net".into(),
        },
        SignatureProvider {
            id: "interserver".into(),
            name: "InterServer".into(),
            description: "Lightweight macro and script malware signatures".into(),
            focus: "Office macros, scripts".into(),
            estimated_signatures: 50_000,
            estimated_footprint_mb: 15,
            fp_risk: FpRisk::Low,
            update_frequency: "Daily".into(),
            license: "Free".into(),
            db_files: vec!["interserver256.hdb".into()],
            update_url: Some("http://sigs.interserver.net/".into()),
            available: false, // HTTP-only — HTTPS required by update pipeline
            stability: ProviderStability::Community,
            recommendation: RecommendationLevel::Optional,
            fp_explanation: "Lightweight hash-based detection. Minimal false positive risk.".into(),
            use_case: "Users who want additional coverage for Office macro malware with minimal system impact.".into(),
            homepage: "https://sigs.interserver.net".into(),
            license_url: "https://sigs.interserver.net".into(),
            attribution: "InterServer Signatures - https://sigs.interserver.net".into(),
        },
    ]
}

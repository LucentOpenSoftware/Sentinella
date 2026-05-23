//! YARA-X Rule Engine Layer
//!
//! Compiles YARA rules at startup, caches the compiled form, and scans
//! file buffers against the rule set. Each match is translated into an
//! ARGUS [`Finding`] with human-readable descriptions — raw YARA output
//! is never exposed to the user.
//!
//! ## Rule Loading
//!
//! Rules are loaded from `runtime/argus/rules/yara/*.yar` at startup.
//! The compiled form is cached so subsequent scans don't recompile.
//! Rules can be hot-reloaded via `reload()` without restarting the daemon.
//!
//! ## Rule Metadata
//!
//! Rules should include YARA metadata for proper ARGUS integration:
//!
//! ```yara
//! rule example {
//!     meta:
//!         description = "Human-readable finding description"
//!         author      = "Sentinella"
//!         severity    = "high"       // info, low, medium, high, critical
//!         weight      = 20           // ARGUS score contribution (0-50)
//!         category    = "stealer"    // For ARGUS classification
//!     strings:
//!         $s1 = "malicious_pattern"
//!     condition:
//!         $s1
//! }
//! ```

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use tracing::{debug, info, warn};

use crate::verdict::{Finding, Layer, Severity};

/// Default weight for rules without a `weight` meta field.
const DEFAULT_WEIGHT: u32 = 15;

/// Maximum number of findings from YARA per file (prevent noise).
const MAX_FINDINGS_PER_FILE: usize = 20;

/// The compiled YARA rule engine.
pub struct YaraEngine {
    /// Compiled rules — behind RwLock for hot-reload.
    rules: RwLock<Option<yara_x::Rules>>,
    /// Number of rules currently loaded.
    rule_count: std::sync::atomic::AtomicU64,
    /// Source directories for rule files.
    rule_dirs: Vec<PathBuf>,
}

impl YaraEngine {
    /// Create a new (empty) YARA engine. Call `load_rules()` to populate.
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(None),
            rule_count: std::sync::atomic::AtomicU64::new(0),
            rule_dirs: Vec::new(),
        }
    }

    /// Number of compiled rules currently loaded.
    pub fn rule_count(&self) -> u64 {
        self.rule_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Load and compile YARA rules from one or more directories.
    ///
    /// Scans for `*.yar` and `*.yara` files recursively. Compiles all
    /// rules into a single `Rules` object for efficient scanning.
    ///
    /// On failure, the previous rule set is preserved (never leaves the
    /// engine without rules if it previously had them).
    pub fn load_rules(&self, dirs: &[PathBuf]) -> Result<u64, String> {
        let mut compiler = yara_x::Compiler::new();
        let mut file_count = 0u64;
        let mut errors = Vec::new();

        for dir in dirs {
            if !dir.exists() {
                debug!(path = %dir.display(), "YARA rule directory does not exist — skipping");
                continue;
            }

            let entries = match collect_rule_files(dir) {
                Ok(e) => e,
                Err(e) => {
                    warn!(path = %dir.display(), %e, "Failed to read YARA rule directory");
                    continue;
                }
            };

            for entry in entries {
                match std::fs::read_to_string(&entry) {
                    Ok(source) => {
                        // Add namespace based on filename for organization.
                        let ns = entry
                            .file_stem()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or("default".into());

                        match compiler.new_namespace(&ns).add_source(source.as_bytes()) {
                            Ok(_) => {
                                file_count += 1;
                                debug!(file = %entry.display(), "YARA rule file loaded");
                            }
                            Err(e) => {
                                let msg = format!("{}: {e}", entry.display());
                                warn!(msg, "YARA rule compilation error");
                                errors.push(msg);
                            }
                        }
                    }
                    Err(e) => {
                        warn!(file = %entry.display(), %e, "Cannot read YARA rule file");
                    }
                }
            }
        }

        if file_count == 0 && errors.is_empty() {
            info!("No YARA rule files found — YARA layer inactive");
            return Ok(0);
        }

        // Compile all rules.
        let compiled = compiler.build();

        // Count rules in the compiled set.
        let count = compiled.iter().count() as u64;

        // Atomic swap — previous rules stay active until this completes.
        {
            let mut guard = self.rules.write().unwrap_or_else(|e| {
                warn!("YARA rules RwLock poisoned — recovering");
                e.into_inner()
            });
            *guard = Some(compiled);
        }

        self.rule_count
            .store(count, std::sync::atomic::Ordering::Relaxed);

        if errors.is_empty() {
            info!(
                rules = count,
                files = file_count,
                "YARA rules compiled successfully",
            );
        } else {
            warn!(
                rules = count,
                files = file_count,
                errors = errors.len(),
                "YARA rules compiled with {} error(s)",
                errors.len(),
            );
        }

        Ok(count)
    }

    /// Load rules on a thread with a large stack (8 MB).
    ///
    /// YARA-X uses wasmtime for JIT compilation, and cranelift's code
    /// generation can exhaust the default 1 MB stack. This method spawns
    /// a dedicated thread with 8 MB stack for the compilation phase.
    pub fn load_rules_on_large_stack(&self, dirs: &[PathBuf]) -> Result<u64, String> {
        // Collect rule sources on the current thread (cheap I/O).
        let mut all_sources: Vec<(String, String)> = Vec::new(); // (namespace, source)
        for dir in dirs {
            if !dir.exists() {
                continue;
            }
            let entries = match collect_rule_files(dir) {
                Ok(e) => e,
                Err(e) => {
                    warn!(path = %dir.display(), %e, "Failed to read YARA rule directory");
                    continue;
                }
            };
            for entry in entries {
                match std::fs::read_to_string(&entry) {
                    Ok(source) => {
                        let ns = entry
                            .file_stem()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or("default".into());
                        all_sources.push((ns, source));
                        debug!(file = %entry.display(), "YARA rule file loaded");
                    }
                    Err(e) => warn!(file = %entry.display(), %e, "Cannot read YARA rule file"),
                }
            }
        }

        if all_sources.is_empty() {
            info!("No YARA rule files found — YARA layer inactive");
            return Ok(0);
        }

        let file_count = all_sources.len();

        // Compile on a thread with 8 MB stack.
        let compile_result = std::thread::Builder::new()
            .name("yara-compile".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || -> Result<(yara_x::Rules, Vec<String>), String> {
                let mut compiler = yara_x::Compiler::new();
                let mut errors = Vec::new();

                for (ns, source) in &all_sources {
                    if let Err(e) = compiler.new_namespace(ns).add_source(source.as_bytes()) {
                        errors.push(format!("{ns}: {e}"));
                    }
                }

                let compiled = compiler.build();
                Ok((compiled, errors))
            })
            .map_err(|e| format!("Failed to spawn YARA compiler thread: {e}"))?
            .join()
            .map_err(|_| "YARA compiler thread panicked".to_string())?;

        let (compiled, errors) = compile_result?;
        let count = compiled.iter().count() as u64;

        // Atomic swap.
        {
            let mut guard = self.rules.write().unwrap_or_else(|e| {
                warn!("YARA rules RwLock poisoned — recovering");
                e.into_inner()
            });
            *guard = Some(compiled);
        }
        self.rule_count
            .store(count, std::sync::atomic::Ordering::Relaxed);

        if errors.is_empty() {
            info!(
                rules = count,
                files = file_count,
                "YARA rules compiled successfully"
            );
        } else {
            for err in &errors {
                warn!("YARA compile error: {err}");
            }
            warn!(
                rules = count,
                files = file_count,
                errors = errors.len(),
                "YARA rules compiled with {} error(s)",
                errors.len()
            );
        }

        Ok(count)
    }

    /// Hot-reload rules from the previously configured directories.
    pub fn reload(&self) -> Result<u64, String> {
        if self.rule_dirs.is_empty() {
            return Err("No rule directories configured".into());
        }
        self.load_rules(&self.rule_dirs.clone())
    }

    /// Set the rule directories for future reload calls.
    pub fn set_rule_dirs(&mut self, dirs: Vec<PathBuf>) {
        self.rule_dirs = dirs;
    }

    /// Scan a byte buffer against the compiled YARA rules.
    ///
    /// Returns ARGUS findings — raw YARA output is translated into
    /// human-readable intelligence descriptions.
    pub fn scan(&self, data: &[u8]) -> Vec<Finding> {
        // Skip YARA on very large files — malware is typically <20MB.
        // Large files (firmware, installers, game assets) waste time in YARA
        // and are already covered by ClamAV signatures + structural analysis.
        const YARA_MAX_SCAN_SIZE: usize = 50 * 1024 * 1024; // 50 MB
        if data.len() > YARA_MAX_SCAN_SIZE {
            debug!(
                size = data.len(),
                "Skipping YARA scan — file too large (>50MB)"
            );
            return vec![];
        }

        let guard = self.rules.read().unwrap_or_else(|e| {
            warn!("YARA rules RwLock poisoned — recovering");
            e.into_inner()
        });

        let rules = match guard.as_ref() {
            Some(r) => r,
            None => return vec![], // No rules loaded.
        };

        let mut scanner = yara_x::Scanner::new(rules);
        scanner.set_timeout(std::time::Duration::from_secs(10)); // was 30s, reduced

        let scan_results = match scanner.scan(data) {
            Ok(r) => r,
            Err(e) => {
                debug!(%e, "YARA scan error");
                return vec![];
            }
        };

        let mut findings = Vec::new();

        for matching_rule in scan_results.matching_rules() {
            if findings.len() >= MAX_FINDINGS_PER_FILE {
                break;
            }

            let finding = translate_match(matching_rule);
            findings.push(finding);
        }

        findings
    }
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Rule match → ARGUS Finding translation ────────────────────────

/// Translate a YARA rule match into an ARGUS Finding.
///
/// Uses rule metadata (`description`, `severity`, `weight`, `category`)
/// to produce a coherent, human-readable finding. Falls back to
/// intelligent defaults if metadata is missing.
fn translate_match(rule: yara_x::Rule<'_, '_>) -> Finding {
    let rule_name = rule.identifier();

    // Extract metadata fields.
    // yara-x metadata() returns an iterator of (&str, MetaValue) tuples.
    let mut description = None;
    let mut severity_str = None;
    let mut weight_val = None;
    let mut category = None;
    let mut author = None;

    for (key, value) in rule.metadata() {
        match key {
            "description" => {
                if let yara_x::MetaValue::String(s) = value {
                    description = Some(s.to_string());
                }
            }
            "severity" => {
                if let yara_x::MetaValue::String(s) = value {
                    severity_str = Some(s.to_lowercase());
                }
            }
            "weight" => {
                if let yara_x::MetaValue::Integer(n) = value {
                    weight_val = Some(n as u32);
                }
            }
            "category" => {
                if let yara_x::MetaValue::String(s) = value {
                    category = Some(s.to_string());
                }
            }
            "author" => {
                if let yara_x::MetaValue::String(s) = value {
                    author = Some(s.to_string());
                }
            }
            _ => {}
        }
    }

    // Determine severity.
    let severity = match severity_str.as_deref() {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        Some("info") => Severity::Info,
        _ => infer_severity_from_name(rule_name),
    };

    // Determine weight.
    let weight = weight_val.unwrap_or_else(|| match severity {
        Severity::Critical => 35,
        Severity::High => 25,
        Severity::Medium => DEFAULT_WEIGHT,
        Severity::Low => 8,
        Severity::Info => 0,
    });

    // Build human-readable description.
    let desc = description.unwrap_or_else(|| humanize_rule_name(rule_name, category.as_deref()));

    // Build technical detail with pack attribution.
    let mut tech_parts = Vec::new();
    tech_parts.push(format!("Rule: {rule_name}"));
    let ns = rule.namespace();
    if !ns.is_empty() && ns != "default" {
        // Namespace = pack filename stem (e.g., "sentinella_ransomware").
        let pack_name = ns.strip_prefix("sentinella_").unwrap_or(ns);
        tech_parts.push(format!("Pack: {pack_name}"));
    }
    if let Some(ref cat) = category {
        tech_parts.push(format!("Category: {cat}"));
    }
    if let Some(ref auth) = author {
        tech_parts.push(format!("Source: {auth}"));
    }

    // Count matching patterns.
    let pattern_count = rule.patterns().filter(|p| p.matches().len() > 0).count();
    if pattern_count > 0 {
        tech_parts.push(format!("{pattern_count} pattern(s) matched"));
    }

    Finding {
        layer: Layer::YaraRules,
        severity,
        weight,
        description: desc,
        technical_detail: Some(tech_parts.join(" | ")),
    }
}

/// Infer severity from the rule name if no metadata is present.
fn infer_severity_from_name(name: &str) -> Severity {
    let lower = name.to_lowercase();
    if lower.contains("malware")
        || lower.contains("trojan")
        || lower.contains("ransomware")
        || lower.contains("stealer")
        || lower.contains("rat")
        || lower.contains("backdoor")
    {
        Severity::High
    } else if lower.contains("suspicious")
        || lower.contains("obfusc")
        || lower.contains("packed")
        || lower.contains("dropper")
        || lower.contains("loader")
    {
        Severity::Medium
    } else if lower.contains("pup") || lower.contains("adware") || lower.contains("generic") {
        Severity::Low
    } else {
        Severity::Medium
    }
}

/// Generate a human-readable description from a rule name.
///
/// Transforms `suspicious_obf_js_eval` → "ARGUS identified suspicious
/// obfuscated JavaScript evaluation behavior."
fn humanize_rule_name(name: &str, category: Option<&str>) -> String {
    let lower = name.to_lowercase();

    // Try category-based descriptions first.
    if let Some(cat) = category {
        return match cat {
            "stealer" | "credential_theft" => format!(
                "ARGUS identified credential theft behavior matching known stealer patterns."
            ),
            "packer" | "packed" => format!(
                "ARGUS detected executable packing or protection consistent with malware evasion."
            ),
            "script_abuse" => format!(
                "ARGUS observed suspicious scripting behavior associated with malware delivery."
            ),
            "deception" => format!(
                "ARGUS identified file deception techniques used to disguise malicious content."
            ),
            "persistence" => {
                format!("ARGUS detected system persistence mechanisms commonly used by malware.")
            }
            "miner" => format!("ARGUS identified cryptocurrency mining behavior."),
            _ => format!("ARGUS behavioral rule matched: {cat} category."),
        };
    }

    // Fallback: infer from rule name.
    if lower.contains("discord") || lower.contains("token_steal") {
        "ARGUS identified behavior associated with Discord credential theft.".into()
    } else if lower.contains("stealer") || lower.contains("infostealer") {
        "ARGUS identified information-stealing behavior targeting sensitive data.".into()
    } else if lower.contains("obfusc") && lower.contains("js") {
        "ARGUS identified obfuscated JavaScript execution patterns.".into()
    } else if lower.contains("powershell") || lower.contains("ps1") {
        "ARGUS detected suspicious PowerShell execution behavior.".into()
    } else if lower.contains("webhook") || lower.contains("exfil") {
        "ARGUS identified data exfiltration patterns via webhook endpoints.".into()
    } else if lower.contains("packed") || lower.contains("upx") || lower.contains("themida") {
        "ARGUS detected executable packing consistent with detection evasion.".into()
    } else if lower.contains("ransomware") || lower.contains("ransom") {
        "ARGUS identified behavioral indicators consistent with ransomware.".into()
    } else if lower.contains("miner") || lower.contains("crypto") {
        "ARGUS detected cryptocurrency mining indicators.".into()
    } else if lower.contains("rat") || lower.contains("backdoor") {
        "ARGUS identified remote access tool or backdoor behavior.".into()
    } else if lower.contains("dropper") || lower.contains("loader") {
        "ARGUS detected malware dropper or loader characteristics.".into()
    } else if lower.contains("fake") || lower.contains("disguise") {
        "ARGUS identified file disguise or impersonation techniques.".into()
    } else {
        format!("ARGUS behavioral rule triggered: pattern consistent with known threat indicators.")
    }
}

// ── File collection ───────────────────────────────────────────────

/// Recursively collect `.yar` and `.yara` files from a directory.
fn collect_rule_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect_recursive(dir, &mut files)?;
    files.sort(); // Deterministic load order.
    Ok(files)
}

fn collect_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("Cannot read {}: {e}", dir.display()))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();

        if path.is_dir() {
            collect_recursive(&path, files)?;
        } else if let Some(ext) = path.extension() {
            let ext_lower = ext.to_string_lossy().to_lowercase();
            if ext_lower == "yar" || ext_lower == "yara" {
                files.push(path);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_engine() {
        let engine = YaraEngine::new();
        assert_eq!(engine.rule_count(), 0);
        let findings = engine.scan(b"test data");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_compile_and_scan() {
        let engine = YaraEngine::new();

        // Create a temp rule file.
        let dir = std::env::temp_dir().join("argus_yara_test");
        std::fs::create_dir_all(&dir).unwrap();
        let rule_path = dir.join("test.yar");
        std::fs::write(
            &rule_path,
            r#"
            rule test_eicar {
                meta:
                    description = "ARGUS identified a known test pattern."
                    severity = "high"
                    weight = 30
                    category = "test"
                strings:
                    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
                condition:
                    $eicar
            }
        "#,
        )
        .unwrap();

        let count = engine.load_rules(&[dir.clone()]).unwrap();
        assert!(count >= 1, "Expected at least 1 rule, got {count}");

        // Scan EICAR test string.
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let findings = engine.scan(eicar);
        assert!(!findings.is_empty(), "Expected YARA match on EICAR");
        assert_eq!(findings[0].layer, Layer::YaraRules);
        assert_eq!(findings[0].weight, 30);
        assert!(findings[0].description.contains("ARGUS"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_humanize_rule_names() {
        assert!(humanize_rule_name("discord_token_stealer", None).contains("Discord"));
        assert!(humanize_rule_name("suspicious_powershell_encoded", None).contains("PowerShell"));
        assert!(humanize_rule_name("generic_something", None).contains("ARGUS"));
    }
}

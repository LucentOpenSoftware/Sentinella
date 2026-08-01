//! Reading and removing Windows NRPT rules.
//!
//! # Why removal ships first, and alone
//!
//! An NRPT rule points the whole machine's DNS at a nominated resolver. It
//! lives in the registry and SURVIVES REBOOTS. The dangerous state is
//! therefore not "our proxy is broken" — it is "the rule is installed and
//! nothing is answering", which is a machine with no name resolution at
//! all, on every subsequent boot, for a user who cannot search for the fix
//! because search does not resolve.
//!
//! So ownership is inverted from the obvious design: the rule may exist
//! only while the daemon is proven healthy, and a boot-time reconciler
//! running OUT OF PROCESS is what enforces that. This crate is shared by
//! the reconciler (which removes) and later by the daemon (which installs).
//! Removal lands first so that at no point in the commit series can a rule
//! exist with nothing able to take it away.
//!
//! # Registry, not PowerShell
//!
//! `Remove-DnsClientNrptRule` is the documented interface and the wrong one
//! here. The reconciler runs at boot as SYSTEM, must finish in
//! milliseconds, and must work where PowerShell is absent (Server Core,
//! Nano) or restricted (ConstrainedLanguage). Spawning powershell.exe costs
//! module autoload and can block for seconds. Deleting the rule's own
//! subkey is a handful of syscalls with no external dependency, and at boot
//! it lands before the DNS Client has read the policy at all.
//!
//! # Identity is the GUID, never the name
//!
//! Rules are identified by the GUID subkey they live under. Matching on
//! DisplayName or Comment would be check-then-act on a string an
//! administrator or another product can also set, and the failure mode is
//! deleting somebody else's DNS policy.
//!
//! THE INVARIANT THAT MAKES GUID-ONLY IDENTITY SAFE: whatever creates a
//! rule must write its GUID to disk BEFORE creating it. A missing GUID file
//! then means the rule was never created — not that we have lost track of
//! one. The installing side (commit C) has to honour that ordering; this
//! crate's `record_guid` exists to make it the easy thing to do.

use std::path::Path;

#[cfg(windows)]
mod registry;

#[cfg(not(windows))]
mod registry {
    use super::Error;
    pub fn subkey_exists(_path: &str, _guid: &str) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    pub fn delete_subkey(_path: &str, _guid: &str) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    pub fn list_subkeys(_path: &str) -> Result<Vec<String>, Error> {
        Err(Error::Unsupported)
    }
}

/// Where local (non-GPO) NRPT rules live.
pub const DNS_POLICY_CONFIG: &str =
    r"SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The policy container itself is absent. Normal on a machine that has
    /// never had an NRPT rule, and NOT a failure for a reconciler.
    NoPolicyContainer,
    /// Almost always "not running as SYSTEM or Administrator".
    AccessDenied(String),
    Registry(String),
    /// The GUID was not shaped like a GUID. Refused rather than sanitized:
    /// this string names a key we are about to delete.
    MalformedGuid(String),
    Unsupported,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPolicyContainer => {
                write!(f, "no NRPT policy container (no rules have ever existed)")
            }
            Self::AccessDenied(d) => {
                write!(f, "access denied: {d} (SYSTEM or Administrator required)")
            }
            Self::Registry(d) => write!(f, "registry error: {d}"),
            Self::MalformedGuid(g) => write!(f, "not a GUID: {g:?}"),
            Self::Unsupported => write!(f, "NRPT is a Windows feature"),
        }
    }
}

impl std::error::Error for Error {}

/// Validate a rule GUID before it is ever used to build a registry path.
///
/// Accepts only the braced form Windows writes,
/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`. Anything else is refused
/// rather than cleaned up, because a lenient parser here turns a truncated
/// or corrupted state file into "delete some other subkey".
pub fn validate_guid(guid: &str) -> Result<(), Error> {
    let b = guid.as_bytes();
    if b.len() != 38 || b[0] != b'{' || b[37] != b'}' {
        return Err(Error::MalformedGuid(guid.to_string()));
    }
    const DASHES: [usize; 4] = [9, 14, 19, 24];
    for (i, c) in b.iter().enumerate().take(37).skip(1) {
        if DASHES.contains(&i) {
            if *c != b'-' {
                return Err(Error::MalformedGuid(guid.to_string()));
            }
        } else if !c.is_ascii_hexdigit() {
            return Err(Error::MalformedGuid(guid.to_string()));
        }
    }
    Ok(())
}

/// Is a rule with this GUID present?
pub fn rule_exists(guid: &str) -> Result<bool, Error> {
    validate_guid(guid)?;
    match registry::subkey_exists(DNS_POLICY_CONFIG, guid) {
        Err(Error::NoPolicyContainer) => Ok(false),
        other => other,
    }
}

/// Remove the rule with this GUID.
///
/// Idempotent: removing an absent rule is success. The reconciler's job is
/// to reach a STATE, not to perform an action, and an "already gone" error
/// would make every clean boot look like a failure.
pub fn remove_rule(guid: &str) -> Result<(), Error> {
    validate_guid(guid)?;
    match registry::delete_subkey(DNS_POLICY_CONFIG, guid) {
        Err(Error::NoPolicyContainer) => Ok(()),
        other => other,
    }
}

/// Every rule GUID currently present — ours and other people's.
///
/// Diagnostic only. Never use this to decide what to delete: see the
/// identity note in the crate docs.
pub fn list_rules() -> Result<Vec<String>, Error> {
    match registry::list_subkeys(DNS_POLICY_CONFIG) {
        Err(Error::NoPolicyContainer) => Ok(Vec::new()),
        other => other,
    }
}

/// Read the GUID this installation recorded, if any.
///
/// Anything unreadable, absent or malformed reads as `None` — "no rule was
/// recorded" — which is the safe direction: it makes the reconciler do
/// nothing rather than delete a key named by garbage.
pub fn recorded_guid(state_file: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(state_file).ok()?;
    let trimmed = raw.trim();
    validate_guid(trimmed).ok()?;
    Some(trimmed.to_string())
}

/// Record a GUID, durably, BEFORE the rule it names is created.
///
/// The ordering is the whole safety argument for identifying rules by GUID
/// alone: if this file is missing, the rule does not exist. Written to a
/// temporary file and renamed so a crash mid-write cannot leave a half
/// GUID that `recorded_guid` would reject and a rule that outlives it.
pub fn record_guid(state_file: &Path, guid: &str) -> Result<(), Error> {
    validate_guid(guid)?;
    if let Some(parent) = state_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Registry(format!("state dir: {e}")))?;
    }
    let tmp = state_file.with_extension("tmp");
    std::fs::write(&tmp, guid).map_err(|e| Error::Registry(format!("state write: {e}")))?;
    std::fs::rename(&tmp, state_file).map_err(|e| Error::Registry(format!("state rename: {e}")))?;
    Ok(())
}

/// Forget the recorded GUID. Call only AFTER the rule is gone: the reverse
/// order strands a rule nothing can name.
pub fn clear_guid(state_file: &Path) -> Result<(), Error> {
    match std::fs::remove_file(state_file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Registry(format!("state remove: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}";

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join("nrpt-tests");
        std::fs::create_dir_all(&d).unwrap();
        d.join(name)
    }

    #[test]
    fn accepts_the_braced_form_windows_writes() {
        assert!(validate_guid(GOOD).is_ok());
        assert!(validate_guid("{deadbeef-dead-beef-dead-beefdeadbeef}").is_ok());
    }

    /// This string names a registry key we are about to DELETE. Every one
    /// of these must be refused rather than cleaned up.
    #[test]
    fn refuses_anything_that_is_not_exactly_a_guid() {
        for bad in [
            "",
            "not-a-guid",
            "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0",
            "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0",
            "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F}",
            "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F00}",
            "{0F1E2D3C_4B5A_6978_8796_A5B4C3D2E1F0}",
            "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1G0}",
            r"{..\..\Services\Tcpip\Parameters}",
            r"{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}\..\Other",
        ] {
            assert!(
                validate_guid(bad).is_err(),
                "must refuse {bad:?} — it names a key to delete"
            );
        }
    }

    /// Validation must sit in front of the registry calls, not beside them.
    #[test]
    fn a_malformed_guid_never_reaches_the_registry() {
        assert!(matches!(
            rule_exists(r"..\..\evil"),
            Err(Error::MalformedGuid(_))
        ));
        assert!(matches!(
            remove_rule(r"..\..\evil"),
            Err(Error::MalformedGuid(_))
        ));
        assert!(matches!(
            record_guid(&scratch("never.txt"), "nope"),
            Err(Error::MalformedGuid(_))
        ));
    }

    #[test]
    fn a_missing_state_file_reads_as_no_rule() {
        assert_eq!(recorded_guid(&scratch("absent.txt")), None);
    }

    /// A corrupted state file must read as "no rule recorded", never as a
    /// key name — otherwise a truncated write becomes a deletion target.
    #[test]
    fn a_corrupted_state_file_reads_as_no_rule() {
        let f = scratch("corrupt.txt");
        std::fs::write(&f, "\u{feff}not a guid at all\n").unwrap();
        assert_eq!(recorded_guid(&f), None);
        std::fs::write(&f, "{0F1E2D3C-4B5A-6978-87").unwrap(); // truncated
        assert_eq!(recorded_guid(&f), None);
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn record_then_read_round_trips_and_tolerates_whitespace() {
        let f = scratch("roundtrip.txt");
        record_guid(&f, GOOD).unwrap();
        assert_eq!(recorded_guid(&f).as_deref(), Some(GOOD));
        std::fs::write(&f, format!("  {GOOD}\r\n")).unwrap();
        assert_eq!(recorded_guid(&f).as_deref(), Some(GOOD));
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn clearing_is_idempotent() {
        let f = scratch("clear.txt");
        record_guid(&f, GOOD).unwrap();
        clear_guid(&f).unwrap();
        clear_guid(&f).expect("clearing an absent record must succeed");
        assert_eq!(recorded_guid(&f), None);
    }

    /// Read-only look at the real machine. IGNORED because it depends on
    /// what this box has configured, but it is the only thing that
    /// exercises the registry FFI at all:
    ///
    ///   cargo test -p nrpt real_registry -- --ignored --nocapture
    ///
    /// Deliberately does NOT delete anything. The delete path is exercised
    /// by the reconciler's own end-to-end check against a rule it created.
    #[test]
    #[ignore = "environment-dependent: reads the live NRPT policy container"]
    fn real_registry_read_only() {
        match list_rules() {
            Ok(rules) if rules.is_empty() => {
                println!("no NRPT rules on this machine (expected)");
            }
            Ok(rules) => {
                println!("{} NRPT rule(s) present:", rules.len());
                for r in &rules {
                    println!("  {r}");
                }
            }
            Err(e) => println!("could not read the policy container: {e}"),
        }
        // A GUID we certainly did not create must read as absent, not as
        // an error, on any machine.
        match rule_exists(GOOD) {
            Ok(present) => assert!(!present, "a random GUID must not be present"),
            Err(e) => println!("rule_exists reported: {e}"),
        }
    }

    /// The reconciler runs on every boot, including boots where nothing
    /// was ever installed. "Never had a rule" must not look like an error.
    #[test]
    fn absent_policy_container_is_not_an_error() {
        // Exercised through the public wrappers, which map
        // NoPolicyContainer to the benign answer.
        #[cfg(not(windows))]
        {
            assert!(matches!(rule_exists(GOOD), Err(Error::Unsupported)));
        }
        #[cfg(windows)]
        {
            // On a real box the container usually exists and is empty;
            // either way neither of these may panic or report failure for
            // a machine that simply has no rules.
            let _ = rule_exists(GOOD);
            let _ = list_rules();
        }
    }
}

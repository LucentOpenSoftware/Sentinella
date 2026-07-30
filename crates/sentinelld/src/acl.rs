//! DACL policy + startup repair for the Sentinella data root and secret files.
//!
//! v0.1.12 workstreams I + J. Two confirmed findings drove this module:
//!
//! 1. **Data root has no restrictive DACL.** The MSI sets no `Permission`
//!    on `C:\ProgramData\Sentinella` and the daemon only ACLs specific
//!    secret files. The root therefore inherits `%ProgramData%`'s DACL —
//!    which grants BUILTIN\Users read AND "create folders / append data" —
//!    or, on a dev box where a user-context process created the tree first,
//!    leaves the installing user as OWNER with full control over the scan
//!    cache, config, and state databases.
//! 2. **`.vault_key` / `vault_integrity_key` ACLs were creation-only.**
//!    `icacls` ran when the key file was first written; nothing re-asserted
//!    it on later startups, so any later relaxation (observed in the field
//!    as `Nicolas:(R)` on the key) persisted forever.
//!
//! ## Policy (chosen DACLs)
//!
//! - **Data root**: owner BUILTIN\Administrators, protected DACL with
//!   exactly `SYSTEM:(OI)(CI)(F)` + `Administrators:(OI)(CI)(F)`. No
//!   BUILTIN\Users ACE at all — the GUI reaches everything through IPC;
//!   the single file it must read directly (`state\ipc_secret`) carries
//!   its own explicit ACL (see below) which is unaffected by the root
//!   policy because secret files disable inheritance.
//! - **Daemon-only secrets** (`.vault_key`, `vault_integrity_key`):
//!   `SYSTEM:(R)` + `Administrators:(R)`, inheritance removed. Mirrors the
//!   creation-time ACL in `quarantine::restrict_file_permissions` exactly
//!   (R7-LETHAL rationale: the vault key encrypts every quarantined
//!   malware sample — Users read turns quarantine into a public archive).
//! - **Shared secret** (`state\ipc_secret`): adds `Users:(R)` — the
//!   unelevated GUI must read it. Mirrors `ipc::state` creation-time ACL.
//!
//! Owner is deliberately repaired (set to Administrators): a non-admin
//! owner retains implicit READ_CONTROL/WRITE_DAC and could simply undo any
//! DACL we write, so DACL-only repair against a hostile owner is cosmetic.
//!
//! ## Idempotence
//!
//! Repair is compare-first: the current security descriptor is read as
//! SDDL (via the Win32 API — `icacls` *display* output is localized and
//! unparseable), parsed, and evaluated. A conforming descriptor is a pure
//! no-op; `icacls` is only invoked when the descriptor deviates. Writes
//! reuse the codebase's existing icacls pattern (raw SIDs, exit-status +
//! stderr checked, `system32_tool` + `quiet_windows`).
//!
//! When the root DACL needed repair, existing children still carry stale
//! *copies* of the old inherited ACEs (Windows does not retro-propagate),
//! so a one-time `icacls /reset /T` normalizes the tree to inherit the new
//! root policy. `/reset` touches only DACLs — SACLs (audit ACEs) are
//! preserved — and the known secret files are re-asserted immediately
//! afterwards, closing the window where their explicit ACLs were reset.
//!
//! ## Failure posture
//!
//! - Root DACL repair failure → `error!` log, daemon continues in an
//!   explicitly degraded state (an AV that refuses to start cannot report
//!   anything; the threat model here is local non-admin tampering, not the
//!   daemon's own availability).
//! - Secret-file ACL failure → **fail closed**: the caller treats the key
//!   as unusable (same posture as a crypto-init failure in quarantine
//!   today). The key itself is NEVER rotated or replaced — only its ACL
//!   is repaired.
//! - Unparseable security descriptor → fail closed (never rewrite an ACL
//!   we could not reason about; for secrets, refuse to use the key).
//!
//! ## Dev / portable mode
//!
//! DACL hardening is skipped unless the process token is SYSTEM (the
//! production service account). A dev daemon runs as the developer; ACLing
//! its `runtime/` tree to SYSTEM+Admins would lock the unelevated dev GUI
//! and test processes out. Portable mode's exe-dir trust rules
//! (`paths::is_trusted_install_dir`) already exclude user-writable roots.
//!
//! Non-Windows builds keep a minimal equivalent: `chmod 0700` on the data
//! root, `chmod 0600` on secrets, compare-first. (The Unix daemon runs
//! root-only by packaging; full POSIX ACLs are out of scope.)

use std::path::Path;

// ─────────────────────────────────────────────────────────────────────
// Pure policy logic — platform independent, unit-testable without admin.
// ─────────────────────────────────────────────────────────────────────

/// FILE_ALL_ACCESS.
pub const FILE_ALL_ACCESS: u32 = 0x1F01FF;
/// FILE_GENERIC_READ (what `icacls (R)` produces).
pub const FILE_GENERIC_READ: u32 = 0x120089;

/// Well-known SIDs (normalized long form used for comparisons).
pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
pub const SID_USERS: &str = "S-1-5-32-545";

/// Bounded parsing: SDDL strings derive from on-disk state (an attacker
/// with WRITE_DAC on the object controls them), so cap both total length
/// and ACE count before any allocation.
const MAX_SDDL_LEN: usize = 64 * 1024;
const MAX_ACES: usize = 512;

/// One parsed DACL access-control entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// `D` (deny) vs `A` (allow).
    pub deny: bool,
    /// `ID` — inherited from a parent object (vs. set explicitly).
    pub inherited: bool,
    /// `OI` — child files inherit this ACE.
    pub object_inherit: bool,
    /// `CI` — child directories inherit this ACE.
    pub container_inherit: bool,
    /// `IO` — inherit-only; does not apply to the object itself.
    pub inherit_only: bool,
    /// Access mask (SDDL letter pairs or `0x…` hex decoded).
    pub rights: u32,
    /// Trustee SID, normalized to long form (`S-1-5-…`).
    pub sid: String,
}

/// Parsed owner + DACL view of a security descriptor (SACL ignored — we
/// never read or modify audit policy).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SdInfo {
    /// Owner SID (normalized), if an `O:` section was present.
    pub owner: Option<String>,
    /// False = NULL DACL (SE_DACL_PRESENT clear) — world-full-control.
    pub dacl_present: bool,
    /// `P` flag — DACL protected from inheritance (`/inheritance:r`).
    pub dacl_protected: bool,
    pub aces: Vec<Ace>,
}

/// Which canned policy an object is evaluated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    /// The data root directory itself.
    DataRoot,
    /// `.vault_key`, `vault_integrity_key` — SYSTEM + Admins read only.
    DaemonOnlySecret,
    /// `state\ipc_secret` — additionally readable by BUILTIN\Users (GUI).
    SharedSecret,
}

/// What `evaluate` decided about the current descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclVerdict {
    /// Descriptor conforms — do NOT touch it (no ACL churn per boot).
    Secure,
    /// Deviation that the canonical icacls repair fixes.
    NeedsRepair {
        /// Owner is not SYSTEM/Administrators.
        owner: bool,
        /// DACL structure deviates from policy.
        dacl: bool,
    },
    /// Descriptor could not be reasoned about — do not modify, do not
    /// trust (for secrets: refuse to use the object).
    FailClosed(String),
}

/// Normalize a SDDL trustee token to a long-form SID for comparison.
/// Accepts both the aliases SDDL emits (`SY`, `BA`, `BU`, `CO`) and the
/// long forms, so either rendering compares equal.
fn norm_sid(s: &str) -> String {
    match s {
        "SY" => SID_SYSTEM.to_string(),
        "BA" => SID_ADMINISTRATORS.to_string(),
        "BU" => SID_USERS.to_string(),
        "CO" => "S-1-3-0".to_string(),
        other => other.to_ascii_uppercase(),
    }
}

fn is_admin_sid(s: &str) -> bool {
    s == SID_SYSTEM || s == SID_ADMINISTRATORS
}

/// Decode an SDDL rights field into an access mask.
///
/// Handles the letter pairs ConvertSecurityDescriptorToStringSecurityDescriptor
/// emits for standard combinations (`FA`, `FR`, …) and `0x` hex for odd
/// masks. Unknown letters → Err (fail closed: we refuse to reason about a
/// descriptor we cannot fully decode).
fn parse_rights(s: &str) -> Result<u32, String> {
    if s.is_empty() || s.len() > 10 {
        return Err(format!("invalid rights field len {}", s.len()));
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).map_err(|e| format!("bad hex rights {s:?}: {e}"));
    }
    if s.len() % 2 != 0 {
        return Err(format!("odd-length rights field {s:?}"));
    }
    let mut mask = 0u32;
    let b = s.as_bytes();
    for pair in b.chunks_exact(2) {
        let bits = match pair {
            // Generic rights.
            b"GA" => 0x1000_0000,
            b"GR" => 0x8000_0000,
            b"GW" => 0x4000_0000,
            b"GX" => 0x2000_0000,
            // File/directory shorthand.
            b"FA" => FILE_ALL_ACCESS,
            b"FR" => FILE_GENERIC_READ,
            b"FW" => 0x120116,
            b"FX" => 0x1200A0,
            // Specific rights (bit aliases shared by files and DS objects).
            b"CC" => 0x1,
            b"DC" => 0x2,
            b"LC" => 0x4,
            b"SW" => 0x8,
            b"RP" => 0x10,
            b"WP" => 0x20,
            b"DT" => 0x40,
            b"LO" => 0x80,
            b"CR" => 0x100,
            // Standard rights.
            b"SD" => 0x1_0000,   // DELETE
            b"RC" => 0x2_0000,   // READ_CONTROL
            b"WD" => 0x4_0000,   // WRITE_DAC
            b"WO" => 0x8_0000,   // WRITE_OWNER
            _ => return Err(format!("unknown SDDL rights pair {:?}", String::from_utf8_lossy(pair))),
        };
        mask |= bits;
    }
    Ok(mask)
}

/// Parse the `O:` + `D:` sections of an SDDL string.
///
/// `G:` (group) is skipped — policy never depends on it. `S:` (SACL) is
/// skipped — we never touch audit ACEs. Errors are fail-closed signals:
/// callers must NOT modify (or, for secrets, use) the object.
pub fn parse_sddl(sddl: &str) -> Result<SdInfo, String> {
    if sddl.len() > MAX_SDDL_LEN {
        return Err(format!("SDDL too long: {} bytes", sddl.len()));
    }
    let mut info = SdInfo::default();
    let bytes = sddl.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let section = &sddl[i..i + 2];
        i += 2;
        // Section content runs until the next section marker or EOF.
        let start = i;
        while i + 1 < bytes.len() && !matches!(&sddl[i..i + 2], "O:" | "G:" | "D:" | "S:") {
            i += 1;
        }
        // Trailing single char (no room for a 2-char marker).
        if i + 1 >= bytes.len() && i < bytes.len() {
            i = bytes.len();
        }
        let content = &sddl[start..i];
        match section {
            "O:" => {
                if content.is_empty() || content.len() > 256 {
                    return Err("invalid owner section".into());
                }
                info.owner = Some(norm_sid(content));
            }
            "D:" => parse_dacl(content, &mut info)?,
            "G:" | "S:" => {} // ignored by policy (see module docs)
            _ => return Err(format!("unexpected SDDL content at byte {start}")),
        }
    }
    Ok(info)
}

fn parse_dacl(content: &str, info: &mut SdInfo) -> Result<(), String> {
    info.dacl_present = true;
    let mut rest = content;
    // DACL control flags precede the first ACE: P (protected), AI, AR.
    loop {
        if let Some(r) = rest.strip_prefix("AI").or_else(|| rest.strip_prefix("AR")) {
            rest = r;
        } else if let Some(r) = rest.strip_prefix('P') {
            info.dacl_protected = true;
            rest = r;
        } else {
            break;
        }
    }
    while !rest.is_empty() {
        if info.aces.len() >= MAX_ACES {
            return Err(format!("more than {MAX_ACES} ACEs"));
        }
        if !rest.starts_with('(') {
            return Err(format!("expected '(' in DACL, found {rest:?}"));
        }
        let end = rest.find(')').ok_or("unterminated ACE")?;
        let ace = &rest[1..end];
        info.aces.push(parse_ace(ace)?);
        rest = &rest[end + 1..];
    }
    Ok(())
}

fn parse_ace(ace: &str) -> Result<Ace, String> {
    // (type;flags;rights;object_guid;inherit_guid;account_sid)
    let fields: Vec<&str> = ace.split(';').collect();
    if fields.len() != 6 {
        return Err(format!("ACE has {} fields (expected 6)", fields.len()));
    }
    let deny = match fields[0] {
        "A" => false,
        "D" => true,
        other => {
            return Err(format!(
                "unsupported ACE type {other:?} (object/audit/callback ACE)"
            ))
        }
    };
    let mut a = Ace {
        deny,
        inherited: false,
        object_inherit: false,
        container_inherit: false,
        inherit_only: false,
        rights: parse_rights(fields[2])?,
        sid: String::new(),
    };
    let flags = fields[1];
    if flags.len() % 2 != 0 {
        return Err(format!("odd ACE flags {flags:?}"));
    }
    for pair in flags.as_bytes().chunks_exact(2) {
        match pair {
            b"CI" => a.container_inherit = true,
            b"OI" => a.object_inherit = true,
            b"IO" => a.inherit_only = true,
            b"ID" => a.inherited = true,
            b"NP" => {} // no-propagate: no policy impact
            _ => return Err(format!("unknown ACE flag {:?}", String::from_utf8_lossy(pair))),
        }
    }
    if !fields[3].is_empty() || !fields[4].is_empty() {
        return Err("object GUIDs in ACE (unsupported)".into());
    }
    if fields[5].is_empty() || fields[5].len() > 256 {
        return Err("empty/oversized ACE trustee".into());
    }
    a.sid = norm_sid(fields[5]);
    Ok(a)
}

/// The exact allow-ACE set each policy requires: `(sid, rights, oi, ci)`.
/// Anything beyond or different from this set is a deviation.
fn required_aces(kind: PolicyKind) -> Vec<(&'static str, u32, bool, bool)> {
    match kind {
        PolicyKind::DataRoot => vec![
            (SID_SYSTEM, FILE_ALL_ACCESS, true, true),
            (SID_ADMINISTRATORS, FILE_ALL_ACCESS, true, true),
        ],
        PolicyKind::DaemonOnlySecret => vec![
            (SID_SYSTEM, FILE_GENERIC_READ, false, false),
            (SID_ADMINISTRATORS, FILE_GENERIC_READ, false, false),
        ],
        PolicyKind::SharedSecret => vec![
            (SID_SYSTEM, FILE_GENERIC_READ, false, false),
            (SID_ADMINISTRATORS, FILE_GENERIC_READ, false, false),
            (SID_USERS, FILE_GENERIC_READ, false, false),
        ],
    }
}

/// Evaluate a parsed descriptor against a policy.
///
/// Exact-set semantics: the DACL must be protected, contain no deny ACEs,
/// and its allow ACEs must be precisely the required set (no missing, no
/// extra — an extra read-only `Users:(R)` on a vault key is still a
/// repair, per the observed `Nicolas:(R)` anomaly). Owner must be SYSTEM
/// or Administrators (see module docs for why we repair owner).
pub fn evaluate(info: &SdInfo, kind: PolicyKind) -> AclVerdict {
    let owner_ok = info.owner.as_deref().map(is_admin_sid).unwrap_or(false);
    if info.owner.is_none() {
        return AclVerdict::FailClosed("security descriptor has no owner".into());
    }
    if !info.dacl_present {
        // NULL DACL = everyone full control — insecure but well-defined;
        // repairable by writing the canonical DACL.
        return AclVerdict::NeedsRepair {
            owner: !owner_ok,
            dacl: true,
        };
    }
    let mut dacl_bad = !info.dacl_protected;
    if !dacl_bad {
        let mut required: Vec<(&str, u32, bool, bool)> = required_aces(kind);
        for ace in &info.aces {
            if ace.deny || ace.inherited || ace.inherit_only {
                dacl_bad = true;
                break;
            }
            let key = (ace.sid.as_str(), ace.rights, ace.object_inherit, ace.container_inherit);
            match required.iter().position(|r| *r == key) {
                Some(pos) => {
                    required.swap_remove(pos);
                }
                None => {
                    dacl_bad = true; // extra ACE (e.g. stray Users:(R))
                    break;
                }
            }
        }
        if !required.is_empty() {
            dacl_bad = true; // missing required grant
        }
    }
    if dacl_bad || !owner_ok {
        AclVerdict::NeedsRepair {
            owner: !owner_ok,
            dacl: dacl_bad,
        }
    } else {
        AclVerdict::Secure
    }
}

/// DACL-only view of the child-dir rule (owner assessed separately so the
/// repair can distinguish `/setowner /T` from `/reset /T`).
pub fn child_dir_dacl_is_clean(info: &SdInfo) -> bool {
    info.dacl_present
        && !info.dacl_protected
        && !info.aces.is_empty()
        && info
            .aces
            .iter()
            .all(|a| a.inherited && !a.deny && is_admin_sid(&a.sid))
}

/// Spot-check rule for *immediate child directories* of the data root
/// (cheap partial-state detector; see `ensure_data_root_acl`): a healthy
/// child has an unprotected DACL consisting solely of ACEs inherited from
/// the (already-repaired) root — hence only SYSTEM/Administrators trustees
/// — plus an admin owner. Anything else (explicit ACEs, deny ACEs, Users
/// grants, non-admin owner) marks the tree as contaminated and triggers
/// the one-time `/reset /T` normalization.
// Only consumed by tests in this binary crate (production code assesses
/// owner and DACL separately via `child_dir_dacl_is_clean`).
#[allow(dead_code)]
pub fn child_dir_is_clean(info: &SdInfo) -> bool {
    let owner_ok = info.owner.as_deref().map(is_admin_sid).unwrap_or(false);
    owner_ok && child_dir_dacl_is_clean(info)
}

/// Canonical SDDL for each policy — documentation and idempotence tests:
/// evaluating the canonical descriptor MUST yield `Secure`, which is what
/// makes a second repair pass a no-op.
// Only consumed by tests + docs in this binary crate.
#[allow(dead_code)]
pub fn canonical_sddl(kind: PolicyKind) -> &'static str {
    match kind {
        PolicyKind::DataRoot => "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        PolicyKind::DaemonOnlySecret => "O:BAG:SYD:P(A;;FR;;;SY)(A;;FR;;;BA)",
        PolicyKind::SharedSecret => "O:BAG:SYD:P(A;;FR;;;SY)(A;;FR;;;BA)(A;;FR;;;BU)",
    }
}

/// Reject secret paths that are missing, directories, or reparse points.
///
/// A symlink/junction at `.vault_key` would redirect key reads/writes into
/// attacker-chosen territory; a directory there means something is deeply
/// wrong. Fail closed in both cases. Pure `symlink_metadata` — no admin
/// needed, unit-tested cross-platform.
pub fn reject_unsafe_secret_path(path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("{}: stat failed: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if crate::scan::is_reparse_point(path) {
        return Err(format!("{}: reparse point at secret path", path.display()));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Public entry points
// ─────────────────────────────────────────────────────────────────────

/// Outcome of a secret-file ACL (re-)assertion.
///
/// `Secure`/`Repaired` are constructed only by the production (non-test)
/// backend — under `cfg(test)` `assert_secret_acl` always returns `Skipped`
/// so the user-running test process can't lock itself out of its own temp
/// files — hence the test-build dead-code allowance.
#[cfg_attr(test, allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretAclStatus {
    /// Already conforming — nothing was modified.
    Secure,
    /// Deviated; canonical ACL applied and re-verified.
    Repaired,
    /// Not evaluated (test build, or process is not SYSTEM).
    Skipped,
}

/// Re-assert the ACL on a secret file (workstream J).
///
/// Compare-first: reads the current descriptor, evaluates against `kind`,
/// repairs only on deviation, re-verifies after repair. The file itself is
/// never modified — a valid key with a wrong ACL keeps its bytes.
///
/// `Err` = fail closed (unparseable descriptor, unsafe path, or repair did
/// not converge). Callers must treat the secret as unusable — this matches
/// quarantine's existing crypto-init failure posture.
pub fn assert_secret_acl(path: &Path, kind: PolicyKind) -> Result<SecretAclStatus, String> {
    reject_unsafe_secret_path(path)?;

    // Under `cargo test` the test process runs as the user, not SYSTEM;
    // applying a SYSTEM-only ACL would lock it out of its own temp files
    // (same rationale as quarantine::restrict_file_permissions).
    #[cfg(test)]
    {
        let _ = kind;
        return Ok(SecretAclStatus::Skipped);
    }

    #[cfg(all(target_os = "windows", not(test)))]
    {
        if !imp::current_process_is_system() {
            // Dev/foreground run — see module docs ("Dev / portable mode").
            tracing::debug!(path = %path.display(), "not SYSTEM — skipping secret ACL assertion");
            return Ok(SecretAclStatus::Skipped);
        }
        return imp::ensure_secret_acl(path, kind).map(|o| match o {
            imp::SecretOutcome::Secure => SecretAclStatus::Secure,
            imp::SecretOutcome::Repaired => SecretAclStatus::Repaired,
        });
    }

    #[cfg(all(not(target_os = "windows"), not(test)))]
    {
        let _ = kind;
        unix_chmod_if_needed(path, 0o600)?;
        Ok(SecretAclStatus::Secure)
    }
}

/// Startup repair for the data root + already-existing secrets
/// (workstream I). Never panics, never blocks daemon startup: failures are
/// logged at `error!` and the daemon continues in a documented degraded
/// state (see module docs).
///
/// Call after `PathManager` init + `ensure_dirs`, before any subsystem
/// reads secrets or config.
pub fn startup_hardening(pm: &crate::paths::PathManager) {
    #[cfg(target_os = "windows")]
    {
        let root = pm.root();
        if crate::scan::is_reparse_point(root) {
            tracing::error!(
                root = %root.display(),
                "data root is a reparse point — refusing to touch ACLs (fail closed)"
            );
            return;
        }
        if !imp::current_process_is_system() {
            tracing::debug!("not running as SYSTEM — data-root DACL hardening skipped (dev/foreground)");
            return;
        }
        match imp::ensure_data_root_acl(root) {
            imp::RootOutcome::AlreadySecure => {
                tracing::debug!(root = %root.display(), "data root DACL conforms to policy");
            }
            imp::RootOutcome::Repaired { owner_fixed, tree_normalized } => {
                tracing::info!(
                    root = %root.display(),
                    owner_fixed, tree_normalized,
                    "data root DACL repaired to SYSTEM+Administrators policy"
                );
                // The tree normalization (/reset /T) reset DACLs on ALL
                // children, including the explicit ACLs on secret files.
                // Re-assert every known secret that exists right now; the
                // lazy re-assertions (IntegrityVault::init, get_vault_key,
                // ipc secret load) cover keys created later this boot.
                for (path, kind) in [
                    (pm.ipc_secret(), PolicyKind::SharedSecret),
                    (pm.vault_integrity_key(), PolicyKind::DaemonOnlySecret),
                    (pm.quarantine_dir().join(".vault_key"), PolicyKind::DaemonOnlySecret),
                ] {
                    if path.exists() {
                        match imp::ensure_secret_acl(&path, kind) {
                            Ok(imp::SecretOutcome::Secure) | Ok(imp::SecretOutcome::Repaired) => {}
                            Err(e) => tracing::error!(
                                path = %path.display(), error = %e,
                                "secret ACL re-assertion failed after tree normalization — file may be over- or under-permissioned"
                            ),
                        }
                    }
                }
            }
            imp::RootOutcome::Degraded(reason) => {
                tracing::error!(
                    root = %root.display(),
                    reason = %reason,
                    "data root DACL hardening FAILED — running with a potentially user-writable data root"
                );
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Err(e) = unix_chmod_if_needed(pm.root(), 0o700) {
            tracing::error!(root = %pm.root().display(), error = %e, "data root chmod 0700 failed");
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn unix_chmod_if_needed(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    let cur = meta.permissions().mode() & 0o777;
    // Compare-first: no churn when group/other bits are already clear.
    if cur & 0o077 != 0 || cur & 0o700 != mode & 0o700 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {:o} {}: {e}", mode, path.display()))?;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Windows implementation
// ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod imp {
    //! Win32 + icacls mechanics. All policy decisions live in the pure
    //! layer above; this module only reads/applies descriptors.
    //!
    //! WHY a mix of Win32 (read) and icacls (write): `icacls` *display*
    //! output is localized (trustee names translate), so it cannot be
    //! parsed for the compare-first decision — SDDL from
    //! `ConvertSecurityDescriptorToStringSecurityDescriptorW` is
    //! locale-independent. Writes reuse the codebase's established icacls
    //! pattern (raw `*S-…` SIDs work on every locale); we only check exit
    //! status + stderr, never parse output.

    use super::*;
    use std::path::Path;

    /// Outcome of `ensure_data_root_acl`.
    #[derive(Debug)]
    pub enum RootOutcome {
        AlreadySecure,
        Repaired {
            owner_fixed: bool,
            tree_normalized: bool,
        },
        Degraded(String),
    }

    /// Outcome of `ensure_secret_acl` (mirror of the public enum; kept
    /// separate so `imp` is usable from the #[ignore] integration test
    /// without the cfg(test) skip in `assert_secret_acl`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SecretOutcome {
        Secure,
        Repaired,
    }

    /// Run icacls with the given args; Ok only on exit code 0. stderr is
    /// bounded before it reaches a log/error string.
    fn run_icacls(args: &[&str]) -> Result<(), String> {
        use crate::win_process::{system32_tool, QuietCommand};
        let out = std::process::Command::new(system32_tool("icacls.exe"))
            .args(args)
            .quiet_windows()
            .output()
            .map_err(|e| format!("icacls spawn failed: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        let mut err = String::from_utf8_lossy(&out.stderr).into_owned();
        if err.len() > 2048 {
            err.truncate(2048);
        }
        Err(format!("icacls exited {} — {err}", out.status))
    }

    /// Read owner + DACL of a file-system object as an SDDL string.
    ///
    /// SAFETY: all pointers passed to GetNamedSecurityInfoW are either
    /// null or point to stack slots that outlive the call. On success the
    /// returned security descriptor is a LocalAlloc'd buffer freed exactly
    /// once via LocalFree before returning. The SDDL output string is
    /// likewise LocalAlloc'd and freed exactly once; its content is copied
    /// out through a NUL-scan bounded to MAX_SDDL_LEN before the free.
    pub fn read_sddl(path: &Path) -> Result<String, String> {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::LocalFree;
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        };

        let wide: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
            .chain(std::iter::once(0))
            .collect();

        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 buffer; the out
        // pointers reference live stack slots.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                windows::core::PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            )
        };
        if rc.0 != 0 {
            return Err(format!("GetNamedSecurityInfo failed: win32 {}", rc.0));
        }
        // Guard: free the SD on every exit path below.
        struct SdGuard(PSECURITY_DESCRIPTOR);
        impl Drop for SdGuard {
            fn drop(&mut self) {
                if !self.0 .0.is_null() {
                    // SAFETY: buffer came from GetNamedSecurityInfoW (LocalAlloc).
                    unsafe {
                        let _ = LocalFree(windows::Win32::Foundation::HLOCAL(self.0 .0));
                    }
                }
            }
        }
        let _guard = SdGuard(sd);

        let mut sddl_ptr = PWSTR::null();
        // SAFETY: `sd` is a valid security descriptor; `sddl_ptr` receives
        // a LocalAlloc'd string on success.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                1, // SDDL_REVISION_1
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut sddl_ptr,
                None,
            )
        };
        if ok.is_err() || sddl_ptr.is_null() {
            return Err("ConvertSecurityDescriptorToStringSecurityDescriptor failed".into());
        }
        // Bounded copy out of the LocalAlloc'd buffer, then free it.
        let mut units: Vec<u16> = Vec::new();
        // SAFETY: `sddl_ptr` points to a NUL-terminated UTF-16 string for
        // its LocalAlloc'd lifetime (still alive here); the scan is capped.
        unsafe {
            let mut p = sddl_ptr.0;
            while units.len() < MAX_SDDL_LEN && *p != 0 {
                units.push(*p);
                p = p.add(1);
            }
            let _ = LocalFree(windows::Win32::Foundation::HLOCAL(
                sddl_ptr.0 as *mut core::ffi::c_void,
            ));
        }
        Ok(String::from_utf16_lossy(&units))
    }

    /// True when the current process token's user is SYSTEM (S-1-5-18).
    /// Fail-safe: any API error → false (hardening skipped, logged).
    pub fn current_process_is_system() -> bool {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // SAFETY: GetCurrentProcess returns a pseudo-handle (always valid).
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
            return false;
        }
        struct TokenGuard(windows::Win32::Foundation::HANDLE);
        impl Drop for TokenGuard {
            fn drop(&mut self) {
                // SAFETY: handle from OpenProcessToken, closed once.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
        let _guard = TokenGuard(token);

        // TOKEN_USER for a user SID fits comfortably in 256 bytes.
        let mut buf = [0u8; 256];
        let mut ret_len = 0u32;
        // SAFETY: `buf` is a writable 256-byte buffer; GetTokenInformation
        // writes at most `ret_len` bytes into it.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                buf.len() as u32,
                &mut ret_len,
            )
        };
        if ok.is_err() || ret_len as usize > buf.len() {
            return false;
        }
        // SAFETY: GetTokenInformation succeeded, so `buf` holds a valid
        // TOKEN_USER; the SID pointer refers to memory inside the token
        // information buffer, valid until `_guard` drops.
        let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
        let mut sid_str = windows::core::PWSTR::null();
        // SAFETY: `user.User.Sid` is a valid SID (see above); `sid_str`
        // receives a LocalAlloc'd string on success, freed below.
        let ok = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_str) };
        if ok.is_err() || sid_str.is_null() {
            return false;
        }
        let mut units = [0u16; 64];
        let mut n = 0usize;
        // SAFETY: `sid_str` is a NUL-terminated LocalAlloc'd string; the
        // copy is bounded to 64 UTF-16 units (S-1-5-18 is 8 chars).
        unsafe {
            let mut p = sid_str.0;
            while n < units.len() && *p != 0 {
                units[n] = *p;
                n += 1;
                p = p.add(1);
            }
            let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
                sid_str.0 as *mut core::ffi::c_void,
            ));
        }
        String::from_utf16_lossy(&units[..n]) == SID_SYSTEM
    }

    /// Evaluate → repair-if-needed → re-verify the data root DACL.
    /// Compare-first: a conforming descriptor is a pure no-op.
    pub fn ensure_data_root_acl(root: &Path) -> RootOutcome {
        let sddl = match read_sddl(root) {
            Ok(s) => s,
            Err(e) => return RootOutcome::Degraded(format!("cannot read root SD: {e}")),
        };
        let info = match parse_sddl(&sddl) {
            Ok(i) => i,
            // Fail closed: never rewrite an ACL we could not parse.
            Err(e) => return RootOutcome::Degraded(format!("unparseable root SDDL: {e}")),
        };

        let verdict = evaluate(&info, PolicyKind::DataRoot);
        let mut children_were_dirty = false;
        let (fix_owner, fix_dacl) = match verdict {
            AclVerdict::Secure => {
                // Root conforms — cheap spot-check of immediate children to
                // catch partial states (e.g. a crash mid-normalization, or
                // a subtree ACLed before this hardening existed).
                match assess_children(root) {
                    Ok(a) if a.is_clean() => return RootOutcome::AlreadySecure,
                    Ok(a) => {
                        children_were_dirty = true;
                        (a.needs_owner_fix, a.needs_reset)
                    }
                    Err(e) => {
                        return RootOutcome::Degraded(format!("child dir spot-check failed: {e}"))
                    }
                }
            }
            AclVerdict::NeedsRepair { owner, dacl } => (owner, dacl),
            AclVerdict::FailClosed(r) => return RootOutcome::Degraded(r),
        };

        let root_str = root.to_string_lossy().into_owned();

        // Owner first: while a non-admin owns the root they hold implicit
        // WRITE_DAC and could undo anything else we set. Deliberate policy:
        // take ownership (set to Administrators). SYSTEM holds
        // SeTakeOwnershipPrivilege, so this also covers the hostile-owner
        // case. `/T` fixes the whole tree for the same reason.
        if fix_owner {
            if let Err(e) = run_icacls(&[
                &root_str,
                "/setowner",
                "*S-1-5-32-544",
                "/T",
                "/C",
                "/Q",
            ]) {
                return RootOutcome::Degraded(format!("setowner failed: {e}"));
            }
        }

        // Canonical root DACL: protected, SYSTEM+Admins full, inheritable.
        if fix_dacl {
            if let Err(e) = run_icacls(&[
                &root_str,
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)(F)",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)(F)",
                "/Q",
            ]) {
                return RootOutcome::Degraded(format!("root DACL grant failed: {e}"));
            }
            // Children created under the OLD root DACL still carry stale
            // inherited ACE copies; Windows does not retro-propagate. Reset
            // every child to inherit the new root policy. `/reset` only
            // rebuilds DACLs from inheritance — SACLs (audit ACEs) are
            // untouched — and secret-file ACLs are re-asserted by the
            // caller immediately after.
            if let Err(e) = run_icacls(&[&root_str, "/reset", "/T", "/C", "/Q"]) {
                return RootOutcome::Degraded(format!("tree normalization (/reset) failed: {e}"));
            }
        }

        // Re-verify: never claim secure state without observing it.
        let after = match read_sddl(root).and_then(|s| parse_sddl(&s)) {
            Ok(i) => i,
            Err(e) => return RootOutcome::Degraded(format!("post-repair read failed: {e}")),
        };
        match evaluate(&after, PolicyKind::DataRoot) {
            AclVerdict::Secure => {
                // If the trigger was dirty children, re-verify those too —
                // a surviving hostile child owner would keep WRITE_DAC.
                if children_were_dirty {
                    match assess_children(root) {
                        Ok(a) if a.is_clean() => {}
                        Ok(_) => {
                            return RootOutcome::Degraded(
                                "child dir normalization did not converge".into(),
                            )
                        }
                        Err(e) => {
                            return RootOutcome::Degraded(format!(
                                "post-repair child check failed: {e}"
                            ))
                        }
                    }
                }
                RootOutcome::Repaired {
                    owner_fixed: fix_owner,
                    tree_normalized: fix_dacl,
                }
            }
            other => RootOutcome::Degraded(format!(
                "repair did not converge (post-repair verdict: {other:?})"
            )),
        }
    }

    /// Aggregate deviation state of the root's immediate child directories.
    struct ChildAssessment {
        /// Some child DACL deviates from pure-inheritance → `/reset /T`.
        needs_reset: bool,
        /// Some child has a non-admin owner → `/setowner /T`.
        needs_owner_fix: bool,
    }

    impl ChildAssessment {
        fn is_clean(&self) -> bool {
            !self.needs_reset && !self.needs_owner_fix
        }
    }

    /// Assess immediate child directories against the pure-inheritance
    /// model (see `child_dir_is_clean`). Bounded: only direct children,
    /// reparse points skipped.
    fn assess_children(root: &Path) -> Result<ChildAssessment, String> {
        let mut assessment = ChildAssessment {
            needs_reset: false,
            needs_owner_fix: false,
        };
        let entries =
            std::fs::read_dir(root).map_err(|e| format!("read_dir {}: {e}", root.display()))?;
        for entry in entries.flatten() {
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            // No reparse following: a junction child is skipped here and
            // skipped by /reset /T semantics we care about (icacls does not
            // follow junctions with /T either).
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            if crate::scan::is_reparse_point(&entry.path()) {
                continue;
            }
            let sddl = read_sddl(&entry.path())
                .map_err(|e| format!("read child SD {}: {e}", entry.path().display()))?;
            let info = parse_sddl(&sddl)
                .map_err(|e| format!("parse child SDDL {}: {e}", entry.path().display()))?;
            if !info.owner.as_deref().map(is_admin_sid).unwrap_or(false) {
                assessment.needs_owner_fix = true;
            }
            if !child_dir_dacl_is_clean(&info) {
                assessment.needs_reset = true;
            }
        }
        Ok(assessment)
    }

    /// Apply (if needed) the canonical ACL on a secret file, then
    /// re-verify. Never modifies file contents.
    pub fn ensure_secret_acl(path: &Path, kind: PolicyKind) -> Result<SecretOutcome, String> {
        let sddl = read_sddl(path)?;
        let info = parse_sddl(&sddl).map_err(|e| format!("unparseable SDDL: {e}"))?;
        let (fix_owner, fix_dacl) = match evaluate(&info, kind) {
            AclVerdict::Secure => return Ok(SecretOutcome::Secure),
            AclVerdict::NeedsRepair { owner, dacl } => (owner, dacl),
            AclVerdict::FailClosed(r) => return Err(r),
        };

        let path_str = path.to_string_lossy().into_owned();
        if fix_owner {
            run_icacls(&[&path_str, "/setowner", "*S-1-5-32-544", "/Q"])
                .map_err(|e| format!("setowner: {e}"))?;
        }
        if fix_dacl {
            // Mirror the creation-time ACLs exactly (raw SIDs — R9-LETHAL:
            // localized group names fail silently on non-English Windows).
            let mut args: Vec<&str> = vec![
                &path_str,
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(R)",
                "/grant:r",
                "*S-1-5-32-544:(R)",
            ];
            if kind == PolicyKind::SharedSecret {
                args.push("/grant:r");
                args.push("*S-1-5-32-545:(R)");
            }
            run_icacls(&args).map_err(|e| format!("grant: {e}"))?;
        }

        let after = read_sddl(path).and_then(|s| parse_sddl(&s))?;
        match evaluate(&after, kind) {
            AclVerdict::Secure => Ok(SecretOutcome::Repaired),
            other => Err(format!("secret ACL repair did not converge: {other:?}")),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Opt-in Windows integration test. PREREQUISITES: run elevated
        /// (`cargo test -p sentinelld -- --ignored acl`), on NTFS. Applies
        /// the real repair against a temp dir and a temp "secret" file and
        /// verifies via SDDL read-back plus an icacls display sanity check
        /// (icacls output is localized, so we only assert it succeeds and
        /// mentions the root path — SDDL is the real oracle).
        #[test]
        #[ignore = "requires elevation + NTFS; run explicitly"]
        fn elevated_repair_roundtrip() {
            let base = std::env::temp_dir().join(format!("sent_acl_itest_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("state")).unwrap();
            let secret = base.join("state").join(".vault_key");
            std::fs::write(&secret, [7u8; 32]).unwrap();

            // Contaminate: grant Users full control on root + secret.
            let root_str = base.to_string_lossy().into_owned();
            let secret_str = secret.to_string_lossy().into_owned();
            run_icacls(&[&root_str, "/grant", "*S-1-5-32-545:(OI)(CI)(F)"]).unwrap();
            run_icacls(&[&secret_str, "/grant", "*S-1-5-32-545:(R)"]).unwrap();

            let info = parse_sddl(&read_sddl(&base).unwrap()).unwrap();
            assert!(matches!(
                evaluate(&info, PolicyKind::DataRoot),
                AclVerdict::NeedsRepair { .. }
            ));

            // First pass: repairs.
            match ensure_data_root_acl(&base) {
                RootOutcome::Repaired { .. } => {}
                other => panic!("expected Repaired, got {other:?}"),
            }
            // Second pass: idempotent no-op.
            assert!(matches!(
                ensure_data_root_acl(&base),
                RootOutcome::AlreadySecure
            ));

            // Secret: repair then idempotent no-op.
            assert_eq!(
                ensure_secret_acl(&secret, PolicyKind::DaemonOnlySecret).unwrap(),
                SecretOutcome::Repaired
            );
            assert_eq!(
                ensure_secret_acl(&secret, PolicyKind::DaemonOnlySecret).unwrap(),
                SecretOutcome::Secure
            );
            // Key material untouched by ACL repair.
            assert_eq!(std::fs::read(&secret).unwrap(), vec![7u8; 32]);

            // icacls display sanity (localized output — only exit status).
            run_icacls(&[&root_str]).unwrap();

            let _ = std::fs::remove_dir_all(&base);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Pure-logic tests (no admin, no Windows APIs)
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn info(sddl: &str) -> SdInfo {
        parse_sddl(sddl).expect("test SDDL must parse")
    }

    // ── Canonical policy round-trips (idempotence at the decision layer:
    //    the repair target evaluates to Secure, so a second pass is a
    //    no-op — the same SDDL results). ────────────────────────────────

    #[test]
    fn canonical_sddls_evaluate_secure() {
        for kind in [
            PolicyKind::DataRoot,
            PolicyKind::DaemonOnlySecret,
            PolicyKind::SharedSecret,
        ] {
            let parsed = info(canonical_sddl(kind));
            assert_eq!(
                evaluate(&parsed, kind),
                AclVerdict::Secure,
                "canonical SDDL for {kind:?} must be Secure (idempotence)"
            );
        }
    }

    // ── Root policy deviations ─────────────────────────────────────────

    #[test]
    fn root_users_full_control_needs_repair() {
        let sd = info("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)");
        assert_eq!(
            evaluate(&sd, PolicyKind::DataRoot),
            AclVerdict::NeedsRepair {
                owner: false,
                dacl: true
            }
        );
    }

    #[test]
    fn root_users_read_only_still_needs_repair() {
        // Policy decision: NO Users ACE on the data root at all — the only
        // user-readable artifact (ipc_secret) carries its own explicit ACL.
        let sd = info("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)");
        assert!(matches!(
            evaluate(&sd, PolicyKind::DataRoot),
            AclVerdict::NeedsRepair { dacl: true, .. }
        ));
    }

    #[test]
    fn root_inherited_programdata_dacl_needs_repair() {
        // Fresh-install state: root inherits %ProgramData% DACL — BU read
        // plus a create-folders/append-data special ACE. Unprotected +
        // inherited + extra trustee → repair.
        let sd = info(
            "O:SYG:SYD:AI(A;ID;FA;;;SY)(A;OICIIOID;GA;;;CO)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)",
        );
        assert_eq!(
            evaluate(&sd, PolicyKind::DataRoot),
            AclVerdict::NeedsRepair {
                owner: false,
                dacl: true
            }
        );
    }

    #[test]
    fn root_wrong_owner_flags_owner_repair() {
        // Dev-box contamination: installing user owns the tree.
        let sd = info("O:S-1-5-21-1001-2002-3003-1001G:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert_eq!(
            evaluate(&sd, PolicyKind::DataRoot),
            AclVerdict::NeedsRepair {
                owner: true,
                dacl: false
            }
        );
    }

    #[test]
    fn root_null_dacl_needs_repair_not_failclosed() {
        // No D: section = NULL DACL = everyone full control. Well-defined
        // insecure state → repair, not fail-closed.
        let sd = info("O:SYG:SY");
        assert_eq!(
            evaluate(&sd, PolicyKind::DataRoot),
            AclVerdict::NeedsRepair {
                owner: false,
                dacl: true
            }
        );
    }

    // ── Vault key policy deviations ────────────────────────────────────

    #[test]
    fn vault_key_users_read_needs_repair() {
        // The observed Nicolas:(R) anomaly class: any Users ACE on the key.
        let sd = info("O:BAG:SYD:P(A;;FR;;;SY)(A;;FR;;;BA)(A;;FR;;;BU)");
        assert_eq!(
            evaluate(&sd, PolicyKind::DaemonOnlySecret),
            AclVerdict::NeedsRepair {
                owner: false,
                dacl: true
            }
        );
    }

    #[test]
    fn vault_key_users_full_needs_repair() {
        let sd = info("O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)");
        assert!(matches!(
            evaluate(&sd, PolicyKind::DaemonOnlySecret),
            AclVerdict::NeedsRepair { dacl: true, .. }
        ));
    }

    #[test]
    fn vault_key_unprotected_inheritance_needs_repair() {
        let sd = info("O:BAG:SYD:(A;;FR;;;SY)(A;;FR;;;BA)");
        assert!(matches!(
            evaluate(&sd, PolicyKind::DaemonOnlySecret),
            AclVerdict::NeedsRepair { dacl: true, .. }
        ));
    }

    #[test]
    fn vault_key_user_owner_flags_owner_repair() {
        let sd = info("O:S-1-5-21-1001-2002-3003-1001D:P(A;;FR;;;SY)(A;;FR;;;BA)");
        assert_eq!(
            evaluate(&sd, PolicyKind::DaemonOnlySecret),
            AclVerdict::NeedsRepair {
                owner: true,
                dacl: false
            }
        );
    }

    #[test]
    fn vault_key_deny_ace_needs_repair() {
        let sd = info("O:BAG:SYD:P(D;;FR;;;SY)(A;;FR;;;SY)(A;;FR;;;BA)");
        assert!(matches!(
            evaluate(&sd, PolicyKind::DaemonOnlySecret),
            AclVerdict::NeedsRepair { dacl: true, .. }
        ));
    }

    #[test]
    fn ipc_secret_users_read_is_policy_conformant() {
        // Shared secret policy explicitly includes BU read for the GUI.
        let sd = info("O:BAG:SYD:P(A;;FR;;;SY)(A;;FR;;;BA)(A;;FR;;;BU)");
        assert_eq!(evaluate(&sd, PolicyKind::SharedSecret), AclVerdict::Secure);
    }

    // ── Malformed input → fail closed ──────────────────────────────────

    #[test]
    fn malformed_sddl_fails_closed() {
        for bad in [
            "garbage",
            "D:PAI(A;OICI;FA;;;SY",           // truncated ACE
            "O:BAD:P(A;;ZZ;;;SY)(A;;FR;;;BA)", // unknown rights letters
            "O:BAD:P(XA;;FR;;;SY)",            // unsupported ACE type
            "O:BAD:P(A;;FR;;;)",               // empty trustee
            "O:BAD:Z(A;;FR;;;SY)",             // unknown DACL flag
        ] {
            assert!(
                parse_sddl(bad).is_err(),
                "malformed SDDL must be rejected (fail closed): {bad:?}"
            );
        }
        // Missing owner is unreasoned → FailClosed verdict.
        let sd = parse_sddl("D:P(A;;FR;;;SY)(A;;FR;;;BA)").unwrap();
        assert!(matches!(
            evaluate(&sd, PolicyKind::DaemonOnlySecret),
            AclVerdict::FailClosed(_)
        ));
    }

    #[test]
    fn oversized_sddl_rejected() {
        let huge = "O:BA".to_string() + &"A".repeat(MAX_SDDL_LEN);
        assert!(parse_sddl(&huge).is_err());
    }

    // ── Parser semantics ───────────────────────────────────────────────

    #[test]
    fn hex_rights_equal_letter_rights() {
        let a = parse_rights("FA").unwrap();
        let b = parse_rights("0x1F01FF").unwrap();
        assert_eq!(a, b, "FA must equal 0x1F01FF");
        let r = parse_rights("FR").unwrap();
        assert_eq!(r, 0x120089, "FR must equal FILE_GENERIC_READ");
    }

    #[test]
    fn sid_aliases_normalize() {
        assert_eq!(norm_sid("SY"), SID_SYSTEM);
        assert_eq!(norm_sid("BA"), SID_ADMINISTRATORS);
        assert_eq!(norm_sid("BU"), SID_USERS);
        assert_eq!(norm_sid("S-1-5-18"), SID_SYSTEM);
        // Long forms compare equal to aliases in evaluation.
        let sd = info("O:S-1-5-32-544D:P(A;;FR;;;S-1-5-18)(A;;FR;;;S-1-5-32-544)");
        assert_eq!(evaluate(&sd, PolicyKind::DaemonOnlySecret), AclVerdict::Secure);
    }

    #[test]
    fn duplicate_ace_is_a_deviation() {
        // Two identical required ACEs = one extra → repair.
        let sd = info("O:BAD:P(A;;FR;;;SY)(A;;FR;;;SY)(A;;FR;;;BA)");
        assert!(matches!(
            evaluate(&sd, PolicyKind::DaemonOnlySecret),
            AclVerdict::NeedsRepair { dacl: true, .. }
        ));
    }

    // ── Child-dir spot-check rule ──────────────────────────────────────

    #[test]
    fn child_dir_clean_rule() {
        // Healthy: unprotected, all inherited, admin trustees only.
        let clean = info("O:SYD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)");
        assert!(child_dir_is_clean(&clean));
        // Explicit ACE (ID missing) → contaminated.
        let explicit = info("O:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert!(!child_dir_is_clean(&explicit));
        // Inherited Users grant → contaminated.
        let users = info("O:SYD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FR;;;BU)");
        assert!(!child_dir_is_clean(&users));
        // Protected child (explicitly ACLed) → contaminated.
        let protected = info("O:SYD:PAI(A;OICIID;FA;;;SY)");
        assert!(!child_dir_is_clean(&protected));
        // Non-admin owner → contaminated.
        let bad_owner = info("O:S-1-5-21-1-2-3-1001D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)");
        assert!(!child_dir_is_clean(&bad_owner));
    }

    // ── Secret path safety (regular file / reparse / dir rejection) ────

    #[test]
    fn secret_path_checks() {
        let dir = std::env::temp_dir().join(format!("sent_acl_path_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Regular file → OK.
        let f = dir.join(".vault_key");
        std::fs::write(&f, [1u8; 32]).unwrap();
        assert!(reject_unsafe_secret_path(&f).is_ok());

        // Directory at key path → reject.
        let d = dir.join("keydir");
        std::fs::create_dir_all(&d).unwrap();
        assert!(reject_unsafe_secret_path(&d).is_err());

        // Missing → reject.
        assert!(reject_unsafe_secret_path(&dir.join("nope")).is_err());

        // Reparse point at key path → reject (symlink creation needs no
        // privilege on unix; on Windows it may — tolerate EPERM there).
        #[cfg(unix)]
        {
            let link = dir.join("link_key");
            std::os::unix::fs::symlink(&f, &link).unwrap();
            assert!(reject_unsafe_secret_path(&link).is_err());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! WeedHack runtime behavioural signals.
//!
//! ARGUS catches WeedHack JARs on disk via the JAR layer + IOC hash list.
//! This module catches WeedHack **already running** — the case where:
//!
//!   * a user dropped the JAR before Sentinella was installed,
//!   * the JAR was pulled from a memory-only loader,
//!   * the JAR signature mutated faster than the IOC list,
//!   * the user double-clicked through a warning anyway.
//!
//! Whatever the entry path, an executing WeedHack instance ALWAYS exhibits
//! a small, distinctive set of runtime behaviours rooted at a `javaw.exe`
//! ancestor. This module encodes those behaviours as additive signals to
//! `compute_chain_suspicion`, pushing live infections to a Critical chain
//! score that ARGUS escalates into a quarantine-and-terminate response.
//!
//! ## Detection model
//!
//! Each runtime signal is one of:
//!
//!   * **TRANSITION**   — parent-child image pair never seen in legit Java
//!                        usage (e.g. `javaw.exe → schtasks.exe`).
//!   * **CMDLINE**      — command-line literal that's a WeedHack fingerprint
//!                        regardless of who spawned it (e.g.
//!                        `schtasks /create /tn "JavaSecurityUpdater"`).
//!   * **ARTIFACT**     — process image path that matches a dropped WeedHack
//!                        component (e.g. `Pjibf.exe`, the v0.2 backdoor).
//!
//! Signals are deliberately scored to clear the chain-suspicion cap (30) so
//! that **any single confirmed WeedHack runtime signal triggers a Critical
//! lineage finding** — no need to compound multiple to reach the threshold.
//! False-positive surface is low because every signal pivots on a literal
//! string (`JavaSecurityUpdater`, `Pjibf.exe`, `Microsoft\SecurityUpdates\`)
//! or an unnatural Java-child transition.
//!
//! ## Why these signals
//!
//! - **`javaw.exe → schtasks.exe`**: legitimate Minecraft mods never create
//!   scheduled tasks. WeedHack does, with the exact task name
//!   `JavaSecurityUpdater` (impersonates Java Update Scheduler).
//! - **`javaw.exe → reg.exe`**: legit Minecraft never writes registry keys.
//!   WeedHack uses this for Run-key fallback persistence.
//! - **`javaw.exe → wscript.exe Updater.vbs`**: the dropped VBS launcher
//!   that re-spawns the JAR at user logon.
//! - **`powershell.exe ... -DisableRealtimeMonitoring`** under a javaw root:
//!   the AVHelper class invokes this to disable Defender real-time
//!   protection before stealer-stage execution.
//! - **`%APPDATA%\Microsoft\SecurityUpdates\Pjibf.exe`** image path: the
//!   v0.2 native backdoor stage. Running that image at all means the
//!   stealer has already completed Stage 2 and is starting Stage 3.

#![allow(dead_code)]

use super::ProcessNode;

/// Per-node WeedHack signal evaluation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WeedHackSignal {
    /// `javaw.exe` ancestor spawned a command shell, script engine, or
    /// registry/scheduler tool — Java-of-Minecraft never does this.
    UnnaturalJavaChild,
    /// Command line contains the literal `JavaSecurityUpdater` task name.
    JavaSecurityUpdaterTask,
    /// Command line drops or executes `Updater.vbs` (logon-persistence).
    UpdaterVbsLaunch,
    /// Command line references `Microsoft\SecurityUpdates\` AppData folder.
    SecurityUpdatesAppData,
    /// Command line disables Defender real-time monitoring under a Java root.
    DefenderDisableUnderJava,
    /// Image path or command line references `Pjibf.exe` (v0.2 backdoor).
    Pjibf,
    /// Command line writes Run-key persistence from a `javaw.exe` root.
    RunKeyFromJava,
    /// HTTP POST to a public Ethereum RPC endpoint carrying the WeedHack
    /// EtherHiding function selector (`0xce6d41de`) — source process is
    /// a `javaw.exe`. The selector + endpoint pair is unique to WeedHack.
    EtherHidingFromJava,
    /// An unsigned DLL from a user-writable path (`%TEMP%` / `%APPDATA%` /
    /// `Microsoft\SecurityUpdates`) was loaded into a browser process that
    /// has a `javaw.exe` ancestor — classic stealer DLL injection.
    BrowserInjectionFromJava,
    /// A `javaw.exe` process read ≥3 distinct browser/wallet credential
    /// stores within a short window — bulk-harvest burst.
    WalletHarvestBurst,
}

impl WeedHackSignal {
    /// Suspicion weight contributed by this signal to the chain score.
    /// Each signal alone clears `compute_chain_suspicion`'s cap (30) and
    /// pushes the chain to a Critical finding.
    pub const fn weight(self) -> u32 {
        match self {
            // Pjibf execution = stage 3 confirmed. Strongest single signal.
            WeedHackSignal::Pjibf => 60,
            // `JavaSecurityUpdater` is the literal WeedHack task name —
            // no legitimate scheduled task on Windows uses this string.
            WeedHackSignal::JavaSecurityUpdaterTask => 55,
            // Updater.vbs + SecurityUpdates folder are the dropped artifacts.
            WeedHackSignal::UpdaterVbsLaunch => 45,
            WeedHackSignal::SecurityUpdatesAppData => 45,
            // Defender-disable under java root is a strong correlation,
            // though `Set-MpPreference` itself isn't WeedHack-unique.
            WeedHackSignal::DefenderDisableUnderJava => 40,
            // Run-key persistence + java root is suggestive but used by
            // benign Java updaters too — paired with other signals.
            WeedHackSignal::RunKeyFromJava => 35,
            // Java spawning unnatural children = strong suspicion but
            // possible in some build-tooling edge cases — needs corroboration.
            WeedHackSignal::UnnaturalJavaChild => 32,
            // EtherHiding RPC call from java = exact-match family fingerprint.
            // selector + RPC host + Java caller has no legitimate analog.
            WeedHackSignal::EtherHidingFromJava => 60,
            // Browser DLL injection from java = the stealer doing its job
            // in real time. Strong but a few legitimate Java browser
            // automation frameworks could theoretically trip this.
            WeedHackSignal::BrowserInjectionFromJava => 50,
            // Wallet/browser bulk-harvest = a Java process reading wallet
            // stores it has no business touching. Time-correlated burst.
            WeedHackSignal::WalletHarvestBurst => 50,
        }
    }

    /// Short human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            WeedHackSignal::Pjibf => "WeedHack v0.2 backdoor binary (Pjibf.exe) execution",
            WeedHackSignal::JavaSecurityUpdaterTask => {
                "WeedHack persistence task creation (JavaSecurityUpdater)"
            }
            WeedHackSignal::UpdaterVbsLaunch => "WeedHack logon-persistence VBS (Updater.vbs)",
            WeedHackSignal::SecurityUpdatesAppData => {
                "WeedHack persistence folder (%APPDATA%\\Microsoft\\SecurityUpdates)"
            }
            WeedHackSignal::DefenderDisableUnderJava => {
                "Defender real-time protection disabled from Java process tree"
            }
            WeedHackSignal::RunKeyFromJava => "Run-key persistence written from Java process tree",
            WeedHackSignal::UnnaturalJavaChild => {
                "javaw.exe spawning shell / script engine / scheduler"
            }
            WeedHackSignal::EtherHidingFromJava => {
                "WeedHack EtherHiding C2 lookup (Ethereum RPC + selector 0xce6d41de) from Java"
            }
            WeedHackSignal::BrowserInjectionFromJava => {
                "Unsigned DLL loaded into browser from user-writable path under Java ancestry"
            }
            WeedHackSignal::WalletHarvestBurst => {
                "javaw.exe reading ≥3 wallet / browser credential stores within bulk-harvest window"
            }
        }
    }

    /// A *pathognomonic* signal is one whose firing condition is unique to
    /// WeedHack with no benign analog — usually because it pivots on a
    /// literal WeedHack-only string (`Pjibf.exe`, `JavaSecurityUpdater`,
    /// the EtherHiding selector). Pathognomonic signals are sufficient on
    /// their own to escalate a campaign past the "suspicious" tier; the
    /// campaign tracker reads this flag, the chain-finding emitter does
    /// not depend on it (this method is purely additive).
    pub const fn is_pathognomonic(self) -> bool {
        matches!(
            self,
            WeedHackSignal::Pjibf
                | WeedHackSignal::JavaSecurityUpdaterTask
                | WeedHackSignal::EtherHidingFromJava
        )
    }
}

/// Inspect a chain for WeedHack runtime signals. Returns every distinct
/// signal that fires. Caller sums their weights into `chain_suspicion`.
pub fn evaluate_chain(chain: &[ProcessNode]) -> Vec<WeedHackSignal> {
    if chain.is_empty() {
        return Vec::new();
    }

    let mut hits: Vec<WeedHackSignal> = Vec::new();
    let java_root_present = chain.iter().any(|n| is_javaw(&n.image_name));

    // Per-node command-line checks. Many signals are command-line fingerprints
    // that can fire on any node — but if there's no `javaw.exe` ancestor we
    // skip the java-conditioned signals to avoid lighting up benign Defender
    // configuration scripts.
    for node in chain {
        let cmd = node.command_line.as_deref().unwrap_or("");
        let cmd_lower_owned;
        let cmd_lower = if cmd.is_empty() {
            ""
        } else {
            cmd_lower_owned = cmd.to_ascii_lowercase();
            cmd_lower_owned.as_str()
        };

        let img_lower = node.image_name.to_ascii_lowercase();
        let path_lower = node.image_path.to_ascii_lowercase();

        // ── Pjibf backdoor (v0.2) — fires regardless of lineage. The image
        //    name is a unique random string only WeedHack uses; seeing it
        //    means the stealer dropped + launched its second-stage payload.
        if img_lower == "pjibf.exe"
            || path_lower.ends_with("\\pjibf.exe")
            || cmd_lower.contains("pjibf.exe")
        {
            push_unique(&mut hits, WeedHackSignal::Pjibf);
        }

        // ── JavaSecurityUpdater scheduled task name — unique literal.
        if cmd_lower.contains("javasecurityupdater") {
            push_unique(&mut hits, WeedHackSignal::JavaSecurityUpdaterTask);
        }

        // ── Updater.vbs persistence artifact.
        if cmd_lower.contains("updater.vbs") {
            push_unique(&mut hits, WeedHackSignal::UpdaterVbsLaunch);
        }

        // ── %APPDATA%\Microsoft\SecurityUpdates\ folder reference.
        if cmd_lower.contains("\\microsoft\\securityupdates")
            || path_lower.contains("\\microsoft\\securityupdates")
        {
            push_unique(&mut hits, WeedHackSignal::SecurityUpdatesAppData);
        }

        // ── Defender disable — only counts under a javaw root.
        if java_root_present
            && is_powershell(&img_lower)
            && (cmd_lower.contains("disablerealtimemonitoring")
                || cmd_lower.contains("disableiavprotection")
                || cmd_lower.contains("disablebehaviormonitoring")
                || cmd_lower.contains("add-mppreference"))
        {
            push_unique(&mut hits, WeedHackSignal::DefenderDisableUnderJava);
        }

        // ── Run-key persistence under a Java root.
        if java_root_present
            && (img_lower == "reg.exe" || is_powershell(&img_lower))
            && cmd_lower.contains("currentversion\\run")
        {
            push_unique(&mut hits, WeedHackSignal::RunKeyFromJava);
        }
    }

    // Per-transition: unnatural Java child.
    for window in chain.windows(2) {
        let parent = &window[0];
        let child = &window[1];
        if is_javaw(&parent.image_name) && is_unnatural_java_child(&child.image_name) {
            push_unique(&mut hits, WeedHackSignal::UnnaturalJavaChild);
            break; // one is enough; weight is already strong.
        }
    }

    hits
}

/// Total weight contributed by all detected signals.
pub fn chain_score(chain: &[ProcessNode]) -> u32 {
    evaluate_chain(chain)
        .iter()
        .map(|s| s.weight())
        .sum()
}

/// Human-readable explanation suitable for an ARGUS finding description.
pub fn describe_signals(hits: &[WeedHackSignal]) -> String {
    if hits.is_empty() {
        return String::new();
    }
    let labels: Vec<&str> = hits.iter().map(|s| s.label()).collect();
    format!("WeedHack runtime signals: {}", labels.join("; "))
}

fn push_unique(hits: &mut Vec<WeedHackSignal>, sig: WeedHackSignal) {
    if !hits.contains(&sig) {
        hits.push(sig);
    }
}

fn is_javaw(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "javaw.exe" || lower == "java.exe"
}

fn is_powershell(name: &str) -> bool {
    name == "powershell.exe" || name == "pwsh.exe"
}

/// Image names that legitimate Minecraft Java NEVER spawns as children.
/// Build tools (mvn, gradle) might spawn cmd/javac but not these — and
/// build tools aren't `javaw.exe` (they're cmd/gradle wrappers).
fn is_unnatural_java_child(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "schtasks.exe"
            | "reg.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "bitsadmin.exe"
            | "certutil.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "powershell.exe"
            | "pwsh.exe"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn node(pid: u32, ppid: u32, name: &str, cmd: Option<&str>) -> ProcessNode {
        ProcessNode {
            pid,
            parent_pid: ppid,
            image_path: format!("C:\\Program Files\\Java\\bin\\{name}"),
            image_name: name.to_string(),
            command_line: cmd.map(|s| s.to_string()),
            is_signed: None,
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    fn appdata_node(pid: u32, ppid: u32, name: &str, cmd: Option<&str>) -> ProcessNode {
        ProcessNode {
            pid,
            parent_pid: ppid,
            image_path: format!(
                "C:\\Users\\test\\AppData\\Roaming\\Microsoft\\SecurityUpdates\\{name}"
            ),
            image_name: name.to_string(),
            command_line: cmd.map(|s| s.to_string()),
            is_signed: None,
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    #[test]
    fn empty_chain_no_signals() {
        assert!(evaluate_chain(&[]).is_empty());
        assert_eq!(chain_score(&[]), 0);
    }

    #[test]
    fn pjibf_alone_triggers_critical() {
        let chain = vec![appdata_node(2, 1, "Pjibf.exe", None)];
        let hits = evaluate_chain(&chain);
        assert!(hits.contains(&WeedHackSignal::Pjibf));
        assert!(
            chain_score(&chain) >= 30,
            "Pjibf alone must clear chain cap, got {}",
            chain_score(&chain)
        );
    }

    #[test]
    fn javasecurityupdater_task_creation_fires() {
        let chain = vec![
            node(1, 0, "explorer.exe", None),
            node(2, 1, "javaw.exe", Some("javaw.exe -jar Component.jar")),
            node(
                3,
                2,
                "schtasks.exe",
                Some(
                    "schtasks /create /tn \"JavaSecurityUpdater\" /tr \"wscript.exe ...\" /sc onlogon",
                ),
            ),
        ];
        let hits = evaluate_chain(&chain);
        assert!(hits.contains(&WeedHackSignal::JavaSecurityUpdaterTask));
        assert!(hits.contains(&WeedHackSignal::UnnaturalJavaChild));
        // schtasks signal alone = 55 — already over chain cap.
        assert!(chain_score(&chain) >= 55);
    }

    #[test]
    fn updater_vbs_in_appdata_double_fires() {
        let chain = vec![
            node(1, 0, "javaw.exe", None),
            node(
                2,
                1,
                "wscript.exe",
                Some(
                    "wscript.exe \"C:\\Users\\test\\AppData\\Roaming\\Microsoft\\SecurityUpdates\\Updater.vbs\"",
                ),
            ),
        ];
        let hits = evaluate_chain(&chain);
        // Three signals: unnatural java child + Updater.vbs + SecurityUpdates folder.
        assert!(hits.contains(&WeedHackSignal::UnnaturalJavaChild));
        assert!(hits.contains(&WeedHackSignal::UpdaterVbsLaunch));
        assert!(hits.contains(&WeedHackSignal::SecurityUpdatesAppData));
    }

    #[test]
    fn defender_disable_outside_java_does_not_fire() {
        // Sysadmin running Set-MpPreference under explorer is NOT WeedHack.
        let chain = vec![
            node(1, 0, "explorer.exe", None),
            node(
                2,
                1,
                "powershell.exe",
                Some("Set-MpPreference -DisableRealtimeMonitoring $true"),
            ),
        ];
        let hits = evaluate_chain(&chain);
        assert!(!hits.contains(&WeedHackSignal::DefenderDisableUnderJava));
    }

    #[test]
    fn defender_disable_under_java_fires() {
        let chain = vec![
            node(1, 0, "explorer.exe", None),
            node(2, 1, "javaw.exe", None),
            node(
                3,
                2,
                "powershell.exe",
                Some("Set-MpPreference -DisableRealtimeMonitoring $true"),
            ),
        ];
        let hits = evaluate_chain(&chain);
        assert!(hits.contains(&WeedHackSignal::DefenderDisableUnderJava));
        assert!(hits.contains(&WeedHackSignal::UnnaturalJavaChild));
    }

    #[test]
    fn run_key_persistence_under_java_fires() {
        let chain = vec![
            node(1, 0, "javaw.exe", None),
            node(
                2,
                1,
                "reg.exe",
                Some(
                    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v \"SecUpdate\" /d \"...\\Updater.vbs\"",
                ),
            ),
        ];
        let hits = evaluate_chain(&chain);
        assert!(hits.contains(&WeedHackSignal::RunKeyFromJava));
        assert!(hits.contains(&WeedHackSignal::UpdaterVbsLaunch));
        assert!(hits.contains(&WeedHackSignal::UnnaturalJavaChild));
    }

    #[test]
    fn unnatural_java_child_alone_strong_but_corroboratable() {
        let chain = vec![
            node(1, 0, "javaw.exe", None),
            node(2, 1, "cmd.exe", None),
        ];
        // cmd.exe isn't in the unnatural list (cmd.exe is common for redirects).
        // schtasks/reg/wscript/etc ARE.
        let hits = evaluate_chain(&chain);
        assert!(!hits.contains(&WeedHackSignal::UnnaturalJavaChild));
    }

    #[test]
    fn schtasks_from_java_fires_unnatural_child() {
        let chain = vec![
            node(1, 0, "javaw.exe", None),
            node(2, 1, "schtasks.exe", None),
        ];
        let hits = evaluate_chain(&chain);
        assert!(hits.contains(&WeedHackSignal::UnnaturalJavaChild));
        assert!(chain_score(&chain) >= 30, "must clear chain cap");
    }

    #[test]
    fn clean_minecraft_no_signals() {
        let chain = vec![
            node(1, 0, "explorer.exe", None),
            node(2, 1, "MinecraftLauncher.exe", None),
            node(3, 2, "javaw.exe", Some("javaw.exe -jar minecraft.jar")),
        ];
        let hits = evaluate_chain(&chain);
        assert!(hits.is_empty(), "clean Minecraft must produce zero signals");
        assert_eq!(chain_score(&chain), 0);
    }

    #[test]
    fn describe_is_human_readable() {
        let hits = vec![
            WeedHackSignal::JavaSecurityUpdaterTask,
            WeedHackSignal::UnnaturalJavaChild,
        ];
        let desc = describe_signals(&hits);
        assert!(desc.contains("JavaSecurityUpdater"));
        assert!(desc.contains("javaw.exe"));
    }
}

//! Layer 5: Specialty Pattern Detection
//!
//! Detects specific malware families and behaviors targeting modern
//! threat ecosystems: Discord stealers, fake updaters, credential
//! theft, webhook exfiltration, and Electron abuse.

use crate::verdict::{Finding, Layer, Severity};

/// Analyze binary content for known malware patterns.
/// This works on raw file bytes — no parsing needed.
pub fn analyze(path: &str, data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();

    detect_discord_stealer(data, &mut findings);
    detect_webhook_exfiltration(data, &mut findings);
    detect_credential_access(data, &mut findings);
    detect_crypto_patterns(data, &mut findings);
    detect_persistence_indicators(data, &mut findings);
    detect_fake_game_mod(path, data, &mut findings);

    findings
}

// ── Discord token stealer patterns ─────────────────────────────────

fn detect_discord_stealer(data: &[u8], findings: &mut Vec<Finding>) {
    let mut indicators = Vec::new();

    // Discord local storage paths.
    let discord_paths = [
        b"discord\\Local Storage" as &[u8],
        b"discordptb\\Local Storage",
        b"discordcanary\\Local Storage",
        b"discord/Local Storage",
    ];

    for path_pattern in &discord_paths {
        if contains_bytes(data, path_pattern) {
            indicators.push("References Discord local storage directory");
            break;
        }
    }

    // LevelDB file extensions (Discord stores tokens in LevelDB).
    if contains_bytes(data, b".ldb") && contains_bytes(data, b"leveldb") {
        indicators.push("References LevelDB files used by Discord");
    }

    // Discord token regex patterns.
    if contains_bytes(data, b"[MN][A-Za-z\\d]") || contains_bytes(data, b"mfa.") {
        // Rough check — token matching regex embedded in binary.
        if contains_bytes(data, b"webhook") || indicators.len() >= 1 {
            indicators.push("Contains Discord token format patterns");
        }
    }

    // Encrypted token prefix (Discord DPAPI).
    if contains_bytes(data, b"dQw4w9WgXcQ:") {
        indicators.push("References Discord encrypted token prefix (DPAPI)");
    }

    match indicators.len() {
        0 => {}
        1 => {
            findings.push(Finding {
                layer: Layer::PatternDetection,
                severity: Severity::Medium,
                weight: 15,
                description: format!(
                    "Executable accesses Discord application data — {}",
                    indicators[0]
                ),
                technical_detail: Some(indicators.join("; ")),
            });
        }
        _ => {
            findings.push(Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 30,
                description: format!(
                    "Multiple indicators of Discord token theft behavior ({} markers detected).",
                    indicators.len(),
                ),
                technical_detail: Some(indicators.join("; ")),
            });
        }
    }
}

// ── Webhook exfiltration ───────────────────────────────────────────

fn detect_webhook_exfiltration(data: &[u8], findings: &mut Vec<Finding>) {
    let mut exfil_targets = Vec::new();

    // Discord webhook URLs.
    if contains_bytes(data, b"discord.com/api/webhooks/")
        || contains_bytes(data, b"discordapp.com/api/webhooks/")
    {
        exfil_targets.push("Discord webhook");
    }

    // Telegram bot API.
    if contains_bytes(data, b"api.telegram.org/bot") {
        exfil_targets.push("Telegram Bot API");
    }

    if !exfil_targets.is_empty() {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::High,
            weight: 25,
            description: format!(
                "Executable contains {} endpoint(s) — commonly used to exfiltrate stolen data.",
                exfil_targets.join(" and "),
            ),
            technical_detail: Some(format!(
                "Exfiltration targets: {}",
                exfil_targets.join(", ")
            )),
        });
    }
}

// ── Credential access patterns ─────────────────────────────────────

fn detect_credential_access(data: &[u8], findings: &mut Vec<Finding>) {
    let mut indicators = Vec::new();

    // Browser credential storage paths.
    let browser_paths = [
        b"\\Google\\Chrome\\User Data" as &[u8],
        b"\\Microsoft\\Edge\\User Data",
        b"\\BraveSoftware\\Brave-Browser\\User Data",
        b"\\Mozilla\\Firefox\\Profiles",
        b"\\Opera Software\\Opera Stable",
    ];

    let mut browser_count = 0;
    for bp in &browser_paths {
        if contains_bytes(data, bp) {
            browser_count += 1;
        }
    }

    if browser_count >= 2 {
        indicators.push(format!(
            "Accesses {browser_count} browser credential directories"
        ));
    }

    // Login Data / Web Data (Chrome SQLite databases).
    if contains_bytes(data, b"Login Data") && contains_bytes(data, b"Web Data") {
        indicators.push("References browser credential databases (Login Data, Web Data)".into());
    }

    // Crypto wallet paths.
    let wallet_paths = [
        b"\\Exodus\\exodus.wallet" as &[u8],
        b"\\Atomic\\Local Storage",
        b"\\Electrum\\wallets",
        b"wallet.dat",
    ];

    let mut wallet_count = 0;
    for wp in &wallet_paths {
        if contains_bytes(data, wp) {
            wallet_count += 1;
        }
    }

    if wallet_count >= 1 {
        indicators.push(format!(
            "Accesses {wallet_count} cryptocurrency wallet location(s)"
        ));
    }

    if !indicators.is_empty() {
        // Require multiple indicators — single browser access is common in
        // legitimate software (backup tools, password managers, etc.).
        let severity = if indicators.len() >= 3 {
            Severity::High
        } else if indicators.len() >= 2 {
            Severity::Medium
        } else {
            Severity::Low
        };
        let weight = if indicators.len() >= 3 {
            25
        } else if indicators.len() >= 2 {
            15
        } else {
            5
        };

        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity,
            weight,
            description: format!(
                "Executable accesses credential storage locations typically targeted by information stealers ({} indicator(s)).",
                indicators.len(),
            ),
            technical_detail: Some(indicators.join("; ")),
        });
    }
}

// ── Cryptocurrency patterns ────────────────────────────────────────

fn detect_crypto_patterns(data: &[u8], findings: &mut Vec<Finding>) {
    // Clipboard hijacking — wallet address regex patterns.
    // Bitcoin, Ethereum, Monero address format strings in binary.
    let mut crypto_indicators = Vec::new();

    if contains_bytes(data, b"bc1q") && contains_bytes(data, b"SetClipboard") {
        crypto_indicators.push("Bitcoin address replacement via clipboard");
    }

    if contains_bytes(data, b"0x")
        && contains_bytes(data, b"GetClipboardData")
        && contains_bytes(data, b"SetClipboardData")
    {
        crypto_indicators.push("Clipboard monitoring for crypto addresses");
    }

    // Mining.
    if contains_bytes(data, b"stratum+tcp://") || contains_bytes(data, b"stratum+ssl://") {
        crypto_indicators.push("Cryptocurrency mining pool connection string");
    }

    if contains_bytes(data, b"xmrig") || contains_bytes(data, b"CryptoNight") {
        crypto_indicators.push("References to cryptocurrency mining software");
    }

    for indicator in &crypto_indicators {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::High,
            weight: 22,
            description: format!("Cryptocurrency-related malware behavior: {indicator}"),
            technical_detail: None,
        });
    }
}

// ── Persistence indicators in binary content ───────────────────────

fn detect_persistence_indicators(data: &[u8], findings: &mut Vec<Finding>) {
    let mut persistence_methods = Vec::new();

    // Registry Run key manipulation.
    if contains_bytes(data, b"\\CurrentVersion\\Run") {
        persistence_methods.push("Registry Run key modification");
    }

    // Startup folder.
    if contains_bytes(data, b"\\Start Menu\\Programs\\Startup") {
        persistence_methods.push("Startup folder manipulation");
    }

    // Scheduled task creation.
    if contains_bytes(data, b"schtasks") && contains_bytes(data, b"/create") {
        persistence_methods.push("Scheduled task creation");
    }

    // WMI persistence.
    if contains_bytes(data, b"__EventFilter") && contains_bytes(data, b"__EventConsumer") {
        persistence_methods.push("WMI event subscription (advanced persistence)");
    }

    if persistence_methods.len() >= 2 {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::High,
            weight: 22,
            description: format!(
                "Executable uses {} persistence mechanisms — establishing multiple footholds is a strong malware indicator.",
                persistence_methods.len(),
            ),
            technical_detail: Some(persistence_methods.join("; ")),
        });
    } else if persistence_methods.len() == 1 {
        // Single persistence mechanism is extremely common in legitimate software.
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Info,
            weight: 1,
            description: format!(
                "Executable references a system persistence mechanism: {}",
                persistence_methods[0]
            ),
            technical_detail: None,
        });
    }
}

// ── Fake game mod / updater detection ───────────────────────────────

fn detect_fake_game_mod(path: &str, data: &[u8], findings: &mut Vec<Finding>) {
    let path_lower = path.to_lowercase();
    let name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Check if the filename suggests a game mod/cheat/updater.
    let game_keywords = [
        "roblox",
        "minecraft",
        "fortnite",
        "valorant",
        "sims",
        "gta",
        "apex",
        "csgo",
        "cs2",
        "pubg",
        "overwatch",
        "warzone",
        "league",
        "dota",
    ];
    let mod_keywords = [
        "mod",
        "cheat",
        "hack",
        "trainer",
        "spoofer",
        "injector",
        "aimbot",
        "wallhack",
        "esp",
        "unban",
        "hwid",
        "skin changer",
        "skinchanger",
        "exploit",
    ];

    let has_game = game_keywords
        .iter()
        .any(|&k| name.contains(k) || path_lower.contains(k));
    let has_mod = mod_keywords.iter().any(|&k| name.contains(k));

    if !has_game && !has_mod {
        return;
    }

    // Check for credential theft indicators in the binary.
    let mut steal_indicators = 0u32;
    if contains_bytes(data, b"discord") || contains_bytes(data, b"Discord") {
        steal_indicators += 1;
    }
    if contains_bytes(data, b"Login Data") {
        steal_indicators += 1;
    }
    if contains_bytes(data, b"webhook") || contains_bytes(data, b"Webhook") {
        steal_indicators += 1;
    }
    if contains_bytes(data, b"Local Storage") {
        steal_indicators += 1;
    }
    if contains_bytes(data, b"wallet") {
        steal_indicators += 1;
    }
    if contains_bytes(data, b"token") {
        steal_indicators += 1;
    }
    if contains_bytes(data, b"api.telegram") {
        steal_indicators += 1;
    }
    if contains_bytes(data, b"Chrome\\User Data") {
        steal_indicators += 1;
    }

    if has_game && has_mod && steal_indicators >= 2 {
        // Game cheat/mod with stealing capabilities = almost certainly malware.
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Critical,
            weight: 45,
            description: format!(
                "Executable presents as a game modification tool but contains credential harvesting capabilities — this is a textbook fake game mod stealer."
            ),
            technical_detail: Some(format!("Game keywords + mod keywords + {steal_indicators} credential theft indicators in binary")),
        });
    } else if (has_game || has_mod) && steal_indicators >= 3 {
        // Either game-themed or mod-themed with strong stealing indicators.
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::High,
            weight: 30,
            description: "Executable combines game/mod-related naming with multiple credential harvesting indicators — highly suspicious.".into(),
            technical_detail: Some(format!("{steal_indicators} credential theft indicators found")),
        });
    } else if has_mod && steal_indicators >= 1 {
        // Mod/cheat/hack tool with any stealing indicator.
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Medium,
            weight: 15,
            description: "Executable is named as a game cheat or modification tool — these are the #1 malware distribution vector targeting gamers.".into(),
            technical_detail: Some(format!("Filename: {name}")),
        });
    }
}

// ── Utility ────────────────────────────────────────────────────────

/// Case-sensitive byte substring search.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

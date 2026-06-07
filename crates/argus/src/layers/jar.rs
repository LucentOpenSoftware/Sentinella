//! Layer: JAR / Java-archive structural analysis.
//!
//! Detects malicious Java archives by parsing the ZIP container, reading the
//! `META-INF/MANIFEST.MF` for the declared `Main-Class`, and scanning class-file
//! constant-pool strings for credential-targeting paths, AV-disable commands,
//! and known C2 infrastructure.
//!
//! Targeted family: **WeedHack** (Minecraft MaaS infostealer, active since
//! 2026-01, ~116k confirmed infections per McAfee Labs research). Entry point
//! `DonutDupe.jar`, EtherHiding C2 (pulls current C2 domain from Ethereum
//! blockchain storage so traditional domain blocklists are stale), 56 browser
//! crypto wallets, 12 desktop wallets, 36 browsers, Discord/Steam/Telegram
//! credential paths, Minecraft launcher session IDs.
//!
//! Secondary coverage: the broader Java-infostealer class — anyone targeting
//! the same browser/wallet/chat surfaces gets flagged by string-pool signals
//! regardless of family.
//!
//! Cost: parses up to `MAX_ENTRIES` ZIP entries, decompresses up to
//! `MAX_TOTAL_DECOMPRESSED` bytes total, scans up to `MAX_STRING_SCAN_BYTES`
//! per class file. Bounded against zip-bomb / decompression-bomb input.

use crate::verdict::{Finding, Layer, Severity};
use std::io::Read;

/// ZIP local-file-header magic (`PK\x03\x04`). Shared by JAR/WAR/EAR/APK/OOXML.
fn is_zip_magic(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == [0x50, 0x4B, 0x03, 0x04]
}

/// Bounded parser cost — never let attacker-supplied input run us unbounded.
const MAX_ENTRIES: usize = 4096;
const MAX_TOTAL_DECOMPRESSED: u64 = 64 * 1024 * 1024; // 64 MiB total
const MAX_PER_ENTRY_DECOMPRESSED: u64 = 8 * 1024 * 1024; // 8 MiB per class
const MAX_STRING_SCAN_BYTES: usize = 4 * 1024 * 1024; // 4 MiB per entry

/// Analyze a JAR (or generic ZIP) for malicious Java-archive patterns.
///
/// Caller decides routing — this returns empty findings on non-ZIP data,
/// on archives whose contents don't look like a Java archive (no manifest +
/// no `.class` entries), and on zero/corrupt input.
pub fn analyze(_path: &str, data: &[u8]) -> Vec<Finding> {
    // `_path` is accepted to match the sibling layer signatures
    // (script::analyze / patterns::analyze) — future path-based heuristics
    // (e.g. "JAR sitting under .minecraft/mods/") will use it.
    let mut findings = Vec::new();

    if !is_zip_magic(data) {
        return findings;
    }

    let cursor = std::io::Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return findings, // Corrupt / unsupported ZIP — defer to other layers.
    };

    let n_entries = archive.len();
    if n_entries > MAX_ENTRIES {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 4,
            description: format!(
                "Archive declares {n_entries} entries — very high entry count is associated with zip-bomb droppers."
            ),
            technical_detail: None,
        });
    }

    let mut has_manifest = false;
    let mut main_class: Option<String> = None;
    let mut class_count = 0usize;
    let mut total_decompressed = 0u64;
    let mut hit = JarStringHits::default();
    let mut has_native_lib = false;

    for i in 0..n_entries.min(MAX_ENTRIES) {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.name().to_string();

        if total_decompressed >= MAX_TOTAL_DECOMPRESSED {
            break;
        }
        let read_cap = MAX_PER_ENTRY_DECOMPRESSED
            .min(MAX_TOTAL_DECOMPRESSED - total_decompressed);

        if name == "META-INF/MANIFEST.MF" {
            has_manifest = true;
            let mut buf = Vec::new();
            if let Ok(n) = entry.by_ref().take(read_cap).read_to_end(&mut buf) {
                total_decompressed += n as u64;
                main_class = parse_manifest_main_class(&buf);
            }
            continue;
        }

        if name.ends_with(".class") {
            class_count += 1;
            let scan_cap = (MAX_STRING_SCAN_BYTES as u64).min(read_cap);
            let mut buf = Vec::with_capacity(scan_cap.min(64 * 1024) as usize);
            if let Ok(n) = entry.by_ref().take(scan_cap).read_to_end(&mut buf) {
                total_decompressed += n as u64;
                scan_class_strings(&buf, &mut hit);
            }
            continue;
        }

        // Non-class entries (resources, native libs, embedded scripts).
        // Don't decompress fully — just inspect the entry name.
        if name.ends_with(".dll")
            || name.ends_with(".so")
            || name.ends_with(".dylib")
            || name.ends_with(".jnilib")
        {
            has_native_lib = true;
        }
    }

    if !has_manifest && class_count == 0 {
        // Not a Java archive — bail (caller may have passed OOXML / APK /
        // a plain ZIP). Don't synthesize JAR findings from non-JAR content.
        return findings;
    }

    // ── Findings ───────────────────────────────────────────────────

    // Layer-routing rationale:
    //
    // Findings that are **specific IoC-class indicators** (curated class
    // names, family signature strings, family domains) route to
    // `Layer::IocCorrelation`, which is uncapped — these are family
    // attribution, not generic structural inference. The per-finding weight
    // is the final contribution.
    //
    // **Pattern-class indicators** (AV-disable command strings,
    // EtherHiding-pattern Eth RPC references — patterns of *malware
    // behavior* observed across families) route to `Layer::PatternDetection`
    // (cap 25 — shared budget across all pattern findings).
    //
    // **Behavior-class indicators** (targeting browser cookie paths, wallet
    // files, chat-app token paths, Minecraft session files, process exec)
    // route to `Layer::StructuralAnalysis` (cap 30 — shared budget across
    // structural findings). Generic infostealer = clusters of these but no
    // family IoC.

    // ── IoC-class family attribution (uncapped, high-confidence) ──

    if let Some(ref mc) = main_class {
        if is_known_bad_main_class(mc) {
            findings.push(Finding {
                layer: Layer::IocCorrelation,
                severity: Severity::Critical,
                weight: 60,
                description: format!(
                    "JAR Main-Class '{mc}' matches a known malicious entry point (WeedHack family infostealer)."
                ),
                technical_detail: Some(format!(
                    "META-INF/MANIFEST.MF declares Main-Class: {mc}"
                )),
            });
        }
    }

    if hit.weedhack_signature {
        // Routed to IoC (uncapped) with `KnownMalware` tag — collapses against
        // the main-class finding (architectural intent: "we've identified the
        // family" should not multi-count).
        findings.push(Finding {
            layer: Layer::IocCorrelation,
            severity: Severity::Critical,
            weight: 50,
            description: "JAR contains distinctive WeedHack family strings (Stage1/2/3 handler classes, init markers, EtherHiding function selector, persistence task name, or embedded native-stage UUIDs).".into(),
            technical_detail: Some(
                "Match against curated set across all four WeedHack stages — see WEEDHACK_SIGNATURE_STRINGS".into(),
            ),
        });
    }

    if hit.weedhack_jnic {
        // JNIC-obfuscated namespace — DIFFERENT tag class (route to
        // PatternDetection, description triggers `Evasion` tag).
        // This finding SURVIVES the IoC dedup-collapse — critical for
        // catching obfuscated stages where the main-class allowlist misses.
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Critical,
            weight: 20,
            description: "JAR contains a JNIC-obfuscated WeedHack stage namespace — Java Native Interface Compiler packs the bytecode into a native DLL for anti-analysis evasion. Distinctive per stage (lXpXvp=Stage1v2, BSOMwJ=Stage2, fwcMeR=Stage3).".into(),
            technical_detail: Some(
                "Match against dev.jnic.lXpXvp / dev.jnic.BSOMwJ / dev.jnic.fwcMeR".into(),
            ),
        });
    }

    if hit.weedhack_domain {
        // Domain stays in IoC (uncapped) — dedups with class/signature under
        // `KnownMalware`, BUT critical when those are missing (e.g. third-party
        // unpacker that only leaves the URL literal). 45-weight ensures
        // domain-alone clears Suspicious (≥26).
        findings.push(Finding {
            layer: Layer::IocCorrelation,
            severity: Severity::Critical,
            weight: 45,
            description: "JAR references a known WeedHack C2 / staging domain — direct link to operator infrastructure.".into(),
            technical_detail: Some(
                "Match against receiver.cy / weedhack.cy / whreceive.ru / whreceiver.ru / remotev2.whreceive.ru / marsalek.cy / huehnchenfarm.ru".into(),
            ),
        });
    }

    if hit.weedhack_hardcoded_ip {
        // Hardcoded IP (v0.2 update) — Pattern layer, Exfiltration tag, will
        // dedup with the domain finding above but counted ONCE = still useful
        // when domain is missing (operators rotate to IP-only fallback).
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Critical,
            weight: 18,
            description: "JAR contains the hardcoded WeedHack v0.2 fallback IP (45.141.119.34) — used when DNS-based blocklists take down the dotted-domain C2.".into(),
            technical_detail: Some("Hardcoded IP literal in class strings".into()),
        });
    }

    if hit.weedhack_persistence_path {
        // Routed to StructuralAnalysis with `Persistence` tag (via description
        // keyword "persistence" / "scheduled task"). Independent score.
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Critical,
            weight: 18,
            description: "JAR references WeedHack persistence artifacts — drops a scheduled task / VBS launcher into AppData under a Microsoft-impersonating folder.".into(),
            technical_detail: Some(
                "Strings reference Microsoft\\SecurityUpdates, SecurityInfo.json, security.lock, Updater.vbs, or Pjibf.exe (v0.2 backdoor)".into(),
            ),
        });
    }

    // ── Pattern-class indicators (capped at CAP_PATTERN = 25 shared) ──

    if hit.disables_av {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::High,
            weight: 18,
            description: "JAR contains Windows Defender disable commands — common pre-payload step for Java stealers and loaders.".into(),
            technical_detail: Some(
                "Strings reference Set-MpPreference, Add-MpPreference -ExclusionPath, MpCmdRun, or sc stop WinDefend".into(),
            ),
        });
    }

    if hit.eth_rpc {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::High,
            weight: 18,
            description: "JAR references Ethereum public RPC endpoints — consistent with EtherHiding C2 (malware reads its current C2 domain from blockchain storage so traditional blocklists are stale).".into(),
            technical_detail: Some(
                "Strings include infura.io / alchemy.com / cloudflare-eth.com / ankr.com endpoints".into(),
            ),
        });
    }

    // ── Behavior-class indicators (capped at CAP_STRUCTURAL = 30 shared) ──

    if hit.browser_credentials {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 14,
            description: "JAR targets browser credential stores — typical infostealer credential-access behavior.".into(),
            technical_detail: Some(
                "Strings reference browser Cookies, Login Data, or Web Data paths".into(),
            ),
        });
    }

    if hit.crypto_wallets {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 14,
            description: "JAR targets cryptocurrency wallet files — consistent with wallet-drainer stealer functionality.".into(),
            technical_detail: Some(
                "Strings reference Electrum / Exodus / Atomic / MetaMask paths or wallet.dat / keystore files".into(),
            ),
        });
    }

    if hit.chat_tokens {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 10,
            description: "JAR targets Discord / Steam / Telegram session tokens.".into(),
            technical_detail: Some(
                "Strings reference token storage paths for chat or gaming platforms".into(),
            ),
        });
    }

    if hit.minecraft_session {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 10,
            description: "JAR reads Minecraft launcher session data — credential theft consistent with the WeedHack Minecraft MaaS campaign.".into(),
            technical_detail: Some(
                "Strings reference .minecraft/launcher_profiles.json, accounts.json, or launcher_accounts.json".into(),
            ),
        });
    }

    if hit.process_exec {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 3,
            description: "JAR invokes process execution (Runtime.exec / ProcessBuilder).".into(),
            technical_detail: None,
        });
    }

    if has_native_lib {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 3,
            description: "JAR bundles native libraries (.dll/.so/.dylib/.jnilib).".into(),
            technical_detail: None,
        });
    }

    findings
}

/// Aggregated flags set by scanning class-file bytes for known strings.
#[derive(Default)]
struct JarStringHits {
    disables_av: bool,
    eth_rpc: bool,
    browser_credentials: bool,
    crypto_wallets: bool,
    chat_tokens: bool,
    minecraft_session: bool,
    process_exec: bool,
    weedhack_signature: bool,
    weedhack_jnic: bool,
    weedhack_domain: bool,
    weedhack_hardcoded_ip: bool,
    weedhack_persistence_path: bool,
}

/// Parse the `Main-Class:` line from a manifest. Returns `None` if not present
/// or unparseable. Modified UTF-8 is treated as UTF-8 for the purposes of the
/// `Main-Class:` ASCII header.
fn parse_manifest_main_class(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Main-Class:") {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Curated list of confirmed-malicious Java entry-point class names from
/// public threat intelligence. Conservative — only entries with strong
/// public attribution.
///
/// Sources:
/// - McAfee Labs WeedHack research (2026-06)
/// - 0xresetti technical analysis (github.io/weedhack.html)
fn is_known_bad_main_class(class_name: &str) -> bool {
    const KNOWN_BAD: &[&str] = &[
        // WeedHack — directly observed loader / entry points.
        "DonutDupe",
        "me.mclauncher.LoaderClient",
        "me.mclauncher.MEntrypoint",
        "me.mclauncher.IMCL",
        "me.mclauncher.StagingHelper",
        "me.mclauncher.RPCHelper",
        // WeedHack — Stage 2/3 (stealer + RAT) entry classes.
        "dev.majanito.Main",
        "dev.majanito.security.Main",
        "dev.jnic.JNICLoader",
        // WeedHack — older family namespace observed in early-2026 builds.
        "me.weedhack.Main",
        "net.weedhack.Loader",
        "weedhack.client.Main",
    ];
    KNOWN_BAD.iter().any(|bad| class_name.contains(bad))
}

/// Distinctive byte patterns observed in WeedHack stages 1-3 that survive
/// class-name obfuscation (the operators rename classes between releases
/// but the embedded strings stay because they're functional).
///
/// Sourced from McAfee Labs research, 0xresetti technical analysis
/// (github.io/weedhack.html), and YARA rules `Weedhack_Stage1_v1`,
/// `Weedhack_Stage1_v2`, `Weedhack_Stage2_Stealer`, `Weedhack_Stage3_RAT`,
/// `Weedhack_Persistence`. Hitting any of these is high-confidence family
/// attribution.
const WEEDHACK_SIGNATURE_STRINGS: &[&[u8]] = &[
    // ── Stage 1 v1 (pure-Java loader) markers ─────────────────────
    b"initializeWeedhack",
    b"WeedhackFile",
    b"$jnicLoader",
    b"Mod init state: M",
    b"Resource state: S",
    b"StagingHelper",
    // ── Stage 1 v2 (JNIC + Blockchain C2) markers ─────────────────
    b"RPCHelper",
    b"MEntrypoint",
    b"IMCL",
    // ── Stage 2 (Stealer) handler classes ─────────────────────────
    b"BrowserHandler",
    b"CookieHandler",
    b"PasswordHandler",
    b"DiscordHandler",
    b"DllInjectionHelper",
    b"CryptoHelper",
    // ── Stage 3 (Premium RAT) handler classes ─────────────────────
    b"KeyLoggingHandler",
    b"WebcamShareHandler",
    b"ScreenShareHandler",
    b"CmdHandler",
    b"FileSystemHandler",
    b"KeyboardInputHandler",
    b"MouseInputHandler",
    // ── Persistence module classes + names ────────────────────────
    b"JavaSecurityUpdater",
    b"ElevationHelper",
    b"AVHelper",
    b"SchedulerHelper",
    b"ComponentHelper",
    // ── EtherHiding function selector + name ──────────────────────
    b"0xce6d41de",
    b"getVerifiedText",
    // ── Embedded native-stage resource UUIDs (per stage) ──────────
    b"c4f763d6-e34c-42e9-bba1-b80cfa5a55df", // Stage 1 v2 DLL
    b"a125e430-2459-4702-9797-49fce5f280ae", // Stage 2 DLL
    // ── Fabric mod descriptor used as a Minecraft-mod lure ────────
    b"loaderclient",
];

/// JNIC-obfuscated package names — Java Native Interface Compiler
/// (jnic) packs the bytecode into a native DLL. The wrapper Java
/// classes have stage-specific obfuscated names that are distinctive
/// fingerprints — they don't appear in any legitimate Minecraft mod.
const WEEDHACK_JNIC_NAMESPACES: &[&[u8]] = &[
    b"dev/jnic/lXpXvp", // Stage 1 v2
    b"dev/jnic/BSOMwJ", // Stage 2 (stealer)
    b"dev/jnic/fwcMeR", // Stage 3 (RAT)
    // Forward-slash variants only — class files always use `/` even
    // on Windows. We also accept the dotted Java form.
    b"dev.jnic.lXpXvp",
    b"dev.jnic.BSOMwJ",
    b"dev.jnic.fwcMeR",
];

/// Observed WeedHack C2 / staging domains (from public threat intel).
/// We scan for these as substrings — operators rotate domains via
/// EtherHiding, but the seed domains often persist in older builds.
const WEEDHACK_DOMAINS: &[&[u8]] = &[
    b"receiver.cy",
    b"weedhack.cy",
    b"whreceive.ru",
    b"whreceiver.ru",
    b"remotev2.whreceive.ru",
    b"marsalek.cy",
    b"huehnchenfarm.ru",
];

/// Hardcoded IPs observed in WeedHack v2 (2026-02-21 update). Operators
/// occasionally drop a direct IP literal to bypass DNS-based detection.
const WEEDHACK_HARDCODED_IPS: &[&[u8]] = &[
    b"45.141.119.34",
];

/// Persistence-stage file paths and filenames dropped by `SecurityManager.jar`
/// and friends. Distinctive enough to be near-conclusive on their own when
/// observed inside a JAR (no legitimate Minecraft mod drops to a
/// `Microsoft\SecurityUpdates` folder).
const WEEDHACK_PERSISTENCE_PATHS: &[&[u8]] = &[
    b"Microsoft\\SecurityUpdates",
    b"Microsoft/SecurityUpdates",
    b"SecurityInfo.json",
    b"security.lock",
    b"Updater.vbs",
    // The `Pjibf.exe` PureLogs/PureHVNC NETReactor backdoor name observed
    // in the v0.2 (2026-02-21) update.
    b"Pjibf.exe",
];

/// Scan raw class-file bytes for known suspicious strings. We don't parse the
/// constant pool — the strings are length-prefixed Modified UTF-8 in the
/// constant pool section, and raw byte substring search is sufficient (and
/// faster) for the patterns we care about.
fn scan_class_strings(class_bytes: &[u8], hit: &mut JarStringHits) {
    let limit = class_bytes.len().min(MAX_STRING_SCAN_BYTES);
    let scan = &class_bytes[..limit];

    const AV_DISABLE: &[&[u8]] = &[
        b"Set-MpPreference",
        b"Add-MpPreference",
        b"MpCmdRun",
        b"-ExclusionPath",
        b"-DisableRealtimeMonitoring",
        b"sc stop WinDefend",
        b"net stop WinDefend",
    ];
    if !hit.disables_av && AV_DISABLE.iter().any(|p| contains_bytes(scan, p)) {
        hit.disables_av = true;
    }

    const ETH_RPC: &[&[u8]] = &[
        b"infura.io",
        b"alchemy.com",
        b"cloudflare-eth.com",
        b"ankr.com/eth",
        b"mainnet.infura",
        b"eth.llamarpc.com",
    ];
    if !hit.eth_rpc && ETH_RPC.iter().any(|p| contains_bytes(scan, p)) {
        hit.eth_rpc = true;
    }

    const BROWSER_CREDS: &[&[u8]] = &[
        b"Google\\Chrome\\User Data",
        b"Google/Chrome/User Data",
        b"Microsoft\\Edge\\User Data",
        b"Microsoft/Edge/User Data",
        b"Mozilla\\Firefox\\Profiles",
        b"Mozilla/Firefox/Profiles",
        b"BraveSoftware\\Brave-Browser",
        b"Opera Software\\Opera Stable",
        b"\\Login Data",
        b"/Login Data",
        b"\\Cookies",
        b"\\Web Data",
        b"\\Local State",
    ];
    if !hit.browser_credentials && BROWSER_CREDS.iter().any(|p| contains_bytes(scan, p)) {
        hit.browser_credentials = true;
    }

    const WALLETS: &[&[u8]] = &[
        b"Electrum",
        b"Exodus",
        b"exodus.wallet",
        b"Atomic\\Local Storage",
        b"Atomic/Local Storage",
        b"MetaMask",
        b"nkbihfbeogaeaoehlefnkodbefgpgknn", // MetaMask Chrome extension ID
        b"wallet.dat",
        b"keystore",
        b"Bitcoin\\wallets",
        b"Litecoin\\wallets",
        b"Coinbase",
        b"TrustWallet",
        b"Phantom",
    ];
    if !hit.crypto_wallets && WALLETS.iter().any(|p| contains_bytes(scan, p)) {
        hit.crypto_wallets = true;
    }

    const CHAT: &[&[u8]] = &[
        b"discord\\Local Storage",
        b"Discord\\Local Storage",
        b"discord/Local Storage",
        b"discordcanary",
        b"discordptb",
        b"Telegram Desktop\\tdata",
        b"Telegram Desktop/tdata",
        b"Steam\\config\\loginusers.vdf",
        b"Steam/config/loginusers.vdf",
        b"Steam\\config\\config.vdf",
    ];
    if !hit.chat_tokens && CHAT.iter().any(|p| contains_bytes(scan, p)) {
        hit.chat_tokens = true;
    }

    const MINECRAFT: &[&[u8]] = &[
        b".minecraft/launcher_profiles.json",
        b".minecraft\\launcher_profiles.json",
        b".minecraft/accounts.json",
        b".minecraft\\accounts.json",
        b"launcher_accounts.json",
        b"usercache.json",
        b"TLauncher",
        b"FeatherClient",
        b"LunarClient",
        b"BadlionClient",
    ];
    if !hit.minecraft_session && MINECRAFT.iter().any(|p| contains_bytes(scan, p)) {
        hit.minecraft_session = true;
    }

    const EXEC: &[&[u8]] = &[
        b"java/lang/Runtime",
        b"ProcessBuilder",
        b"cmd.exe",
        b"powershell",
    ];
    if !hit.process_exec && EXEC.iter().any(|p| contains_bytes(scan, p)) {
        hit.process_exec = true;
    }

    // WeedHack-specific distinctive strings (survive class-name obfuscation).
    if !hit.weedhack_signature
        && WEEDHACK_SIGNATURE_STRINGS.iter().any(|p| contains_bytes(scan, p))
    {
        hit.weedhack_signature = true;
    }

    // JNIC-obfuscated WeedHack stage packages — stage-specific fingerprints.
    if !hit.weedhack_jnic
        && WEEDHACK_JNIC_NAMESPACES.iter().any(|p| contains_bytes(scan, p))
    {
        hit.weedhack_jnic = true;
    }

    // WeedHack C2 / staging domains seen as substrings.
    if !hit.weedhack_domain
        && WEEDHACK_DOMAINS.iter().any(|p| contains_bytes(scan, p))
    {
        hit.weedhack_domain = true;
    }

    // Hardcoded WeedHack v0.2 IP literal.
    if !hit.weedhack_hardcoded_ip
        && WEEDHACK_HARDCODED_IPS.iter().any(|p| contains_bytes(scan, p))
    {
        hit.weedhack_hardcoded_ip = true;
    }

    // WeedHack persistence file paths (Microsoft\SecurityUpdates, Updater.vbs, etc.).
    if !hit.weedhack_persistence_path
        && WEEDHACK_PERSISTENCE_PATHS.iter().any(|p| contains_bytes(scan, p))
    {
        hit.weedhack_persistence_path = true;
    }
}

/// Plain byte-substring search. The pattern layer has an Aho-Corasick
/// automaton but it operates on the whole file at once — for class-file
/// scanning we run many short scans on small buffers, so per-call
/// substring search is simpler and adequate.
fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_magic_recognition() {
        assert!(is_zip_magic(&[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00]));
        assert!(!is_zip_magic(&[0x4D, 0x5A])); // MZ
        assert!(!is_zip_magic(&[0x50, 0x4B, 0x05, 0x06])); // empty-archive marker
        assert!(!is_zip_magic(&[]));
        assert!(!is_zip_magic(&[0x50]));
    }

    #[test]
    fn analyze_non_zip_returns_empty() {
        assert!(analyze("x.exe", b"MZ\x00\x00").is_empty());
        assert!(analyze("x.jar", b"").is_empty());
    }

    #[test]
    fn known_bad_main_class_matches_weedhack_family() {
        assert!(is_known_bad_main_class("DonutDupe"));
        assert!(is_known_bad_main_class("me.weedhack.Main"));
        assert!(is_known_bad_main_class("net.weedhack.Loader"));
        assert!(is_known_bad_main_class("weedhack.client.Main"));

        // Substring within a longer class name still matches — this is
        // intentional (loader stubs may wrap the family name).
        assert!(is_known_bad_main_class("com.foo.DonutDupeLoader"));

        // Legitimate Minecraft mod class — must NOT match.
        assert!(!is_known_bad_main_class("net.minecraftforge.fml.common.Mod"));
        assert!(!is_known_bad_main_class("net.fabricmc.api.ClientModInitializer"));
    }

    #[test]
    fn manifest_main_class_parse() {
        let m = b"Manifest-Version: 1.0\nMain-Class: DonutDupe\nClass-Path: lib/foo.jar\n";
        assert_eq!(parse_manifest_main_class(m), Some("DonutDupe".to_string()));

        let m2 = b"Manifest-Version: 1.0\n\n"; // no main class
        assert_eq!(parse_manifest_main_class(m2), None);

        // Leading whitespace on the value is trimmed.
        let m3 = b"Main-Class:     com.example.Foo  \n";
        assert_eq!(parse_manifest_main_class(m3), Some("com.example.Foo".to_string()));
    }

    #[test]
    fn scan_class_strings_av_disable() {
        let mut hit = JarStringHits::default();
        scan_class_strings(b"prefix Set-MpPreference suffix", &mut hit);
        assert!(hit.disables_av);
        assert!(!hit.eth_rpc);
    }

    #[test]
    fn scan_class_strings_eth_rpc() {
        let mut hit = JarStringHits::default();
        scan_class_strings(b"https://mainnet.infura.io/v3/abc", &mut hit);
        assert!(hit.eth_rpc);
    }

    #[test]
    fn scan_class_strings_browser_creds() {
        let mut hit = JarStringHits::default();
        scan_class_strings(b"Google\\Chrome\\User Data\\Default\\Cookies", &mut hit);
        assert!(hit.browser_credentials);
    }

    #[test]
    fn scan_class_strings_crypto_wallets() {
        let mut hit = JarStringHits::default();
        scan_class_strings(b"AppData\\Roaming\\Exodus\\exodus.wallet", &mut hit);
        assert!(hit.crypto_wallets);
    }

    #[test]
    fn scan_class_strings_minecraft() {
        let mut hit = JarStringHits::default();
        scan_class_strings(b"%APPDATA%\\.minecraft\\launcher_profiles.json", &mut hit);
        assert!(hit.minecraft_session);
    }

    #[test]
    fn scan_class_strings_combined() {
        let mut hit = JarStringHits::default();
        let blob = b"\
            AppData\\Roaming\\.minecraft/launcher_profiles.json \
            discord\\Local Storage \\Login Data \
            https://mainnet.infura.io/v3/foo \
            Set-MpPreference -DisableRealtimeMonitoring \
            java/lang/Runtime ProcessBuilder";
        scan_class_strings(blob, &mut hit);
        assert!(hit.minecraft_session);
        assert!(hit.chat_tokens);
        assert!(hit.browser_credentials);
        assert!(hit.eth_rpc);
        assert!(hit.disables_av);
        assert!(hit.process_exec);
    }

    #[test]
    fn contains_bytes_edge_cases() {
        assert!(!contains_bytes(b"abc", b""));
        assert!(!contains_bytes(b"abc", b"abcd"));
        assert!(contains_bytes(b"abc", b"a"));
        assert!(contains_bytes(b"abc", b"abc"));
        assert!(contains_bytes(b"xxxneedlexxx", b"needle"));
    }

    /// End-to-end against a real (synthetic) malicious-shaped JAR built
    /// in-memory. Asserts the high-weight findings fire.
    #[test]
    fn synthetic_weedhack_shaped_jar() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            w.start_file("META-INF/MANIFEST.MF", opts).unwrap();
            w.write_all(b"Manifest-Version: 1.0\nMain-Class: DonutDupe\n").unwrap();
            w.start_file("DonutDupe.class", opts).unwrap();
            // Synthetic class file: just the strings we'd see in the
            // constant pool. Real bytecode parser would skip the header
            // but raw substring scan finds them either way.
            w.write_all(
                b"\xca\xfe\xba\xbe...const pool...\
                  https://mainnet.infura.io/v3/key \
                  Set-MpPreference -ExclusionPath \
                  AppData\\Roaming\\.minecraft\\launcher_profiles.json \
                  Google\\Chrome\\User Data\\Default\\Cookies \
                  MetaMask Exodus discord\\Local Storage \
                  java/lang/Runtime ProcessBuilder",
            ).unwrap();
            w.finish().unwrap();
        }

        let findings = analyze("evil.jar", &buf);
        // Headline: known main class → IoC (uncapped) at weight 60.
        assert!(
            findings.iter().any(|f| f.weight == 60 && f.layer == Layer::IocCorrelation),
            "expected DonutDupe IoC finding: {findings:?}"
        );
        // EtherHiding + AV-disable land under PatternDetection at weight 18 each.
        assert!(
            findings.iter().any(|f| f.weight == 18 && f.layer == Layer::PatternDetection),
            "expected EtherHiding/AV-disable PatternDetection finding: {findings:?}"
        );
        // Sum of raw weights (before convergence caps) is comfortably > 100.
        let total: u32 = findings.iter().map(|f| f.weight).sum();
        assert!(total > 100, "expected aggregate raw weight > 100, got {total}");
    }

    /// Legitimate Minecraft mod shape — minimal manifest, no suspicious
    /// strings. Should generate zero findings.
    #[test]
    fn legitimate_mod_shape_clean() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            w.start_file("META-INF/MANIFEST.MF", opts).unwrap();
            w.write_all(
                b"Manifest-Version: 1.0\nMain-Class: net.minecraftforge.fml.common.Mod\n",
            ).unwrap();
            w.start_file("com/example/ExampleMod.class", opts).unwrap();
            w.write_all(
                b"\xca\xfe\xba\xbe...just normal mod bytecode and resource references...",
            ).unwrap();
            w.finish().unwrap();
        }

        let findings = analyze("good.jar", &buf);
        assert!(findings.is_empty(), "expected zero findings on a clean mod, got {findings:?}");
    }

    /// Non-Java ZIP (e.g. OOXML / APK / plain ZIP) — no manifest, no .class
    /// entries. Should bail without spurious findings.
    #[test]
    fn non_java_zip_bails() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            w.start_file("word/document.xml", opts).unwrap();
            w.write_all(b"<xml>some legit document</xml>").unwrap();
            w.finish().unwrap();
        }

        let findings = analyze("doc.docx", &buf);
        assert!(findings.is_empty(), "expected zero findings on non-Java ZIP, got {findings:?}");
    }
}

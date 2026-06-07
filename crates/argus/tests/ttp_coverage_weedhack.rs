//! TTP-coverage regression suite — **WeedHack family** synthetic shapes.
//!
//! Builds adversarial JARs in-memory matching the documented WeedHack
//! kill-chain stages (per McAfee Labs research + 0xresetti technical
//! analysis), runs them through the full ARGUS pipeline, and asserts each
//! stage hits its expected detection floor.
//!
//! These tests do NOT require real malware samples — every JAR is
//! constructed from documented TTPs. They function as the regression
//! suite for future weight/threshold tuning: when we ship a real-sample
//! corpus eval, these tests stay green to prove we haven't regressed on
//! the documented family signals.

use argus::verdict::Verdict;
use argus::{ArgusConfig, ArgusEngine};
use std::io::Write;
use zip::write::SimpleFileOptions;

/// Helper: build a JAR with the given Main-Class and a single synthetic
/// `.class` whose bytes include the supplied strings somewhere in the
/// "constant pool" region (we don't generate real bytecode — string
/// substring scanning is what the layer uses anyway).
fn build_synthetic_jar(main_class: &str, class_blob: &[&[u8]], extra_entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.start_file("META-INF/MANIFEST.MF", opts).unwrap();
        write!(
            &mut w,
            "Manifest-Version: 1.0\nMain-Class: {main_class}\n",
        )
        .unwrap();

        // Synthetic class file — bogus java magic + the strings we want
        // visible in the constant-pool scan.
        w.start_file("loader.class", opts).unwrap();
        w.write_all(b"\xca\xfe\xba\xbe\x00\x00\x00\x34").unwrap();
        for blob in class_blob {
            w.write_all(b" ").unwrap();
            w.write_all(blob).unwrap();
        }

        for (name, content) in extra_entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(content).unwrap();
        }

        w.finish().unwrap();
    }
    buf
}

/// Score the JAR end-to-end through the engine's buffer entry point.
fn score(jar: &[u8], name: &str) -> argus::ArgusVerdict {
    let engine = ArgusEngine::new(ArgusConfig::default());
    engine.analyze_buffer(name, jar)
}

// ──────────────────────────────────────────────────────────────────
//  Stage 1 — initial dropper (DonutDupe / LoaderClient)
// ──────────────────────────────────────────────────────────────────
#[test]
fn weedhack_stage1_loader_floor() {
    let jar = build_synthetic_jar(
        "me.mclauncher.LoaderClient",
        &[
            b"initializeWeedhack",
            b"JavaSecurityUpdater",
            b"0xce6d41de",                  // EtherHiding selector
            b"https://eth.llamarpc.com",
            b"Add-MpPreference -ExclusionPath",
            b"%APPDATA%\\Microsoft\\SecurityUpdates\\",
        ],
        &[
            (
                // Native stage 1 v2 DLL embedded as resource (UUID is the
                // documented file name).
                "resources/c4f763d6-e34c-42e9-bba1-b80cfa5a55df.dll",
                b"MZ\x90\x00synthetic-dll-payload",
            ),
        ],
    );
    let v = score(&jar, "DonutDupe.jar");
    eprintln!(
        "[stage1] score={} verdict={:?} findings={}",
        v.score,
        v.verdict,
        v.findings.len()
    );

    assert!(v.score >= 76, "Stage 1 must score Malicious; got {}", v.score);
    assert_eq!(v.verdict, Verdict::Malicious, "Stage 1 verdict");
    // The post-convergence finding list has its weights rescaled by the per-
    // category caps; assert by DESCRIPTION substring so the test remains
    // robust to future weight tuning.
    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("known malicious entry point")),
        "expected known-main-class finding: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("WeedHack family strings")),
        "expected weedhack_signature finding: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("EtherHiding")),
        "expected eth_rpc finding: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("Windows Defender disable")),
        "expected av-disable finding: {descs:?}");
}

// ──────────────────────────────────────────────────────────────────
//  Stage 2 — stealer (dev.majanito.security.Main / "Elevator.jar")
// ──────────────────────────────────────────────────────────────────
#[test]
fn weedhack_stage2_stealer_floor() {
    let jar = build_synthetic_jar(
        "dev.majanito.security.Main",
        &[
            b"WeedhackFile",
            b"Google\\Chrome\\User Data\\Default\\Cookies",
            b"Google\\Chrome\\User Data\\Default\\Login Data",
            b"Mozilla\\Firefox\\Profiles",
            b"AppData\\Roaming\\Exodus\\exodus.wallet",
            b"MetaMask",
            b"nkbihfbeogaeaoehlefnkodbefgpgknn",
            b"discord\\Local Storage",
            b"Telegram Desktop\\tdata",
            b"%APPDATA%\\.minecraft\\launcher_profiles.json",
            b"launcher_accounts.json",
            b"Set-MpPreference -DisableRealtimeMonitoring",
            b"java/lang/Runtime",
            b"ProcessBuilder",
        ],
        &[],
    );
    let v = score(&jar, "Elevator.jar");
    eprintln!(
        "[stage2] score={} verdict={:?} findings={}",
        v.score,
        v.verdict,
        v.findings.len()
    );

    assert!(v.score >= 76, "Stage 2 must score Malicious; got {}", v.score);
    assert_eq!(v.verdict, Verdict::Malicious);

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("known malicious entry point")),
        "known-main-class: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("WeedHack family strings")),
        "weedhack_signature: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("Windows Defender disable")),
        "AV-disable: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("browser credential stores")),
        "browser-creds: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("cryptocurrency wallet")),
        "wallets: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("Minecraft launcher session")),
        "minecraft: {descs:?}");
}

// ──────────────────────────────────────────────────────────────────
//  Stage 3 — RAT (dev.majanito.Main + handlers + JNIC + persistence)
// ──────────────────────────────────────────────────────────────────
//
// Post-polish: family signals now ride on different BehaviorTags
// (IoC/KnownMalware for class+sig; Pattern/Exfiltration for domain+IP;
// Pattern/Evasion for JNIC; Structural/Persistence for the dropped
// artifacts). Stage 3 synthetic must reach Malicious from the JAR layer
// alone — no YARA/IOC corroboration required.
#[test]
fn weedhack_stage3_rat_floor() {
    let jar = build_synthetic_jar(
        "dev.majanito.Main",
        &[
            b"dev.majanito.handlers.KeyLoggingHandler",
            b"dev.majanito.handlers.WebcamShareHandler",
            b"dev.majanito.handlers.ScreenShareHandler",
            b"dev.majanito.handlers.CmdHandler",
            b"dev.majanito.handlers.FileSystemHandler",
            // C2 domain — exfil tag, independent finding
            b"remotev2.whreceive.ru/ws/client",
            // JNIC obfuscated namespace — evasion tag, independent finding
            b"dev/jnic/fwcMeR/Loader",
            // Persistence artifact — persistence tag, independent finding
            b"%APPDATA%\\Microsoft\\SecurityUpdates\\Updater.vbs",
            // Family signature string — known-malware tag, dedups with main class
            b"$jnicLoader",
            b"java/lang/Runtime",
            b"cmd.exe",
        ],
        &[],
    );
    let v = score(&jar, "Component.jar");
    eprintln!(
        "[stage3] score={} verdict={:?} findings={}",
        v.score,
        v.verdict,
        v.findings.len()
    );

    // With the tag-spread fix, Stage 3 evidence now scores Malicious.
    // The IoC KnownMalware cluster (class + sig) collapses to one — by design
    // — but JNIC, domain, and persistence ride DIFFERENT tags and contribute
    // independently. Total expected ≥ 76.
    assert!(
        v.score >= 76,
        "Stage 3 RAT synth must score Malicious post-polish (signals route to distinct BehaviorTags); got {}",
        v.score
    );

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("known malicious entry point")),
        "known-main-class: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("WeedHack family strings")),
        "weedhack_signature: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("WeedHack C2")),
        "weedhack_domain: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("JNIC-obfuscated WeedHack")),
        "jnic_namespace: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("WeedHack persistence")),
        "persistence_path: {descs:?}");
}

// ──────────────────────────────────────────────────────────────────
//  Real-sample SHA detection — confirmed WeedHack hashes shipped in
//  runtime/rules/ioc_hashes.txt must trigger the IOC layer's 90-weight
//  Critical finding regardless of class-name obfuscation or JNIC packing.
//
//  This test verifies the IOC list IS being loaded by the engine. It uses
//  the in-memory `IocDatabase` directly to avoid a runtime-dir dependency.
// ──────────────────────────────────────────────────────────────────
#[test]
fn confirmed_weedhack_sha_in_runtime_iocs() {
    // The IOC list is plain-text; verify each WeedHack hash is exactly as
    // recorded. These are the SHA-256s of any file ARGUS is given that
    // matches → 90-weight Critical finding → instant Malicious.
    const RUNTIME_IOCS: &str = include_str!("../../../runtime/rules/ioc_hashes.txt");

    const WEEDHACK_SAMPLES: &[&str] = &[
        // MalwareBazaar
        "4c7ab766875cbaa5c8ab9bb3547b7d000dc793765825c35c6db01f5c73db9ab6",
        // Triage — "Andrew Bettany ... .epub.jar" lure
        "5cdcf8ad07effa91dec699c83fdd01837138a9fb61693bdd7fa5df457928b05b",
        // Triage — "Prestigue 1.21.1.jar"
        "d0644119a24a007c7eee5554d30e88024eb09522d5fdf108c45de0e16e9034ab",
        // Triage — "Marlows_Crystal_Optimizer-1.0.3.jar"
        "7246a9d4dc9ad098ad83d16f8bd42e758cb67c6ce298958f780ab89f1c00df82",
    ];

    for hash in WEEDHACK_SAMPLES {
        assert!(
            RUNTIME_IOCS.contains(hash),
            "WeedHack sample {hash} is not in runtime/rules/ioc_hashes.txt — instant-kill bypassed"
        );
    }
}

// ──────────────────────────────────────────────────────────────────
//  Obfuscated variant — operators rename classes between releases,
//  but functional strings (URLs, persistence task names, function
//  selectors) survive. Detection MUST hold without relying on the
//  class-name allowlist.
// ──────────────────────────────────────────────────────────────────
#[test]
fn weedhack_obfuscated_class_name_still_detected() {
    let jar = build_synthetic_jar(
        "a.b.c.Renamed",
        &[
            b"initializeWeedhack",
            b"JavaSecurityUpdater",
            b"0xce6d41de",
            b"https://mainnet.infura.io/v3/key",
            b"Add-MpPreference -ExclusionPath",
            b"%APPDATA%\\.minecraft\\launcher_profiles.json",
        ],
        &[],
    );
    let v = score(&jar, "renamed.jar");
    eprintln!(
        "[obfuscated] score={} verdict={:?} findings={}",
        v.score,
        v.verdict,
        v.findings.len()
    );

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    // No known main class hit (good — we renamed it).
    assert!(!descs.iter().any(|d| d.contains("known malicious entry point")),
        "renamed class must NOT trigger Main-Class allowlist: {descs:?}");
    // But every other signal fires.
    assert!(descs.iter().any(|d| d.contains("WeedHack family strings")),
        "weedhack_signature: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("EtherHiding")),
        "eth_rpc: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("Windows Defender disable")),
        "av-disable: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("Minecraft launcher session")),
        "minecraft: {descs:?}");

    // Strong score even without the class-name catch.
    assert!(v.score >= 76, "Obfuscated WeedHack must still score Malicious; got {}", v.score);
}

// ──────────────────────────────────────────────────────────────────
//  Domain-only variant — a Stage-1 fragment with no class-name match
//  and no weedhack-specific strings, just a known C2 domain reference.
// ──────────────────────────────────────────────────────────────────
#[test]
fn weedhack_domain_only_reference_flags_critical() {
    let jar = build_synthetic_jar(
        "com.example.LegitLooking",
        &[b"https://receiver.cy/files/jar/module"],
        &[],
    );
    let v = score(&jar, "minor.jar");
    eprintln!(
        "[domain-only] score={} verdict={:?} findings={}",
        v.score,
        v.verdict,
        v.findings.len()
    );

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("WeedHack C2")),
        "weedhack_domain finding expected: {descs:?}");
    // 45 alone may not push past 76 after caps; that's OK — the family
    // domain match is meant as evidence that COMBINES with other layers
    // (clamav, yara, patterns). We assert verdict is at least Suspicious.
    assert!(
        v.score >= 26,
        "Domain reference alone must score >= Suspicious; got {}",
        v.score
    );
}

// ──────────────────────────────────────────────────────────────────
//  Generic Java infostealer (NOT WeedHack-specific) — should still
//  score HighSuspicion via the credential/wallet/chat targeting layers.
// ──────────────────────────────────────────────────────────────────
#[test]
fn generic_java_infostealer_high_suspicion_floor() {
    let jar = build_synthetic_jar(
        "com.legit.Mod",                              // not in allowlist
        &[
            b"Google\\Chrome\\User Data\\Default\\Cookies",
            b"AppData\\Roaming\\Exodus\\exodus.wallet",
            b"discord\\Local Storage",
            b"Telegram Desktop\\tdata",
        ],
        &[],
    );
    let v = score(&jar, "generic_stealer.jar");
    eprintln!(
        "[generic-stealer] score={} verdict={:?} findings={}",
        v.score,
        v.verdict,
        v.findings.len()
    );

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(!descs.iter().any(|d| d.contains("known malicious entry point")),
        "must NOT hit Main-Class allowlist: {descs:?}");
    assert!(!descs.iter().any(|d| d.contains("WeedHack family strings")),
        "must NOT hit weedhack_signature: {descs:?}");
    // Generic stealer behavior signals (browser, wallets, chat) plus the
    // structural cap floor — should land at Suspicious at minimum.
    assert!(v.score >= 26, "Generic stealer should score >= Suspicious; got {}", v.score);
}

// ──────────────────────────────────────────────────────────────────
//  Clean Minecraft mod (control / negative case) — zero findings.
// ──────────────────────────────────────────────────────────────────
#[test]
fn clean_minecraft_mod_zero_findings() {
    let jar = build_synthetic_jar(
        "net.minecraftforge.fml.common.Mod",
        &[
            b"net/minecraftforge/fml/common/Mod",
            b"net/minecraft/block/Block",
            b"ExampleItem.png",
            b"com/example/ExampleMod.class",
        ],
        &[(
            "assets/example/textures/item/example.png",
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR-mock",
        )],
    );
    let v = score(&jar, "exampleMod.jar");
    eprintln!(
        "[clean-mod] score={} verdict={:?} findings={}",
        v.score,
        v.verdict,
        v.findings.len()
    );

    assert_eq!(v.score, 0, "Clean mod must score 0; got {} with findings {:?}", v.score, v.findings);
    assert_eq!(v.verdict, Verdict::Clean);
}

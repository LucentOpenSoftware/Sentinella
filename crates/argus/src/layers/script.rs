//! Layer 4: Script Analysis
//!
//! Detects suspicious patterns in script files: PowerShell, JavaScript,
//! batch files, VBScript. Focuses on obfuscation, encoded commands,
//! and download cradles commonly used by malware loaders.

use crate::verdict::{Finding, Layer, Severity};

/// Analyze script content for suspicious patterns.
/// Caller should determine file type by extension or MIME before calling.
pub fn analyze(path: &str, data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let ext = std::path::Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Only analyze text-like files.
    let content = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => {
            // Try lossy conversion for partial text files.
            return findings; // Binary files handled elsewhere.
        }
    };

    match ext.as_str() {
        "ps1" | "psm1" | "psd1" => analyze_powershell(content, &mut findings),
        "js" | "jse" => analyze_javascript(content, &mut findings),
        "vbs" | "vbe" => analyze_vbscript(content, &mut findings),
        "bat" | "cmd" => analyze_batch(content, &mut findings),
        "reg" => analyze_regfile(content, &mut findings),
        _ => {
            // Check if content looks like a script regardless of extension.
            if content.contains("powershell") || content.contains("Invoke-") {
                analyze_powershell(content, &mut findings);
            }
            if content.contains("eval(") || content.contains("Function(") {
                analyze_javascript(content, &mut findings);
            }
        }
    }

    findings
}

// ── PowerShell analysis ────────────────────────────────────────────

fn analyze_powershell(content: &str, findings: &mut Vec<Finding>) {
    let lower = content.to_lowercase();

    // Encoded command (base64 powershell execution).
    if lower.contains("-encodedcommand") || lower.contains("-enc ") || lower.contains("-ec ") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 25,
            description: "PowerShell script uses encoded command execution — a technique to hide malicious payloads from inspection.".into(),
            technical_detail: Some("Contains -EncodedCommand or -enc parameter".into()),
        });
    }

    // Execution policy bypass.
    if lower.contains("-executionpolicy bypass")
        || lower.contains("-ep bypass")
        || lower.contains("set-executionpolicy unrestricted")
    {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Medium,
            weight: 12,
            description: "PowerShell script bypasses execution policy — reduces security restrictions on script execution.".into(),
            technical_detail: Some("Execution policy bypass detected".into()),
        });
    }

    // Download cradles.
    let download_patterns = [
        ("invoke-webrequest", "Invoke-WebRequest download"),
        ("invoke-restmethod", "Invoke-RestMethod download"),
        ("downloadstring", "DownloadString download cradle"),
        ("downloadfile", "DownloadFile download cradle"),
        ("net.webclient", "Net.WebClient download"),
        ("start-bitstransfer", "BITS transfer download"),
        (
            "invoke-expression",
            "Invoke-Expression (dynamic code execution)",
        ),
        ("iex(", "IEX alias (dynamic code execution)"),
        ("iex (", "IEX alias (dynamic code execution)"),
    ];

    let mut download_found = Vec::new();
    for &(pattern, desc) in &download_patterns {
        if lower.contains(pattern) {
            download_found.push(desc);
        }
    }

    if download_found.len() >= 2 {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 22,
            description: "PowerShell script contains a download-and-execute pattern — a common malware loader technique.".into(),
            technical_detail: Some(format!("Patterns: {}", download_found.join(", "))),
        });
    } else if download_found.len() == 1 {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Medium,
            weight: 10,
            description: format!(
                "PowerShell script uses {} — may be part of a download chain.",
                download_found[0]
            ),
            technical_detail: None,
        });
    }

    // AMSI bypass attempts.
    if lower.contains("amsiscanbuffer")
        || lower.contains("amsiutils")
        || lower.contains("amsiinitfailed")
    {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Critical,
            weight: 35,
            description: "PowerShell script attempts to bypass Windows AMSI (Anti-Malware Scan Interface) — a strong indicator of malicious intent.".into(),
            technical_detail: Some("AMSI bypass pattern detected".into()),
        });
    }

    // Reflection/assembly loading (fileless techniques).
    if lower.contains("[reflection.assembly]::load") || lower.contains("assembly.load(") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 18,
            description: "PowerShell script loads .NET assemblies from memory — a fileless execution technique used to avoid disk-based detection.".into(),
            technical_detail: Some("[Reflection.Assembly]::Load detected".into()),
        });
    }

    // Windows Defender exclusion manipulation (stealer setup).
    if lower.contains("add-mppreference") && lower.contains("exclusionpath") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Critical,
            weight: 30,
            description: "PowerShell script adds Windows Defender exclusion paths — a technique used by stealers to prevent scanning of malware staging directories.".into(),
            technical_detail: Some("Add-MpPreference -ExclusionPath detected".into()),
        });
    }

    // Registry manipulation for persistence.
    if (lower.contains("new-itemproperty") || lower.contains("set-itemproperty"))
        && lower.contains("\\run")
    {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 20,
            description: "PowerShell script modifies the Windows Registry Run key — establishing persistence to survive reboots.".into(),
            technical_detail: Some("Registry Run key modification via PowerShell".into()),
        });
    }

    // Credential harvesting via COM objects.
    if lower.contains("system.net.networkcredential")
        || (lower.contains("get-credential") && lower.contains("-message"))
    {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 18,
            description: "PowerShell script attempts to capture user credentials — may display a fake login prompt.".into(),
            technical_detail: Some("Credential harvesting via Get-Credential or NetworkCredential".into()),
        });
    }
}

// ── JavaScript analysis ────────────────────────────────────────────

fn analyze_javascript(content: &str, findings: &mut Vec<Finding>) {
    let lower = content.to_lowercase();

    // Heavily obfuscated JS (long eval chains, string concatenation abuse).
    let eval_count = lower.matches("eval(").count();
    if eval_count >= 3 {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 20,
            description: format!(
                "JavaScript contains {eval_count} nested eval() calls — a common obfuscation technique used to hide malicious code."
            ),
            technical_detail: Some(format!("{eval_count} eval() invocations")),
        });
    } else if eval_count >= 1 {
        // Single eval is common in legitimate code, but note it.
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Low,
            weight: 3,
            description: "JavaScript uses eval() for dynamic code execution.".into(),
            technical_detail: None,
        });
    }

    // String.fromCharCode chains (obfuscation).
    let charcode_count = lower.matches("fromcharcode").count();
    if charcode_count >= 5 {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Medium,
            weight: 15,
            description: "JavaScript constructs strings from character codes — a technique to hide readable strings from analysis.".into(),
            technical_detail: Some(format!("{charcode_count} fromCharCode() calls")),
        });
    }

    // ActiveXObject (WSH/HTA scripts).
    if lower.contains("activexobject") || lower.contains("wscript.shell") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 20,
            description: "Script creates ActiveX objects for system access — allows arbitrary command execution outside the browser sandbox.".into(),
            technical_detail: Some("ActiveXObject or WScript.Shell instantiation detected".into()),
        });
    }

    // atob + eval (decode + execute pattern).
    if lower.contains("atob(") && eval_count >= 1 {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 18,
            description: "JavaScript decodes base64 data and executes it — a common payload delivery technique.".into(),
            technical_detail: Some("atob() + eval() combination detected".into()),
        });
    }
}

// ── VBScript analysis ──────────────────────────────────────────────

fn analyze_vbscript(content: &str, findings: &mut Vec<Finding>) {
    let lower = content.to_lowercase();

    if lower.contains("createobject(\"wscript.shell\")")
        || lower.contains("createobject(\"shell.application\")")
    {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 18,
            description:
                "VBScript creates a system shell object — enables arbitrary command execution."
                    .into(),
            technical_detail: Some(
                "WScript.Shell or Shell.Application CreateObject detected".into(),
            ),
        });
    }

    if lower.contains("execute(") || lower.contains("executeglobal(") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Medium,
            weight: 15,
            description: "VBScript dynamically executes code at runtime — may hide malicious payload.".into(),
            technical_detail: Some("Execute() or ExecuteGlobal() detected".into()),
        });
    }
}

// ── Batch file analysis ────────────────────────────────────────────

fn analyze_batch(content: &str, findings: &mut Vec<Finding>) {
    let lower = content.to_lowercase();

    // PowerShell invocation from batch (common dropper pattern).
    if lower.contains("powershell")
        && (lower.contains("-enc") || lower.contains("invoke-") || lower.contains("downloadstring"))
    {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 22,
            description: "Batch file launches PowerShell with suspicious parameters — common dropper behavior.".into(),
            technical_detail: Some("Batch → PowerShell execution chain detected".into()),
        });
    }

    // certutil abuse (download + decode).
    if lower.contains("certutil") && (lower.contains("-urlcache") || lower.contains("-decode")) {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 20,
            description: "Batch file abuses certutil.exe for file download or decoding — a Living-Off-The-Land technique.".into(),
            technical_detail: Some("certutil -urlcache or -decode detected".into()),
        });
    }

    // Disabling Defender via batch.
    if lower.contains("set-mppreference") && lower.contains("disablerealtimemonitoring") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Critical,
            weight: 35,
            description: "Script attempts to disable Windows Defender real-time monitoring.".into(),
            technical_detail: Some("Set-MpPreference -DisableRealtimeMonitoring detected".into()),
        });
    }

    // Adding Defender exclusions.
    if lower.contains("add-mppreference") && lower.contains("exclusionpath") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Critical,
            weight: 30,
            description: "Script adds Windows Defender exclusion paths — a technique to prevent scanning of malware staging directories.".into(),
            technical_detail: Some("Add-MpPreference -ExclusionPath detected".into()),
        });
    }

    // bitsadmin abuse (LOLBin download).
    if lower.contains("bitsadmin") && (lower.contains("/transfer") || lower.contains("/addfile")) {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 18,
            description: "Batch file uses bitsadmin.exe to download files — a Living-Off-The-Land download technique.".into(),
            technical_detail: Some("bitsadmin /transfer or /addfile detected".into()),
        });
    }

    // mshta abuse (run HTA from URL).
    if lower.contains("mshta")
        && (lower.contains("http") || lower.contains("javascript:") || lower.contains("vbscript:"))
    {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 22,
            description: "Script executes code via mshta.exe — a LOLBin technique that bypasses application whitelisting.".into(),
            technical_detail: Some("mshta.exe code execution detected".into()),
        });
    }

    // reg.exe abuse (silent registry modification).
    if lower.contains("reg add") && lower.contains("/f") && lower.contains("\\run") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 20,
            description: "Batch file silently modifies the Registry Run key for persistence."
                .into(),
            technical_detail: Some("reg add ... \\Run ... /f detected".into()),
        });
    }

    // sc.exe service creation.
    if lower.contains("sc create") || lower.contains("sc.exe create") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Medium,
            weight: 12,
            description:
                "Batch file creates a Windows service — may establish system-level persistence."
                    .into(),
            technical_detail: Some("sc create detected".into()),
        });
    }
}

// ── Registry file analysis ─────────────────────────────────────────

fn analyze_regfile(content: &str, findings: &mut Vec<Finding>) {
    let lower = content.to_lowercase();

    // Check it's actually a reg file.
    if !lower.starts_with("windows registry editor") && !lower.starts_with("regedit4") {
        return;
    }

    // Run key persistence.
    if lower.contains("\\currentversion\\run]") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 20,
            description: "Registry file adds entries to the Run key — establishes persistence to auto-execute on login.".into(),
            technical_detail: Some("HKCU or HKLM\\...\\CurrentVersion\\Run modification".into()),
        });
    }

    // Disabling security features.
    if lower.contains("disableantispy")
        || lower.contains("disableantivirus")
        || lower.contains("disablerealtimemonitoring")
    {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Critical,
            weight: 35,
            description: "Registry file disables Windows security features — a critical indicator of malicious intent.".into(),
            technical_detail: Some("Security feature disable flags found in .reg file".into()),
        });
    }

    // Image File Execution Options (debugger hijacking).
    if lower.contains("image file execution options") {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 25,
            description: "Registry file modifies Image File Execution Options — a technique to hijack process execution or block security software.".into(),
            technical_detail: Some("IFEO (Image File Execution Options) modification".into()),
        });
    }
}

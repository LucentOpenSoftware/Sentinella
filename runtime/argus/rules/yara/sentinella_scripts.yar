/*
    Sentinella ARGUS Intelligence Pack — Script Abuse Detection
    Category: script_abuse
    Version: 2024.1
    Author: Sentinella
    License: GPL-2.0

    Detects malicious scripting patterns: PowerShell abuse, JavaScript
    obfuscation, batch file droppers, and Living-Off-The-Land techniques.
*/

rule powershell_encoded_command {
    meta:
        description = "ARGUS detected PowerShell encoded command execution — a technique commonly used to conceal malicious payloads."
        severity = "high"
        weight = 22
        category = "script_abuse"
        author = "Sentinella"

    strings:
        $ps1 = "powershell" ascii nocase
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $enc3 = "-ec " ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase

    condition:
        $ps1 and (any of ($enc*) or ($bypass and $hidden))
}

rule powershell_download_execute {
    meta:
        description = "ARGUS identified a PowerShell download-and-execute pattern — a common malware delivery mechanism."
        severity = "high"
        weight = 25
        category = "script_abuse"
        author = "Sentinella"

    strings:
        $iwr = "Invoke-WebRequest" ascii nocase
        $irm = "Invoke-RestMethod" ascii nocase
        $wc = "Net.WebClient" ascii nocase
        $dl1 = "DownloadString" ascii nocase
        $dl2 = "DownloadFile" ascii nocase
        $iex = "Invoke-Expression" ascii nocase
        $iex2 = "IEX(" ascii nocase
        $iex3 = "IEX (" ascii nocase

    condition:
        any of ($iwr, $irm, $wc, $dl1, $dl2) and any of ($iex, $iex2, $iex3)
}

rule amsi_bypass_attempt {
    meta:
        description = "ARGUS detected an attempt to bypass Windows AMSI (Anti-Malware Scan Interface) — a strong indicator of malicious intent."
        severity = "critical"
        weight = 35
        category = "script_abuse"
        author = "Sentinella"

    strings:
        $amsi1 = "AmsiScanBuffer" ascii nocase
        $amsi2 = "AmsiUtils" ascii nocase
        $amsi3 = "amsiInitFailed" ascii nocase
        $amsi4 = "AmsiContext" ascii nocase
        $patch = "VirtualProtect" ascii nocase

    condition:
        2 of ($amsi*) or (any of ($amsi*) and $patch)
}

rule defender_tampering {
    meta:
        description = "ARGUS identified an attempt to disable or tamper with Windows Defender — a critical security evasion technique."
        severity = "critical"
        weight = 35
        category = "script_abuse"
        author = "Sentinella"

    strings:
        $disable1 = "DisableRealtimeMonitoring" ascii nocase
        $disable2 = "Set-MpPreference" ascii nocase
        $exclude = "Add-MpPreference" ascii nocase
        $excl_path = "ExclusionPath" ascii nocase
        $tamper_disable = "TamperProtection" ascii nocase
        $tamper_set = "Set-MpPreference" ascii nocase

    condition:
        ($disable1 and $disable2) or
        ($exclude and $excl_path) or
        ($tamper_disable and $tamper_set)
}

rule certutil_abuse {
    meta:
        description = "ARGUS detected certutil.exe abuse for file download or payload decoding — a Living-Off-The-Land technique."
        severity = "high"
        weight = 20
        category = "script_abuse"
        author = "Sentinella"

    strings:
        $certutil = "certutil" ascii nocase
        $urlcache = "-urlcache" ascii nocase
        $decode = "-decode" ascii nocase
        $split = "-split" ascii nocase

    condition:
        $certutil and any of ($urlcache, $decode, $split)
}

rule obfuscated_javascript_eval {
    meta:
        description = "ARGUS identified heavily obfuscated JavaScript with dynamic code execution — consistent with malware payload delivery."
        severity = "medium"
        weight = 15
        category = "script_abuse"
        author = "Sentinella"

    strings:
        $eval = "eval(" ascii
        $func = "Function(" ascii
        $atob = "atob(" ascii
        $fcc = "fromCharCode" ascii
        $unescape = "unescape(" ascii

    condition:
        ($eval and $atob) or
        ($eval and $fcc and #fcc > 3) or
        ($func and $atob) or
        ($unescape and ($eval or $fcc)) or
        (#eval > 3)
}

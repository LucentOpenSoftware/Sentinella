/*
    Sentinella ARGUS Intelligence Pack — Suspicious Updater Detection
    Category: suspicious_updater
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects fake updaters, trojanized update mechanisms, and
    malware disguised as software updates.
*/

rule fake_updater_with_download {
    meta:
        description = "ARGUS detected a small executable named as an updater that downloads and executes remote content — consistent with fake updater malware campaigns."
        severity = "high"
        weight = 20
        category = "suspicious_updater"
        author = "Sentinella"
    strings:
        $name1 = "updater" ascii nocase
        $name2 = "update" ascii nocase
        $dl1 = "URLDownloadToFileA" ascii
        $dl2 = "URLDownloadToFileW" ascii
        $dl3 = "InternetOpenUrlA" ascii
        // Execution via less common APIs (not CreateProcessW which every app uses).
        $exec1 = "WinExec" ascii
        $exec2 = "ShellExecuteA" ascii
        // Anti-analysis indicators that real updaters don't need.
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "SleepEx" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5242880 and
        any of ($name*) and
        any of ($dl*) and
        (any of ($exec*) or any of ($anti*))
}

rule fake_updater_small_unsigned {
    meta:
        description = "ARGUS detected a small executable named as an updater with suspicious behavior — small fake updaters are a common malware delivery mechanism."
        severity = "medium"
        weight = 12
        category = "suspicious_updater"
        author = "Sentinella"
    strings:
        $name1 = "updater" ascii nocase
        $name2 = "patcher" ascii nocase
        $http = "http" ascii nocase
        $temp = "%TEMP%" ascii
        // Require suspicious indicators — legitimate updaters exist and use HTTP + temp paths.
        $susp1 = "IsDebuggerPresent" ascii
        $susp2 = "VirtualProtect" ascii
        $susp3 = "discord" ascii nocase
        $susp4 = "webhook" ascii nocase
        $susp5 = "Login Data" ascii
        $susp6 = "token" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2097152 and
        any of ($name*) and
        ($http or $temp) and
        any of ($susp*)
}

rule supply_chain_dll_sideload {
    meta:
        description = "ARGUS detected a DLL in a location suggesting DLL sideloading — a supply chain attack technique where a malicious DLL is placed next to a legitimate executable."
        severity = "high"
        weight = 22
        category = "suspicious_updater"
        author = "Sentinella"
    strings:
        $mz = { 4D 5A }
        $export = "DllMain" ascii
        $version = "version.dll" ascii nocase
        $winhttp = "winhttp.dll" ascii nocase
        $crypt32 = "crypt32.dll" ascii nocase
        $profapi = "profapi.dll" ascii nocase
    condition:
        $mz at 0 and $export and
        any of ($version, $winhttp, $crypt32, $profapi)
}

rule trojanized_installer_persistence {
    meta:
        description = "ARGUS detected an installer that writes to autorun registry keys and makes network connections — may be a trojanized installer establishing a backdoor."
        severity = "high"
        weight = 20
        category = "suspicious_updater"
        author = "Sentinella"
    strings:
        // Real persistence — must be actual registry Run key write, not just any string.
        $persist1 = "\\CurrentVersion\\Run" ascii nocase
        // Real network — exclude WSAStartup (every network app), require actual HTTP/connection APIs.
        $net1 = "InternetOpenA" ascii
        $net2 = "WinHttpConnect" ascii
        $net3 = "HttpOpenRequestA" ascii
        // Installer indicators.
        $install = "install" ascii nocase
        $setup = "setup" ascii nocase
        // Must also write to disk (dropper behavior).
        $write1 = "WriteFile" ascii
        $write2 = "CopyFileW" ascii
    condition:
        uint16(0) == 0x5A4D and
        $persist1 and
        any of ($net*) and
        any of ($install, $setup) and
        any of ($write*)
}

/*
    Sentinella ARGUS Intelligence Pack — Generic Trojan Behaviors
    Category: trojan
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0
    Source: original_heuristic — behaviors from public MITRE ATT&CK T1055, T1036, T1497
*/

rule trojan_download_execute_chain {
    meta:
        description = "ARGUS detected a download-and-execute chain — the executable downloads remote content and launches it, a classic trojan delivery mechanism."
        severity = "high"
        weight = 28
        category = "trojan"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $dl1 = "URLDownloadToFileA" ascii
        $dl2 = "URLDownloadToFileW" ascii
        $dl3 = "InternetReadFile" ascii
        $write = "WriteFile" ascii
        $exec1 = "CreateProcessW" ascii
        $exec2 = "ShellExecuteW" ascii
        $exec3 = "WinExec" ascii
        $temp = "GetTempPathW" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($dl*) and $write and any of ($exec*) and $temp
}

rule trojan_self_copy_persistence {
    meta:
        description = "ARGUS detected an executable that copies itself to a persistent location and registers for auto-start — establishing a trojan foothold."
        severity = "high"
        weight = 25
        category = "trojan"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $self = "GetModuleFileNameW" ascii
        $copy = "CopyFileW" ascii
        $appdata = "APPDATA" ascii
        $persist1 = "\\CurrentVersion\\Run" ascii nocase
        $persist2 = "RegSetValueExW" ascii
    condition:
        uint16(0) == 0x5A4D and
        $self and $copy and $appdata and
        any of ($persist*)
}

rule trojan_system_discovery {
    meta:
        description = "ARGUS detected systematic system information gathering combined with network capabilities and suspicious behavior — consistent with trojan reconnaissance before C2 check-in."
        severity = "medium"
        weight = 12
        category = "trojan"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $info1 = "GetComputerNameW" ascii
        $info2 = "GetUserNameW" ascii
        $info3 = "GetVersionExW" ascii
        $info4 = "GetSystemInfo" ascii
        $net1 = "InternetOpenA" ascii
        $net2 = "WSAStartup" ascii
        $net3 = "WinHttpOpen" ascii
        // Require suspicious indicators — legitimate apps gather system info + use network too.
        $susp1 = "IsDebuggerPresent" ascii
        $susp2 = "cmd.exe" ascii nocase
        $susp3 = "\\CurrentVersion\\Run" ascii nocase
        $susp4 = "VirtualAlloc" ascii
        $susp5 = "WriteProcessMemory" ascii
    condition:
        uint16(0) == 0x5A4D and
        all of ($info*) and any of ($net*) and
        any of ($susp*)
}

rule trojan_hidden_window_execution {
    meta:
        description = "ARGUS detected process creation with a hidden window — the executable launches child processes invisibly, a common trojan stealth technique."
        severity = "medium"
        weight = 15
        category = "trojan"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $create = "CreateProcessW" ascii
        $startup = "STARTUPINFOW" ascii
        $hidden = { 00 00 00 00 01 00 00 00 }  // dwFlags=1, wShowWindow=0 (SW_HIDE)
        $shell = "cmd.exe" ascii nocase
        $ps = "powershell" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $create and ($startup or $hidden) and
        any of ($shell, $ps)
}

rule trojan_mutex_single_instance {
    meta:
        description = "ARGUS detected mutex creation for single-instance enforcement combined with persistence — a technique to prevent duplicate infections."
        severity = "low"
        weight = 8
        category = "trojan"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $mutex1 = "CreateMutexW" ascii
        $mutex2 = "CreateMutexA" ascii
        $persist = "\\CurrentVersion\\Run" ascii nocase
        $copy = "CopyFileW" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($mutex*) and $persist and $copy
}

rule trojan_spyware_combo {
    meta:
        description = "ARGUS detected a combination of keyboard hooking, screenshot capture, and network transmission — consistent with comprehensive spyware."
        severity = "critical"
        weight = 35
        category = "trojan"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $hook = "SetWindowsHookExW" ascii
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "GetKeyState" ascii
        $ss1 = "BitBlt" ascii
        $ss2 = "GetDesktopWindow" ascii
        $ss3 = "CreateCompatibleBitmap" ascii
        $ws = "WSAStartup" ascii
        $inet = "InternetOpenA" ascii
        $winhttp = "WinHttpOpen" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($hook and any of ($key*)) and
        2 of ($ss*) and
        any of ($ws, $inet, $winhttp)
}

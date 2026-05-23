/*
    Sentinella ARGUS Intelligence Pack — Backdoor & RAT Detection
    Category: backdoor
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0
    Source: original_heuristic — behaviors from public MITRE ATT&CK T1571, T1095, T1573
*/

rule backdoor_remote_shell {
    meta:
        description = "ARGUS detected a remote shell capability — accepts commands over a network socket and executes them locally."
        severity = "critical"
        weight = 35
        category = "backdoor"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $sock1 = "WSAStartup" ascii
        $sock2 = "connect" ascii
        $recv = "recv" ascii
        $exec1 = "CreateProcessW" ascii
        $exec2 = "cmd.exe" ascii nocase
        $exec3 = "cmd /c" ascii nocase
        $pipe1 = "CreatePipe" ascii
        $pipe2 = "PeekNamedPipe" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($sock*) and $recv and
        any of ($exec*) and any of ($pipe*)
}

rule backdoor_persistence_beacon {
    meta:
        description = "ARGUS detected an executable combining system persistence with periodic network beaconing and command execution — consistent with a persistent backdoor."
        severity = "critical"
        weight = 30
        category = "backdoor"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $persist1 = "\\CurrentVersion\\Run" ascii nocase
        $persist2 = "schtasks" ascii nocase
        $net1 = "InternetOpenA" ascii
        $net2 = "WinHttpConnect" ascii
        $sleep = "Sleep" ascii
        $timer = "SetTimer" ascii
        // Require command execution or evasion — normal installers persist + use network + sleep too.
        $exec1 = "cmd.exe" ascii nocase
        $exec2 = "powershell" ascii nocase
        $exec3 = "CreateProcessW" ascii
        $evasion1 = "IsDebuggerPresent" ascii
        $evasion2 = "VirtualProtect" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($persist*) and any of ($net*) and any of ($sleep, $timer) and
        (any of ($exec*) or any of ($evasion*))
}

rule backdoor_reverse_connect {
    meta:
        description = "ARGUS detected reverse-connection capability — the executable initiates outbound connections to a remote host, typical of reverse shells and RATs."
        severity = "high"
        weight = 28
        category = "backdoor"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $ws = "WSAStartup" ascii
        $connect = "connect" ascii
        $send = "send" ascii
        $recv = "recv" ascii
        $shell = "cmd.exe" ascii nocase
        $ps = "powershell" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $ws and $connect and $send and $recv and
        any of ($shell, $ps)
}

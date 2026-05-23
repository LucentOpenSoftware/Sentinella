/*
    Sentinella ARGUS Intelligence Pack — Evasion Techniques
    Category: evasion
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects anti-analysis, sandbox detection, and security tool
    evasion techniques used by modern malware.
*/

rule evasion_sandbox_detection {
    meta:
        description = "ARGUS detected sandbox/VM detection checks — malware may refuse to execute in analysis environments to avoid detection."
        severity = "medium"
        weight = 15
        category = "evasion"
        author = "Sentinella"
    strings:
        $vm1 = "VMware" ascii nocase
        $vm2 = "VirtualBox" ascii nocase
        $vm3 = "VBOX" ascii
        $vm4 = "Hyper-V" ascii nocase
        $vm5 = "SbieDll" ascii
        $vm6 = "sbiedll.dll" ascii nocase
        $check1 = "GetModuleHandleA" ascii
        $check2 = "IsProcessorFeaturePresent" ascii
    condition:
        uint16(0) == 0x5A4D and
        3 of ($vm*) and
        any of ($check*)
}

rule evasion_delayed_execution {
    meta:
        description = "ARGUS detected extended sleep combined with memory allocation and execution — a technique to outlast sandbox analysis timeouts before deploying the payload."
        severity = "medium"
        weight = 10
        category = "evasion"
        author = "Sentinella"
    strings:
        $sleep1 = "Sleep" ascii
        $sleep2 = "NtDelayExecution" ascii
        $sleep3 = "WaitForSingleObject" ascii
        $large_delay = { B8 80 96 98 00 }  // 10,000,000 ms = ~2.7 hours
        $alloc = "VirtualAlloc" ascii
        // Require actual evasion indicators — Sleep + VirtualAlloc is too common alone.
        $exec1 = "VirtualProtect" ascii
        $exec2 = "WriteProcessMemory" ascii
        $exec3 = "CreateRemoteThread" ascii
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "NtQueryInformationProcess" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($sleep*) and
        ($large_delay or ($alloc and any of ($exec*)) or ($alloc and any of ($anti*)))
}

rule evasion_ntdll_unhooking {
    meta:
        description = "ARGUS detected ntdll.dll unhooking — removing security hooks placed by EDR/AV products to monitor system calls."
        severity = "critical"
        weight = 30
        category = "evasion"
        author = "Sentinella"
    strings:
        $ntdll = "ntdll.dll" ascii nocase
        $map = "MapViewOfFile" ascii
        $protect = "VirtualProtect" ascii
        $write = "WriteProcessMemory" ascii
        $memcpy = "memcpy" ascii
    condition:
        uint16(0) == 0x5A4D and
        $ntdll and $protect and
        any of ($map, $write, $memcpy)
}

rule evasion_ppid_spoofing {
    meta:
        description = "ARGUS detected parent process ID spoofing — a technique to make malicious processes appear to be spawned by legitimate system processes."
        severity = "high"
        weight = 25
        category = "evasion"
        author = "Sentinella"
    strings:
        $attr = "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" ascii
        $init = "InitializeProcThreadAttributeList" ascii
        $update = "UpdateProcThreadAttribute" ascii
        $create = "CreateProcessW" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($attr or ($init and $update)) and $create
}

rule evasion_timestomping {
    meta:
        description = "ARGUS detected file timestamp manipulation combined with suspicious behavior — modifying creation/modification times to avoid forensic timeline analysis."
        severity = "medium"
        weight = 10
        category = "evasion"
        author = "Sentinella"
    strings:
        $set1 = "SetFileTime" ascii
        $set2 = "NtSetInformationFile" ascii
        $get = "GetFileTime" ascii
        $create = "CreateFileW" ascii
        // Require additional suspicious context — many legitimate apps use SetFileTime.
        $susp1 = "IsDebuggerPresent" ascii
        $susp2 = "\\CurrentVersion\\Run" ascii nocase
        $susp3 = "cmd.exe" ascii nocase
        $susp4 = "VirtualProtect" ascii
        $susp5 = "WriteProcessMemory" ascii
        $susp6 = "CreateRemoteThread" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($set*) and $get and $create and
        any of ($susp*)
}

rule evasion_disable_event_logging {
    meta:
        description = "ARGUS detected Windows event log tampering — clearing or disabling event logs to destroy forensic evidence."
        severity = "critical"
        weight = 30
        category = "evasion"
        author = "Sentinella"
    strings:
        $clear1 = "ClearEventLogW" ascii
        $clear2 = "wevtutil" ascii nocase
        $clear3 = "clear-log" ascii nocase
        $evt1 = "Security" ascii
        $evt2 = "System" ascii
        $evt3 = "Application" ascii
    condition:
        any of ($clear*) and 2 of ($evt*)
}

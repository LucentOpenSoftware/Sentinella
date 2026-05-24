/*
    Sentinella ARGUS Intelligence Pack — Defense Evasion 2026
    Category: evasion
    Version: 2026.1
    Author: Sentinella
    License: GPL-2.0

    Detects modern defense evasion techniques prevalent in 2025-2026 threat
    landscape including AMSI bypass, ETW patching, Defender exclusion abuse,
    direct syscalls, Heaven's Gate transitions, and API unhooking.
*/

rule evasion_amsi_bypass_memory_patch {
    meta:
        description = "ARGUS detected AMSI bypass via memory patching — attackers overwrite AmsiScanBuffer or AmsiOpenSession in memory to disable antimalware scanning of scripts and .NET assemblies."
        severity = "critical"
        weight = 30
        category = "evasion"
        author = "Sentinella"

    strings:
        // AMSI function targets
        $amsi1 = "AmsiScanBuffer" ascii
        $amsi2 = "AmsiOpenSession" ascii
        $amsi3 = "AmsiInitialize" ascii
        $amsi4 = "amsi.dll" ascii nocase

        // Patching infrastructure
        $patch1 = "VirtualProtect" ascii
        $patch2 = "WriteProcessMemory" ascii
        $patch3 = "Marshal.Copy" ascii
        $patch4 = "RtlMoveMemory" ascii

        // Known AMSI patch byte sequences
        // mov eax, 0x80070057 (E_INVALIDARG) + ret
        $bytes1 = { B8 57 00 07 80 C3 }
        // xor eax, eax + ret (force S_OK)
        $bytes2 = { 31 C0 C3 }
        // ret (single byte patch)
        $bytes3 = { C2 18 00 }

        // PowerShell AMSI bypass strings
        $ps1 = "System.Management.Automation.AmsiUtils" ascii
        $ps2 = "amsiInitFailed" ascii
        $ps3 = "AmsiContext" ascii

    condition:
        (any of ($amsi*) and any of ($patch*)) or
        any of ($bytes*) and any of ($amsi*) or
        (any of ($ps*) and any of ($patch*))
}

rule evasion_etw_patching {
    meta:
        description = "ARGUS detected ETW (Event Tracing for Windows) patching — attackers disable ETW providers to blind security products that rely on telemetry events for detection."
        severity = "critical"
        weight = 28
        category = "evasion"
        author = "Sentinella"

    strings:
        // ETW function targets
        $etw1 = "EtwEventWrite" ascii
        $etw2 = "NtTraceEvent" ascii
        $etw3 = "NtTraceControl" ascii
        $etw4 = "EtwNotificationRegister" ascii
        $etw5 = "EtwEventRegister" ascii

        // Patching / hooking
        $patch1 = "VirtualProtect" ascii
        $patch2 = "WriteProcessMemory" ascii
        $patch3 = "GetProcAddress" ascii
        $patch4 = "GetModuleHandleA" ascii

        // Known ETW patch: ret (0xC3) written to EtwEventWrite
        $ret_patch = { C3 } // single ret opcode (matched contextually)

        // .NET ETW bypass
        $dotnet1 = "Reflection.Assembly" ascii
        $dotnet2 = "System.Diagnostics.Tracing" ascii
        $dotnet3 = "EventSource" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($etw*) and any of ($patch*) or
        (2 of ($etw*) and any of ($dotnet*))
}

rule evasion_defender_exclusion_abuse {
    meta:
        description = "ARGUS detected Windows Defender exclusion abuse — attackers add path, process, or extension exclusions to allow malware to operate without being scanned."
        severity = "high"
        weight = 25
        category = "evasion"
        author = "Sentinella"

    strings:
        // PowerShell Defender exclusion commands
        $ps1 = "Add-MpPreference" ascii nocase
        $ps2 = "Set-MpPreference" ascii nocase
        $ps3 = "-ExclusionPath" ascii nocase
        $ps4 = "-ExclusionProcess" ascii nocase
        $ps5 = "-ExclusionExtension" ascii nocase

        // Registry-based exclusions
        $reg1 = "Windows Defender\\Exclusions\\Paths" ascii nocase
        $reg2 = "Windows Defender\\Exclusions\\Extensions" ascii nocase
        $reg3 = "Windows Defender\\Exclusions\\Processes" ascii nocase

        // Disable Defender features via registry/policy
        $disable1 = "DisableRealtimeMonitoring" ascii nocase
        $disable2 = "DisableBehaviorMonitoring" ascii nocase
        $disable3 = "DisableOnAccessProtection" ascii nocase
        $disable4 = "DisableIOAVProtection" ascii nocase
        $disable5 = "DisableAntiSpyware" ascii nocase

    condition:
        (any of ($ps1, $ps2) and any of ($ps3, $ps4, $ps5)) or
        2 of ($reg*) or
        2 of ($disable*)
}

rule evasion_timestamp_stomping_2026 {
    meta:
        description = "ARGUS detected advanced timestamp stomping — manipulating file timestamps via direct NT API calls to evade forensic timeline analysis and file system monitoring."
        severity = "high"
        weight = 20
        category = "evasion"
        author = "Sentinella"

    strings:
        // Timestamp manipulation APIs
        $api1 = "SetFileTime" ascii
        $api2 = "NtSetInformationFile" ascii
        $api3 = "ZwSetInformationFile" ascii
        $api4 = "SetFileInformationByHandle" ascii
        $api5 = "FileBasicInformation" ascii

        // Evidence of deliberate timestamp cloning
        $clone1 = "GetFileTime" ascii
        $clone2 = "NtQueryInformationFile" ascii
        $clone3 = "FILETIME" ascii

        // Suspicious context: combine with other evasion/malware indicators
        $susp1 = "VirtualAlloc" ascii
        $susp2 = "CreateRemoteThread" ascii
        $susp3 = "NtCreateFile" ascii
        $susp4 = "\\CurrentVersion\\Run" ascii nocase
        $susp5 = "DeleteFileW" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($api*) and any of ($clone*) and
        2 of ($susp*)
}

rule evasion_process_hollowing {
    meta:
        description = "ARGUS detected process hollowing indicators — a technique where a legitimate process is started suspended, its memory is unmapped, and malicious code is injected in its place."
        severity = "critical"
        weight = 30
        category = "evasion"
        author = "Sentinella"

    strings:
        // Process creation in suspended state
        $create1 = "CreateProcessW" ascii
        $create2 = "CreateProcessA" ascii
        $create3 = "CREATE_SUSPENDED" ascii
        $create4 = { 04 00 00 00 } // CREATE_SUSPENDED flag value

        // Memory manipulation for hollowing
        $hollow1 = "NtUnmapViewOfSection" ascii
        $hollow2 = "ZwUnmapViewOfSection" ascii
        $hollow3 = "NtWriteVirtualMemory" ascii
        $hollow4 = "WriteProcessMemory" ascii
        $hollow5 = "VirtualAllocEx" ascii

        // Thread context manipulation to redirect execution
        $ctx1 = "SetThreadContext" ascii
        $ctx2 = "NtSetContextThread" ascii
        $ctx3 = "GetThreadContext" ascii
        $ctx4 = "ResumeThread" ascii
        $ctx5 = "NtResumeThread" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($create*) and
        any of ($hollow*) and
        any of ($ctx*)
}

rule evasion_direct_syscalls {
    meta:
        description = "ARGUS detected direct syscall invocation patterns — bypassing ntdll.dll to make system calls directly, evading userland hooks placed by EDR/AV products."
        severity = "critical"
        weight = 28
        category = "evasion"
        author = "Sentinella"

    strings:
        // Syscall stub patterns (x64)
        // mov r10, rcx; mov eax, SSN; syscall
        $stub_x64 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 }

        // Syscall stub patterns (x86)
        // mov eax, SSN; mov edx, esp; sysenter
        $stub_x86 = { B8 ?? ?? 00 00 8B D4 0F 34 }

        // Known syscall resolution frameworks
        $framework1 = "NtAllocateVirtualMemory" ascii
        $framework2 = "NtProtectVirtualMemory" ascii
        $framework3 = "NtCreateThreadEx" ascii
        $framework4 = "NtWriteVirtualMemory" ascii
        $framework5 = "NtQueueApcThread" ascii
        $framework6 = "NtMapViewOfSection" ascii

        // Syscall number resolution
        $resolve1 = "syscall" ascii
        $resolve2 = "SSN" ascii
        $resolve3 = "SyscallNumber" ascii
        $resolve4 = "GetSyscallNumber" ascii

        // Common direct syscall tools
        $tool1 = "SysWhispers" ascii
        $tool2 = "HellsGate" ascii
        $tool3 = "TartarusGate" ascii
        $tool4 = "FreshyCalls" ascii
        $tool5 = "SyscallJmp" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            ($stub_x64 and 2 of ($framework*)) or
            ($stub_x86 and 2 of ($framework*)) or
            any of ($tool*) or
            (any of ($resolve*) and 3 of ($framework*))
        )
}

rule evasion_heavens_gate {
    meta:
        description = "ARGUS detected Heaven's Gate technique — transitioning from 32-bit to 64-bit execution mode to evade 32-bit security hooks and analysis tools."
        severity = "critical"
        weight = 30
        category = "evasion"
        author = "Sentinella"

    strings:
        // Far call/jump to 0x33 segment selector (switch to 64-bit mode)
        $gate1 = { EA ?? ?? ?? ?? 33 00 }     // jmp far 0x33:addr
        $gate2 = { 9A ?? ?? ?? ?? 33 00 }     // call far 0x33:addr
        $gate3 = { 6A 33 E8 }                  // push 0x33; call (retf variant)
        $gate4 = { 6A 33 CB }                  // push 0x33; retf

        // Return to 32-bit mode via 0x23 selector
        $ret32_1 = { 6A 23 CB }               // push 0x23; retf
        $ret32_2 = { EA ?? ?? ?? ?? 23 00 }   // jmp far 0x23:addr

        // WoW64 transition indicators
        $wow1 = "wow64cpu.dll" ascii nocase
        $wow2 = "wow64win.dll" ascii nocase
        $wow3 = "Wow64Transition" ascii
        $wow4 = "NtWow64" ascii

        // Context: should be PE32 (not PE32+) doing 64-bit things
        $pe32 = { 50 45 00 00 4C 01 } // PE signature + i386 machine

    condition:
        $pe32 and
        (any of ($gate*) and any of ($ret32_*)) or
        ($pe32 and any of ($gate*) and any of ($wow*))
}

rule evasion_api_unhooking_ntdll_reload {
    meta:
        description = "ARGUS detected API unhooking via ntdll.dll reload — loading a clean copy of ntdll from disk or KnownDLLs to overwrite EDR-hooked functions and restore original syscall stubs."
        severity = "critical"
        weight = 28
        category = "evasion"
        author = "Sentinella"

    strings:
        // ntdll.dll path references
        $ntdll1 = "ntdll.dll" ascii nocase
        $ntdll2 = "\\System32\\ntdll.dll" ascii nocase
        $ntdll3 = "\\KnownDlls\\ntdll.dll" ascii nocase
        $ntdll4 = "\\SystemRoot\\System32\\ntdll.dll" ascii nocase

        // Mapping / reading fresh copy
        $map1 = "CreateFileW" ascii
        $map2 = "CreateFileMappingW" ascii
        $map3 = "MapViewOfFile" ascii
        $map4 = "NtOpenSection" ascii
        $map5 = "NtMapViewOfSection" ascii

        // .text section overwrite
        $overwrite1 = "VirtualProtect" ascii
        $overwrite2 = "memcpy" ascii
        $overwrite3 = "RtlCopyMemory" ascii
        $overwrite4 = ".text" ascii

        // Module enumeration for hook removal
        $enum1 = "GetModuleHandleA" ascii
        $enum2 = "GetModuleInformation" ascii
        $enum3 = "NtQueryVirtualMemory" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($ntdll*) and
        2 of ($map*) and
        any of ($overwrite*)
}

rule evasion_smart_applocker_bypass {
    meta:
        description = "ARGUS detected AppLocker/WDAC bypass indicators — using trusted Microsoft binaries or alternate execution methods to circumvent application whitelisting policies."
        severity = "high"
        weight = 22
        category = "evasion"
        author = "Sentinella"

    strings:
        // Known AppLocker bypass LOLBins
        $lol1 = "MSBuild.exe" ascii nocase
        $lol2 = "InstallUtil.exe" ascii nocase
        $lol3 = "RegAsm.exe" ascii nocase
        $lol4 = "RegSvcs.exe" ascii nocase
        $lol5 = "cmstp.exe" ascii nocase
        $lol6 = "msiexec.exe" ascii nocase
        $lol7 = "presentationhost.exe" ascii nocase

        // Bypass context indicators
        $ctx1 = "/U " ascii nocase        // InstallUtil uninstall mode
        $ctx2 = "/s " ascii nocase        // cmstp silent
        $ctx3 = "/q " ascii nocase        // msiexec quiet
        $ctx4 = "/unsafe" ascii nocase
        $ctx5 = "InvokeMethod" ascii
        $ctx6 = "DotNetToJScript" ascii

        // Alternate execution streams
        $alt1 = "Assembly.Load" ascii
        $alt2 = "Reflection.Assembly" ascii
        $alt3 = "[System.Reflection" ascii

    condition:
        (2 of ($lol*) and any of ($ctx*)) or
        (any of ($lol*) and any of ($alt*)) or
        ($lol6 and $ctx3 and any of ($alt*))
}

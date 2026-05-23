/*
    Sentinella ARGUS Intelligence Pack — .NET Obfuscation & Malware
    Category: dotnet_malware
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects obfuscated .NET executables and common .NET malware patterns.
*/

rule dotnet_confuserex_obfuscation {
    meta:
        description = "ARGUS detected ConfuserEx obfuscation in a .NET executable — an open-source obfuscator heavily abused by malware authors."
        severity = "high"
        weight = 22
        category = "dotnet_malware"
        author = "Sentinella"
    strings:
        $dotnet = "_CorExeMain" ascii
        $confuser1 = "ConfuserEx" ascii
        $confuser2 = "Confuser.Core" ascii
        $confuser3 = { 43 6F 6E 66 75 73 65 72 }
    condition:
        uint16(0) == 0x5A4D and $dotnet and any of ($confuser*)
}

rule dotnet_reactor_obfuscation {
    meta:
        description = "ARGUS detected .NET Reactor protection — a commercial obfuscator used to protect both legitimate and malicious .NET applications."
        severity = "medium"
        weight = 15
        category = "dotnet_malware"
        author = "Sentinella"
    strings:
        $dotnet = "_CorExeMain" ascii
        $reactor1 = ".NET Reactor" ascii
        $reactor2 = "ReactorHelper" ascii
    condition:
        uint16(0) == 0x5A4D and $dotnet and any of ($reactor*)
}

rule dotnet_assembly_load_reflection {
    meta:
        description = "ARGUS detected a .NET executable that loads assemblies via reflection — a fileless execution technique used to load malware from memory."
        severity = "high"
        weight = 20
        category = "dotnet_malware"
        author = "Sentinella"
    strings:
        $dotnet = "_CorExeMain" ascii
        $load1 = "Assembly.Load" ascii
        $load2 = "Assembly.LoadFrom" ascii
        $load3 = "Assembly.LoadFile" ascii
        $invoke = "Invoke" ascii
        $frombase64 = "FromBase64String" ascii
    condition:
        uint16(0) == 0x5A4D and $dotnet and
        any of ($load*) and ($invoke or $frombase64)
}

rule dotnet_process_injection {
    meta:
        description = "ARGUS detected .NET code performing process injection — loading native APIs for memory manipulation across process boundaries."
        severity = "critical"
        weight = 30
        category = "dotnet_malware"
        author = "Sentinella"
    strings:
        $dotnet = "_CorExeMain" ascii
        $p1 = "VirtualAllocEx" ascii
        $p2 = "WriteProcessMemory" ascii
        $p3 = "CreateRemoteThread" ascii
        $p4 = "NtUnmapViewOfSection" ascii
        $dll = "DllImport" ascii
    condition:
        uint16(0) == 0x5A4D and $dotnet and $dll and
        2 of ($p1, $p2, $p3, $p4)
}

rule dotnet_credential_stealer {
    meta:
        description = "ARGUS detected a .NET executable accessing multiple credential storage locations — consistent with a .NET-based information stealer."
        severity = "high"
        weight = 28
        category = "dotnet_malware"
        author = "Sentinella"
    strings:
        $dotnet = "_CorExeMain" ascii
        $chrome = "Chrome" ascii
        $firefox = "Firefox" ascii
        $edge = "Edge" ascii
        $login = "Login Data" ascii
        $cookies = "Cookies" ascii
        $discord = "discord" ascii nocase
        $telegram = "Telegram" ascii
    condition:
        uint16(0) == 0x5A4D and $dotnet and
        3 of ($chrome, $firefox, $edge, $login, $cookies, $discord, $telegram)
}

rule dotnet_heavily_obfuscated {
    meta:
        description = "ARGUS detected a .NET executable with characteristics of heavy obfuscation — non-standard metadata, encrypted resources, or anti-decompilation techniques."
        severity = "medium"
        weight = 15
        category = "dotnet_malware"
        author = "Sentinella"
    strings:
        $dotnet = "_CorExeMain" ascii
        // Common obfuscation artifacts.
        $obf1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $obf2 = "GetManifestResourceStream" ascii
        $obf3 = "GZipStream" ascii
        $obf4 = "DeflateStream" ascii
        $obf5 = "SymmetricAlgorithm" ascii
    condition:
        uint16(0) == 0x5A4D and $dotnet and
        $obf1 and 2 of ($obf2, $obf3, $obf4, $obf5)
}

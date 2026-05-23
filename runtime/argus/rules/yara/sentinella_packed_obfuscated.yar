/*
    Sentinella ARGUS Intelligence Pack — Packed/Obfuscated Generic Detection
    Category: packed_obfuscated
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0
    Source: original_heuristic — behaviors from public analysis of packing techniques
*/

rule packed_nuitka_compiled {
    meta:
        description = "ARGUS detected a Nuitka-compiled Python executable — while Nuitka is a legitimate compiler, it is increasingly used to package Python stealers into single executables."
        severity = "medium"
        weight = 10
        category = "packed_obfuscated"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $nuitka1 = "Nuitka" ascii
        $nuitka2 = "nuitka" ascii nocase
        $python = "python" ascii nocase
        $onefile = "__compiled__" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($nuitka*) and ($python or $onefile)
}

rule packed_high_entropy_small_imports {
    meta:
        description = "ARGUS detected a small PE with minimal import table that resolves functions at runtime — indicators of custom packing."
        severity = "low"
        weight = 6
        category = "packed_obfuscated"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $mz = { 4D 5A }
        $load = "LoadLibraryA" ascii
        $get = "GetProcAddress" ascii
        $kernel = "KERNEL32.dll" ascii nocase
    condition:
        $mz at 0 and
        $load and $get and
        // Truly minimal imports — only KERNEL32 referenced once.
        #kernel == 1 and
        filesize > 100000 and filesize < 2097152
}

rule packed_bat_to_exe {
    meta:
        description = "ARGUS detected a batch-to-EXE compiled script — commonly used to disguise batch file malware as a native executable."
        severity = "medium"
        weight = 12
        category = "packed_obfuscated"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $bat2exe1 = "Bat To Exe" ascii nocase
        $bat2exe2 = "bat2exe" ascii nocase
        $iexpress = "IExpress" ascii
        $cmd = "@echo off" ascii nocase
        $batch = ".bat" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($bat2exe*) or ($iexpress and $cmd) or ($cmd and $batch))
}

rule packed_go_binary_stealer {
    meta:
        description = "ARGUS detected a Go-compiled executable with credential harvesting capabilities — Go-based stealers are increasingly common due to easy cross-compilation."
        severity = "high"
        weight = 22
        category = "packed_obfuscated"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $go1 = "runtime.main" ascii
        $go2 = "runtime.goexit" ascii
        $go3 = "Go build ID:" ascii
        $steal1 = "Login Data" ascii
        $steal2 = "discord" ascii nocase
        $steal3 = "wallet" ascii nocase
        $steal4 = "Cookies" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($go*) and 2 of ($steal*)
}

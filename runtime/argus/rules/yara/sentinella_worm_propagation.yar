/*
    Sentinella ARGUS Intelligence Pack — Worm & Propagation Detection
    Category: worm
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0
    Source: original_heuristic — behaviors from public MITRE ATT&CK T1091, T1080
*/

rule worm_autorun_inf {
    meta:
        description = "ARGUS detected autorun.inf creation targeting removable drives — a classic worm propagation technique to auto-execute on USB insertion."
        severity = "high"
        weight = 25
        category = "worm"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $autorun = "autorun.inf" ascii nocase
        $open = "open=" ascii nocase
        $shellexec = "shellexecute=" ascii nocase
        $drive1 = "GetDriveTypeW" ascii
        $drive2 = "GetLogicalDrives" ascii
    condition:
        ($autorun and any of ($open, $shellexec)) or
        (uint16(0) == 0x5A4D and $autorun and any of ($drive*))
}

rule worm_removable_drive_copy {
    meta:
        description = "ARGUS detected an executable that enumerates drive types and copies itself to removable drives — a USB worm propagation pattern."
        severity = "high"
        weight = 25
        category = "worm"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $drive = "GetDriveTypeW" ascii
        $copy1 = "CopyFileW" ascii
        $copy2 = "CopyFileExW" ascii
        $self = "GetModuleFileNameW" ascii
        $removable = { 02 00 00 00 }  // DRIVE_REMOVABLE = 2
    condition:
        uint16(0) == 0x5A4D and
        $drive and $self and
        any of ($copy*) and $removable
}

rule worm_network_share_spread {
    meta:
        description = "ARGUS detected network share enumeration combined with file copying — consistent with worm propagation across network shares."
        severity = "high"
        weight = 28
        category = "worm"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $enum1 = "WNetEnumResourceW" ascii
        $enum2 = "WNetOpenEnumW" ascii
        $enum3 = "NetShareEnum" ascii
        $copy1 = "CopyFileW" ascii
        $copy2 = "CopyFileExW" ascii
        $self = "GetModuleFileNameW" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($enum*) and any of ($copy*) and $self
}

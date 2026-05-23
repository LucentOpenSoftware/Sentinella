/*
    Sentinella ARGUS Intelligence Pack — Ransomware Indicators
    Category: ransomware
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0
*/

rule ransomware_file_encryption_loop {
    meta:
        description = "ARGUS detected file enumeration combined with cryptographic operations — consistent with ransomware encryption behavior."
        severity = "critical"
        weight = 35
        category = "ransomware"
        author = "Sentinella"
    strings:
        $find1 = "FindFirstFileW" ascii
        $find2 = "FindNextFileW" ascii
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "CryptGenKey" ascii
        $crypt3 = "BCryptEncrypt" ascii
        $aes = "AES" ascii
        $rsa = "RSA" ascii
    condition:
        uint16(0) == 0x5A4D and
        all of ($find*) and
        (any of ($crypt*) or ($aes and $rsa))
}

rule ransomware_shadow_delete {
    meta:
        description = "ARGUS detected Volume Shadow Copy deletion — a hallmark ransomware technique to prevent file recovery."
        severity = "critical"
        weight = 40
        category = "ransomware"
        author = "Sentinella"
    strings:
        $vss1 = "vssadmin" ascii nocase
        $vss2 = "delete shadows" ascii nocase
        $vss3 = "wmic shadowcopy delete" ascii nocase
        $vss4 = "bcdedit" ascii nocase
        $vss5 = "recoveryenabled" ascii nocase
        $wbadmin = "wbadmin delete catalog" ascii nocase
    condition:
        any of ($vss1, $vss3, $wbadmin) or
        ($vss2) or
        ($vss4 and $vss5)
}

rule ransomware_ransom_note_indicators {
    meta:
        description = "ARGUS detected strings commonly found in ransomware ransom notes — payment demands, encryption notices, and recovery instructions."
        severity = "high"
        weight = 28
        category = "ransomware"
        author = "Sentinella"
    strings:
        // Strong ransom indicators — multi-word phrases unlikely in legitimate software.
        $strong1 = "your files have been encrypted" ascii nocase
        $strong2 = "recover your files" ascii nocase
        $strong3 = "ransom" ascii nocase
        $strong4 = ".onion" ascii nocase
        $strong5 = "tor browser" ascii nocase
        // Supporting indicators — common in ransom notes but also in legit crypto apps.
        $support1 = "bitcoin" ascii nocase
        $support2 = "decrypt" ascii nocase
        $support3 = "private key" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($strong*) or (any of ($strong*) and 2 of ($support*)))
}

rule ransomware_extension_append {
    meta:
        description = "ARGUS detected file renaming with new extension patterns — consistent with ransomware marking encrypted files."
        severity = "high"
        weight = 22
        category = "ransomware"
        author = "Sentinella"
    strings:
        $move1 = "MoveFileW" ascii
        $move2 = "MoveFileExW" ascii
        $rename = "rename" ascii
        $find = "FindFirstFileW" ascii
        $ext1 = ".locked" ascii nocase
        $ext2 = ".encrypted" ascii nocase
        $ext3 = ".crypt" ascii nocase
        $ext4 = ".enc" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($move*, $rename) and
        $find and
        any of ($ext*)
}

rule ransomware_wallpaper_change {
    meta:
        description = "ARGUS detected desktop wallpaper modification combined with encryption indicators — ransomware often changes the wallpaper to display ransom demands."
        severity = "high"
        weight = 22
        category = "ransomware"
        author = "Sentinella"
    strings:
        $wall1 = "SystemParametersInfoW" ascii
        $wall2 = "SPI_SETDESKWALLPAPER" ascii
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "BCryptEncrypt" ascii
        $find = "FindFirstFileW" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($wall1 or $wall2) and
        any of ($crypt*) and $find
}

rule ransomware_network_share_enum {
    meta:
        description = "ARGUS detected network share enumeration combined with file encryption — ransomware spreading to mapped drives and network shares."
        severity = "critical"
        weight = 30
        category = "ransomware"
        author = "Sentinella"
    strings:
        $net1 = "WNetEnumResourceW" ascii
        $net2 = "WNetOpenEnumW" ascii
        $net3 = "NetShareEnum" ascii
        $crypt = "CryptEncrypt" ascii
        $find = "FindFirstFileW" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($net*) and $crypt and $find
}

rule ransomware_process_termination {
    meta:
        description = "ARGUS detected mass process termination targeting databases and office applications — ransomware kills processes to release file locks before encryption."
        severity = "high"
        weight = 25
        category = "ransomware"
        author = "Sentinella"
    strings:
        $kill1 = "taskkill" ascii nocase
        $kill2 = "TerminateProcess" ascii
        $db1 = "sqlservr" ascii nocase
        $db2 = "mysqld" ascii nocase
        $db3 = "oracle" ascii nocase
        $office1 = "winword" ascii nocase
        $office2 = "excel" ascii nocase
        $office3 = "outlook" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($kill*) and
        (2 of ($db*) or 2 of ($office*))
}

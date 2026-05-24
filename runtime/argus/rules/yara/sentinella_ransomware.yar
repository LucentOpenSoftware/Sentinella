/*
    Sentinella ARGUS Intelligence Pack — Ransomware Indicators
    Category: ransomware
    Version: 2026.1
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

rule ransomware_lockbit3_blackcat_akira {
    meta:
        description = "ARGUS detected string patterns associated with LockBit 3.0, BlackCat (ALPHV), or Akira ransomware families — high-profile RaaS operations responsible for widespread enterprise attacks."
        severity = "critical"
        weight = 40
        category = "ransomware"
        author = "Sentinella"
    strings:
        // LockBit 3.0 indicators
        $lb1 = "LockBit" ascii nocase
        $lb2 = "lockbit3" ascii nocase
        $lb3 = "LockBit_Ransomware" ascii nocase
        $lb4 = { 4C 6F 63 6B 42 69 74 20 33 2E 30 }  // "LockBit 3.0"
        $lb5 = "restorefilestx" ascii nocase
        // BlackCat / ALPHV indicators
        $bc1 = "ALPHV" ascii
        $bc2 = "BlackCat" ascii nocase
        $bc3 = "access-key" ascii
        $bc4 = "--access-token" ascii
        $bc5 = "esxi_vm_list" ascii
        $bc6 = "safemode" ascii nocase
        // Akira indicators
        $ak1 = "akira_readme" ascii nocase
        $ak2 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4cez" ascii nocase
        $ak3 = ".akira" ascii nocase
        $ak4 = "powershell" ascii nocase
        $ak5 = "-ep bypass" ascii nocase
        // Common RaaS encryption markers
        $enc1 = "CryptGenRandom" ascii
        $enc2 = "BCryptEncrypt" ascii
        $enc3 = "ChaChaPoly" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($lb*) or 2 of ($bc*) or 2 of ($ak*)) and
        any of ($enc*)
}

rule ransomware_onion_ransom_urls {
    meta:
        description = "ARGUS detected .onion Tor hidden service URLs embedded in executables — consistent with ransomware payment portals and leak sites used for double extortion."
        severity = "critical"
        weight = 35
        category = "ransomware"
        author = "Sentinella"
    strings:
        // Onion URL patterns (v2 and v3 addresses)
        $onion_v3 = /[a-z2-7]{56}\.onion/ ascii nocase
        $onion_v2 = /[a-z2-7]{16}\.onion/ ascii nocase
        // Ransom note context strings
        $note1 = "your files" ascii nocase
        $note2 = "decrypt" ascii nocase
        $note3 = "payment" ascii nocase
        $note4 = "recover" ascii nocase
        $note5 = "contact us" ascii nocase
        $note6 = "bitcoin" ascii nocase
        $note7 = "monero" ascii nocase
        // Tor Browser guidance
        $tor1 = "tor browser" ascii nocase
        $tor2 = "torbrowser" ascii nocase
        $tor3 = "torproject.org" ascii nocase
    condition:
        any of ($onion_v2, $onion_v3) and
        (2 of ($note*) or any of ($tor*))
}

rule ransomware_shadow_delete_powershell {
    meta:
        description = "ARGUS detected Volume Shadow Copy deletion via PowerShell, WMI, or advanced command-line techniques — modern ransomware uses PowerShell and WMI to bypass simple vssadmin detection."
        severity = "critical"
        weight = 38
        category = "ransomware"
        author = "Sentinella"
    strings:
        // PowerShell shadow deletion
        $ps1 = "Get-WmiObject" ascii nocase
        $ps2 = "Win32_ShadowCopy" ascii nocase
        $ps3 = "Delete()" ascii nocase
        $ps4 = "Get-CimInstance" ascii nocase
        $ps5 = "Remove-CimInstance" ascii nocase
        // WMIC advanced variants
        $wmic1 = "wmic" ascii nocase
        $wmic2 = "shadowcopy" ascii nocase
        $wmic3 = "delete" ascii nocase
        // PowerShell disable recovery
        $rec1 = "Set-MpPreference" ascii nocase
        $rec2 = "DisableRealtimeMonitoring" ascii nocase
        $rec3 = "bcdedit" ascii nocase
        $rec4 = "recoveryenabled" ascii nocase
        $rec5 = "No" ascii nocase
        // vssadmin resize trick to invalidate shadows
        $resize1 = "vssadmin" ascii nocase
        $resize2 = "resize shadowstorage" ascii nocase
        $resize3 = "MaxSize=" ascii nocase
    condition:
        (($ps1 or $ps4) and $ps2 and $ps3) or
        ($ps4 and $ps5 and $ps2) or
        ($wmic1 and $wmic2 and $wmic3) or
        ($rec1 and $rec2) or
        ($rec3 and $rec4 and $rec5) or
        ($resize1 and $resize2 and $resize3)
}

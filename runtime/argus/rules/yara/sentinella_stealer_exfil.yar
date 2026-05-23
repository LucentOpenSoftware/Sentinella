/*
    Sentinella ARGUS Intelligence Pack — Stealer Exfiltration Chains
    Category: stealer_exfil
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects complete steal→collect→package→exfiltrate chains that
    combine data harvesting with outbound transmission.
*/

rule stealer_zip_and_send {
    meta:
        description = "ARGUS detected an executable that creates ZIP archives from collected data and transmits them — a complete stealer exfiltration chain."
        severity = "critical"
        weight = 35
        category = "stealer_exfil"
        author = "Sentinella"
    strings:
        $zip1 = "ZipFile" ascii nocase
        $zip2 = "zipfile" ascii nocase
        $zip3 = "CreateZipFile" ascii
        $cred1 = "Login Data" ascii
        $cred2 = "Cookies" ascii
        $cred3 = "discord" ascii nocase
        $send1 = "discord.com/api/webhooks" ascii
        $send2 = "api.telegram.org" ascii
        $send3 = "smtp" ascii nocase
    condition:
        any of ($zip*) and
        2 of ($cred*) and
        any of ($send*)
}

rule stealer_screenshot_capture {
    meta:
        description = "ARGUS detected screenshot capture combined with credential harvesting — consistent with advanced stealers that capture the user's desktop."
        severity = "high"
        weight = 22
        category = "stealer_exfil"
        author = "Sentinella"
    strings:
        $ss1 = "GetDesktopWindow" ascii
        $ss2 = "BitBlt" ascii
        $ss3 = "GetDC" ascii
        $ss4 = "CreateCompatibleBitmap" ascii
        $cred1 = "Login Data" ascii
        $cred2 = "Google\\Chrome\\User Data" ascii nocase
        $cred3 = "discord\\Local Storage" ascii nocase
        $cred4 = "Cookies" ascii
        $cred5 = "wallet" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        3 of ($ss*) and
        2 of ($cred*)
}

rule stealer_wifi_password_harvest {
    meta:
        description = "ARGUS detected WiFi password extraction — using netsh to export saved wireless network credentials."
        severity = "high"
        weight = 20
        category = "stealer_exfil"
        author = "Sentinella"
    strings:
        $netsh = "netsh" ascii nocase
        $wlan = "wlan" ascii nocase
        $show = "show" ascii nocase
        $profile = "profile" ascii nocase
        $key = "key=clear" ascii nocase
    condition:
        $netsh and $wlan and $show and $profile and $key
}

rule stealer_system_fingerprint {
    meta:
        description = "ARGUS detected systematic hardware and system fingerprinting combined with credential indicators — collecting machine identity data typically sent to C2 alongside stolen credentials."
        severity = "medium"
        weight = 12
        category = "stealer_exfil"
        author = "Sentinella"
    strings:
        $hw1 = "Win32_Processor" ascii
        $hw2 = "Win32_VideoController" ascii
        $hw3 = "Win32_DiskDrive" ascii
        $hw4 = "Win32_OperatingSystem" ascii
        $hw5 = "Win32_ComputerSystem" ascii
        $net = "ipinfo.io" ascii nocase
        $geo = "geoip" ascii nocase
        // Require credential theft indicators alongside fingerprinting.
        $cred1 = "Login Data" ascii
        $cred2 = "discord" ascii nocase
        $cred3 = "wallet" ascii nocase
        $cred4 = "Cookies" ascii
        $cred5 = "webhook" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($hw*) or (any of ($net, $geo) and any of ($cred*))) and
        any of ($cred*)
}

rule stealer_telegram_session_theft {
    meta:
        description = "ARGUS detected access to Telegram Desktop session data — stealing Telegram sessions allows full account takeover."
        severity = "high"
        weight = 25
        category = "stealer_exfil"
        author = "Sentinella"
    strings:
        $tdata1 = "\\Telegram Desktop\\tdata" ascii nocase
        $tdata2 = "tdata" ascii
        $key = "key_datas" ascii
        $map = "map" ascii
        $copy = "CopyFileW" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($tdata*) and
        ($key or $map or $copy)
}

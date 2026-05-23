/*
    Sentinella ARGUS Intelligence Pack — Credential Tool Detection
    Category: credential_tools
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects known credential extraction tools and their patterns.
    These are legitimate security tools that are heavily abused by attackers.
*/

rule mimikatz_strings {
    meta:
        description = "ARGUS detected strings associated with Mimikatz credential extraction tool — a primary post-exploitation tool used in nearly every major breach."
        severity = "critical"
        weight = 40
        category = "credential_tools"
        author = "Sentinella"
    strings:
        $m1 = "sekurlsa" ascii nocase
        $m2 = "kerberos" ascii nocase
        $m3 = "logonpasswords" ascii nocase
        $m4 = "wdigest" ascii nocase
        $m5 = "mimikatz" ascii nocase
        $m6 = "gentilkiwi" ascii nocase
        $m7 = "mimilib" ascii nocase
        $m8 = "kuhl_m" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule lazagne_stealer {
    meta:
        description = "ARGUS detected patterns associated with LaZagne credential recovery tool — extracts passwords from browsers, email clients, databases, and system stores."
        severity = "critical"
        weight = 35
        category = "credential_tools"
        author = "Sentinella"
    strings:
        $lz1 = "lazagne" ascii nocase
        $lz2 = "softwares" ascii nocase
        $lz3 = "all" ascii nocase
        $mod1 = "browsers" ascii nocase
        $mod2 = "mails" ascii nocase
        $mod3 = "wifi" ascii nocase
        $mod4 = "sysadmin" ascii nocase
        $mod5 = "databases" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ($lz1 or ($lz2 and $lz3 and 3 of ($mod*)))
}

rule dpapi_credential_extraction {
    meta:
        description = "ARGUS detected DPAPI credential extraction patterns — decrypting Windows-protected secrets including browser passwords, WiFi keys, and certificates."
        severity = "high"
        weight = 25
        category = "credential_tools"
        author = "Sentinella"
    strings:
        $dpapi1 = "CryptUnprotectData" ascii
        $master = "Protect\\S-" ascii nocase
        $chrome1 = "Login Data" ascii
        $chrome2 = "Local State" ascii
        $aes = "AES" ascii
        $key = "encrypted_key" ascii
    condition:
        uint16(0) == 0x5A4D and
        $dpapi1 and ($master or ($chrome1 and ($chrome2 or $key or $aes)))
}

rule clipboard_stealer {
    meta:
        description = "ARGUS detected clipboard monitoring and replacement behavior — may hijack cryptocurrency addresses or steal copied credentials."
        severity = "high"
        weight = 22
        category = "credential_tools"
        author = "Sentinella"
    strings:
        $get = "GetClipboardData" ascii
        $set = "SetClipboardData" ascii
        $open = "OpenClipboard" ascii
        $timer = "SetTimer" ascii
        $sleep = "Sleep" ascii
    condition:
        uint16(0) == 0x5A4D and
        $get and $set and $open and
        any of ($timer, $sleep)
}

rule keylogger_indicators {
    meta:
        description = "ARGUS detected keyboard hooking and keystroke capture patterns — consistent with keylogger behavior."
        severity = "high"
        weight = 28
        category = "credential_tools"
        author = "Sentinella"
    strings:
        $hook1 = "SetWindowsHookExA" ascii
        $hook2 = "SetWindowsHookExW" ascii
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "GetKeyState" ascii
        $key3 = "GetKeyboardState" ascii
        $log = "WriteFile" ascii
        $wh_keyboard = { 02 00 00 00 }  // WH_KEYBOARD = 2
        $wh_keyboard_ll = { 0D 00 00 00 }  // WH_KEYBOARD_LL = 13
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($hook*) and any of ($wh_keyboard, $wh_keyboard_ll)) or
        (2 of ($key*) and $log))
}

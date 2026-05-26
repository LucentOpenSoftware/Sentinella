/*
    Sentinella ARGUS Intelligence Pack — Credential Tool Detection
    Category: credential_tools
    Version: 2026.1
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

rule mimikatz_22_advanced {
    meta:
        description = "ARGUS detected Mimikatz 2.2+ module patterns including sekurlsa, lsadump, and kerberos ticket operations — covers modern Mimikatz variants with updated module names and command structures."
        severity = "critical"
        weight = 42
        category = "credential_tools"
        author = "Sentinella"
    strings:
        // Mimikatz 2.2+ sekurlsa module commands
        $sek1 = "sekurlsa::logonpasswords" ascii nocase
        $sek2 = "sekurlsa::wdigest" ascii nocase
        $sek3 = "sekurlsa::msv" ascii nocase
        $sek4 = "sekurlsa::tspkg" ascii nocase
        $sek5 = "sekurlsa::credman" ascii nocase
        $sek6 = "sekurlsa::dpapi" ascii nocase
        $sek7 = "sekurlsa::minidump" ascii nocase
        // lsadump module commands
        $lsa1 = "lsadump::sam" ascii nocase
        $lsa2 = "lsadump::secrets" ascii nocase
        $lsa3 = "lsadump::cache" ascii nocase
        $lsa4 = "lsadump::dcsync" ascii nocase
        $lsa5 = "lsadump::trust" ascii nocase
        $lsa6 = "lsadump::lsa" ascii nocase
        // Kerberos module commands
        $krb1 = "kerberos::golden" ascii nocase
        $krb2 = "kerberos::ptt" ascii nocase
        $krb3 = "kerberos::list" ascii nocase
        // Mimikatz internal strings (2.2+)
        $int1 = "kuhl_m_sekurlsa" ascii
        $int2 = "kuhl_m_lsadump" ascii
        $int3 = "kuhl_m_kerberos" ascii
        $int4 = "kuhl_m_dpapi" ascii
        $int5 = "benjamin" ascii nocase  // gentilkiwi reference
        $int6 = "delpy" ascii nocase
        // Privilege escalation
        $priv1 = "privilege::debug" ascii nocase
        $priv2 = "token::elevate" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($sek*) or 2 of ($lsa*) or 2 of ($krb*) or
        3 of ($int*) or
        (any of ($priv*) and (any of ($sek*) or any of ($lsa*))))
}

rule lazagne_pypykatz_credential_tools {
    meta:
        description = "ARGUS detected LaZagne or Pypykatz credential extraction tool indicators — Python-based credential recovery tools that extract passwords from browsers, system stores, and LSASS memory dumps."
        severity = "critical"
        weight = 36
        category = "credential_tools"
        author = "Sentinella"
    strings:
        // LaZagne specific patterns
        $lz1 = "lazagne" ascii nocase
        $lz2 = "laZagne" ascii
        $lz3 = "AlessandroZ" ascii  // LaZagne author
        $lz4 = "softwares.browsers" ascii
        $lz5 = "softwares.sysadmin" ascii
        $lz6 = "softwares.wifi" ascii
        $lz7 = "softwares.mails" ascii
        // Pypykatz specific patterns
        $pp1 = "pypykatz" ascii nocase
        $pp2 = "minidump" ascii nocase
        $pp3 = "lsass" ascii nocase
        $pp4 = "skelsec" ascii  // pypykatz author
        $pp5 = "MiniDumpReadDumpStream" ascii
        $pp6 = "MiniDumpWriteDump" ascii
        // Common credential store targets
        $store1 = "Login Data" ascii
        $store2 = "Cookies" ascii
        $store3 = "Web Data" ascii
        $store4 = "Local State" ascii
        $store5 = "chrome" ascii nocase
        $store6 = "firefox" ascii nocase
        $store7 = "credential" ascii nocase
        $store8 = "vault" ascii nocase
    condition:
        (2 of ($lz*)) or
        (2 of ($pp*) and $pp3) or
        ($pp3 and any of ($pp5, $pp6) and any of ($store*))
}

rule lsass_dump_comsvcs {
    meta:
        description = "ARGUS detected LSASS process memory dumping via comsvcs.dll MiniDump — a living-off-the-land technique that uses the legitimate comsvcs.dll to dump LSASS memory for offline credential extraction."
        severity = "critical"
        weight = 40
        category = "credential_tools"
        author = "Sentinella"
    strings:
        // comsvcs.dll MiniDump patterns
        $csv1 = "comsvcs.dll" ascii nocase
        $csv2 = "comsvcs" ascii nocase
        $mini1 = "MiniDump" ascii nocase
        $mini2 = "#24" ascii                // MiniDump ordinal in comsvcs.dll
        $mini3 = "minidump" ascii nocase
        // LSASS targeting
        $lsass1 = "lsass.exe" ascii nocase
        $lsass2 = "lsass" ascii nocase
        $lsass3 = "lsass.dmp" ascii nocase
        // rundll32 invocation patterns
        $rundll1 = "rundll32" ascii nocase
        $rundll2 = "rundll32.exe" ascii nocase
        // PowerShell LSASS dump variants
        $ps1 = "Get-Process" ascii nocase
        $ps2 = "MiniDumpWriteDump" ascii
        $ps3 = "dbghelp.dll" ascii nocase
        $ps4 = "dbgcore.dll" ascii nocase
        // Task Manager / ProcDump alternatives
        $alt1 = "procdump" ascii nocase
        $alt2 = "procdump64" ascii nocase
        $alt3 = "-ma lsass" ascii nocase
        $alt4 = "Out-Minidump" ascii nocase
        $alt5 = "sqldumper.exe" ascii nocase
    condition:
        (($csv1 or $csv2) and any of ($mini*) and any of ($rundll*)) or
        (any of ($lsass*) and any of ($mini*) and any of ($rundll*)) or
        (any of ($ps1, $ps2, $ps3, $ps4) and any of ($lsass*)) or
        (any of ($alt1, $alt2) and $alt3) or
        ($alt4 and any of ($lsass*)) or
        ($alt5 and any of ($lsass*))
}

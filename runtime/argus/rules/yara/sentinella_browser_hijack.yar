/*
    Sentinella ARGUS Intelligence Pack — Browser & Extension Hijacking
    Category: browser_hijack
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects browser extension manipulation, search engine hijacking,
    and proxy/certificate injection.
*/

rule browser_extension_sideload {
    meta:
        description = "ARGUS detected code that installs or modifies browser extensions — may inject malicious extensions for credential theft or ad injection."
        severity = "high"
        weight = 22
        category = "browser_hijack"
        author = "Sentinella"
    strings:
        $ext_dir1 = "\\Extensions\\" ascii nocase
        $ext_dir2 = "\\Google\\Chrome\\User Data" ascii nocase
        $ext_dir3 = "\\Microsoft\\Edge\\User Data" ascii nocase
        $manifest = "manifest.json" ascii nocase
        $write = "WriteFile" ascii
        $create = "CreateFileW" ascii
    condition:
        uint16(0) == 0x5A4D and
        2 of ($ext_dir*) and
        $manifest and
        any of ($write, $create)
}

rule browser_proxy_injection {
    meta:
        description = "ARGUS detected system proxy configuration modification — may redirect web traffic through a malicious proxy for credential interception."
        severity = "high"
        weight = 22
        category = "browser_hijack"
        author = "Sentinella"
    strings:
        $proxy1 = "ProxyServer" ascii nocase
        $proxy2 = "ProxyEnable" ascii nocase
        $proxy3 = "Internet Settings" ascii nocase
        $reg = "RegSetValueExW" ascii
    condition:
        uint16(0) == 0x5A4D and
        $proxy3 and any of ($proxy1, $proxy2) and $reg
}

rule browser_certificate_injection {
    meta:
        description = "ARGUS detected root certificate installation — may enable man-in-the-middle attacks on HTTPS traffic."
        severity = "critical"
        weight = 30
        category = "browser_hijack"
        author = "Sentinella"
    strings:
        $cert1 = "CertAddEncodedCertificateToStore" ascii
        $cert2 = "CertOpenSystemStoreW" ascii
        $cert3 = "ROOT" ascii
        $cert4 = "X509Certificate" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($cert1, $cert2) and ($cert3 or $cert4)
}

rule browser_history_exfiltration {
    meta:
        description = "ARGUS detected access to browser history and bookmark databases across multiple browsers — consistent with information harvesting."
        severity = "high"
        weight = 20
        category = "browser_hijack"
        author = "Sentinella"
    strings:
        $hist1 = "History" ascii
        $hist2 = "Bookmarks" ascii
        $hist3 = "places.sqlite" ascii
        $chrome = "Chrome" ascii nocase
        $edge = "Edge" ascii nocase
        $firefox = "Firefox" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        2 of ($hist*) and
        2 of ($chrome, $edge, $firefox)
}

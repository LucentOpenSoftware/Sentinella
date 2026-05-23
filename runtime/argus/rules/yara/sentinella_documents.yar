/*
    Sentinella ARGUS Intelligence Pack — Malicious Document Detection
    Category: document
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects malicious PDFs, Office documents with suspicious macros,
    and document-based attack vectors.
*/

rule pdf_javascript_exploit {
    meta:
        description = "ARGUS detected JavaScript embedded in a PDF document — a common vector for PDF-based exploits."
        severity = "high"
        weight = 25
        category = "document"
        author = "Sentinella"
    strings:
        $pdf = "%PDF-" ascii
        $js1 = "/JavaScript" ascii
        $js2 = "/JS " ascii
        $js3 = "/JS(" ascii
        $action = "/OpenAction" ascii
        $launch = "/Launch" ascii
        $aa = "/AA" ascii
    condition:
        $pdf at 0 and
        any of ($js*) and
        any of ($action, $launch, $aa)
}

rule pdf_embedded_executable {
    meta:
        description = "ARGUS detected a PE executable embedded within a PDF file — a technique to deliver malware disguised as a document."
        severity = "critical"
        weight = 40
        category = "document"
        author = "Sentinella"
    strings:
        $pdf = "%PDF-" ascii
        $mz = { 4D 5A 90 00 }
        $pe = "This program cannot be run in DOS mode" ascii
    condition:
        $pdf at 0 and ($mz or $pe)
}

rule pdf_uri_autoaction {
    meta:
        description = "ARGUS detected a PDF with automatic URI navigation — may redirect to malicious download or phishing page on open."
        severity = "medium"
        weight = 15
        category = "document"
        author = "Sentinella"
    strings:
        $pdf = "%PDF-" ascii
        $uri = "/URI" ascii
        $action = "/OpenAction" ascii
        $s = "/S /URI" ascii
    condition:
        $pdf at 0 and $uri and ($action or $s)
}

rule office_macro_autoopen {
    meta:
        description = "ARGUS detected an Office document with auto-executing macro code — a classic malware delivery mechanism."
        severity = "high"
        weight = 22
        category = "document"
        author = "Sentinella"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $auto1 = "AutoOpen" ascii nocase
        $auto2 = "Auto_Open" ascii nocase
        $auto3 = "Document_Open" ascii nocase
        $auto4 = "Workbook_Open" ascii nocase
        $shell = "Shell" ascii
        $wscript = "WScript" ascii
        $powershell = "powershell" ascii nocase
    condition:
        $ole at 0 and
        any of ($auto*) and
        any of ($shell, $wscript, $powershell)
}

rule office_macro_download {
    meta:
        description = "ARGUS detected an Office macro that downloads and executes external content — a malware dropper pattern."
        severity = "critical"
        weight = 35
        category = "document"
        author = "Sentinella"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $auto1 = "AutoOpen" ascii nocase
        $auto2 = "Document_Open" ascii nocase
        $dl1 = "URLDownloadToFile" ascii nocase
        $dl2 = "XMLHTTP" ascii nocase
        $dl3 = "WinHttp" ascii nocase
        $dl4 = "Inet" ascii nocase
        $exec1 = "Shell" ascii
        $exec2 = "CreateObject" ascii
    condition:
        $ole at 0 and
        any of ($auto*) and
        any of ($dl*) and
        any of ($exec*)
}

rule lnk_command_execution {
    meta:
        description = "ARGUS detected a Windows shortcut (.lnk) file with embedded command execution — a technique to run PowerShell or cmd via a double-click."
        severity = "high"
        weight = 22
        category = "document"
        author = "Sentinella"
    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $ps = "powershell" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $mshta = "mshta" ascii nocase
        $wscript = "wscript" ascii nocase
        $cscript = "cscript" ascii nocase
    condition:
        $lnk at 0 and any of ($ps, $cmd, $mshta, $wscript, $cscript)
}

rule iso_img_dropper {
    meta:
        description = "ARGUS detected an ISO/IMG disk image containing executable content — a technique to bypass Mark-of-the-Web and deliver malware."
        severity = "medium"
        weight = 15
        category = "document"
        author = "Sentinella"
    strings:
        // ISO 9660 magic.
        $iso = "CD001" ascii
        // Embedded PE.
        $mz = "MZ" ascii
        $pe_sig = "PE\x00\x00" ascii
    condition:
        $iso in (0x8000..0x8800) and $mz and $pe_sig
}

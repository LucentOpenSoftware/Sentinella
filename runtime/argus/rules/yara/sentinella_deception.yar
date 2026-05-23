/*
    Sentinella ARGUS Intelligence Pack — Deception & Evasion Detection
    Category: deception
    Version: 2024.1
    Author: Sentinella
    License: GPL-2.0

    Detects file disguise techniques, packer abuse, and anti-analysis
    mechanisms commonly used by modern malware.
*/

rule pyinstaller_packed_executable {
    meta:
        description = "ARGUS identified a PyInstaller-packaged executable — while legitimate, this format is commonly abused by Python-based stealers and malware."
        severity = "medium"
        weight = 10
        category = "packer"
        author = "Sentinella"

    strings:
        $meipass = "_MEIPASS" ascii
        $mei_magic = { 4D 45 49 0C 0B 0A 0B 0E }
        $python_dll = /python3\d{1,2}\.dll/ ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        ($mei_magic or ($meipass and $python_dll))
}

rule nodejs_sea_executable {
    meta:
        description = "ARGUS detected a Node.js Single Executable Application — this packaging format can conceal Node.js-based malware."
        severity = "medium"
        weight = 10
        category = "packer"
        author = "Sentinella"

    strings:
        $fuse = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2" ascii
        $blob = "NODE_SEA_BLOB" ascii

    condition:
        uint16(0) == 0x5A4D and any of them
}

rule suspicious_persistence_combo {
    meta:
        description = "ARGUS detected multiple system persistence mechanisms in a single executable — a strong indicator of malware establishing footholds."
        severity = "high"
        weight = 22
        category = "persistence"
        author = "Sentinella"

    strings:
        $run_key = "\\CurrentVersion\\Run" ascii nocase
        $startup = "\\Start Menu\\Programs\\Startup" ascii nocase
        $schtasks = "schtasks" ascii nocase
        $task_create = "/create" ascii nocase
        $wmi_filter = "__EventFilter" ascii
        $wmi_consumer = "__EventConsumer" ascii
        $service_create = "CreateServiceW" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($run_key, $startup, $service_create) or
            ($schtasks and $task_create and any of ($run_key, $startup)) or
            ($wmi_filter and $wmi_consumer)
        )
}

rule fake_document_executable {
    meta:
        description = "ARGUS identified an executable masquerading as a document — a social engineering technique to trick users into running malware."
        severity = "critical"
        weight = 40
        category = "deception"
        author = "Sentinella"

    strings:
        $mz = { 4D 5A }
        $rtlo = { E2 80 AE }
        $double_pdf_exe = ".pdf.exe" ascii nocase
        $double_doc_exe = ".doc.exe" ascii nocase
        $double_docx_exe = ".docx.exe" ascii nocase
        $double_xls_scr = ".xls.scr" ascii nocase
        $double_jpg_exe = ".jpg.exe" ascii nocase

    condition:
        $mz at 0 and ($rtlo or any of ($double_*))
}

rule suspicious_electron_app {
    meta:
        description = "ARGUS identified a potentially weaponized Electron application with dangerous security configurations."
        severity = "medium"
        weight = 15
        category = "deception"
        author = "Sentinella"

    strings:
        $node_int = "nodeIntegration" ascii
        $ctx_iso_off = "contextIsolation" ascii
        $web_sec_off = "webSecurity" ascii
        $electron = "electron" ascii nocase
        $asar = ".asar" ascii

    condition:
        $electron and $asar and
        ($node_int or $ctx_iso_off or $web_sec_off)
}

rule cryptominer_indicators {
    meta:
        description = "ARGUS detected cryptocurrency mining software indicators."
        severity = "high"
        weight = 22
        category = "miner"
        author = "Sentinella"

    strings:
        $stratum1 = "stratum+tcp://" ascii
        $stratum2 = "stratum+ssl://" ascii
        $xmrig = "xmrig" ascii nocase
        $cryptonight = "CryptoNight" ascii nocase
        $randomx = "RandomX" ascii nocase
        $pool = "pool.minergate" ascii nocase
        $hashrate = "hashrate" ascii nocase
        $mining = "mining" ascii nocase

    condition:
        any of ($stratum*) or
        $xmrig or
        $pool or
        ($cryptonight and $hashrate) or
        ($randomx and $mining)
}

/*
    Sentinella ARGUS Intelligence Pack — Dropper & Loader Detection
    Category: dropper
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects AutoIt droppers, archive-based payload staging, HTA payloads,
    and multi-stage loader chains.
*/

rule autoit_compiled_script {
    meta:
        description = "ARGUS detected an AutoIt compiled script — while AutoIt is a legitimate automation tool, compiled AutoIt scripts are frequently used as malware droppers."
        severity = "medium"
        weight = 12
        category = "dropper"
        author = "Sentinella"
    strings:
        $au3_1 = "AutoIt" ascii
        $au3_2 = "AU3!EA06" ascii
        $au3_3 = "#AutoIt3Wrapper" ascii
        $au3_4 = "AutoItObject" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule autoit_dropper_with_stealer {
    meta:
        description = "ARGUS detected an AutoIt script with credential theft capabilities — a common dropper pattern for delivering stealers."
        severity = "high"
        weight = 28
        category = "dropper"
        author = "Sentinella"
    strings:
        $au3 = "AutoIt" ascii
        $steal1 = "Chrome" ascii nocase
        $steal2 = "Login Data" ascii
        $steal3 = "discord" ascii nocase
        $steal4 = "webhook" ascii nocase
        $steal5 = "Cookies" ascii
    condition:
        uint16(0) == 0x5A4D and $au3 and 2 of ($steal*)
}

rule hta_with_powershell {
    meta:
        description = "ARGUS detected an HTA file executing PowerShell — a multi-stage attack technique that uses HTML Applications to launch script-based payloads."
        severity = "high"
        weight = 25
        category = "dropper"
        author = "Sentinella"
    strings:
        $hta = "<HTA:APPLICATION" ascii nocase
        $ps1 = "powershell" ascii nocase
        $ps2 = "Invoke-Expression" ascii nocase
        $ps3 = "IEX" ascii
        $ps4 = "-enc" ascii nocase
        $script = "<script" ascii nocase
    condition:
        $hta and $script and any of ($ps*)
}

rule hta_with_wscript {
    meta:
        description = "ARGUS detected an HTA file creating shell objects — allows arbitrary command execution through the HTML Application host."
        severity = "high"
        weight = 22
        category = "dropper"
        author = "Sentinella"
    strings:
        $hta = "<HTA:APPLICATION" ascii nocase
        $ws1 = "WScript.Shell" ascii nocase
        $ws2 = "Shell.Application" ascii nocase
        $ws3 = "CreateObject" ascii nocase
        $run = ".Run" ascii
    condition:
        $hta and any of ($ws*) and ($ws3 or $run)
}

rule sfx_archive_with_script {
    meta:
        description = "ARGUS detected a self-extracting archive containing script files — a technique to deliver and auto-execute malicious payloads."
        severity = "medium"
        weight = 15
        category = "dropper"
        author = "Sentinella"
    strings:
        $mz = { 4D 5A }
        $sfx1 = "WinRAR SFX" ascii
        $sfx2 = "7-Zip SFX" ascii
        $sfx3 = "Setup=" ascii
        $sfx4 = "RunProgram=" ascii
        $script1 = ".bat" ascii nocase
        $script2 = ".cmd" ascii nocase
        $script3 = ".ps1" ascii nocase
        $script4 = ".vbs" ascii nocase
    condition:
        $mz at 0 and
        any of ($sfx*) and
        any of ($script*)
}

rule dropper_temp_extraction {
    meta:
        description = "ARGUS detected a small executable that creates files in temporary directories and executes them with obfuscation indicators — a dropper behavior pattern."
        severity = "medium"
        weight = 12
        category = "dropper"
        author = "Sentinella"
    strings:
        $temp1 = "GetTempPathW" ascii
        $temp2 = "GetTempFileNameW" ascii
        $temp3 = "%TEMP%" ascii
        $temp4 = "\\AppData\\Local\\Temp" ascii nocase
        $exec1 = "ShellExecuteW" ascii
        $exec2 = "WinExec" ascii
        // Require obfuscation/evasion indicators — real installers don't need these.
        $obf1 = "VirtualProtect" ascii
        $obf2 = "IsDebuggerPresent" ascii
        $obf3 = "NtQueryInformationProcess" ascii
        $obf4 = "GetTickCount" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 3145728 and
        2 of ($temp*) and
        any of ($exec*) and
        any of ($obf*)
}

rule archive_payload_zip_in_pe {
    meta:
        description = "ARGUS detected a ZIP archive embedded within a PE executable — may contain second-stage payloads extracted at runtime."
        severity = "low"
        weight = 8
        category = "dropper"
        author = "Sentinella"
    strings:
        $mz = { 4D 5A }
        $pk = { 50 4B 03 04 }
        $exe_in_zip = ".exe" ascii
        $dll_in_zip = ".dll" ascii
    condition:
        $mz at 0 and $pk and
        any of ($exe_in_zip, $dll_in_zip)
}

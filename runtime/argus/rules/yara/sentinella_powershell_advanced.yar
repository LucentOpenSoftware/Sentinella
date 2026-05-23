/*
    Sentinella ARGUS Intelligence Pack — Advanced PowerShell Detection
    Category: powershell
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Deep detection of PowerShell-based attack techniques beyond basic
    encoded commands. Covers cradle variants, AMSI patches, and
    fileless execution patterns.
*/

rule powershell_cradle_net_webclient {
    meta:
        description = "ARGUS detected a PowerShell Net.WebClient download cradle — fetches and potentially executes remote content."
        severity = "high"
        weight = 22
        category = "powershell"
        author = "Sentinella"
    strings:
        $wc = "New-Object Net.WebClient" ascii nocase
        $dl1 = "DownloadString" ascii nocase
        $dl2 = "DownloadFile" ascii nocase
        $dl3 = "DownloadData" ascii nocase
    condition:
        $wc and any of ($dl*)
}

rule powershell_cradle_invoke_webrequest {
    meta:
        description = "ARGUS detected a PowerShell Invoke-WebRequest cradle with execution — downloads and runs remote scripts."
        severity = "high"
        weight = 22
        category = "powershell"
        author = "Sentinella"
    strings:
        $iwr1 = "Invoke-WebRequest" ascii nocase
        $iwr2 = "Invoke-RestMethod" ascii nocase
        $iwr3 = "wget " ascii nocase
        $iwr4 = "curl " ascii nocase
        $iex1 = "Invoke-Expression" ascii nocase
        $iex2 = "IEX(" ascii nocase
        $iex3 = "IEX (" ascii nocase
        $pipe = "|" ascii
    condition:
        any of ($iwr*) and (any of ($iex*) or $pipe)
}

rule powershell_base64_with_decompress {
    meta:
        description = "ARGUS detected PowerShell base64 decoding combined with decompression — a multi-layer obfuscation technique for hiding payloads."
        severity = "high"
        weight = 25
        category = "powershell"
        author = "Sentinella"
    strings:
        $b64 = "FromBase64String" ascii nocase
        $decomp1 = "DeflateStream" ascii nocase
        $decomp2 = "GZipStream" ascii nocase
        $decomp3 = "IO.Compression" ascii nocase
        $iex = "Invoke-Expression" ascii nocase
    condition:
        $b64 and any of ($decomp*) and $iex
}

rule powershell_amsi_patch_bytes {
    meta:
        description = "ARGUS detected specific byte patterns used to patch AMSI in memory — a critical indicator of an active attempt to disable Windows security scanning."
        severity = "critical"
        weight = 35
        category = "powershell"
        author = "Sentinella"
    strings:
        // Common AMSI patch bytes: mov eax, 0x80070057 (E_INVALIDARG) + ret
        $patch1 = { B8 57 00 07 80 C3 }
        // Alternative: xor eax,eax + ret (return S_OK without scanning)
        $patch2 = { 31 C0 C3 }
        $amsi = "amsi.dll" ascii nocase
    condition:
        $amsi and any of ($patch*)
}

rule powershell_etw_bypass {
    meta:
        description = "ARGUS detected Event Tracing for Windows (ETW) bypass — disabling security telemetry to avoid detection during payload execution."
        severity = "critical"
        weight = 30
        category = "powershell"
        author = "Sentinella"
    strings:
        $etw1 = "EtwEventWrite" ascii nocase
        $etw2 = "ntdll" ascii nocase
        $patch1 = "VirtualProtect" ascii nocase
        $patch2 = "Marshal.Copy" ascii nocase
        $reflection = "[System.Reflection" ascii nocase
    condition:
        $etw1 and ($etw2 or $reflection) and any of ($patch*)
}

rule powershell_scheduled_task_persistence {
    meta:
        description = "ARGUS detected PowerShell creating a scheduled task for persistence — ensures malware survives reboots."
        severity = "high"
        weight = 20
        category = "powershell"
        author = "Sentinella"
    strings:
        $reg1 = "Register-ScheduledTask" ascii nocase
        $reg2 = "New-ScheduledTaskAction" ascii nocase
        $reg3 = "New-ScheduledTaskTrigger" ascii nocase
        $schtasks = "schtasks" ascii nocase
        $create = "/create" ascii nocase
    condition:
        ($reg1 and any of ($reg2, $reg3)) or
        ($schtasks and $create)
}

rule powershell_rundll32_proxy {
    meta:
        description = "ARGUS detected PowerShell invoking rundll32 as an execution proxy — a technique to bypass application whitelisting."
        severity = "high"
        weight = 22
        category = "powershell"
        author = "Sentinella"
    strings:
        $ps = "powershell" ascii nocase
        $rundll = "rundll32" ascii nocase
        $js = "javascript:" ascii nocase
        $dll = ".dll" ascii nocase
    condition:
        $ps and $rundll and ($js or $dll)
}

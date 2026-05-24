/*
    Sentinella ARGUS Intelligence Pack — Modern Loader & Dropper Techniques
    Category: credential_theft
    Version: 2026.1
    Author: Sentinella
    License: GPL-2.0

    Detects modern loader and dropper techniques including DLL sideloading,
    reflective DLL loading, .NET Assembly.Load from memory, PowerShell
    download cradles, LOLBin proxy execution, and MotW bypass via
    container files.
*/

rule loader_dll_sideloading {
    meta:
        description = "ARGUS detected DLL sideloading indicators — attackers place malicious DLLs alongside vulnerable legitimate applications that load them via predictable search order hijacking."
        severity = "high"
        weight = 22
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // Known sideload-vulnerable applications and their target DLLs
        $app1 = "OneDriveUpdater.exe" ascii nocase
        $app2 = "teams.exe" ascii nocase
        $app3 = "Slack.exe" ascii nocase
        $app4 = "notepad++.exe" ascii nocase
        $app5 = "winword.exe" ascii nocase
        $app6 = "vmnat.exe" ascii nocase
        $app7 = "Acrobat.exe" ascii nocase

        // Common sideloaded DLL names
        $dll1 = "version.dll" ascii nocase
        $dll2 = "userenv.dll" ascii nocase
        $dll3 = "msasn1.dll" ascii nocase
        $dll4 = "dbghelp.dll" ascii nocase
        $dll5 = "cryptsp.dll" ascii nocase
        $dll6 = "TextShaping.dll" ascii nocase
        $dll7 = "WINSTA.dll" ascii nocase

        // DLL hijack infrastructure
        $hijack1 = "LoadLibraryW" ascii
        $hijack2 = "GetProcAddress" ascii
        $hijack3 = "DllMain" ascii

        // Suspicious payload behavior in sideloaded context
        $payload1 = "VirtualAlloc" ascii
        $payload2 = "VirtualProtect" ascii
        $payload3 = "CreateThread" ascii

    condition:
        uint16(0) == 0x5A4D and
        (any of ($app*) and any of ($dll*) and any of ($payload*)) or
        (2 of ($dll*) and all of ($hijack*) and any of ($payload*))
}

rule loader_reflective_dll_injection {
    meta:
        description = "ARGUS detected reflective DLL loading patterns — loading a DLL entirely from memory without touching disk, bypassing standard DLL load monitoring and file-based scanning."
        severity = "critical"
        weight = 28
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // Reflective loading function names
        $ref1 = "ReflectiveLoader" ascii
        $ref2 = "ReflectiveDllInjection" ascii
        $ref3 = "MemoryLoadLibrary" ascii
        $ref4 = "MemoryModule" ascii

        // Manual PE loading indicators
        $pe1 = "IMAGE_DOS_HEADER" ascii
        $pe2 = "IMAGE_NT_HEADERS" ascii
        $pe3 = "IMAGE_SECTION_HEADER" ascii
        $pe4 = "IMAGE_IMPORT_DESCRIPTOR" ascii

        // Memory allocation + execution
        $mem1 = "VirtualAlloc" ascii
        $mem2 = "VirtualProtect" ascii
        $mem3 = "NtAllocateVirtualMemory" ascii
        $mem4 = "RtlMoveMemory" ascii

        // Relocation and import resolution
        $fix1 = "IMAGE_BASE_RELOCATION" ascii
        $fix2 = "GetProcAddress" ascii
        $fix3 = "LoadLibraryA" ascii
        $fix4 = "LdrLoadDll" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($ref*) or
            (2 of ($pe*) and 2 of ($mem*) and any of ($fix*))
        )
}

rule loader_dotnet_assembly_load_memory {
    meta:
        description = "ARGUS detected .NET Assembly.Load from memory — loading .NET assemblies directly from byte arrays without files on disk, commonly used to execute credential stealers and post-exploitation tools."
        severity = "high"
        weight = 25
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // Assembly loading from memory
        $load1 = "Assembly.Load(" ascii
        $load2 = "Assembly.Load(byte" ascii
        $load3 = "[Reflection.Assembly]::Load" ascii
        $load4 = "Assembly.LoadFrom" ascii
        $load5 = "AppDomain.CurrentDomain.Load" ascii
        $load6 = "Assembly.UnsafeLoadFrom" ascii

        // Base64/byte array preparation
        $prep1 = "Convert.FromBase64String" ascii
        $prep2 = "FromBase64String" ascii
        $prep3 = "System.IO.MemoryStream" ascii
        $prep4 = "GZipStream" ascii
        $prep5 = "DeflateStream" ascii

        // Method invocation after loading
        $invoke1 = "EntryPoint.Invoke" ascii
        $invoke2 = "GetType(" ascii
        $invoke3 = "InvokeMember" ascii
        $invoke4 = "CreateInstance" ascii
        $invoke5 = "MethodInfo" ascii

    condition:
        any of ($load*) and
        any of ($prep*) and
        any of ($invoke*)
}

rule loader_powershell_download_cradle {
    meta:
        description = "ARGUS detected a PowerShell download cradle — chaining web download with in-memory execution to fetch and run remote payloads without writing to disk."
        severity = "high"
        weight = 24
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // Download methods
        $dl1 = "Invoke-WebRequest" ascii nocase
        $dl2 = "New-Object Net.WebClient" ascii nocase
        $dl3 = "Net.WebClient" ascii nocase
        $dl4 = "DownloadString(" ascii nocase
        $dl5 = "DownloadFile(" ascii nocase
        $dl6 = "DownloadData(" ascii nocase
        $dl7 = "Invoke-RestMethod" ascii nocase
        $dl8 = "Start-BitsTransfer" ascii nocase
        $dl9 = "wget " ascii nocase
        $dl10 = "curl " ascii nocase

        // Execution methods
        $exec1 = "Invoke-Expression" ascii nocase
        $exec2 = "IEX(" ascii nocase
        $exec3 = "IEX (" ascii nocase
        $exec4 = "iex(" ascii nocase
        $exec5 = ".Invoke(" ascii
        $exec6 = "-EncodedCommand" ascii nocase
        $exec7 = "-enc " ascii nocase
        $exec8 = "powershell -e " ascii nocase

        // Obfuscation of cradle
        $obf1 = "[char]" ascii nocase
        $obf2 = "-join" ascii nocase
        $obf3 = "-replace" ascii nocase
        $obf4 = "[Convert]::" ascii nocase
        $obf5 = "FromBase64" ascii nocase

    condition:
        any of ($dl*) and any of ($exec*) or
        (any of ($dl*) and 2 of ($obf*))
}

rule loader_certutil_bitsadmin_abuse {
    meta:
        description = "ARGUS detected certutil or bitsadmin abuse for payload download — using built-in Windows utilities as download proxies to bypass application-level controls and blend with legitimate system activity."
        severity = "high"
        weight = 22
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // Certutil download abuse
        $cert1 = "certutil" ascii nocase
        $cert2 = "-urlcache" ascii nocase
        $cert3 = "-split" ascii nocase
        $cert4 = "-decode" ascii nocase
        $cert5 = "-decodehex" ascii nocase
        $cert6 = "-f " ascii nocase

        // Bitsadmin download abuse
        $bits1 = "bitsadmin" ascii nocase
        $bits2 = "/transfer" ascii nocase
        $bits3 = "/download" ascii nocase
        $bits4 = "/priority" ascii nocase
        $bits5 = "Start-BitsTransfer" ascii nocase

        // Download URL indicators
        $url1 = "http://" ascii nocase
        $url2 = "https://" ascii nocase
        $url3 = "ftp://" ascii nocase

    condition:
        ($cert1 and any of ($cert2, $cert3, $cert4, $cert5) and any of ($url*)) or
        ($bits1 and any of ($bits2, $bits3) and any of ($url*)) or
        ($bits5 and any of ($url*) and $cert6)
}

rule loader_lolbin_proxy_execution {
    meta:
        description = "ARGUS detected LOLBin proxy execution — abusing mshta, regsvr32, or rundll32 to execute arbitrary code through trusted Microsoft binaries, bypassing application whitelisting."
        severity = "high"
        weight = 24
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // Mshta abuse
        $mshta1 = "mshta" ascii nocase
        $mshta2 = "mshta.exe" ascii nocase
        $mshta3 = "javascript:" ascii nocase
        $mshta4 = "vbscript:" ascii nocase

        // Regsvr32 abuse (Squiblydoo)
        $reg1 = "regsvr32" ascii nocase
        $reg2 = "/s " ascii nocase
        $reg3 = "/i:" ascii nocase
        $reg4 = "scrobj.dll" ascii nocase
        $reg5 = ".sct" ascii nocase

        // Rundll32 abuse
        $rund1 = "rundll32" ascii nocase
        $rund2 = "rundll32.exe" ascii nocase
        $rund3 = "javascript:" ascii nocase
        $rund4 = "shell32.dll" ascii nocase
        $rund5 = ",#" ascii  // ordinal-based DLL function call

        // Remote payload fetch in LOLBin context
        $remote1 = "http://" ascii nocase
        $remote2 = "https://" ascii nocase
        $remote3 = "\\\\*\\" ascii  // UNC path

        // Inline script indicators
        $script1 = "ActiveXObject" ascii
        $script2 = "WScript.Shell" ascii nocase
        $script3 = "GetObject" ascii
        $script4 = "ScriptControl" ascii

    condition:
        ($mshta1 and (any of ($mshta3, $mshta4) or any of ($script*))) or
        ($reg1 and $reg3 and any of ($reg4, $reg5, $remote1, $remote2)) or
        (any of ($rund1, $rund2) and any of ($remote*) and any of ($script*)) or
        (any of ($mshta1, $reg1, $rund1) and any of ($remote*) and any of ($script*))
}

rule loader_iso_vhd_motw_bypass {
    meta:
        description = "ARGUS detected ISO/VHD/IMG container abuse for Mark-of-the-Web bypass — packaging malicious payloads inside disk image files so extracted contents lack the MotW zone identifier, bypassing SmartScreen and Protected View."
        severity = "high"
        weight = 24
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // ISO 9660 magic
        $iso_magic = { 43 44 30 30 31 }       // "CD001" at offset 0x8001+

        // VHD footer magic
        $vhd_magic = "conectix" ascii

        // VHDX file identifier
        $vhdx_magic = "vhdxfile" ascii

        // IMG/disk image indicators
        $img1 = ".iso" ascii nocase
        $img2 = ".vhd" ascii nocase
        $img3 = ".vhdx" ascii nocase
        $img4 = ".img" ascii nocase

        // Payload types commonly abused inside containers
        $payload1 = ".exe" ascii nocase
        $payload2 = ".dll" ascii nocase
        $payload3 = ".lnk" ascii nocase
        $payload4 = ".bat" ascii nocase
        $payload5 = ".cmd" ascii nocase
        $payload6 = ".js" ascii nocase
        $payload7 = ".vbs" ascii nocase
        $payload8 = ".ps1" ascii nocase
        $payload9 = ".hta" ascii nocase

        // MotW-related references
        $motw1 = "Zone.Identifier" ascii
        $motw2 = "ZoneId" ascii
        $motw3 = ":Zone.Identifier" ascii

    condition:
        (any of ($iso_magic, $vhd_magic, $vhdx_magic) and 2 of ($payload*)) or
        (2 of ($img*) and any of ($motw*) and any of ($payload*)) or
        (any of ($iso_magic, $vhd_magic, $vhdx_magic) and any of ($motw*))
}

rule loader_wmi_event_subscription_persistence {
    meta:
        description = "ARGUS detected WMI event subscription for persistent code execution — creating WMI event filters and consumers to execute payloads on system events without traditional persistence mechanisms."
        severity = "high"
        weight = 24
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // WMI event subscription classes
        $wmi1 = "__EventFilter" ascii
        $wmi2 = "__EventConsumer" ascii
        $wmi3 = "__FilterToConsumerBinding" ascii
        $wmi4 = "ActiveScriptEventConsumer" ascii
        $wmi5 = "CommandLineEventConsumer" ascii

        // WMI creation methods
        $create1 = "Set-WmiInstance" ascii nocase
        $create2 = "Invoke-WmiMethod" ascii nocase
        $create3 = "ManagementClass" ascii
        $create4 = "Put(" ascii
        $create5 = "ExecMethod" ascii

        // Event query language
        $wql1 = "SELECT * FROM" ascii nocase
        $wql2 = "__InstanceCreationEvent" ascii
        $wql3 = "__InstanceModificationEvent" ascii
        $wql4 = "Win32_ProcessStartTrace" ascii

    condition:
        2 of ($wmi*) and any of ($create*) or
        (any of ($wmi*) and any of ($wql*) and any of ($create*))
}

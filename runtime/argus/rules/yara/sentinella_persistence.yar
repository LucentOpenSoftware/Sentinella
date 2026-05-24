/*
    Sentinella ARGUS Intelligence Pack — Persistence & Evasion
    Category: persistence
    Version: 2026.1
    Author: Sentinella
    License: GPL-2.0

    Detects advanced persistence mechanisms, security tool evasion,
    and environment discovery behavior.
*/

rule scheduled_task_persistence {
    meta:
        description = "ARGUS detected creation of a Windows scheduled task for persistence — ensures malware survives reboots by registering as a recurring task."
        severity = "high"
        weight = 20
        category = "persistence"
        author = "Sentinella"
    strings:
        $schtasks = "schtasks" ascii nocase
        $create = "/create" ascii nocase
        $sc = "/sc" ascii nocase
        $tr = "/tr" ascii nocase
        $tn = "/tn" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $schtasks and $create and $tr and ($sc or $tn)
}

rule wmi_persistence {
    meta:
        description = "ARGUS detected WMI event subscription creation — an advanced persistence technique that survives reboots and is difficult to detect."
        severity = "high"
        weight = 25
        category = "persistence"
        author = "Sentinella"
    strings:
        $filter = "__EventFilter" ascii
        $consumer1 = "CommandLineEventConsumer" ascii
        $consumer2 = "ActiveScriptEventConsumer" ascii
        $binding = "FilterToConsumerBinding" ascii
        $wmi = "ManagementObject" ascii
    condition:
        uint16(0) == 0x5A4D and
        $filter and any of ($consumer*) and ($binding or $wmi)
}

rule security_tool_termination {
    meta:
        description = "ARGUS detected code that targets security tools for termination — a critical evasion technique used by ransomware and advanced malware."
        severity = "critical"
        weight = 35
        category = "persistence"
        author = "Sentinella"
    strings:
        $taskkill = "taskkill" ascii nocase
        $malw1 = "malwarebytes" ascii nocase
        $malw2 = "avgui" ascii nocase
        $malw3 = "avguard" ascii nocase
        $malw4 = "msmpeng" ascii nocase
        $malw5 = "mcshield" ascii nocase
        $malw6 = "kavtray" ascii nocase
        $malw7 = "egui" ascii nocase
        $malw8 = "bdagent" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $taskkill and 3 of ($malw*)
}

rule environment_discovery {
    meta:
        description = "ARGUS detected systematic environment discovery behavior — gathering hardware, network, and software information typically seen in initial reconnaissance stages."
        severity = "medium"
        weight = 12
        category = "persistence"
        author = "Sentinella"
    strings:
        $info1 = "systeminfo" ascii nocase
        $info2 = "ipconfig" ascii nocase
        $info3 = "whoami" ascii nocase
        $info4 = "hostname" ascii nocase
        $info5 = "net user" ascii nocase
        $info6 = "tasklist" ascii nocase
        $info7 = "wmic" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        4 of ($info*)
}

rule uac_bypass_fodhelper {
    meta:
        description = "ARGUS detected a UAC bypass technique using fodhelper.exe — allows privilege escalation without triggering the UAC consent prompt."
        severity = "critical"
        weight = 30
        category = "persistence"
        author = "Sentinella"
    strings:
        $fod = "fodhelper" ascii nocase
        $reg1 = "ms-settings\\Shell\\Open\\command" ascii nocase
        $reg2 = "DelegateExecute" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $fod and ($reg1 or $reg2)
}

rule uac_bypass_eventvwr {
    meta:
        description = "ARGUS detected a UAC bypass technique using eventvwr.exe — exploits registry hijacking for silent privilege escalation."
        severity = "critical"
        weight = 30
        category = "persistence"
        author = "Sentinella"
    strings:
        $evt = "eventvwr" ascii nocase
        $reg = "mscfile\\Shell\\Open\\command" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $evt and $reg
}

rule scheduled_task_com_persistence {
    meta:
        description = "ARGUS detected scheduled task creation via COM objects (ITaskService / ITaskFolder) — an advanced persistence technique that avoids schtasks.exe command-line logging and can bypass endpoint detection rules."
        severity = "high"
        weight = 28
        category = "persistence"
        author = "Sentinella"
    strings:
        // Task Scheduler COM CLSIDs and interface names
        $clsid = "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}" ascii nocase  // TaskScheduler CLSID
        $iid1 = "ITaskService" ascii
        $iid2 = "ITaskFolder" ascii
        $iid3 = "ITaskDefinition" ascii
        $iid4 = "IRegistrationInfo" ascii
        $iid5 = "ITriggerCollection" ascii
        $iid6 = "IActionCollection" ascii
        // COM instantiation
        $com1 = "CoCreateInstance" ascii
        $com2 = "CLSIDFromProgID" ascii
        $com3 = "Schedule.Service" ascii nocase
        // Registration methods
        $reg1 = "RegisterTaskDefinition" ascii
        $reg2 = "RegisterTask" ascii
        $reg3 = "GetFolder" ascii
        $reg4 = "Connect" ascii
        // PowerShell COM-based task creation
        $ps1 = "New-Object -ComObject" ascii nocase
        $ps2 = "Schedule.Service" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (($clsid and any of ($com*)) or
        (2 of ($iid*) and any of ($reg*)) or
        ($com3 and $reg1) or
        ($ps1 and $ps2))
}

rule wmi_event_subscription_persistence {
    meta:
        description = "ARGUS detected WMI event subscription persistence via WMI scripting or PowerShell — creates persistent event filters and consumers that survive reboots and execute arbitrary code on trigger conditions."
        severity = "critical"
        weight = 32
        category = "persistence"
        author = "Sentinella"
    strings:
        // WMI event subscription classes
        $class1 = "__EventFilter" ascii
        $class2 = "CommandLineEventConsumer" ascii
        $class3 = "ActiveScriptEventConsumer" ascii
        $class4 = "__FilterToConsumerBinding" ascii
        $class5 = "__IntervalTimerInstruction" ascii
        $class6 = "__AbsoluteTimerInstruction" ascii
        // WMI creation methods
        $create1 = "Set-WmiInstance" ascii nocase
        $create2 = "New-CimInstance" ascii nocase
        $create3 = "SWbemServices" ascii
        $create4 = "ExecMethod" ascii
        $create5 = "SpawnInstance_" ascii
        $create6 = "PutInstance" ascii
        // WMI namespace targets
        $ns1 = "root\\subscription" ascii nocase
        $ns2 = "root\\cimv2" ascii nocase
        $ns3 = "root/subscription" ascii nocase
        // WMI persistence trigger events
        $trigger1 = "Win32_ProcessStartTrace" ascii
        $trigger2 = "__InstanceCreationEvent" ascii
        $trigger3 = "__InstanceModificationEvent" ascii
        $trigger4 = "Win32_LogonSession" ascii
    condition:
        (2 of ($class*) and any of ($create*)) or
        (any of ($class*) and any of ($ns*) and any of ($create*)) or
        (any of ($trigger*) and $class1 and any of ($class2, $class3))
}

rule dll_search_order_hijack_system32 {
    meta:
        description = "ARGUS detected indicators of DLL search order hijacking targeting System32 — involves planting a malicious DLL in a location that is searched before the legitimate System32 path, enabling code execution in the context of trusted processes."
        severity = "critical"
        weight = 30
        category = "persistence"
        author = "Sentinella"
    strings:
        // Common hijackable DLLs in System32
        $dll1 = "version.dll" ascii nocase
        $dll2 = "winmm.dll" ascii nocase
        $dll3 = "userenv.dll" ascii nocase
        $dll4 = "dbghelp.dll" ascii nocase
        $dll5 = "msimg32.dll" ascii nocase
        $dll6 = "dwmapi.dll" ascii nocase
        $dll7 = "uxtheme.dll" ascii nocase
        $dll8 = "cryptsp.dll" ascii nocase
        $dll9 = "profapi.dll" ascii nocase
        $dll10 = "WTSAPI32.dll" ascii nocase
        // DLL forwarding / proxying indicators
        $fwd1 = "DllGetClassObject" ascii
        $fwd2 = "DllCanUnloadNow" ascii
        $fwd3 = "GetProcAddress" ascii
        $fwd4 = "LoadLibraryA" ascii
        $fwd5 = "LoadLibraryW" ascii
        $fwd6 = "LoadLibraryExW" ascii
        // Path manipulation for hijack
        $path1 = "SetDllDirectoryW" ascii
        $path2 = "AddDllDirectory" ascii
        $path3 = "\\System32\\" ascii nocase
        $path4 = "GetSystemDirectoryW" ascii
        // Proxy DLL pattern: loading original and forwarding exports
        $proxy1 = "original" ascii nocase
        $proxy2 = "_orig" ascii nocase
        $proxy3 = ".dll.bak" ascii nocase
        $proxy4 = "real_" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2097152 and
        (2 of ($dll*) and 2 of ($fwd*) and any of ($path*)) or
        (any of ($dll*) and any of ($proxy*) and 2 of ($fwd*)) or
        (any of ($path1, $path2) and 2 of ($dll*) and $path3)
}

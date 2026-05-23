/*
    Sentinella ARGUS Intelligence Pack — Persistence & Evasion
    Category: persistence
    Version: 2025.1
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

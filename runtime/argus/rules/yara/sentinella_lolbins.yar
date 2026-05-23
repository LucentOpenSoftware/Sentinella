/*
    Sentinella ARGUS Intelligence Pack — LOLBin Abuse Detection
    Category: lolbin
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Living-Off-The-Land Binaries — detects abuse of legitimate Windows
    tools for malware delivery, execution, and evasion.
*/

rule lolbin_mshta_payload {
    meta:
        description = "ARGUS detected mshta.exe being invoked with a remote URL or inline script — a technique to execute code bypassing application whitelisting."
        severity = "high"
        weight = 25
        category = "lolbin"
        author = "Sentinella"
    strings:
        $mshta = "mshta" ascii nocase
        $http = "http://" ascii nocase
        $https = "https://" ascii nocase
        $js = "javascript:" ascii nocase
        $vbs = "vbscript:" ascii nocase
    condition:
        $mshta and (any of ($http, $https, $js, $vbs))
}

rule lolbin_regsvr32_scrobj {
    meta:
        description = "ARGUS detected regsvr32.exe Squiblydoo technique — executes remote scriptlets to bypass application whitelisting."
        severity = "high"
        weight = 28
        category = "lolbin"
        author = "Sentinella"
    strings:
        $regsvr = "regsvr32" ascii nocase
        $scrobj = "scrobj.dll" ascii nocase
        $i_flag = "/i:" ascii nocase
        $s_flag = "/s" ascii nocase
    condition:
        $regsvr and $scrobj and ($i_flag or $s_flag)
}

rule lolbin_wmic_process_create {
    meta:
        description = "ARGUS detected WMIC process creation — a technique for lateral movement and remote code execution."
        severity = "high"
        weight = 22
        category = "lolbin"
        author = "Sentinella"
    strings:
        $wmic = "wmic" ascii nocase
        $proc = "process" ascii nocase
        $call = "call" ascii nocase
        $create = "create" ascii nocase
    condition:
        $wmic and $proc and $call and $create
}

rule lolbin_rundll32_javascript {
    meta:
        description = "ARGUS detected rundll32.exe executing JavaScript — a LOLBin technique for code execution without a script file on disk."
        severity = "high"
        weight = 25
        category = "lolbin"
        author = "Sentinella"
    strings:
        $rundll = "rundll32" ascii nocase
        $js = "javascript:" ascii nocase
        $mshtml = "mshtml" ascii nocase
    condition:
        $rundll and ($js or $mshtml)
}

rule lolbin_cmstp_inf_install {
    meta:
        description = "ARGUS detected CMSTP.exe INF-based code execution — a UAC bypass technique that executes commands via Connection Manager profiles."
        severity = "high"
        weight = 25
        category = "lolbin"
        author = "Sentinella"
    strings:
        $cmstp = "cmstp" ascii nocase
        $inf = ".inf" ascii nocase
        $au = "/au" ascii nocase
        $s = "/s" ascii nocase
    condition:
        $cmstp and $inf and ($au or $s)
}

rule lolbin_forfiles_execution {
    meta:
        description = "ARGUS detected forfiles.exe command execution — an uncommon LOLBin technique to run arbitrary commands."
        severity = "medium"
        weight = 18
        category = "lolbin"
        author = "Sentinella"
    strings:
        $forfiles = "forfiles" ascii nocase
        $c_flag = "/c" ascii nocase
        $cmd = "cmd" ascii nocase
    condition:
        $forfiles and $c_flag and $cmd
}

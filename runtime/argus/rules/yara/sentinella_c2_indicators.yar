/*
    Sentinella ARGUS Intelligence Pack — C2 Communication Indicators
    Category: c2_indicators
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects command-and-control communication patterns, dead-drop
    resolvers, and covert channel indicators.
*/

rule c2_pastebin_resolver {
    meta:
        description = "ARGUS detected Pastebin-based C2 resolution — a technique where malware retrieves command server addresses from public paste sites."
        severity = "high"
        weight = 25
        category = "c2_indicators"
        author = "Sentinella"
    strings:
        $paste1 = "pastebin.com/raw/" ascii nocase
        $paste2 = "hastebin.com/raw/" ascii nocase
        $paste3 = "paste.ee/r/" ascii nocase
        $paste4 = "rentry.co/raw/" ascii nocase
        $exec1 = "CreateProcessW" ascii
        $exec2 = "ShellExecuteW" ascii
        $exec3 = "WinExec" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($paste*) and
        any of ($exec*)
}

rule c2_telegram_bot_exfil {
    meta:
        description = "ARGUS detected Telegram Bot API usage for data exfiltration — stolen data is sent to attacker-controlled Telegram channels."
        severity = "high"
        weight = 25
        category = "c2_indicators"
        author = "Sentinella"
    strings:
        $tg1 = "api.telegram.org/bot" ascii
        $tg2 = "/sendDocument" ascii
        $tg3 = "/sendMessage" ascii
        $tg4 = "/sendPhoto" ascii
        $chat = "chat_id" ascii
    condition:
        $tg1 and any of ($tg2, $tg3, $tg4) and $chat
}

rule c2_discord_webhook_stealer {
    meta:
        description = "ARGUS detected Discord webhook infrastructure combined with data collection — a common stealer exfiltration pattern."
        severity = "high"
        weight = 28
        category = "c2_indicators"
        author = "Sentinella"
    strings:
        $wh1 = "discord.com/api/webhooks/" ascii
        $wh2 = "discordapp.com/api/webhooks/" ascii
        $data1 = "embeds" ascii
        $data2 = "content" ascii
        $data3 = "username" ascii
        $collect1 = "Login Data" ascii
        $collect2 = "Cookies" ascii
        $collect3 = "wallet" ascii nocase
    condition:
        any of ($wh*) and
        any of ($data*) and
        any of ($collect*)
}

rule c2_steam_dead_drop {
    meta:
        description = "ARGUS detected Steam community profile used as a dead-drop resolver — malware reads C2 addresses hidden in Steam profile text."
        severity = "high"
        weight = 22
        category = "c2_indicators"
        author = "Sentinella"
    strings:
        $steam = "steamcommunity.com" ascii nocase
        $profile = "/profiles/" ascii
        $http = "InternetOpenUrlA" ascii
        $parse = "regex" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $steam and $profile and ($http or $parse)
}

rule c2_raw_socket_beacon {
    meta:
        description = "ARGUS detected raw socket creation with periodic beaconing behavior combined with evasion — consistent with custom C2 implant communication."
        severity = "high"
        weight = 20
        category = "c2_indicators"
        author = "Sentinella"
    strings:
        $ws1 = "WSAStartup" ascii
        $ws2 = "WSASocketW" ascii
        $connect = "connect" ascii
        $send = "send" ascii
        $recv = "recv" ascii
        $sleep = "Sleep" ascii
        $timer = "SetTimer" ascii
        // Require anti-analysis or obfuscation to distinguish from normal network apps.
        $evasion1 = "IsDebuggerPresent" ascii
        $evasion2 = "VirtualProtect" ascii
        $evasion3 = "NtQueryInformationProcess" ascii
        $evasion4 = "GetTickCount" ascii
        $hidden = "SW_HIDE" ascii
        $cmd = "cmd.exe" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5242880 and
        any of ($ws*) and
        $connect and $send and $recv and
        any of ($sleep, $timer) and
        (any of ($evasion*) or $hidden or $cmd)
}

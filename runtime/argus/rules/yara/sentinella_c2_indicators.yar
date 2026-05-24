/*
    Sentinella ARGUS Intelligence Pack — C2 Communication Indicators
    Category: c2_indicators
    Version: 2026.1
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

rule c2_cobalt_strike_beacon {
    meta:
        description = "ARGUS detected Cobalt Strike 4.x beacon indicators — including watermark patterns, malleable C2 profile artifacts, and named pipe signatures used by one of the most prevalent post-exploitation frameworks."
        severity = "critical"
        weight = 40
        category = "c2_indicators"
        author = "Sentinella"
    strings:
        // Cobalt Strike default named pipes
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii
        $pipe3 = "\\\\.\\pipe\\postex_" ascii
        $pipe4 = "\\\\.\\pipe\\postex_ssh_" ascii
        $pipe5 = "\\\\.\\pipe\\status_" ascii
        // Beacon configuration markers
        $cfg1 = { 00 01 00 01 00 02 }  // beacon type config header
        $cfg2 = { 00 02 00 01 00 02 }  // alternate beacon type
        $cfg3 = "ReflectiveLoader" ascii
        $cfg4 = "%s%s%s%s%s%s%s%s%s" ascii   // beacon format string
        // Malleable C2 profile indicators
        $mc2_1 = "/submit.php" ascii
        $mc2_2 = "/pixel.gif" ascii
        $mc2_3 = "/updates.rss" ascii
        $mc2_4 = "Content-Type: application/octet-stream" ascii
        $mc2_5 = "__cfduid" ascii
        // Cobalt Strike API imports
        $api1 = "VirtualAllocEx" ascii
        $api2 = "CreateRemoteThread" ascii
        $api3 = "WriteProcessMemory" ascii
        // Beacon watermark patterns (encoded 4-byte watermark)
        $watermark = { 2E 2F 2E 2F }
        $beacon_str = "beacon" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($pipe*) or
        any of ($cfg*) or
        (2 of ($mc2_*) and 2 of ($api*)) or
        ($watermark and $beacon_str))
}

rule c2_sliver_implant {
    meta:
        description = "ARGUS detected Sliver C2 framework implant indicators — an open-source adversary emulation framework increasingly used as a Cobalt Strike alternative by threat actors."
        severity = "critical"
        weight = 35
        category = "c2_indicators"
        author = "Sentinella"
    strings:
        // Sliver implant Go package paths
        $go1 = "github.com/bishopfox/sliver" ascii
        $go2 = "sliverpb" ascii
        $go3 = "sliver/protobuf" ascii
        // Sliver implant function names (Go binary artifacts)
        $fn1 = "RunSliver" ascii
        $fn2 = "StartBeaconLoop" ascii
        $fn3 = "ActiveC2" ascii
        $fn4 = "GetBeaconJitter" ascii
        $fn5 = "MtlsConnect" ascii
        $fn6 = "WGConnect" ascii
        $fn7 = "DnsConnect" ascii
        // Sliver transport indicators
        $tr1 = "wg-tunnel" ascii
        $tr2 = ".wg.sliver" ascii
        $tr3 = "mtls" ascii
        // Sliver protocol buffer markers
        $pb1 = "Envelope" ascii
        $pb2 = "tunpb" ascii
        $pb3 = "commonpb" ascii
        // General Go-compiled binary markers combined with Sliver strings
        $gobin = "Go build" ascii
    condition:
        (any of ($go*)) or
        (3 of ($fn*)) or
        ($gobin and 2 of ($tr*) and any of ($pb*))
}

rule c2_dns_over_https_tunnel {
    meta:
        description = "ARGUS detected DNS-over-HTTPS (DoH) endpoints used for C2 tunneling — threat actors abuse encrypted DNS to bypass network monitoring and exfiltrate data through DNS queries to DoH providers."
        severity = "high"
        weight = 28
        category = "c2_indicators"
        author = "Sentinella"
    strings:
        // Major DoH provider endpoints
        $doh1 = "dns.google/resolve" ascii nocase
        $doh2 = "cloudflare-dns.com/dns-query" ascii nocase
        $doh3 = "dns.quad9.net/dns-query" ascii nocase
        $doh4 = "doh.opendns.com/dns-query" ascii nocase
        $doh5 = "dns.nextdns.io" ascii nocase
        $doh6 = "mozilla.cloudflare-dns.com" ascii nocase
        $doh7 = "dns.adguard.com/dns-query" ascii nocase
        // DoH protocol markers
        $proto1 = "application/dns-json" ascii
        $proto2 = "application/dns-message" ascii
        $proto3 = "accept: application/dns" ascii nocase
        // DNS query construction for tunneling
        $tun1 = "TXT" ascii
        $tun2 = "CNAME" ascii
        $tun3 = "AAAA" ascii
        $tun4 = "base64" ascii nocase
        $tun5 = "base32" ascii nocase
        // Network API calls
        $http1 = "HttpSendRequestA" ascii
        $http2 = "InternetOpenA" ascii
        $http3 = "WinHttpSendRequest" ascii
        $http4 = "HttpOpenRequestA" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($doh*) and any of ($proto*)) or
        (any of ($doh*) and 2 of ($tun*) and any of ($http*))
}

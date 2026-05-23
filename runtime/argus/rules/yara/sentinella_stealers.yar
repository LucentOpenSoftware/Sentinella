/*
    Sentinella ARGUS Intelligence Pack — Stealer Detection
    Category: credential_theft
    Version: 2024.1
    Author: Sentinella
    License: GPL-2.0

    Detects common information stealer patterns including Discord token
    theft, browser credential access, and webhook-based exfiltration.
*/

rule discord_token_stealer {
    meta:
        description = "ARGUS identified credential theft behavior targeting Discord authentication tokens."
        severity = "high"
        weight = 28
        category = "credential_theft"
        author = "Sentinella"

    strings:
        $discord_path1 = "discord\\Local Storage" ascii nocase
        $discord_path2 = "discordcanary\\Local Storage" ascii nocase
        $discord_path3 = "discordptb\\Local Storage" ascii nocase
        $token_regex = /[MN][A-Za-z\d]{23,27}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27,}/ ascii
        $dpapi_prefix = "dQw4w9WgXcQ:" ascii
        $leveldb = "leveldb" ascii nocase
        $ldb_ext = ".ldb" ascii

    condition:
        2 of ($discord_path*) or
        ($token_regex and any of ($discord_path*)) or
        ($dpapi_prefix and any of ($discord_path*)) or
        ($leveldb and $ldb_ext and any of ($discord_path*))
}

rule webhook_exfiltration {
    meta:
        description = "ARGUS identified data exfiltration infrastructure using messaging platform webhooks combined with data collection indicators."
        severity = "high"
        weight = 22
        category = "credential_theft"
        author = "Sentinella"

    strings:
        $discord_webhook1 = "discord.com/api/webhooks/" ascii
        $discord_webhook2 = "discordapp.com/api/webhooks/" ascii
        $telegram_bot = "api.telegram.org/bot" ascii
        // Require data collection indicators alongside webhook.
        $cred1 = "Login Data" ascii
        $cred2 = "Cookies" ascii
        $cred3 = "Local Storage" ascii
        $cred4 = "wallet" ascii nocase
        $cred5 = "screenshot" ascii nocase

    condition:
        any of ($discord_webhook*, $telegram_bot) and any of ($cred*)
}

rule browser_credential_harvester {
    meta:
        description = "ARGUS identified systematic access to multiple browser credential stores — consistent with information stealer behavior."
        severity = "high"
        weight = 25
        category = "credential_theft"
        author = "Sentinella"

    strings:
        $chrome = "Google\\Chrome\\User Data" ascii nocase
        $edge = "Microsoft\\Edge\\User Data" ascii nocase
        $brave = "BraveSoftware\\Brave-Browser\\User Data" ascii nocase
        $firefox = "Mozilla\\Firefox\\Profiles" ascii nocase
        $opera = "Opera Software\\Opera Stable" ascii nocase
        $login_data = "Login Data" ascii
        $web_data = "Web Data" ascii
        $cookies = "Cookies" ascii

    condition:
        3 of ($chrome, $edge, $brave, $firefox, $opera) or
        (2 of ($chrome, $edge, $brave, $firefox, $opera) and any of ($login_data, $web_data, $cookies))
}

rule crypto_wallet_stealer {
    meta:
        description = "ARGUS detected access to cryptocurrency wallet storage locations — possible wallet theft attempt."
        severity = "high"
        weight = 22
        category = "credential_theft"
        author = "Sentinella"

    strings:
        $exodus = "Exodus\\exodus.wallet" ascii nocase
        $atomic = "atomic\\Local Storage" ascii nocase
        $electrum = "Electrum\\wallets" ascii nocase
        $metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $wallet_dat = "wallet.dat" ascii

    condition:
        2 of them
}

/*
    Sentinella ARGUS Intelligence Pack — GitHub-Distributed Stealer Detection
    Category: github_stealer
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects fake game mods, updaters, and cracked software distributed
    via GitHub that are actually information stealers. This is the #1
    attack vector targeting gamers and young users in 2024-2026.

    Common patterns:
    - Fake Roblox/Minecraft/Sims/GTA mods
    - Fake game cheats and trainers
    - Fake "updaters" for popular games
    - Fake crypto/AI/productivity tools
    - Usually PyInstaller or .NET packed
    - Steal Discord tokens, browser creds, crypto wallets
    - Exfiltrate via Discord webhooks or Telegram bots
*/

rule fake_game_mod_stealer_pyinstaller {
    meta:
        description = "ARGUS identified a PyInstaller-packaged executable with characteristics of a fake game mod stealer — combines game-related naming with credential theft behavior."
        severity = "critical"
        weight = 40
        category = "github_stealer"
        author = "Sentinella"

    strings:
        // PyInstaller markers.
        $pyinst1 = "_MEIPASS" ascii
        $pyinst2 = { 4D 45 49 0C 0B 0A 0B 0E }
        $pydll = /python3\d{1,2}\.dll/ ascii nocase

        // Game-related strings that suggest fake mod/updater.
        $game1 = "roblox" ascii nocase
        $game2 = "minecraft" ascii nocase
        $game3 = "fortnite" ascii nocase
        $game4 = "valorant" ascii nocase
        $game5 = "sims" ascii nocase
        $game6 = "gta" ascii nocase
        $game7 = "updater" ascii nocase
        $game8 = "mod" ascii nocase
        $game9 = "cheat" ascii nocase
        $game10 = "hack" ascii nocase
        $game11 = "trainer" ascii nocase
        $game12 = "crack" ascii nocase
        $game13 = "keygen" ascii nocase
        $game14 = "skin" ascii nocase
        $game15 = "spoofer" ascii nocase

        // Credential theft indicators.
        $steal1 = "discord" ascii nocase
        $steal2 = "Local Storage" ascii nocase
        $steal3 = "Login Data" ascii nocase
        $steal4 = "webhook" ascii nocase
        $steal5 = "token" ascii nocase
        $steal6 = ".ldb" ascii
        $steal7 = "leveldb" ascii nocase
        $steal8 = "wallet" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        ($pyinst1 or $pyinst2 or $pydll) and
        2 of ($game*) and
        2 of ($steal*)
}

rule fake_game_mod_stealer_dotnet {
    meta:
        description = "ARGUS identified a .NET executable with fake game mod characteristics combined with credential theft behavior."
        severity = "critical"
        weight = 40
        category = "github_stealer"
        author = "Sentinella"

    strings:
        // .NET markers.
        $dotnet1 = "_CorExeMain" ascii
        $dotnet2 = "mscoree.dll" ascii nocase
        $dotnet3 = "#Strings" ascii
        $dotnet4 = "#GUID" ascii

        // Game-related branding.
        $game1 = "roblox" ascii nocase
        $game2 = "minecraft" ascii nocase
        $game3 = "fortnite" ascii nocase
        $game4 = "valorant" ascii nocase
        $game5 = "sims" ascii nocase
        $game6 = "updater" ascii nocase
        $game7 = "mod" ascii nocase
        $game8 = "cheat" ascii nocase
        $game9 = "trainer" ascii nocase
        $game10 = "spoofer" ascii nocase

        // Credential theft.
        $steal1 = "discord" ascii nocase
        $steal2 = "Local Storage" ascii nocase
        $steal3 = "Login Data" ascii nocase
        $steal4 = "api/webhooks" ascii nocase
        $steal5 = "token" ascii nocase
        $steal6 = "Cookies" ascii nocase
        $steal7 = "wallet" ascii nocase
        $steal8 = "api.telegram" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        any of ($dotnet*) and
        2 of ($game*) and
        2 of ($steal*)
}

rule github_release_stealer_pattern {
    meta:
        description = "ARGUS detected an executable combining GitHub release distribution markers with credential harvesting capabilities — consistent with fake open-source tool stealers."
        severity = "high"
        weight = 30
        category = "github_stealer"
        author = "Sentinella"

    strings:
        // GitHub distribution markers.
        $gh1 = "github.com" ascii nocase
        $gh2 = "github.io" ascii nocase
        $gh3 = "githubusercontent" ascii nocase
        $gh4 = "releases/download" ascii nocase

        // Multi-browser credential harvesting (3+ browsers = stealer).
        $browser1 = "Google\\Chrome\\User Data" ascii nocase
        $browser2 = "Microsoft\\Edge\\User Data" ascii nocase
        $browser3 = "BraveSoftware" ascii nocase
        $browser4 = "Mozilla\\Firefox\\Profiles" ascii nocase
        $browser5 = "Opera Software" ascii nocase

        // Exfiltration.
        $exfil1 = "discord.com/api/webhooks" ascii nocase
        $exfil2 = "api.telegram.org/bot" ascii nocase
        $exfil3 = "discordapp.com/api/webhooks" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        any of ($gh*) and
        3 of ($browser*) and
        any of ($exfil*)
}

rule pyarmor_obfuscated_stealer {
    meta:
        description = "ARGUS detected a Pyarmor-obfuscated Python executable — Pyarmor encrypts Python bytecode making static analysis nearly impossible, frequently used by modern stealers."
        severity = "high"
        weight = 28
        category = "github_stealer"
        author = "Sentinella"

    strings:
        $pyarmor1 = "pyarmor" ascii nocase
        $pyarmor2 = "_pytransform" ascii nocase
        $pyarmor3 = "pytransform" ascii nocase
        $pyinst = "_MEIPASS" ascii

        // Combined with stealing indicators.
        $steal1 = "discord" ascii nocase
        $steal2 = "webhook" ascii nocase
        $steal3 = "token" ascii nocase
        $steal4 = "Login Data" ascii nocase
        $steal5 = "wallet" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        any of ($pyarmor*) and
        $pyinst and
        2 of ($steal*)
}

rule stealer_exfiltration_infrastructure {
    meta:
        description = "ARGUS identified an executable with both multi-platform credential harvesting AND data exfiltration endpoints — high-confidence information stealer."
        severity = "critical"
        weight = 45
        category = "github_stealer"
        author = "Sentinella"

    strings:
        // Multi-target credential harvesting (cast a wide net).
        $cred1 = "Login Data" ascii
        $cred2 = "Web Data" ascii
        $cred3 = "Cookies" ascii
        $cred4 = "Local Storage" ascii
        $cred5 = "discord" ascii nocase
        $cred6 = "exodus" ascii nocase
        $cred7 = "metamask" ascii nocase
        $cred8 = "steam" ascii nocase
        $cred9 = "telegram" ascii nocase

        // Data assembly (collecting stolen data before exfil).
        $collect1 = "passwords" ascii nocase
        $collect2 = "autofill" ascii nocase
        $collect3 = "credit" ascii nocase
        $collect4 = "screenshot" ascii nocase
        $collect5 = "system info" ascii nocase
        $collect6 = "ip address" ascii nocase

        // Exfiltration endpoints.
        $exfil1 = "discord.com/api/webhooks/" ascii
        $exfil2 = "api.telegram.org/bot" ascii
        $exfil3 = "discordapp.com/api/webhooks/" ascii

        // ZIP creation for exfil bundle.
        $zip1 = "PK\x03\x04" ascii
        $zip2 = "zipfile" ascii nocase
        $zip3 = "shutil" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        4 of ($cred*) and
        2 of ($collect*) and
        (any of ($exfil*) or any of ($zip*))
}

/*
    Sentinella ARGUS Intelligence Pack — Electron/Node.js Malware Detection
    Category: script_abuse
    Version: 2026.1
    Author: Sentinella
    License: GPL-2.0

    Detects malicious Electron and Node.js application patterns including
    asar archive manipulation, node_modules trojanization, fake Electron
    app impersonation, NSIS/Squirrel installer abuse, preload script
    injection, and child_process spawn abuse. Reflects the massive growth
    of Electron-based malware in 2024-2026.
*/

rule electron_asar_manipulation {
    meta:
        description = "ARGUS detected Electron asar archive manipulation combined with dangerous code execution — modifying asar archives enables injection of malicious code into trusted Electron applications."
        severity = "high"
        weight = 22
        category = "script_abuse"
        author = "Sentinella"

    strings:
        // Asar archive manipulation APIs.
        $asar1 = "asar.extractAll" ascii
        $asar2 = "asar.createPackage" ascii
        $asar3 = "original-fs" ascii
        $asar4 = "createPackageWithOptions" ascii
        $asar5 = "asar extract" ascii nocase

        // File path targeting of Electron app asar archives.
        $target1 = "app.asar" ascii
        $target2 = "resources\\app.asar" ascii nocase
        $target3 = "resources/app.asar" ascii

        // Code injection or modification patterns.
        $inject1 = "fs.writeFileSync" ascii
        $inject2 = "fs.appendFileSync" ascii
        $inject3 = "require('child_process')" ascii
        $inject4 = "child_process" ascii
        $inject5 = "eval(" ascii

    condition:
        (any of ($asar*) or any of ($target*)) and
        any of ($inject*) and
        (any of ($asar*) and any of ($target*))
}

rule node_modules_trojanization {
    meta:
        description = "ARGUS detected node_modules supply chain compromise patterns — malicious postinstall scripts or trojanized packages that execute payloads during npm install."
        severity = "critical"
        weight = 28
        category = "script_abuse"
        author = "Sentinella"

    strings:
        // npm lifecycle script abuse.
        $hook1 = "\"preinstall\"" ascii
        $hook2 = "\"postinstall\"" ascii
        $hook3 = "\"preuninstall\"" ascii

        // Obfuscated or dangerous payload in install scripts.
        $payload1 = "child_process" ascii
        $payload2 = "execSync" ascii
        $payload3 = "spawnSync" ascii
        $payload4 = "Buffer.from(" ascii
        $payload5 = "eval(Buffer" ascii
        $payload6 = "require('https')" ascii
        $payload7 = "require('http')" ascii

        // Exfiltration or C2 during install.
        $exfil1 = "os.hostname()" ascii
        $exfil2 = "os.userInfo()" ascii
        $exfil3 = "os.platform()" ascii
        $exfil4 = "dns.resolve" ascii
        $exfil5 = ".fetch(" ascii

        // Package.json context.
        $pkg1 = "\"name\":" ascii
        $pkg2 = "\"version\":" ascii
        $pkg3 = "\"scripts\":" ascii

    condition:
        any of ($hook*) and
        2 of ($payload*) and
        (any of ($exfil*) or any of ($pkg*))
}

rule fake_electron_app_impersonation {
    meta:
        description = "ARGUS identified an executable impersonating a popular Electron application update or installer — targets Discord, VSCode, Slack, and other widely-used desktop apps."
        severity = "high"
        weight = 25
        category = "script_abuse"
        author = "Sentinella"

    strings:
        // Fake update/installer names for popular Electron apps.
        $fake1 = "DiscordSetup" ascii nocase
        $fake2 = "Discord-Update" ascii nocase
        $fake3 = "VSCodeUpdate" ascii nocase
        $fake4 = "VSCode-Installer" ascii nocase
        $fake5 = "SlackSetup" ascii nocase
        $fake6 = "Slack-Update" ascii nocase
        $fake7 = "TeamsUpdate" ascii nocase
        $fake8 = "SignalSetup" ascii nocase
        $fake9 = "Notion-Update" ascii nocase

        // Electron framework markers (to confirm it claims to be Electron).
        $electron1 = "electron.asar" ascii
        $electron2 = "electron" ascii nocase
        $electron3 = "resources\\app" ascii nocase

        // Malicious behavior not found in legitimate updates.
        $mal1 = "Login Data" ascii
        $mal2 = "Cookies" ascii
        $mal3 = "discord.com/api/webhooks" ascii
        $mal4 = "api.telegram.org/bot" ascii
        $mal5 = "\\CurrentVersion\\Run" ascii nocase
        $mal6 = "CryptUnprotectData" ascii
        $mal7 = "powershell" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        any of ($fake*) and
        any of ($electron*) and
        2 of ($mal*)
}

rule nsis_squirrel_electron_abuse {
    meta:
        description = "ARGUS detected NSIS or Squirrel installer packaging an Electron application with embedded malicious payloads — abuses trusted installer frameworks to deliver trojaned apps."
        severity = "high"
        weight = 22
        category = "script_abuse"
        author = "Sentinella"

    strings:
        // NSIS installer markers.
        $nsis1 = "Nullsoft" ascii
        $nsis2 = "NSIS" ascii
        $nsis3 = "NsExec" ascii

        // Squirrel installer markers.
        $squirrel1 = "Squirrel" ascii
        $squirrel2 = "squirrel.exe" ascii nocase
        $squirrel3 = "--squirrel-install" ascii
        $squirrel4 = "Update.exe" ascii

        // Electron app content inside installer.
        $electron1 = "electron.asar" ascii
        $electron2 = "app.asar" ascii
        $electron3 = "resources\\app" ascii nocase

        // Malicious post-installation behavior.
        $post1 = "powershell" ascii nocase
        $post2 = "cmd /c" ascii nocase
        $post3 = "schtasks" ascii nocase
        $post4 = "\\CurrentVersion\\Run" ascii nocase
        $post5 = "discord.com/api/webhooks" ascii
        $post6 = "Invoke-WebRequest" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (any of ($nsis*) or any of ($squirrel*)) and
        any of ($electron*) and
        2 of ($post*)
}

rule electron_preload_injection {
    meta:
        description = "ARGUS detected Electron preload script injection — malicious preload scripts run in privileged renderer context with full Node.js access, enabling credential theft and code execution."
        severity = "high"
        weight = 25
        category = "script_abuse"
        author = "Sentinella"

    strings:
        // Preload script configuration.
        $preload1 = "preload" ascii
        $preload2 = "webPreferences" ascii
        $preload3 = "contextBridge" ascii

        // Dangerous Electron security settings.
        $danger1 = "nodeIntegration" ascii
        $danger2 = "contextIsolation" ascii
        $danger3 = "webSecurity" ascii
        $danger4 = "allowRunningInsecureContent" ascii
        $danger5 = "experimentalFeatures" ascii

        // Preload script performing credential access or IPC abuse.
        $abuse1 = "require('fs')" ascii
        $abuse2 = "require('child_process')" ascii
        $abuse3 = "require('os')" ascii
        $abuse4 = "ipcRenderer.send" ascii
        $abuse5 = "process.env" ascii
        $abuse6 = "Login Data" ascii
        $abuse7 = "Cookies" ascii

    condition:
        any of ($preload*) and
        2 of ($danger*) and
        2 of ($abuse*)
}

rule node_child_process_abuse {
    meta:
        description = "ARGUS detected Node.js child_process abuse with obfuscated command execution — spawning system commands from Node.js with encoded or hidden arguments indicates malicious behavior."
        severity = "high"
        weight = 22
        category = "script_abuse"
        author = "Sentinella"

    strings:
        // child_process spawn/exec patterns.
        $cp1 = "child_process" ascii
        $cp2 = ".exec(" ascii
        $cp3 = ".execSync(" ascii
        $cp4 = ".spawn(" ascii
        $cp5 = ".spawnSync(" ascii
        $cp6 = "execFile(" ascii

        // Obfuscated or suspicious command targets.
        $cmd1 = "powershell" ascii nocase
        $cmd2 = "cmd.exe" ascii nocase
        $cmd3 = "cmd /c" ascii nocase
        $cmd4 = "wscript" ascii nocase
        $cmd5 = "cscript" ascii nocase
        $cmd6 = "mshta" ascii nocase
        $cmd7 = "certutil" ascii nocase
        $cmd8 = "bitsadmin" ascii nocase

        // Encoding/obfuscation of the payload.
        $obf1 = "Buffer.from(" ascii
        $obf2 = "atob(" ascii
        $obf3 = "\\x" ascii
        $obf4 = "String.fromCharCode" ascii
        $obf5 = "decodeURIComponent" ascii

    condition:
        $cp1 and
        any of ($cp2, $cp3, $cp4, $cp5, $cp6) and
        any of ($cmd*) and
        any of ($obf*)
}

rule electron_discord_injection {
    meta:
        description = "ARGUS detected Discord client modification for token theft — injects JavaScript into Discord's Electron app to intercept authentication tokens, credentials, and payment information."
        severity = "critical"
        weight = 30
        category = "script_abuse"
        author = "Sentinella"

    strings:
        // Discord Electron app modification targets.
        $disc1 = "discord_desktop_core" ascii nocase
        $disc2 = "discord\\modules" ascii nocase
        $disc3 = "discord\\app-" ascii nocase
        $disc4 = "core.asar" ascii

        // Token interception JavaScript.
        $token1 = "getToken" ascii
        $token2 = "localStorage" ascii
        $token3 = "mfa." ascii
        $token4 = "Authorization" ascii
        $token5 = "email" ascii nocase
        $token6 = "password" ascii nocase

        // Exfiltration from injected code.
        $exfil1 = "XMLHttpRequest" ascii
        $exfil2 = "fetch(" ascii
        $exfil3 = "webhook" ascii nocase
        $exfil4 = "discord.com/api/webhooks" ascii
        $exfil5 = "api.telegram.org" ascii

    condition:
        2 of ($disc*) and
        2 of ($token*) and
        any of ($exfil*)
}

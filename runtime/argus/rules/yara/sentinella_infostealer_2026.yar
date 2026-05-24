/*
    Sentinella ARGUS Intelligence Pack — Modern Infostealer Detection (2026)
    Category: credential_theft
    Version: 2026.1
    Author: Sentinella
    License: GPL-2.0

    Detects 2025-2026 infostealer techniques not covered by existing rules:
    Chromium App Bound encryption bypass, modern DPAPI abuse, session token
    theft, MFA data targeting, SSH key harvesting, cloud credential theft,
    and password manager vault targeting.
*/

rule chromium_app_bound_cookie_bypass {
    meta:
        description = "ARGUS detected Chromium App Bound Encryption bypass attempt — targets the v127+ cookie protection mechanism by extracting keys through the IElevator COM interface or direct decryption."
        severity = "critical"
        weight = 30
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // Chromium v127+ App Bound Encryption artifacts.
        $abe1 = "app_bound_encrypted_key" ascii
        $abe2 = "AppBoundEncryptionKey" ascii
        $abe3 = "IElevator" ascii
        $abe4 = "elevation_service" ascii nocase
        $abe5 = "AEAD_AES_256_CBC_HMAC_SHA256" ascii

        // Chrome cookie access alongside bypass.
        $cookie1 = "Cookies" ascii
        $cookie2 = "Network\\Cookies" ascii
        $cookie3 = "encrypted_value" ascii
        $cookie4 = "Local State" ascii
        $cookie5 = "os_crypt" ascii

        // Browser paths indicating multi-browser targeting.
        $path1 = "Google\\Chrome\\User Data" ascii nocase
        $path2 = "Microsoft\\Edge\\User Data" ascii nocase
        $path3 = "BraveSoftware\\Brave-Browser" ascii nocase

    condition:
        2 of ($abe*) and
        2 of ($cookie*) and
        any of ($path*)
}

rule dpapi_masterkey_extraction {
    meta:
        description = "ARGUS detected Windows DPAPI master key extraction — directly accessing master key files enables offline decryption of all DPAPI-protected secrets without calling CryptUnprotectData."
        severity = "critical"
        weight = 28
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // DPAPI master key file access patterns.
        $mk1 = "Microsoft\\Protect\\S-1-5-21-" ascii nocase
        $mk2 = "Microsoft\\Protect\\S-1-5-18" ascii nocase
        $mk3 = "Preferred" ascii
        $mk4 = "masterkey" ascii nocase

        // DPAPI blob parsing structures.
        $blob1 = { 01 00 00 00 D0 8C 9D DF 01 15 D1 11 }
        $blob2 = "CryptUnprotectData" ascii
        $blob3 = "BCryptDecrypt" ascii

        // Domain backup key access (enterprise DPAPI abuse).
        $domain1 = "BCKUPKEY" ascii
        $domain2 = "G$BCKUPKEY" ascii
        $domain3 = "ms-bkrp" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            (any of ($mk1, $mk2) and any of ($blob*)) or
            (any of ($domain*) and any of ($blob*)) or
            ($mk4 and any of ($mk1, $mk2) and $mk3)
        )
}

rule session_token_theft {
    meta:
        description = "ARGUS detected session token and cookie extraction targeting active web sessions — enables account takeover without requiring passwords or MFA."
        severity = "high"
        weight = 25
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // Session-specific cookie names targeted by modern stealers.
        $sess1 = "sessionid" ascii nocase
        $sess2 = "__Secure-1PSID" ascii
        $sess3 = "__Secure-3PSID" ascii
        $sess4 = "SSID" ascii
        $sess5 = "SID" ascii
        $sess6 = ".ROBLOSECURITY" ascii
        $sess7 = "connect.sid" ascii
        $sess8 = "li_at" ascii

        // Cookie database access.
        $db1 = "Cookies" ascii
        $db2 = "Network\\Cookies" ascii
        $db3 = "encrypted_value" ascii
        $db4 = "host_key" ascii
        $db5 = "SELECT " ascii nocase

        // Data exfiltration or collection.
        $exfil1 = "discord.com/api/webhooks" ascii
        $exfil2 = "api.telegram.org" ascii
        $exfil3 = "zipfile" ascii nocase
        $exfil4 = "base64" ascii nocase

    condition:
        3 of ($sess*) and
        2 of ($db*) and
        any of ($exfil*)
}

rule mfa_authenticator_data_theft {
    meta:
        description = "ARGUS detected targeting of MFA authenticator application data — stealing TOTP seeds or authenticator databases enables permanent MFA bypass."
        severity = "critical"
        weight = 28
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // Authenticator app data paths and databases.
        $auth1 = "Authy Desktop" ascii nocase
        $auth2 = "com.authy.authy" ascii nocase
        $auth3 = "Authenticator" ascii nocase
        $auth4 = "Google Authenticator" ascii nocase
        $auth5 = "Microsoft Authenticator" ascii nocase

        // TOTP/2FA data indicators.
        $totp1 = "totp_secret" ascii nocase
        $totp2 = "otpauth://" ascii
        $totp3 = "secret_seed" ascii nocase
        $totp4 = "2fa" ascii nocase
        $totp5 = "authenticator_tokens" ascii nocase
        $totp6 = "otp_secret" ascii nocase

        // File access behavior.
        $file1 = "ReadFile" ascii
        $file2 = "CopyFileW" ascii
        $file3 = "CreateFileW" ascii
        $file4 = "sqlite3" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($auth*) or 2 of ($totp*)) and
        any of ($file*)
}

rule ssh_key_harvester {
    meta:
        description = "ARGUS detected systematic SSH key and configuration harvesting — stealing private keys enables unauthorized remote access to servers and infrastructure."
        severity = "high"
        weight = 25
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // SSH key file targets.
        $ssh1 = "\\.ssh\\id_rsa" ascii nocase
        $ssh2 = "\\.ssh\\id_ed25519" ascii nocase
        $ssh3 = "\\.ssh\\id_ecdsa" ascii nocase
        $ssh4 = "\\.ssh\\known_hosts" ascii nocase
        $ssh5 = "\\.ssh\\config" ascii nocase
        $ssh6 = "\\.ssh\\authorized_keys" ascii nocase

        // SSH key content markers.
        $key1 = "OPENSSH PRIVATE KEY" ascii
        $key2 = "RSA PRIVATE KEY" ascii
        $key3 = "EC PRIVATE KEY" ascii
        $key4 = "PuTTY-User-Key-File" ascii

        // File collection behavior (copy/read/exfil).
        $act1 = "CopyFileW" ascii
        $act2 = "ReadFile" ascii
        $act3 = "discord.com/api/webhooks" ascii
        $act4 = "api.telegram.org" ascii
        $act5 = "zipfile" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (3 of ($ssh*) or 2 of ($key*)) and
        any of ($act*)
}

rule cloud_credential_theft {
    meta:
        description = "ARGUS detected scanning for cloud provider credential files — targeting AWS, Azure, and GCP configuration enables cloud infrastructure compromise."
        severity = "critical"
        weight = 28
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // AWS credential targets.
        $aws1 = "\\.aws\\credentials" ascii nocase
        $aws2 = "\\.aws\\config" ascii nocase
        $aws3 = "aws_access_key_id" ascii nocase
        $aws4 = "aws_secret_access_key" ascii nocase
        $aws5 = "aws_session_token" ascii nocase

        // Azure credential targets.
        $az1 = "\\.azure\\accessTokens.json" ascii nocase
        $az2 = "\\.azure\\azureProfile.json" ascii nocase
        $az3 = "AZURE_CLIENT_SECRET" ascii nocase
        $az4 = "msal_token_cache" ascii nocase

        // GCP credential targets.
        $gcp1 = "application_default_credentials.json" ascii nocase
        $gcp2 = "gcloud\\credentials.db" ascii nocase
        $gcp3 = "GOOGLE_APPLICATION_CREDENTIALS" ascii nocase
        $gcp4 = "gcloud\\access_tokens.db" ascii nocase

        // File collection indicators.
        $collect1 = "ReadFile" ascii
        $collect2 = "CopyFileW" ascii
        $collect3 = "CreateFileW" ascii

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($aws*) or 2 of ($az*) or 2 of ($gcp*)) and
        (
            any of ($collect*) or
            (any of ($aws*) and any of ($az*)) or
            (any of ($aws*) and any of ($gcp*)) or
            (any of ($az*) and any of ($gcp*))
        )
}

rule password_manager_vault_theft {
    meta:
        description = "ARGUS detected targeting of password manager vault databases — accessing locally stored vaults enables offline brute-force attacks against the master password."
        severity = "critical"
        weight = 28
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // KeePass vault files.
        $kp1 = ".kdbx" ascii nocase
        $kp2 = "KeePass" ascii nocase
        $kp3 = "kdbx" ascii nocase

        // Bitwarden local data.
        $bw1 = "Bitwarden" ascii nocase
        $bw2 = "bitwarden-vault" ascii nocase
        $bw3 = "data.json" ascii

        // 1Password local data.
        $op1 = "1Password" ascii nocase
        $op2 = "1password.sqlite" ascii nocase
        $op3 = "onepassword" ascii nocase

        // LastPass local data.
        $lp1 = "LastPass" ascii nocase
        $lp2 = "lastpass" ascii nocase
        $lp3 = "lp_vault" ascii nocase

        // File enumeration and collection behavior.
        $enum1 = "FindFirstFileW" ascii
        $enum2 = "FindNextFileW" ascii
        $enum3 = "CopyFileW" ascii
        $enum4 = "ReadFile" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            ($kp1 and $kp2) or
            (2 of ($bw*)) or
            (2 of ($op*)) or
            (2 of ($lp*)) or
            (any of ($kp*) and any of ($bw*) and any of ($op*))
        ) and
        2 of ($enum*)
}

rule browser_master_key_extraction {
    meta:
        description = "ARGUS detected direct extraction of Chromium browser master encryption key from Local State file — enables decryption of all stored passwords, cookies, and autofill data."
        severity = "high"
        weight = 25
        category = "credential_theft"
        author = "Sentinella"

    strings:
        // Local State file key extraction.
        $ls1 = "Local State" ascii
        $ls2 = "os_crypt" ascii
        $ls3 = "encrypted_key" ascii

        // AES-GCM decryption (used by Chromium v80+).
        $aes1 = "AES" ascii
        $aes2 = "BCryptDecrypt" ascii
        $aes3 = "CryptUnprotectData" ascii
        $aes4 = "GCM" ascii

        // Multi-browser targeting.
        $br1 = "Google\\Chrome\\User Data" ascii nocase
        $br2 = "Microsoft\\Edge\\User Data" ascii nocase
        $br3 = "BraveSoftware\\Brave-Browser" ascii nocase
        $br4 = "Vivaldi\\User Data" ascii nocase
        $br5 = "Opera Software\\Opera Stable" ascii nocase

        // Database interaction.
        $db1 = "Login Data" ascii
        $db2 = "SELECT " ascii nocase
        $db3 = "password_value" ascii

    condition:
        all of ($ls*) and
        any of ($aes*) and
        2 of ($br*) and
        any of ($db*)
}

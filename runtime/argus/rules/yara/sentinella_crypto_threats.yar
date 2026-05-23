/*
    Sentinella ARGUS Intelligence Pack — Cryptocurrency Threats
    Category: crypto_threats
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0

    Detects crypto wallet theft, clipboard hijacking for address
    replacement, and unauthorized mining.
*/

rule crypto_wallet_file_theft {
    meta:
        description = "ARGUS detected access to multiple cryptocurrency wallet file locations — consistent with multi-wallet stealer targeting hardware and software wallets."
        severity = "high"
        weight = 28
        category = "crypto_threats"
        author = "Sentinella"
    strings:
        $exodus = "Exodus" ascii nocase
        $atomic = "atomic" ascii nocase
        $electrum = "Electrum" ascii nocase
        $metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $phantom = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii
        $coinomi = "Coinomi" ascii nocase
        $guarda = "Guarda" ascii nocase
        $copy = "CopyFileW" ascii
        $read = "ReadFile" ascii
    condition:
        uint16(0) == 0x5A4D and
        3 of ($exodus, $atomic, $electrum, $metamask, $phantom, $coinomi, $guarda) and
        any of ($copy, $read)
}

rule crypto_address_clipper {
    meta:
        description = "ARGUS detected clipboard monitoring with cryptocurrency address patterns — replaces wallet addresses in the clipboard to redirect transactions."
        severity = "critical"
        weight = 35
        category = "crypto_threats"
        author = "Sentinella"
    strings:
        $clip1 = "OpenClipboard" ascii
        $clip2 = "SetClipboardData" ascii
        $clip3 = "GetClipboardData" ascii
        // Bitcoin address pattern.
        $btc1 = "bc1q" ascii
        // Ethereum.
        $eth = "0x" ascii
        $regex = "regex" ascii nocase
        $timer = "SetTimer" ascii
    condition:
        uint16(0) == 0x5A4D and
        $clip1 and $clip2 and $clip3 and
        $timer and
        ($regex or $btc1 or $eth)
}

rule crypto_browser_extension_theft {
    meta:
        description = "ARGUS detected targeting of browser-based cryptocurrency wallet extensions — extracting private keys and session data from MetaMask, Phantom, and similar extensions."
        severity = "high"
        weight = 25
        category = "crypto_threats"
        author = "Sentinella"
    strings:
        $ext_path = "\\Extensions\\" ascii nocase
        $chrome = "Chrome" ascii nocase
        $edge = "Edge" ascii nocase
        $brave = "Brave" ascii nocase
        // Known extension IDs.
        $metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $phantom = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii
        $coinbase = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii
        $trust = "egjidjbpglichdcondbcbdnbeeppgdph" ascii
    condition:
        uint16(0) == 0x5A4D and
        $ext_path and any of ($chrome, $edge, $brave) and
        2 of ($metamask, $phantom, $coinbase, $trust)
}

rule crypto_seed_phrase_search {
    meta:
        description = "ARGUS detected searching for cryptocurrency seed phrase files — targeted theft of wallet recovery phrases that grant permanent access to funds."
        severity = "critical"
        weight = 35
        category = "crypto_threats"
        author = "Sentinella"
    strings:
        $seed1 = "seed" ascii nocase
        $seed2 = "mnemonic" ascii nocase
        $seed3 = "recovery" ascii nocase
        $seed4 = "phrase" ascii nocase
        $seed5 = "12 words" ascii nocase
        $seed6 = "24 words" ascii nocase
        $find = "FindFirstFileW" ascii
        $read = "ReadFile" ascii
        $ext1 = ".txt" ascii
        $ext2 = ".json" ascii
    condition:
        uint16(0) == 0x5A4D and
        3 of ($seed*) and
        $find and $read and any of ($ext*)
}

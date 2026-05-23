/*
    Sentinella ARGUS Intelligence Pack — Generic Spyware Detection
    Category: spyware
    Version: 2025.1
    Author: Sentinella
    License: GPL-2.0
    Source: original_heuristic — MITRE ATT&CK T1056, T1113, T1125
*/

rule spyware_webcam_capture {
    meta:
        description = "ARGUS detected webcam capture capability combined with network transmission and file operations — consistent with surveillance spyware."
        severity = "high"
        weight = 22
        category = "spyware"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $cam1 = "capCreateCaptureWindowA" ascii
        $cam2 = "capGetDriverDescription" ascii
        $cam3 = "avicap32.dll" ascii nocase
        $net1 = "WSAStartup" ascii
        $net2 = "InternetOpenA" ascii
        $net3 = "WinHttpOpen" ascii
        $write = "WriteFile" ascii
        $temp = "GetTempPathW" ascii
    condition:
        uint16(0) == 0x5A4D and
        2 of ($cam*) and
        any of ($net*) and
        any of ($write, $temp)
}

rule spyware_audio_recording {
    meta:
        description = "ARGUS detected audio recording capability combined with file writing — may capture ambient audio or voice calls."
        severity = "high"
        weight = 22
        category = "spyware"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $audio1 = "waveInOpen" ascii
        $audio2 = "waveInStart" ascii
        $audio3 = "mciSendStringW" ascii
        $write = "WriteFile" ascii
        $temp = "GetTempPathW" ascii
    condition:
        uint16(0) == 0x5A4D and
        2 of ($audio*) and ($write or $temp)
}

rule spyware_location_tracking {
    meta:
        description = "ARGUS detected geolocation API usage combined with data collection — may be tracking the user's physical location."
        severity = "medium"
        weight = 18
        category = "spyware"
        source_type = "original_heuristic"
        author = "Sentinella"
    strings:
        $geo1 = "ipinfo.io" ascii nocase
        $geo2 = "ip-api.com" ascii nocase
        $geo3 = "geolocation" ascii nocase
        $geo4 = "geoplugin" ascii nocase
        $collect1 = "Login Data" ascii
        $collect2 = "discord" ascii nocase
        $collect3 = "wallet" ascii nocase
    condition:
        any of ($geo*) and any of ($collect*)
}

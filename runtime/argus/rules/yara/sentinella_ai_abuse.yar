/*
    Sentinella ARGUS Intelligence Pack — AI/LLM Abuse Detection
    Category: deception
    Version: 2026.1
    Author: Sentinella
    License: GPL-2.0

    Detects malware abusing AI/LLM branding for social engineering,
    fake AI tool installers, prompt injection payloads in documents,
    LLM API key theft, and deepfake tool distribution. These patterns
    reflect the explosion of AI-themed lures observed in 2025-2026.
*/

rule fake_ai_desktop_installer {
    meta:
        description = "ARGUS identified an executable impersonating a desktop AI assistant installer — no official desktop client exists for most AI services, making this a strong social engineering indicator."
        severity = "critical"
        weight = 30
        category = "deception"
        author = "Sentinella"

    strings:
        // Fake AI product branding embedded in executables.
        $brand1 = "ChatGPT Desktop" ascii nocase
        $brand2 = "ChatGPT-Setup" ascii nocase
        $brand3 = "Claude Desktop Installer" ascii nocase
        $brand4 = "Claude-Setup" ascii nocase
        $brand5 = "Midjourney Desktop" ascii nocase
        $brand6 = "Midjourney-Setup" ascii nocase
        $brand7 = "Copilot Desktop" ascii nocase
        $brand8 = "Gemini Desktop" ascii nocase
        $brand9 = "Gemini-Setup" ascii nocase
        $brand10 = "Sora Desktop" ascii nocase

        // Malicious payload indicators alongside fake branding.
        $payload1 = "powershell" ascii nocase
        $payload2 = "cmd.exe" ascii nocase
        $payload3 = "schtasks" ascii nocase
        $payload4 = "\\CurrentVersion\\Run" ascii nocase
        $payload5 = "Invoke-WebRequest" ascii nocase
        $payload6 = "Net.WebClient" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        any of ($brand*) and
        2 of ($payload*)
}

rule ai_upgrade_social_engineering {
    meta:
        description = "ARGUS detected social engineering lure using fake AI upgrade or premium access promises — a prevalent 2025-2026 phishing technique."
        severity = "high"
        weight = 22
        category = "deception"
        author = "Sentinella"

    strings:
        // Fake upgrade/premium lures.
        $lure1 = "GPT-5 Early Access" ascii nocase
        $lure2 = "ChatGPT Pro Unlock" ascii nocase
        $lure3 = "Claude Pro Free" ascii nocase
        $lure4 = "AI Premium Upgrade" ascii nocase
        $lure5 = "Unlimited GPT Access" ascii nocase
        $lure6 = "Free Copilot Pro" ascii nocase
        $lure7 = "Midjourney Free" ascii nocase
        $lure8 = "AI Credits Generator" ascii nocase
        $lure9 = "GPT Jailbreak" ascii nocase
        $lure10 = "ChatGPT Unlocker" ascii nocase

        // Executable behavior indicators.
        $exec1 = "CreateProcessW" ascii
        $exec2 = "ShellExecuteW" ascii
        $exec3 = "WinExec" ascii

    condition:
        uint16(0) == 0x5A4D and
        2 of ($lure*) and
        any of ($exec*)
}

rule llm_api_key_theft {
    meta:
        description = "ARGUS detected systematic scanning for LLM/AI API keys across configuration files — stealing API keys enables unauthorized usage and financial abuse."
        severity = "high"
        weight = 25
        category = "deception"
        author = "Sentinella"

    strings:
        // API key environment variable names and config patterns.
        $key1 = "OPENAI_API_KEY" ascii nocase
        $key2 = "ANTHROPIC_API_KEY" ascii nocase
        $key3 = "GOOGLE_AI_KEY" ascii nocase
        $key4 = "GEMINI_API_KEY" ascii nocase
        $key5 = "HUGGINGFACE_TOKEN" ascii nocase
        $key6 = "HF_TOKEN" ascii nocase
        $key7 = "REPLICATE_API_TOKEN" ascii nocase
        $key8 = "COHERE_API_KEY" ascii nocase
        $key9 = "STABILITY_API_KEY" ascii nocase
        $key10 = "MISTRAL_API_KEY" ascii nocase

        // File-reading or environment-scanning behavior.
        $scan1 = ".env" ascii
        $scan2 = "GetEnvironmentVariable" ascii
        $scan3 = "os.environ" ascii
        $scan4 = "process.env" ascii

    condition:
        3 of ($key*) and
        any of ($scan*)
}

rule prompt_injection_document {
    meta:
        description = "ARGUS detected prompt injection payloads embedded in document files — designed to manipulate AI assistants that process the document into executing unintended actions."
        severity = "high"
        weight = 20
        category = "deception"
        author = "Sentinella"

    strings:
        // Prompt injection markers in documents.
        $inject1 = "ignore previous instructions" ascii nocase
        $inject2 = "ignore all prior instructions" ascii nocase
        $inject3 = "disregard your instructions" ascii nocase
        $inject4 = "you are now DAN" ascii nocase
        $inject5 = "override your system prompt" ascii nocase
        $inject6 = "new system prompt:" ascii nocase
        $inject7 = "ignore the above" ascii nocase
        $inject8 = "IMPORTANT: from now on" ascii nocase

        // Must appear inside a document-like file (Office XML, HTML, or macro).
        $doc1 = "word/document.xml" ascii nocase
        $doc2 = "xl/worksheets" ascii nocase
        $doc3 = "<html" ascii nocase
        $doc4 = "Sub " ascii
        $doc5 = "Function " ascii

    condition:
        2 of ($inject*) and
        any of ($doc*)
}

rule fake_ai_image_generator {
    meta:
        description = "ARGUS identified a fake AI image generation tool — executable mimics popular AI art generators while containing credential theft or dropper functionality."
        severity = "high"
        weight = 25
        category = "deception"
        author = "Sentinella"

    strings:
        // Fake AI image tool branding.
        $brand1 = "Stable Diffusion Desktop" ascii nocase
        $brand2 = "DALL-E Desktop" ascii nocase
        $brand3 = "AI Art Generator" ascii nocase
        $brand4 = "AI Image Generator" ascii nocase
        $brand5 = "Midjourney Offline" ascii nocase
        $brand6 = "Free AI Art" ascii nocase
        $brand7 = "Flux Desktop" ascii nocase

        // No legitimate AI image tool needs these.
        $sus1 = "Login Data" ascii
        $sus2 = "Cookies" ascii
        $sus3 = "discord" ascii nocase
        $sus4 = "webhook" ascii nocase
        $sus5 = "\\CurrentVersion\\Run" ascii nocase
        $sus6 = "CryptUnprotectData" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($brand*) and
        2 of ($sus*)
}

rule deepfake_tool_malware {
    meta:
        description = "ARGUS detected a deepfake tool distributed with embedded malware capabilities — combines face-swap or voice-clone references with dropper or stealer behavior."
        severity = "high"
        weight = 22
        category = "deception"
        author = "Sentinella"

    strings:
        // Deepfake tool references.
        $df1 = "deepfake" ascii nocase
        $df2 = "face swap" ascii nocase
        $df3 = "faceswap" ascii nocase
        $df4 = "voice clone" ascii nocase
        $df5 = "voiceclone" ascii nocase
        $df6 = "DeepFaceLab" ascii nocase
        $df7 = "roop" ascii nocase

        // Malware indicators that do not belong in legitimate deepfake tools.
        $mal1 = "discord.com/api/webhooks" ascii
        $mal2 = "api.telegram.org/bot" ascii
        $mal3 = "\\CurrentVersion\\Run" ascii nocase
        $mal4 = "schtasks" ascii nocase
        $mal5 = "CryptUnprotectData" ascii
        $mal6 = "Login Data" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($df*) and
        2 of ($mal*)
}

rule ai_phishing_payload_builder {
    meta:
        description = "ARGUS detected indicators of AI-assisted phishing payload construction — templates and automation for generating targeted phishing at scale."
        severity = "high"
        weight = 20
        category = "deception"
        author = "Sentinella"

    strings:
        // Phishing template generation markers.
        $tmpl1 = "phishing_template" ascii nocase
        $tmpl2 = "email_template" ascii nocase
        $tmpl3 = "spear_phish" ascii nocase
        $tmpl4 = "social_engineer" ascii nocase

        // LLM API integration for content generation.
        $api1 = "api.openai.com" ascii
        $api2 = "api.anthropic.com" ascii
        $api3 = "generativelanguage.googleapis.com" ascii
        $api4 = "chat/completions" ascii

        // Target harvesting.
        $target1 = "smtp" ascii nocase
        $target2 = "recipient" ascii nocase
        $target3 = "mail_list" ascii nocase
        $target4 = "target_list" ascii nocase

    condition:
        2 of ($tmpl*) and
        any of ($api*) and
        any of ($target*)
}

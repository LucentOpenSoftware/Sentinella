//! Layer: Software Reputation
//!
//! Recognizes known software by name patterns, publisher strings, and
//! structural fingerprints embedded in PE version info. Recognized software
//! receives a **negative weight** (suspicion reduction), but is NEVER
//! exempted from scanning — every layer still runs.
//!
//! ## Philosophy
//!
//! "We recognize this software. It's expected to have compressed sections,
//! few imports, and a large overlay. That's normal for what it is.
//! But we still scanned it."
//!
//! ## Two-tier system
//!
//! - **Trusted**: Well-established software with years of history, millions
//!   of users, or major corporate/foundation backing. Gets 20-25 point discount.
//! - **Recognized**: Known but smaller projects. Gets 10-15 point discount.
//!
//! Software in the CAUTION list gets NO discount and may receive additional
//! scrutiny via YARA rules.

use crate::verdict::{Finding, Layer, Severity};

// ── Reputation tiers ───────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Tier {
    /// Very well established — major orgs, millions of users.
    Trusted, // 25 discount
    /// Known and legitimate but smaller ecosystem.
    Recognized, // 15 discount
}

impl Tier {
    fn discount(self) -> u32 {
        match self {
            Tier::Trusted => 25,
            Tier::Recognized => 15,
        }
    }
}

struct ReputationEntry {
    patterns: &'static [&'static str],
    publisher: &'static str,
    tier: Tier,
    category: &'static str,
}

// ── Trusted software database ──────────────────────────────────────
// NOT a whitelist. Everything is still scanned. This only reduces
// the suspicion score for software whose structural characteristics
// (compressed sections, large overlays, few imports) are EXPECTED.

const REPUTATION_DB: &[ReputationEntry] = &[
    // ═══════════════════════════════════════════════════════════════
    //  DEVELOPMENT TOOLS & IDEs
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["vscode", "vscodium", "code-"],
        publisher: "Microsoft / VSCodium",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["sublime_text", "sublime-text", "subl"],
        publisher: "Sublime HQ",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["npp.", "notepad++"],
        publisher: "Notepad++",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["eclipse-inst", "eclipse-java", "eclipse-cpp"],
        publisher: "Eclipse Foundation",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["android-studio", "androidstudio"],
        publisher: "Google (Android)",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["postman-"],
        publisher: "Postman Inc",
        tier: Tier::Recognized,
        category: "development",
    },
    ReputationEntry {
        patterns: &["cursor-", "cursorsetup"],
        publisher: "Anysphere (Cursor)",
        tier: Tier::Recognized,
        category: "development",
    },
    ReputationEntry {
        patterns: &["windowsterminal", "microsoft.windowsterminal"],
        publisher: "Microsoft (Terminal)",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["alacritty"],
        publisher: "Alacritty",
        tier: Tier::Recognized,
        category: "development",
    },
    ReputationEntry {
        patterns: &["wezterm"],
        publisher: "WezTerm",
        tier: Tier::Recognized,
        category: "development",
    },
    ReputationEntry {
        patterns: &["vim.", "gvim", "neovim", "nvim"],
        publisher: "Vim/Neovim",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["emacs"],
        publisher: "GNU Emacs",
        tier: Tier::Trusted,
        category: "development",
    },
    // JetBrains suite.
    ReputationEntry {
        patterns: &["ideaic", "ideaiu", "intellij"],
        publisher: "JetBrains (IntelliJ)",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["pycharm"],
        publisher: "JetBrains (PyCharm)",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["webstorm"],
        publisher: "JetBrains (WebStorm)",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["clion"],
        publisher: "JetBrains (CLion)",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["goland"],
        publisher: "JetBrains (GoLand)",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["rustrover"],
        publisher: "JetBrains (RustRover)",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["rider"],
        publisher: "JetBrains (Rider)",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["datagrip"],
        publisher: "JetBrains (DataGrip)",
        tier: Tier::Trusted,
        category: "development",
    },
    ReputationEntry {
        patterns: &["jetbrains-toolbox"],
        publisher: "JetBrains (Toolbox)",
        tier: Tier::Trusted,
        category: "development",
    },
    // ═══════════════════════════════════════════════════════════════
    //  PROGRAMMING LANGUAGES & RUNTIMES
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["python-", "python3"],
        publisher: "Python Software Foundation",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["node-v", "node-", "nodejs"],
        publisher: "OpenJS Foundation (Node.js)",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["dotnet-", "windowsdesktop-runtime", "aspnetcore-runtime"],
        publisher: "Microsoft (.NET)",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["jdk-", "jre-", "openjdk"],
        publisher: "Oracle / Eclipse Adoptium",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["vc_redist", "vcredist"],
        publisher: "Microsoft (Visual C++)",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["rustup-", "cargo-"],
        publisher: "Rust Foundation",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["golang", "go1.", "go-build"],
        publisher: "Google (Go)",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["ruby", "rubyinstaller"],
        publisher: "Ruby Community",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["php-"],
        publisher: "PHP Group",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["llvm-", "clang-", "llvm+clang"],
        publisher: "LLVM Project",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["mingw", "msys2-"],
        publisher: "MinGW / MSYS2",
        tier: Tier::Trusted,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["zig-"],
        publisher: "Zig Software Foundation",
        tier: Tier::Recognized,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["julia-"],
        publisher: "Julia Computing",
        tier: Tier::Recognized,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["deno-", "deno.exe"],
        publisher: "Deno Land",
        tier: Tier::Recognized,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["bun-", "bun.exe"],
        publisher: "Oven (Bun)",
        tier: Tier::Recognized,
        category: "runtime",
    },
    ReputationEntry {
        patterns: &["anaconda", "miniconda"],
        publisher: "Anaconda Inc",
        tier: Tier::Trusted,
        category: "runtime",
    },
    // ═══════════════════════════════════════════════════════════════
    //  VERSION CONTROL
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["git-", "git for windows", "mingit"],
        publisher: "Git / Software Freedom Conservancy",
        tier: Tier::Trusted,
        category: "vcs",
    },
    ReputationEntry {
        patterns: &["githubdesktop", "github desktop"],
        publisher: "GitHub (Desktop)",
        tier: Tier::Trusted,
        category: "vcs",
    },
    ReputationEntry {
        patterns: &["gh_", "gh.exe"],
        publisher: "GitHub (CLI)",
        tier: Tier::Trusted,
        category: "vcs",
    },
    ReputationEntry {
        patterns: &["gitkraken"],
        publisher: "Axosoft (GitKraken)",
        tier: Tier::Recognized,
        category: "vcs",
    },
    ReputationEntry {
        patterns: &["tortoisegit", "tortoisesvn"],
        publisher: "TortoiseGit/SVN",
        tier: Tier::Trusted,
        category: "vcs",
    },
    ReputationEntry {
        patterns: &["sourcetree"],
        publisher: "Atlassian (SourceTree)",
        tier: Tier::Trusted,
        category: "vcs",
    },
    // ═══════════════════════════════════════════════════════════════
    //  BROWSERS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["chrome", "chromesetup", "googlechrome"],
        publisher: "Google (Chrome)",
        tier: Tier::Trusted,
        category: "browser",
    },
    ReputationEntry {
        patterns: &["firefox", "firefox setup"],
        publisher: "Mozilla Foundation",
        tier: Tier::Trusted,
        category: "browser",
    },
    ReputationEntry {
        patterns: &["microsoftedge", "msedge"],
        publisher: "Microsoft (Edge)",
        tier: Tier::Trusted,
        category: "browser",
    },
    ReputationEntry {
        patterns: &["brave", "bravesetup", "bravebrowser"],
        publisher: "Brave Software",
        tier: Tier::Trusted,
        category: "browser",
    },
    ReputationEntry {
        patterns: &["vivaldi"],
        publisher: "Vivaldi Technologies",
        tier: Tier::Recognized,
        category: "browser",
    },
    ReputationEntry {
        patterns: &["tor browser", "torbrowser"],
        publisher: "The Tor Project",
        tier: Tier::Trusted,
        category: "browser",
    },
    // ═══════════════════════════════════════════════════════════════
    //  COMMUNICATION
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["discordsetup", "discord setup", "discord-"],
        publisher: "Discord Inc",
        tier: Tier::Recognized,
        category: "communication",
    },
    ReputationEntry {
        patterns: &["slacksetup", "slack setup", "slack-"],
        publisher: "Slack Technologies",
        tier: Tier::Trusted,
        category: "communication",
    },
    ReputationEntry {
        patterns: &["teams", "microsoftteams"],
        publisher: "Microsoft (Teams)",
        tier: Tier::Trusted,
        category: "communication",
    },
    ReputationEntry {
        patterns: &["zoominstaller", "zoom-", "zoomus"],
        publisher: "Zoom Video Communications",
        tier: Tier::Trusted,
        category: "communication",
    },
    ReputationEntry {
        patterns: &["telegram", "tsetup", "tportable"],
        publisher: "Telegram FZ-LLC",
        tier: Tier::Recognized,
        category: "communication",
    },
    ReputationEntry {
        patterns: &["signal-", "signal setup"],
        publisher: "Signal Foundation",
        tier: Tier::Trusted,
        category: "communication",
    },
    ReputationEntry {
        patterns: &["thunderbird"],
        publisher: "Mozilla (Thunderbird)",
        tier: Tier::Trusted,
        category: "communication",
    },
    ReputationEntry {
        patterns: &["element-"],
        publisher: "Element (Matrix)",
        tier: Tier::Recognized,
        category: "communication",
    },
    // ═══════════════════════════════════════════════════════════════
    //  PRODUCTIVITY
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["libreoffice"],
        publisher: "The Document Foundation",
        tier: Tier::Trusted,
        category: "productivity",
    },
    ReputationEntry {
        patterns: &["notion setup", "notion-"],
        publisher: "Notion Labs",
        tier: Tier::Recognized,
        category: "productivity",
    },
    ReputationEntry {
        patterns: &["obsidian-"],
        publisher: "Obsidian",
        tier: Tier::Recognized,
        category: "productivity",
    },
    ReputationEntry {
        patterns: &["logseq-"],
        publisher: "Logseq",
        tier: Tier::Recognized,
        category: "productivity",
    },
    ReputationEntry {
        patterns: &["zotero-"],
        publisher: "Zotero",
        tier: Tier::Recognized,
        category: "productivity",
    },
    ReputationEntry {
        patterns: &["joplin-"],
        publisher: "Joplin",
        tier: Tier::Recognized,
        category: "productivity",
    },
    // ═══════════════════════════════════════════════════════════════
    //  MEDIA
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["vlc-", "vlc media"],
        publisher: "VideoLAN",
        tier: Tier::Trusted,
        category: "media",
    },
    ReputationEntry {
        patterns: &["audacity-"],
        publisher: "Audacity Team",
        tier: Tier::Trusted,
        category: "media",
    },
    ReputationEntry {
        patterns: &["obs-studio", "obs64", "obs-full"],
        publisher: "OBS Project",
        tier: Tier::Trusted,
        category: "media",
    },
    ReputationEntry {
        patterns: &["handbrake"],
        publisher: "HandBrake",
        tier: Tier::Trusted,
        category: "media",
    },
    ReputationEntry {
        patterns: &["spotify"],
        publisher: "Spotify AB",
        tier: Tier::Trusted,
        category: "media",
    },
    ReputationEntry {
        patterns: &["ffmpeg", "ffprobe", "ffplay"],
        publisher: "FFmpeg Project",
        tier: Tier::Trusted,
        category: "media",
    },
    ReputationEntry {
        patterns: &["foobar2000"],
        publisher: "Piotr Pawlowski",
        tier: Tier::Recognized,
        category: "media",
    },
    ReputationEntry {
        patterns: &["imagemagick", "magick"],
        publisher: "ImageMagick Studio",
        tier: Tier::Trusted,
        category: "media",
    },
    ReputationEntry {
        patterns: &["mpv"],
        publisher: "mpv Project",
        tier: Tier::Recognized,
        category: "media",
    },
    ReputationEntry {
        patterns: &["kdenlive"],
        publisher: "KDE (Kdenlive)",
        tier: Tier::Recognized,
        category: "media",
    },
    // ═══════════════════════════════════════════════════════════════
    //  GRAPHICS & DESIGN
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["gimp-"],
        publisher: "GIMP Team",
        tier: Tier::Trusted,
        category: "graphics",
    },
    ReputationEntry {
        patterns: &["inkscape-"],
        publisher: "Inkscape Project",
        tier: Tier::Trusted,
        category: "graphics",
    },
    ReputationEntry {
        patterns: &["blender-"],
        publisher: "Blender Foundation",
        tier: Tier::Trusted,
        category: "graphics",
    },
    ReputationEntry {
        patterns: &["krita-"],
        publisher: "KDE (Krita)",
        tier: Tier::Trusted,
        category: "graphics",
    },
    ReputationEntry {
        patterns: &["paint.net", "paintdotnet"],
        publisher: "dotPDN LLC",
        tier: Tier::Recognized,
        category: "graphics",
    },
    ReputationEntry {
        patterns: &["darktable"],
        publisher: "darktable Project",
        tier: Tier::Recognized,
        category: "graphics",
    },
    ReputationEntry {
        patterns: &["irfanview", "iview"],
        publisher: "Irfan Skiljan",
        tier: Tier::Recognized,
        category: "graphics",
    },
    ReputationEntry {
        patterns: &["figma"],
        publisher: "Figma Inc",
        tier: Tier::Trusted,
        category: "graphics",
    },
    ReputationEntry {
        patterns: &["drawio", "draw.io"],
        publisher: "JGraph (draw.io)",
        tier: Tier::Recognized,
        category: "graphics",
    },
    // ═══════════════════════════════════════════════════════════════
    //  SYSTEM UTILITIES
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["7z", "7zip"],
        publisher: "Igor Pavlov (7-Zip)",
        tier: Tier::Trusted,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["winrar"],
        publisher: "win.rar GmbH",
        tier: Tier::Trusted,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["everything-", "everything.exe"],
        publisher: "voidtools (Everything)",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["powertoys"],
        publisher: "Microsoft (PowerToys)",
        tier: Tier::Trusted,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["rufus"],
        publisher: "Pete Batard (Rufus)",
        tier: Tier::Trusted,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["sharex"],
        publisher: "ShareX Team",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["chocolatey", "choco"],
        publisher: "Chocolatey Software",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["winget"],
        publisher: "Microsoft (winget)",
        tier: Tier::Trusted,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["autohotkey", "ahk"],
        publisher: "AutoHotkey Foundation",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["crystaldisk"],
        publisher: "Crystal Dew World",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["hwinfo"],
        publisher: "HWiNFO (Martin Malik)",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &[
            "procmon", "procexp", "autoruns", "psexec", "sigcheck", "listdlls",
        ],
        publisher: "Microsoft (Sysinternals)",
        tier: Tier::Trusted,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["treesizefree"],
        publisher: "JAM Software",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["windirstat"],
        publisher: "WinDirStat Team",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["spacesniffer"],
        publisher: "Uderzo Software",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["bleachbit"],
        publisher: "BleachBit",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["greenshot"],
        publisher: "Greenshot",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["flux", "f.lux"],
        publisher: "f.lux Software",
        tier: Tier::Recognized,
        category: "utility",
    },
    ReputationEntry {
        patterns: &["barrier-"],
        publisher: "Barrier (Debauchee)",
        tier: Tier::Recognized,
        category: "utility",
    },
    // ═══════════════════════════════════════════════════════════════
    //  SECURITY
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["malwarebytes"],
        publisher: "Malwarebytes",
        tier: Tier::Trusted,
        category: "security",
    },
    ReputationEntry {
        patterns: &["keepass", "keepassxc"],
        publisher: "KeePass / KeePassXC",
        tier: Tier::Trusted,
        category: "security",
    },
    ReputationEntry {
        patterns: &["bitwarden"],
        publisher: "Bitwarden Inc",
        tier: Tier::Trusted,
        category: "security",
    },
    ReputationEntry {
        patterns: &["1password"],
        publisher: "AgileBits (1Password)",
        tier: Tier::Trusted,
        category: "security",
    },
    ReputationEntry {
        patterns: &["veracrypt"],
        publisher: "IDRIX (VeraCrypt)",
        tier: Tier::Trusted,
        category: "security",
    },
    ReputationEntry {
        patterns: &["gpg4win", "gnupg", "gpg.exe"],
        publisher: "GnuPG Project",
        tier: Tier::Trusted,
        category: "security",
    },
    // ═══════════════════════════════════════════════════════════════
    //  NETWORKING
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["wireshark-"],
        publisher: "Wireshark Foundation",
        tier: Tier::Trusted,
        category: "networking",
    },
    ReputationEntry {
        patterns: &["nmap", "npcap-"],
        publisher: "Nmap Project",
        tier: Tier::Trusted,
        category: "networking",
    },
    ReputationEntry {
        patterns: &["putty", "pscp", "psftp", "plink"],
        publisher: "Simon Tatham (PuTTY)",
        tier: Tier::Trusted,
        category: "networking",
    },
    ReputationEntry {
        patterns: &["winscp"],
        publisher: "Martin Prikryl (WinSCP)",
        tier: Tier::Trusted,
        category: "networking",
    },
    ReputationEntry {
        patterns: &["filezilla"],
        publisher: "FileZilla Project",
        tier: Tier::Trusted,
        category: "networking",
    },
    ReputationEntry {
        patterns: &["curl", "curl.exe"],
        publisher: "curl Project (Daniel Stenberg)",
        tier: Tier::Trusted,
        category: "networking",
    },
    ReputationEntry {
        patterns: &["openvpn"],
        publisher: "OpenVPN Inc",
        tier: Tier::Trusted,
        category: "networking",
    },
    ReputationEntry {
        patterns: &["wireguard"],
        publisher: "WireGuard (Jason Donenfeld)",
        tier: Tier::Trusted,
        category: "networking",
    },
    ReputationEntry {
        patterns: &["mremoteng"],
        publisher: "mRemoteNG",
        tier: Tier::Recognized,
        category: "networking",
    },
    // ═══════════════════════════════════════════════════════════════
    //  VIRTUALIZATION & CONTAINERS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["virtualbox", "vbox"],
        publisher: "Oracle (VirtualBox)",
        tier: Tier::Trusted,
        category: "virtualization",
    },
    ReputationEntry {
        patterns: &["vmware", "vmplayer"],
        publisher: "Broadcom (VMware)",
        tier: Tier::Trusted,
        category: "virtualization",
    },
    ReputationEntry {
        patterns: &["docker"],
        publisher: "Docker Inc",
        tier: Tier::Trusted,
        category: "virtualization",
    },
    ReputationEntry {
        patterns: &["podman"],
        publisher: "Red Hat (Podman)",
        tier: Tier::Recognized,
        category: "virtualization",
    },
    ReputationEntry {
        patterns: &["vagrant"],
        publisher: "HashiCorp (Vagrant)",
        tier: Tier::Trusted,
        category: "virtualization",
    },
    // ═══════════════════════════════════════════════════════════════
    //  GAMING PLATFORMS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["steamsetup", "steam.exe"],
        publisher: "Valve (Steam)",
        tier: Tier::Trusted,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["epicinstaller", "epicgameslauncher"],
        publisher: "Epic Games",
        tier: Tier::Trusted,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["gogsetup", "gog galaxy"],
        publisher: "GOG (CD Projekt)",
        tier: Tier::Trusted,
        category: "gaming",
    },
    // ═══════════════════════════════════════════════════════════════
    //  DRIVERS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["nvidia", "geforce", "nv_"],
        publisher: "NVIDIA Corporation",
        tier: Tier::Trusted,
        category: "driver",
    },
    ReputationEntry {
        patterns: &["amd-software", "radeon", "adrenalin"],
        publisher: "AMD Inc",
        tier: Tier::Trusted,
        category: "driver",
    },
    ReputationEntry {
        patterns: &["intel-", "intel driver"],
        publisher: "Intel Corporation",
        tier: Tier::Trusted,
        category: "driver",
    },
    ReputationEntry {
        patterns: &["realtek"],
        publisher: "Realtek Semiconductor",
        tier: Tier::Trusted,
        category: "driver",
    },
    ReputationEntry {
        patterns: &["logitech", "logi_"],
        publisher: "Logitech",
        tier: Tier::Trusted,
        category: "driver",
    },
    // ═══════════════════════════════════════════════════════════════
    //  DATABASE TOOLS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["dbeaver"],
        publisher: "DBeaver Corp",
        tier: Tier::Recognized,
        category: "database",
    },
    ReputationEntry {
        patterns: &["heidisql"],
        publisher: "HeidiSQL (Ansgar Becker)",
        tier: Tier::Recognized,
        category: "database",
    },
    ReputationEntry {
        patterns: &["pgadmin"],
        publisher: "pgAdmin Development Team",
        tier: Tier::Recognized,
        category: "database",
    },
    ReputationEntry {
        patterns: &["mysql-workbench"],
        publisher: "Oracle (MySQL)",
        tier: Tier::Trusted,
        category: "database",
    },
    ReputationEntry {
        patterns: &["mongodb-compass"],
        publisher: "MongoDB Inc",
        tier: Tier::Recognized,
        category: "database",
    },
    // ═══════════════════════════════════════════════════════════════
    //  SCIENCE & ENGINEERING
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["octave-"],
        publisher: "GNU Octave",
        tier: Tier::Trusted,
        category: "science",
    },
    ReputationEntry {
        patterns: &["r-", "rtools", "rstudio"],
        publisher: "R Foundation / Posit",
        tier: Tier::Trusted,
        category: "science",
    },
    ReputationEntry {
        patterns: &["texlive", "miktex"],
        publisher: "TeX Live / MiKTeX",
        tier: Tier::Trusted,
        category: "science",
    },
    // ═══════════════════════════════════════════════════════════════
    //  PDF & DOCUMENT TOOLS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["sumatrapdf"],
        publisher: "SumatraPDF (Krzysztof Kowalczyk)",
        tier: Tier::Recognized,
        category: "pdf",
    },
    ReputationEntry {
        patterns: &["calibre-"],
        publisher: "Calibre (Kovid Goyal)",
        tier: Tier::Recognized,
        category: "pdf",
    },
    // ═══════════════════════════════════════════════════════════════
    //  CLOUD STORAGE
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["dropbox"],
        publisher: "Dropbox Inc",
        tier: Tier::Trusted,
        category: "cloud",
    },
    ReputationEntry {
        patterns: &["googledrive", "google drive"],
        publisher: "Google (Drive)",
        tier: Tier::Trusted,
        category: "cloud",
    },
    ReputationEntry {
        patterns: &["onedrive"],
        publisher: "Microsoft (OneDrive)",
        tier: Tier::Trusted,
        category: "cloud",
    },
    ReputationEntry {
        patterns: &["nextcloud"],
        publisher: "Nextcloud GmbH",
        tier: Tier::Recognized,
        category: "cloud",
    },
    ReputationEntry {
        patterns: &["syncthing"],
        publisher: "Syncthing Foundation",
        tier: Tier::Recognized,
        category: "cloud",
    },
    ReputationEntry {
        patterns: &["rclone"],
        publisher: "rclone (Nick Craig-Wood)",
        tier: Tier::Recognized,
        category: "cloud",
    },
    // ═══════════════════════════════════════════════════════════════
    //  REMOTE ACCESS (reduced discount — impersonation risk)
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["rustdesk"],
        publisher: "RustDesk",
        tier: Tier::Recognized,
        category: "remote",
    },
    // ═══════════════════════════════════════════════════════════════
    //  DEVOPS & INFRASTRUCTURE
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["terraform"],
        publisher: "HashiCorp (Terraform)",
        tier: Tier::Trusted,
        category: "devops",
    },
    ReputationEntry {
        patterns: &["kubectl"],
        publisher: "Kubernetes / CNCF",
        tier: Tier::Trusted,
        category: "devops",
    },
    ReputationEntry {
        patterns: &["helm"],
        publisher: "Helm / CNCF",
        tier: Tier::Trusted,
        category: "devops",
    },
    // ═══════════════════════════════════════════════════════════════
    //  PACKAGE MANAGERS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["cmake-"],
        publisher: "Kitware (CMake)",
        tier: Tier::Trusted,
        category: "build",
    },
    ReputationEntry {
        patterns: &["ninja"],
        publisher: "Ninja Build",
        tier: Tier::Recognized,
        category: "build",
    },
    ReputationEntry {
        patterns: &["meson"],
        publisher: "Meson Build",
        tier: Tier::Recognized,
        category: "build",
    },
    ReputationEntry {
        patterns: &["scoop"],
        publisher: "Scoop",
        tier: Tier::Recognized,
        category: "utility",
    },
    // ═══════════════════════════════════════════════════════════════
    //  HARDWARE VENDOR SOFTWARE
    // ═══════════════════════════════════════════════════════════════

    // Lenovo.
    ReputationEntry {
        patterns: &["lenovovantage", "lenovo vantage", "lenovo.vantage"],
        publisher: "Lenovo",
        tier: Tier::Trusted,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["lenovo system update", "systemupdate", "tvsu"],
        publisher: "Lenovo (System Update)",
        tier: Tier::Trusted,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["nervecenter", "nerve center", "legionzone", "legion zone"],
        publisher: "Lenovo (Legion)",
        tier: Tier::Recognized,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["lenovo.anyconnect", "lenovomigrationassistant"],
        publisher: "Lenovo",
        tier: Tier::Recognized,
        category: "hardware",
    },
    // ASUS.
    ReputationEntry {
        patterns: &["armourycrate", "armoury crate", "asuslinkremote"],
        publisher: "ASUS (Armoury Crate)",
        tier: Tier::Trusted,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["aisuite", "ai suite"],
        publisher: "ASUS (AI Suite)",
        tier: Tier::Recognized,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["gpuTweak", "gpu tweak"],
        publisher: "ASUS (GPU Tweak)",
        tier: Tier::Recognized,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["auraservice", "aura sync", "aurasync", "lightingservice"],
        publisher: "ASUS (Aura)",
        tier: Tier::Recognized,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["myasus"],
        publisher: "ASUS (MyASUS)",
        tier: Tier::Trusted,
        category: "hardware",
    },
    // MSI.
    ReputationEntry {
        patterns: &["afterburner", "msiafterburner"],
        publisher: "MSI (Afterburner)",
        tier: Tier::Trusted,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["dragoncenter", "dragon center", "msicenter", "msi center"],
        publisher: "MSI (Center)",
        tier: Tier::Recognized,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["mysticlight", "mystic light"],
        publisher: "MSI (Mystic Light)",
        tier: Tier::Recognized,
        category: "hardware",
    },
    // Dell.
    ReputationEntry {
        patterns: &["supportassist", "dellsupportassist", "dell supportassist"],
        publisher: "Dell (SupportAssist)",
        tier: Tier::Trusted,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["dellupdate", "dell update", "dell command update"],
        publisher: "Dell (Update)",
        tier: Tier::Trusted,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["alienware command center", "awcc"],
        publisher: "Dell (Alienware)",
        tier: Tier::Recognized,
        category: "hardware",
    },
    // HP.
    ReputationEntry {
        patterns: &["hp support assistant", "hpsupportassistant", "hpsa"],
        publisher: "HP (Support Assistant)",
        tier: Tier::Trusted,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["hp smart", "hpsmart"],
        publisher: "HP (Smart)",
        tier: Tier::Trusted,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["omen gaming hub", "omengaminghub", "hpomen"],
        publisher: "HP (OMEN)",
        tier: Tier::Recognized,
        category: "hardware",
    },
    // Acer.
    ReputationEntry {
        patterns: &["acer care center", "carecenter"],
        publisher: "Acer (Care Center)",
        tier: Tier::Recognized,
        category: "hardware",
    },
    ReputationEntry {
        patterns: &["nitrosense", "predatorsense"],
        publisher: "Acer (NitroSense/Predator)",
        tier: Tier::Recognized,
        category: "hardware",
    },
    // Gigabyte.
    ReputationEntry {
        patterns: &[
            "gigabyte app center",
            "appcenter",
            "rgbfusion",
            "rgb fusion",
        ],
        publisher: "Gigabyte",
        tier: Tier::Recognized,
        category: "hardware",
    },
    // ═══════════════════════════════════════════════════════════════
    //  PERIPHERAL SOFTWARE
    // ═══════════════════════════════════════════════════════════════

    // Corsair.
    ReputationEntry {
        patterns: &["icue", "corsair icue", "icuesetup"],
        publisher: "Corsair (iCUE)",
        tier: Tier::Trusted,
        category: "peripheral",
    },
    // Razer.
    ReputationEntry {
        patterns: &[
            "razersynapse",
            "razer synapse",
            "razer installer",
            "razerinstaller",
        ],
        publisher: "Razer (Synapse)",
        tier: Tier::Trusted,
        category: "peripheral",
    },
    ReputationEntry {
        patterns: &["razercortex", "razer cortex"],
        publisher: "Razer (Cortex)",
        tier: Tier::Recognized,
        category: "peripheral",
    },
    // SteelSeries.
    ReputationEntry {
        patterns: &["steelseriesgg", "steelseries gg", "steelseriesengine"],
        publisher: "SteelSeries",
        tier: Tier::Recognized,
        category: "peripheral",
    },
    // Logitech.
    ReputationEntry {
        patterns: &["lghub", "logitech g hub", "logighub"],
        publisher: "Logitech (G Hub)",
        tier: Tier::Trusted,
        category: "peripheral",
    },
    ReputationEntry {
        patterns: &["logioptionsplus", "logi options", "logioptions"],
        publisher: "Logitech (Options+)",
        tier: Tier::Trusted,
        category: "peripheral",
    },
    ReputationEntry {
        patterns: &["setpoint"],
        publisher: "Logitech (SetPoint)",
        tier: Tier::Recognized,
        category: "peripheral",
    },
    // HyperX.
    ReputationEntry {
        patterns: &["ngenuity", "hyperx ngenuity"],
        publisher: "HyperX (NGENUITY)",
        tier: Tier::Recognized,
        category: "peripheral",
    },
    // Elgato.
    ReputationEntry {
        patterns: &["stream deck", "streamdeck"],
        publisher: "Elgato (Stream Deck)",
        tier: Tier::Recognized,
        category: "peripheral",
    },
    ReputationEntry {
        patterns: &["wave link", "wavelink"],
        publisher: "Elgato (Wave Link)",
        tier: Tier::Recognized,
        category: "peripheral",
    },
    ReputationEntry {
        patterns: &["elgato camera hub"],
        publisher: "Elgato (Camera Hub)",
        tier: Tier::Recognized,
        category: "peripheral",
    },
    // Cooler Master.
    ReputationEntry {
        patterns: &["masterplus", "masterplus+"],
        publisher: "Cooler Master (MasterPlus)",
        tier: Tier::Recognized,
        category: "peripheral",
    },
    // NZXT.
    ReputationEntry {
        patterns: &["nzxt cam", "nzxtcam"],
        publisher: "NZXT (CAM)",
        tier: Tier::Recognized,
        category: "peripheral",
    },
    // Wacom.
    ReputationEntry {
        patterns: &["wacom", "wacomtablet"],
        publisher: "Wacom",
        tier: Tier::Trusted,
        category: "peripheral",
    },
    // Xbox.
    ReputationEntry {
        patterns: &["xboxaccessories", "xbox accessories"],
        publisher: "Microsoft (Xbox Accessories)",
        tier: Tier::Trusted,
        category: "peripheral",
    },
    ReputationEntry {
        patterns: &["ds4windows"],
        publisher: "DS4Windows",
        tier: Tier::Recognized,
        category: "peripheral",
    },
    // ═══════════════════════════════════════════════════════════════
    //  STORAGE VENDOR SOFTWARE
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["samsung magician", "samsungmagician"],
        publisher: "Samsung (Magician)",
        tier: Tier::Trusted,
        category: "storage",
    },
    ReputationEntry {
        patterns: &["samsung data migration"],
        publisher: "Samsung (Data Migration)",
        tier: Tier::Trusted,
        category: "storage",
    },
    ReputationEntry {
        patterns: &["wd dashboard", "wddashboard", "wd drive utilities"],
        publisher: "Western Digital",
        tier: Tier::Trusted,
        category: "storage",
    },
    ReputationEntry {
        patterns: &["seatools", "discwizard"],
        publisher: "Seagate",
        tier: Tier::Trusted,
        category: "storage",
    },
    ReputationEntry {
        patterns: &["kingston ssd manager", "kingstonmanager"],
        publisher: "Kingston",
        tier: Tier::Recognized,
        category: "storage",
    },
    ReputationEntry {
        patterns: &["crucial storage executive", "storageexecutive"],
        publisher: "Crucial (Micron)",
        tier: Tier::Recognized,
        category: "storage",
    },
    // ═══════════════════════════════════════════════════════════════
    //  AUDIO SOFTWARE
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &[
            "realtek audio",
            "rtkaudioservice",
            "rtkngui",
            "realtekaudiosvc",
        ],
        publisher: "Realtek (Audio)",
        tier: Tier::Trusted,
        category: "audio",
    },
    ReputationEntry {
        patterns: &["dolby", "dolbyatmos", "dolbyaccess", "dolbydax"],
        publisher: "Dolby Laboratories",
        tier: Tier::Trusted,
        category: "audio",
    },
    ReputationEntry {
        patterns: &["soundblaster", "creative sound", "sbcommand"],
        publisher: "Creative Labs",
        tier: Tier::Recognized,
        category: "audio",
    },
    ReputationEntry {
        patterns: &["nahimic"],
        publisher: "Nahimic (SteelSeries)",
        tier: Tier::Recognized,
        category: "audio",
    },
    ReputationEntry {
        patterns: &["voicemeeter", "vb-audio", "vbcable"],
        publisher: "VB-Audio (Voicemeeter)",
        tier: Tier::Recognized,
        category: "audio",
    },
    ReputationEntry {
        patterns: &["equalizerapo"],
        publisher: "Equalizer APO",
        tier: Tier::Recognized,
        category: "audio",
    },
    // ═══════════════════════════════════════════════════════════════
    //  PRINTER SOFTWARE
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["hp printer", "hpprinter", "hp_lj_pro", "hpsetup"],
        publisher: "HP (Printer)",
        tier: Tier::Trusted,
        category: "printer",
    },
    ReputationEntry {
        patterns: &["canon ij", "canonij", "canon_ij", "myimagegardenview"],
        publisher: "Canon",
        tier: Tier::Trusted,
        category: "printer",
    },
    ReputationEntry {
        patterns: &["epson scan", "epsonscan", "epson iprint"],
        publisher: "Epson",
        tier: Tier::Trusted,
        category: "printer",
    },
    ReputationEntry {
        patterns: &["brother", "brotheriprintscan", "controlcenter"],
        publisher: "Brother Industries",
        tier: Tier::Trusted,
        category: "printer",
    },
    // ═══════════════════════════════════════════════════════════════
    //  ENTERPRISE / BUSINESS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["acrord32", "acrobatreader", "acroread", "adobeacrobat"],
        publisher: "Adobe (Acrobat Reader)",
        tier: Tier::Trusted,
        category: "enterprise",
    },
    ReputationEntry {
        patterns: &["creative cloud", "creativecloud", "adobecc"],
        publisher: "Adobe (Creative Cloud)",
        tier: Tier::Trusted,
        category: "enterprise",
    },
    ReputationEntry {
        patterns: &["autocad"],
        publisher: "Autodesk (AutoCAD)",
        tier: Tier::Trusted,
        category: "enterprise",
    },
    ReputationEntry {
        patterns: &["ssms", "sql server management"],
        publisher: "Microsoft (SSMS)",
        tier: Tier::Trusted,
        category: "enterprise",
    },
    ReputationEntry {
        patterns: &["powerbi", "power bi", "pbiddesktop"],
        publisher: "Microsoft (Power BI)",
        tier: Tier::Trusted,
        category: "enterprise",
    },
    ReputationEntry {
        patterns: &["citrixworkspace", "citrix workspace", "citrix receiver"],
        publisher: "Citrix (Workspace)",
        tier: Tier::Trusted,
        category: "enterprise",
    },
    // ═══════════════════════════════════════════════════════════════
    //  SYSTEM MONITORING (additional)
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["gpu-z", "gpuz", "techpowerup-gpu"],
        publisher: "TechPowerUp (GPU-Z)",
        tier: Tier::Recognized,
        category: "monitoring",
    },
    ReputationEntry {
        patterns: &["openhardwaremonitor"],
        publisher: "Open Hardware Monitor",
        tier: Tier::Recognized,
        category: "monitoring",
    },
    ReputationEntry {
        patterns: &["librehardwaremonitor"],
        publisher: "Libre Hardware Monitor",
        tier: Tier::Recognized,
        category: "monitoring",
    },
    ReputationEntry {
        patterns: &["coretemp"],
        publisher: "Core Temp (Arthur Liberman)",
        tier: Tier::Recognized,
        category: "monitoring",
    },
    ReputationEntry {
        patterns: &["rtss", "rivatuner"],
        publisher: "RivaTuner (Unwinder)",
        tier: Tier::Recognized,
        category: "monitoring",
    },
    ReputationEntry {
        patterns: &["occt"],
        publisher: "OCBASE (OCCT)",
        tier: Tier::Recognized,
        category: "monitoring",
    },
    ReputationEntry {
        patterns: &["aida64"],
        publisher: "FinalWire (AIDA64)",
        tier: Tier::Recognized,
        category: "monitoring",
    },
    // ═══════════════════════════════════════════════════════════════
    //  BACKUP & RECOVERY
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["macrium reflect", "macriumreflect"],
        publisher: "Macrium Software",
        tier: Tier::Recognized,
        category: "backup",
    },
    ReputationEntry {
        patterns: &["veeamagent", "veeam agent"],
        publisher: "Veeam Software",
        tier: Tier::Trusted,
        category: "backup",
    },
    // ═══════════════════════════════════════════════════════════════
    //  DISK & PARTITION TOOLS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["ventoy"],
        publisher: "Ventoy",
        tier: Tier::Recognized,
        category: "disk",
    },
    ReputationEntry {
        patterns: &["balenaetcher", "etcher"],
        publisher: "balena (Etcher)",
        tier: Tier::Recognized,
        category: "disk",
    },
    // ═══════════════════════════════════════════════════════════════
    //  STREAMING & CONTENT CREATION
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["streamlabs", "streamlabsobs"],
        publisher: "Streamlabs (Logitech)",
        tier: Tier::Recognized,
        category: "streaming",
    },
    // ═══════════════════════════════════════════════════════════════
    //  EDUCATION & REFERENCE
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["anki"],
        publisher: "Anki (Damien Elmes)",
        tier: Tier::Recognized,
        category: "education",
    },
    ReputationEntry {
        patterns: &["geogebra"],
        publisher: "GeoGebra",
        tier: Tier::Recognized,
        category: "education",
    },
    ReputationEntry {
        patterns: &["stellarium"],
        publisher: "Stellarium",
        tier: Tier::Recognized,
        category: "education",
    },
    // ═══════════════════════════════════════════════════════════════
    //  3D PRINTING & CAD
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["ultimaker-cura", "ultimakercura", "cura.exe"],
        publisher: "UltiMaker (Cura)",
        tier: Tier::Recognized,
        category: "cad",
    },
    ReputationEntry {
        patterns: &["prusaslicer"],
        publisher: "Prusa Research",
        tier: Tier::Recognized,
        category: "cad",
    },
    ReputationEntry {
        patterns: &["bambustudio", "bambu studio"],
        publisher: "Bambu Lab",
        tier: Tier::Recognized,
        category: "cad",
    },
    ReputationEntry {
        patterns: &["freecad"],
        publisher: "FreeCAD",
        tier: Tier::Recognized,
        category: "cad",
    },
    ReputationEntry {
        patterns: &["openscad"],
        publisher: "OpenSCAD",
        tier: Tier::Recognized,
        category: "cad",
    },
    ReputationEntry {
        patterns: &["kicad"],
        publisher: "KiCad",
        tier: Tier::Recognized,
        category: "cad",
    },
    // ═══════════════════════════════════════════════════════════════
    //  ARCHIVE / COMPRESSION (additional)
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["peazip"],
        publisher: "PeaZip (Giorgio Tani)",
        tier: Tier::Recognized,
        category: "archive",
    },
    ReputationEntry {
        patterns: &["bandizip"],
        publisher: "Bandisoft (Bandizip)",
        tier: Tier::Recognized,
        category: "archive",
    },
    // ═══════════════════════════════════════════════════════════════
    //  SCREENSHOT / SCREEN RECORDING (additional)
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["screentogif"],
        publisher: "ScreenToGif (Nicke Manarin)",
        tier: Tier::Recognized,
        category: "screenshot",
    },
    ReputationEntry {
        patterns: &["flameshot"],
        publisher: "Flameshot",
        tier: Tier::Recognized,
        category: "screenshot",
    },
    ReputationEntry {
        patterns: &["licecap"],
        publisher: "Cockos (LICEcap)",
        tier: Tier::Recognized,
        category: "screenshot",
    },
    // ═══════════════════════════════════════════════════════════════
    //  CLIPBOARD / PRODUCTIVITY MICRO-TOOLS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["ditto", "ditto.exe"],
        publisher: "Ditto Clipboard",
        tier: Tier::Recognized,
        category: "productivity",
    },
    ReputationEntry {
        patterns: &["flow launcher", "flowlauncher"],
        publisher: "Flow Launcher",
        tier: Tier::Recognized,
        category: "productivity",
    },
    ReputationEntry {
        patterns: &["keypirinha"],
        publisher: "Keypirinha",
        tier: Tier::Recognized,
        category: "productivity",
    },
    // ═══════════════════════════════════════════════════════════════
    //  DISPLAY / MONITOR
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["displaylink"],
        publisher: "Synaptics (DisplayLink)",
        tier: Tier::Trusted,
        category: "display",
    },
    ReputationEntry {
        patterns: &["twinkletray", "twinkle tray"],
        publisher: "Twinkle Tray",
        tier: Tier::Recognized,
        category: "display",
    },
    // ═══════════════════════════════════════════════════════════════
    //  EMAIL CLIENTS (additional)
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["mailspring"],
        publisher: "Mailspring",
        tier: Tier::Recognized,
        category: "email",
    },
    ReputationEntry {
        patterns: &["emclient", "em client"],
        publisher: "eM Client",
        tier: Tier::Recognized,
        category: "email",
    },
    ReputationEntry {
        patterns: &["betterbird"],
        publisher: "Betterbird",
        tier: Tier::Recognized,
        category: "email",
    },
    // ═══════════════════════════════════════════════════════════════
    //  NETWORK MANAGEMENT (additional)
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["fiddler"],
        publisher: "Progress/Telerik (Fiddler)",
        tier: Tier::Recognized,
        category: "networking",
    },
    ReputationEntry {
        patterns: &["angryip", "ipscan"],
        publisher: "Angry IP Scanner",
        tier: Tier::Recognized,
        category: "networking",
    },
    ReputationEntry {
        patterns: &["netsetman"],
        publisher: "NetSetMan",
        tier: Tier::Recognized,
        category: "networking",
    },
    // ═══════════════════════════════════════════════════════════════
    //  ELECTRON / FRAMEWORK APPS (common FP sources)
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &[
            "claude setup",
            "claude-setup",
            "claudesetup",
            "claude desktop",
        ],
        publisher: "Anthropic (Claude)",
        tier: Tier::Trusted,
        category: "ai_tools",
    },
    ReputationEntry {
        patterns: &["chatgpt", "openai"],
        publisher: "OpenAI",
        tier: Tier::Trusted,
        category: "ai_tools",
    },
    ReputationEntry {
        patterns: &["copilot", "github-copilot"],
        publisher: "GitHub (Copilot)",
        tier: Tier::Trusted,
        category: "ai_tools",
    },
    ReputationEntry {
        patterns: &["windsurf"],
        publisher: "Codeium (Windsurf)",
        tier: Tier::Recognized,
        category: "ai_tools",
    },
    ReputationEntry {
        patterns: &["chromesetup", "chrome setup", "googlechrome"],
        publisher: "Google (Chrome)",
        tier: Tier::Trusted,
        category: "browser",
    },
    ReputationEntry {
        patterns: &["officesetup", "office setup"],
        publisher: "Microsoft (Office)",
        tier: Tier::Trusted,
        category: "productivity",
    },
    ReputationEntry {
        patterns: &["electron", "electron.exe"],
        publisher: "Electron Framework",
        tier: Tier::Recognized,
        category: "framework",
    },
    ReputationEntry {
        patterns: &["nw.exe", "nwjs"],
        publisher: "NW.js Framework",
        tier: Tier::Recognized,
        category: "framework",
    },
    ReputationEntry {
        patterns: &["cefsharp", "cef."],
        publisher: "Chromium Embedded Framework",
        tier: Tier::Recognized,
        category: "framework",
    },
    ReputationEntry {
        patterns: &["tauri", "tauri-app"],
        publisher: "Tauri Framework",
        tier: Tier::Recognized,
        category: "framework",
    },
    // ═══════════════════════════════════════════════════════════════
    //  ADDITIONAL GAME PLATFORMS / LAUNCHERS
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["riotclient", "riot client"],
        publisher: "Riot Games",
        tier: Tier::Trusted,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["leagueclient", "league of legends"],
        publisher: "Riot Games (LoL)",
        tier: Tier::Trusted,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["valorant", "vanguard"],
        publisher: "Riot Games (Valorant)",
        tier: Tier::Trusted,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["ubisoft", "uplay", "ubisoftconnect"],
        publisher: "Ubisoft",
        tier: Tier::Trusted,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["bethesda.net", "bethesdalauncher"],
        publisher: "Bethesda/ZeniMax",
        tier: Tier::Recognized,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["rockstar", "socialclub"],
        publisher: "Rockstar Games",
        tier: Tier::Trusted,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["curseforge", "overwolf"],
        publisher: "Overwolf/CurseForge",
        tier: Tier::Recognized,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["prism", "prismlauncher"],
        publisher: "PrismLauncher",
        tier: Tier::Recognized,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["minecraft"],
        publisher: "Mojang / Microsoft",
        tier: Tier::Trusted,
        category: "gaming",
    },
    ReputationEntry {
        patterns: &["lutris"],
        publisher: "Lutris",
        tier: Tier::Recognized,
        category: "gaming",
    },
    // ═══════════════════════════════════════════════════════════════
    //  COMMUNICATION (additional)
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["whatsapp"],
        publisher: "Meta (WhatsApp)",
        tier: Tier::Trusted,
        category: "communication",
    },
    ReputationEntry {
        patterns: &["signal-desktop", "signal-update"],
        publisher: "Signal Foundation",
        tier: Tier::Trusted,
        category: "communication",
    },
    ReputationEntry {
        patterns: &["element-desktop", "element-"],
        publisher: "Element (Matrix)",
        tier: Tier::Recognized,
        category: "communication",
    },
    ReputationEntry {
        patterns: &["guilded"],
        publisher: "Guilded / Roblox",
        tier: Tier::Recognized,
        category: "communication",
    },
    // ═══════════════════════════════════════════════════════════════
    //  SYSTEM / HARDWARE TOOLS (common FP sources)
    // ═══════════════════════════════════════════════════════════════
    ReputationEntry {
        patterns: &["hwinfo", "hwinfo64"],
        publisher: "HWiNFO",
        tier: Tier::Recognized,
        category: "system",
    },
    ReputationEntry {
        patterns: &["cpuz", "cpu-z"],
        publisher: "CPUID (CPU-Z)",
        tier: Tier::Recognized,
        category: "system",
    },
    ReputationEntry {
        patterns: &["gpuz", "gpu-z"],
        publisher: "TechPowerUp (GPU-Z)",
        tier: Tier::Recognized,
        category: "system",
    },
    ReputationEntry {
        patterns: &["crystaldisk"],
        publisher: "CrystalDiskInfo/Mark",
        tier: Tier::Recognized,
        category: "system",
    },
    ReputationEntry {
        patterns: &["msiafterburner", "afterburner"],
        publisher: "MSI (Afterburner)",
        tier: Tier::Recognized,
        category: "system",
    },
    ReputationEntry {
        patterns: &["furmark"],
        publisher: "FurMark / Geeks3D",
        tier: Tier::Recognized,
        category: "system",
    },
    ReputationEntry {
        patterns: &["aida64"],
        publisher: "FinalWire (AIDA64)",
        tier: Tier::Recognized,
        category: "system",
    },
    ReputationEntry {
        patterns: &["speccy"],
        publisher: "Piriform (Speccy)",
        tier: Tier::Recognized,
        category: "system",
    },
    // Remote desktop / collaboration.
    ReputationEntry {
        patterns: &["parsec", "parsecd"],
        publisher: "Parsec (Unity)",
        tier: Tier::Recognized,
        category: "remote",
    },
    ReputationEntry {
        patterns: &["teamviewer"],
        publisher: "TeamViewer",
        tier: Tier::Trusted,
        category: "remote",
    },
    ReputationEntry {
        patterns: &["anydesk"],
        publisher: "AnyDesk",
        tier: Tier::Recognized,
        category: "remote",
    },
    ReputationEntry {
        patterns: &["rustdesk"],
        publisher: "RustDesk",
        tier: Tier::Recognized,
        category: "remote",
    },
    // Streaming / recording.
    ReputationEntry {
        patterns: &["obs-studio", "obs64", "obs32"],
        publisher: "OBS Project",
        tier: Tier::Trusted,
        category: "streaming",
    },
    ReputationEntry {
        patterns: &["streamlabs"],
        publisher: "Streamlabs",
        tier: Tier::Recognized,
        category: "streaming",
    },
    // Android emulators.
    ReputationEntry {
        patterns: &["bluestacks"],
        publisher: "BlueStacks",
        tier: Tier::Recognized,
        category: "emulator",
    },
    ReputationEntry {
        patterns: &["ldplayer", "dnplayer"],
        publisher: "LDPlayer",
        tier: Tier::Recognized,
        category: "emulator",
    },
    ReputationEntry {
        patterns: &["noxplayer", "nox"],
        publisher: "NoxPlayer",
        tier: Tier::Recognized,
        category: "emulator",
    },
];

// ═══════════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════════

/// Analyze a file for known software reputation.
/// File domains where framework/runtime reputation is meaningful.
fn is_reputation_compatible(path: &str) -> bool {
    let ext = std::path::Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        // Executables.
        "exe" | "dll" | "sys" | "scr" | "com" | "msi" | "msix"
        // Scripts.
        | "ps1" | "psm1" | "bat" | "cmd" | "js" | "jse" | "vbs" | "vbe"
        // Archives that may contain executables.
        | "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz"
        // Installer containers.
        | "appx" | "appxbundle" | "nupkg" | "deb" | "rpm"
        // ELF / Mach-O (no extension or these).
        | "so" | "dylib" | "app" | "dmg"
        // Python/Node/Java.
        | "py" | "pyw" | "jar" | "war" | "whl"
    ) || ext.is_empty() // No extension → could be ELF.
}

pub fn analyze(path: &str, data: &[u8]) -> Vec<Finding> {
    // Domain gate: reputation only applies to executable/script/archive domains.
    if !is_reputation_compatible(path) {
        return vec![];
    }

    let filename = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if let Some(entry) = match_by_filename(&filename) {
        return vec![Finding {
            layer: Layer::Reputation,
            severity: Severity::Info,
            weight: 0,
            description: format!(
                "Recognized as known software from {} — structural anomalies are expected for this type of application.",
                entry.publisher,
            ),
            technical_detail: Some(format!(
                "Publisher: {} | Category: {} | Tier: {} | Discount: -{}",
                entry.publisher,
                entry.category,
                match entry.tier {
                    Tier::Trusted => "Trusted",
                    Tier::Recognized => "Recognized",
                },
                entry.tier.discount(),
            )),
        }];
    }

    if let Some(entry) = match_by_pe_strings(path, data) {
        return vec![Finding {
            layer: Layer::Reputation,
            severity: Severity::Info,
            weight: 0,
            description: format!(
                "Publisher identified as {} via signed Authenticode certificate — structural characteristics are expected.",
                entry.publisher,
            ),
            technical_detail: Some(format!(
                "Publisher: {} | Category: {} | Discount: -{}",
                entry.publisher,
                entry.category,
                entry.tier.discount(),
            )),
        }];
    }

    vec![]
}

/// Number of entries in the reputation database.
pub fn reputation_count() -> usize {
    REPUTATION_DB.len()
}

/// Get the reputation discount for a file.
pub fn reputation_discount(path: &str, data: &[u8]) -> u32 {
    // Domain gate: no discount for non-executable file types.
    if !is_reputation_compatible(path) {
        return 0;
    }

    let filename = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if let Some(entry) = match_by_filename(&filename) {
        // Filename-only match without cert confirmation → halve discount (spoofable).
        if match_by_pe_strings(path, data).is_some() {
            return entry.tier.discount(); // Confirmed by Authenticode cert.
        }
        return entry.tier.discount() / 2; // Unconfirmed → reduced.
    }
    if let Some(entry) = match_by_pe_strings(path, data) {
        return entry.tier.discount();
    }
    0
}

/// Combined analyze + discount in a single pass.
///
/// PERF: `analyze` + `reputation_discount` used to scan the file buffer with
/// `match_by_pe_strings` up to three separate times per file (once in analyze,
/// twice in reputation_discount). This entry point collapses all those scans
/// into one filename lookup and at most one PE-strings scan, returning both
/// the findings and the discount in a single call.
pub fn analyze_with_discount(path: &str, data: &[u8]) -> (Vec<Finding>, u32) {
    // Domain gate: reputation only applies to executable/script/archive domains.
    if !is_reputation_compatible(path) {
        return (vec![], 0);
    }

    let filename = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let filename_match = match_by_filename(&filename);
    // Single Authenticode cert lookup — used to either confirm a filename hit
    // (full vs halved discount) or to serve as the fallback identifier.
    let pe_match = match_by_pe_strings(path, data);

    // Build findings (mirrors `analyze` semantics: filename takes precedence).
    let findings = if let Some(entry) = filename_match {
        vec![Finding {
            layer: Layer::Reputation,
            severity: Severity::Info,
            weight: 0,
            description: format!(
                "Recognized as known software from {} — structural anomalies are expected for this type of application.",
                entry.publisher,
            ),
            technical_detail: Some(format!(
                "Publisher: {} | Category: {} | Tier: {} | Discount: -{}",
                entry.publisher,
                entry.category,
                match entry.tier {
                    Tier::Trusted => "Trusted",
                    Tier::Recognized => "Recognized",
                },
                entry.tier.discount(),
            )),
        }]
    } else if let Some(entry) = pe_match {
        vec![Finding {
            layer: Layer::Reputation,
            severity: Severity::Info,
            weight: 0,
            description: format!(
                "Publisher identified as {} via signed Authenticode certificate — structural characteristics are expected.",
                entry.publisher,
            ),
            technical_detail: Some(format!(
                "Publisher: {} | Category: {} | Discount: -{}",
                entry.publisher,
                entry.category,
                entry.tier.discount(),
            )),
        }]
    } else {
        vec![]
    };

    // Compute discount using the same precedence as `reputation_discount`.
    let discount = if let Some(entry) = filename_match {
        if pe_match.is_some() {
            entry.tier.discount()
        } else {
            entry.tier.discount() / 2
        }
    } else if let Some(entry) = pe_match {
        entry.tier.discount()
    } else {
        0
    };

    (findings, discount)
}

// ═══════════════════════════════════════════════════════════════════
//  Matching logic
// ═══════════════════════════════════════════════════════════════════

fn match_by_filename(filename: &str) -> Option<&'static ReputationEntry> {
    REPUTATION_DB
        .iter()
        .find(|entry| entry.patterns.iter().any(|&p| pattern_matches(filename, p)))
}

/// Match pattern in filename with word-boundary awareness for short patterns.
/// Short all-alphanumeric patterns (≤4 chars like "php", "ruby") require word
/// boundary to avoid matching substrings like "pago", "cargo".
/// Patterns containing non-alphanumeric chars (dots, hyphens like "go1.", "php-")
/// are inherently specific enough — use simple substring match.
fn pattern_matches(filename: &str, pattern: &str) -> bool {
    let all_alnum = pattern.bytes().all(|b| b.is_ascii_alphanumeric());
    if pattern.len() <= 4 && all_alnum {
        // Require word boundary: preceded/followed by non-alnum or string edge.
        let mut pos = 0;
        while let Some(idx) = filename[pos..].find(pattern) {
            let abs = pos + idx;
            let before_ok = abs == 0 || !filename.as_bytes()[abs - 1].is_ascii_alphanumeric();
            let after_pos = abs + pattern.len();
            let after_ok = after_pos >= filename.len()
                || !filename.as_bytes()[after_pos].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
            pos = abs + 1;
            if pos >= filename.len() {
                break;
            }
        }
        false
    } else {
        // Longer patterns or patterns with separators — substring match.
        filename.contains(pattern)
    }
}

/// Identify the publisher by extracting the **real signer subject** from the
/// PE's Authenticode certificate via the Windows CryptoAPI. The `_data`
/// argument is retained for ABI compatibility but is intentionally unused.
///
/// The prior implementation scanned the entire file body for UTF-16LE
/// publisher substrings — an attacker could trivially forge a reputation hit
/// by embedding bytes like "Python Software Foundation" in a `.rsrc` section
/// or debug overlay of an arbitrary unsigned PE. The new path returns `None`
/// for unsigned / unparseable / non-PE files, so the discount only fires
/// when the cert chain actually says the publisher.
fn match_by_pe_strings(path: &str, _data: &[u8]) -> Option<&'static ReputationEntry> {
    #[cfg(target_os = "windows")]
    {
        let signer =
            crate::layers::authenticode::extract_signer(std::path::Path::new(path))?;
        let signer_lower = signer.to_lowercase();

        // Map cert-subject substrings → REPUTATION_DB pattern keys.
        // Only high-confidence mappings — a generic cert (e.g. "Acme Inc")
        // shouldn't earn a reputation discount.
        let mappings: &[(&str, &str)] = &[
            ("python software foundation", "python"),
            ("mozilla", "firefox"),
            ("videolan", "vlc"),
            ("igor pavlov", "7z"),
            ("notepad++", "npp."),
            ("don ho", "npp."),
            ("jetbrains", "ideaic"),
            ("valve", "steam"),
            ("blender", "blender"),
            ("the gimp team", "gimp"),
            ("inkscape", "inkscape"),
            ("keepassxc", "keepass"),
            ("dominik reichl", "keepass"),
        ];

        for &(needle, db_pat) in mappings {
            if signer_lower.contains(needle) {
                if let Some(entry) = REPUTATION_DB
                    .iter()
                    .find(|e| e.patterns.iter().any(|&p| p.contains(db_pat)))
                {
                    return Some(entry);
                }
            }
        }
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Domain gating ──────────────────────────────────────

    #[test]
    fn pdf_not_reputation_compatible() {
        assert!(!is_reputation_compatible("document.pdf"));
        assert!(!is_reputation_compatible("Cupon_de_Pago_ABRIL_2026.pdf"));
    }

    #[test]
    fn image_not_reputation_compatible() {
        assert!(!is_reputation_compatible("photo.png"));
        assert!(!is_reputation_compatible("icon.jpg"));
        assert!(!is_reputation_compatible("banner.webp"));
    }

    #[test]
    fn document_not_reputation_compatible() {
        assert!(!is_reputation_compatible("notes.txt"));
        assert!(!is_reputation_compatible("data.csv"));
        assert!(!is_reputation_compatible("report.docx"));
    }

    #[test]
    fn exe_is_reputation_compatible() {
        assert!(is_reputation_compatible("setup.exe"));
        assert!(is_reputation_compatible("app.dll"));
        assert!(is_reputation_compatible("installer.msi"));
    }

    #[test]
    fn script_is_reputation_compatible() {
        assert!(is_reputation_compatible("deploy.ps1"));
        assert!(is_reputation_compatible("build.bat"));
        assert!(is_reputation_compatible("helper.js"));
    }

    #[test]
    fn archive_is_reputation_compatible() {
        assert!(is_reputation_compatible("app.zip"));
        assert!(is_reputation_compatible("release.7z"));
        assert!(is_reputation_compatible("bundle.tar"));
    }

    // ── Go pattern word boundary ───────────────────────────

    #[test]
    fn go_pattern_no_false_positive_on_pago() {
        // "Cupon_de_Pago" should NOT match Go patterns.
        assert!(match_by_filename("cupon_de_pago_abril_2026.pdf").is_none());
    }

    #[test]
    fn go_pattern_no_false_positive_on_argo() {
        // "argo" shouldn't match anything Go-related.
        assert!(match_by_filename("argo-workflow.exe").is_none());
    }

    #[test]
    fn go_pattern_no_false_positive_on_logo() {
        assert!(match_by_filename("company-logo.png").is_none());
    }

    #[test]
    fn go_pattern_matches_golang() {
        assert!(match_by_filename("golang-1.22.exe").is_some());
    }

    #[test]
    fn go_pattern_matches_go_version() {
        assert!(match_by_filename("go1.22.0.exe").is_some());
    }

    // ── Domain gate blocks reputation on PDF ───────────────

    #[test]
    fn pdf_gets_no_reputation_findings() {
        let findings = analyze("C:\\Downloads\\Cupon_de_Pago.pdf", &[0u8; 100]);
        assert!(findings.is_empty(), "PDF should get no reputation findings");
    }

    #[test]
    fn pdf_gets_no_reputation_discount() {
        let discount = reputation_discount("C:\\Downloads\\Cupon_de_Pago.pdf", &[0u8; 100]);
        assert_eq!(discount, 0, "PDF should get no reputation discount");
    }

    // ── Existing detection still works ─────────────────────

    #[test]
    fn exe_reputation_still_works() {
        let findings = analyze("C:\\Downloads\\vscode-setup.exe", &[0u8; 100]);
        assert!(!findings.is_empty(), "VSCode exe should get reputation");
    }

    #[test]
    fn exe_reputation_discount_works() {
        let discount = reputation_discount("C:\\Downloads\\vscode-setup.exe", &[0u8; 100]);
        assert!(discount > 0, "VSCode exe should get discount");
    }

    // ── Word boundary logic ────────────────────────────────

    #[test]
    fn pattern_matches_word_boundary() {
        // Short all-alnum patterns need boundaries.
        assert!(pattern_matches("ruby-installer.exe", "ruby"));
        assert!(!pattern_matches("cherryblossomruby.exe", "ruby")); // no boundary before

        // Patterns with non-alnum chars use substring (inherently specific).
        assert!(pattern_matches("go1.22.exe", "go1."));
        assert!(pattern_matches("php-8.exe", "php-"));
        // Non-alnum patterns use simple substring — specific enough.
        assert!(!pattern_matches("setup.exe", "go1.")); // no match
    }

    #[test]
    fn pattern_matches_long_substring() {
        // Long patterns (>4 chars) use substring.
        assert!(pattern_matches("vscode-setup.exe", "vscode"));
        assert!(pattern_matches("notepad++.exe", "notepad++"));
    }
}

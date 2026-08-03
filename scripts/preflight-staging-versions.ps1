# preflight-staging-versions.ps1 -- guard against the v0.1.7 release bug
#
# v0.1.7 shipped an installer with a v0.1.5 daemon because
# `release/staging/windows/*.exe` was 4 days stale (the staging script
# was never re-run after the daemon was rebuilt). This script catches
# that class of bug before the Tauri bundle stage by asserting:
#
#   1. Every shipped binary in release/staging/windows/ exists.
#   2. Its PE FileVersion matches the workspace Cargo.toml version.
#   3. Its mtime is within 24 hours of the workspace Cargo.toml mtime
#      (a wall-clock heuristic -- catches the case where the binary
#      compiled at a stale version got copied forward).
#
# Exit code 0 = OK, exit code 1 = mismatch (fails the wrapping build).
# Intended to run from any working directory; resolves paths relative
# to the repo root via the script's own location.
#
# Run manually:
#   pwsh scripts\preflight-staging-versions.ps1
#
# WHAT ACTUALLY RUNS THIS. One command, and it is not the obvious one:
#   cd gui && npm run release:build     -> preflight:staging && tauri build
# There is no tauri:build script and no prebuild hook. `pnpm tauri build`,
# `npm run tauri -- build` and a bare `tauri build` all invoke the Tauri CLI
# directly and never reach this file, so packaging that way ships the
# v0.1.7 stale-daemon class unguarded. Package with release:build, or run
# this script yourself first.

$ErrorActionPreference = "Stop"

# Repo root = script dir / ..
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Staging = Join-Path $RepoRoot "release\staging\windows"
$WorkspaceTomlPath = Join-Path $RepoRoot "Cargo.toml"

if (-not (Test-Path $WorkspaceTomlPath)) {
    Write-Host "[preflight] FATAL: workspace Cargo.toml not found at $WorkspaceTomlPath" -ForegroundColor Red
    exit 1
}

# Extract workspace.package.version from Cargo.toml (single match).
$WorkspaceVersion = $null
foreach ($line in Get-Content $WorkspaceTomlPath) {
    if ($line -match '^\s*version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"') {
        $WorkspaceVersion = $matches[1]
        break
    }
}

if (-not $WorkspaceVersion) {
    Write-Host "[preflight] FATAL: could not parse workspace version from Cargo.toml" -ForegroundColor Red
    exit 1
}

Write-Host "[preflight] workspace version: $WorkspaceVersion" -ForegroundColor Cyan

if (-not (Test-Path $Staging)) {
    Write-Host ""
    Write-Host "[preflight] FATAL: staging dir not found:" -ForegroundColor Red
    Write-Host "             $Staging" -ForegroundColor Red
    Write-Host ""
    Write-Host "Run scripts\stage-windows-package.bat first to populate it" -ForegroundColor Yellow
    Write-Host "(requires cargo build --release of sentinelld, argusd, sentinella-cli)." -ForegroundColor Yellow
    exit 1
}

# Binaries Tauri actually packages into the installer. Mirrored from
# gui/src-tauri/tauri.conf.json `bundle.resources`. Keep in sync.
$ShippedBinaries = @(
    "sentinelld.exe",
    "argusd.exe",
    "sentinella.exe",   # CLI, renamed to sentinella-cli.exe inside the bundle
    # Added to tauri.conf.json during the 0.1.13 web-protection work but not
    # here, so this guard would have passed a stale reconciler through. That
    # is the worst one to miss: it is the only component that can remove the
    # NRPT rule while the daemon is not running.
    "sentinella-dnsreconcile.exe"
)

$WorkspaceTomlMtime = (Get-Item $WorkspaceTomlPath).LastWriteTime
$Now = [DateTime]::UtcNow
$Errors = @()

foreach ($name in $ShippedBinaries) {
    $path = Join-Path $Staging $name
    if (-not (Test-Path $path)) {
        $Errors += "  - $name : MISSING from staging"
        continue
    }
    $info = Get-Item $path
    $ver = $info.VersionInfo.FileVersion
    $mtime = $info.LastWriteTime
    $ageDays = ($Now - $mtime).TotalDays

    if ($ver) {
        Write-Host ("[preflight] {0,-22} v{1,-10} mtime={2:yyyy-MM-dd HH:mm}" -f $name, $ver, $mtime)
        # Compare as 3-component semver. PE FileVersion may be "0.1.7.0".
        $verShort = ($ver -split '\.')[0..2] -join '.'
        if ($verShort -ne $WorkspaceVersion) {
            $Errors += "  - $name : v$verShort != workspace v$WorkspaceVersion"
            $Errors += "    Rebuild + re-stage: cargo build --release -p sentinelld -p argusd -p sentinella-cli && scripts\stage-windows-package.bat"
        }
    } else {
        # argusd.exe and sentinella-cli.exe don't embed FileVersion in
        # their PE headers (no winres build script / cargo doesn't write
        # it automatically for our rustc version). For these, fall back
        # to the mtime heuristic alone -- still catches the v0.1.7 bug
        # where 4-day-stale binaries got shipped.
        Write-Host ("[preflight] {0,-22} v? (no PE FileVersion -- mtime check only) mtime={1:yyyy-MM-dd HH:mm}" -f $name, $mtime) -ForegroundColor DarkYellow
    }

    # mtime heuristic: warn if staging binary is much older than Cargo.toml.
    # This catches the "rebuilt cargo but forgot to re-stage" case.
    if ($mtime -lt $WorkspaceTomlMtime.AddHours(-24)) {
        $Errors += "  - $name : staging copy is more than 24h older than Cargo.toml"
        $Errors += "    Run scripts\stage-windows-package.bat to copy a fresh build forward."
    }
}

# ── Updater signing key ───────────────────────────────────────────────
#
# WHY THIS IS HERE, BEFORE THE BUILD. tauri.conf.json sets
# createUpdaterArtifacts + a minisign pubkey, so every release is SUPPOSED
# to ship a .sig the auto-updater verifies. When TAURI_SIGNING_PRIVATE_KEY
# is not set, the bundler prints "A public key has been found, but no
# private key" -- and then EXITS 0. npm reports a successful build and you
# get an installer that existing users cannot auto-update to. 0.1.13 was
# built unsigned twice before anyone noticed.
#
# The key itself is NOT missing: keys\sentinella-update.key has been in
# place since 2026-05-26 and is gitignored. What goes missing between
# releases is the env var pointing at it, which lives only in whichever
# shell the release was cut from. docs\WORKING_STATE_v0.1.0.md records the
# procedure; nothing enforces it. Catching this here costs a second,
# catching it after the bundle costs the whole build.
#
# ONLY TAURI_SIGNING_PRIVATE_KEY counts, and it holds either the key itself
# or a PATH to the key file. TAURI_SIGNING_PRIVATE_KEY_PATH exists, but the
# CLI changelog (2.10.0) added it for the `tauri signer sign` subcommand;
# `tauri build` does not read it. docs\WORKING_STATE_v0.1.0.md tells you to
# set the _PATH form, and following that doc produces an unsigned build --
# verified here by doing exactly that and watching the bundler still report
# no private key. Accepting _PATH would make this check pass while the build
# stayed unsigned, which is worse than not checking.
#
# This checks only that the variable is NON-EMPTY, and, when it looks like a
# path, that the file exists. It never reads, logs, echoes or validates key
# material.
$TauriConf = Join-Path $RepoRoot "gui\src-tauri\tauri.conf.json"
if (Test-Path $TauriConf) {
    $conf = Get-Content $TauriConf -Raw | ConvertFrom-Json
    $wantsSignature = $false
    if ($conf.bundle.createUpdaterArtifacts) {
        if ($conf.plugins.updater.pubkey) { $wantsSignature = $true }
    }
    $key = $env:TAURI_SIGNING_PRIVATE_KEY
    $haveKey = -not [string]::IsNullOrWhiteSpace($key)
    $DefaultKey = Join-Path $RepoRoot "keys\sentinella-update.key"
    if ($wantsSignature -and -not $haveKey) {
        $Errors += "  - TAURI_SIGNING_PRIVATE_KEY is not set, but tauri.conf.json configures"
        $Errors += "    an updater pubkey, so the bundle would be built UNSIGNED and existing"
        $Errors += "    installs could not auto-update to it."
        if (-not [string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY_PATH)) {
            # The exact trap docs\WORKING_STATE_v0.1.0.md walks you into.
            # Single quotes around the command names, NOT backticks: inside a
            # double-quoted PowerShell string a backtick is the escape
            # character, and the one before the closing quote swallowed it --
            # the file stopped parsing and the guard took every release build
            # down with it.
            $Errors += "    NOTE: TAURI_SIGNING_PRIVATE_KEY_PATH *is* set, and 'tauri build'"
            $Errors += "    ignores it -- that variable is for 'tauri signer sign'. Put the"
            $Errors += "    path in TAURI_SIGNING_PRIVATE_KEY instead; it accepts a path."
        }
        if (Test-Path $DefaultKey) {
            # The usual cause: the key is right there, the variable is not.
            $Errors += "    The key IS on disk. From the repo root, before building:"
            $Errors += "      `$env:TAURI_SIGNING_PRIVATE_KEY = `"$DefaultKey`""
        }
    } elseif ($haveKey -and ($key -match '[\\/]') -and -not (Test-Path -LiteralPath $key)) {
        # It looks like a path and does not resolve. A key that is inline
        # base64 has no separators, so this cannot misfire on one.
        $Errors += "  - TAURI_SIGNING_PRIVATE_KEY looks like a path but no such file exists:"
        $Errors += "      $key"
    }
}

if ($Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "[preflight] FAILED:" -ForegroundColor Red
    foreach ($e in $Errors) { Write-Host $e -ForegroundColor Red }
    Write-Host ""
    Write-Host "If you're packaging a new release, the standard recipe is:" -ForegroundColor Yellow
    Write-Host "  cargo build --release -p sentinelld -p argusd -p sentinella-cli" -ForegroundColor Yellow
    Write-Host "  scripts\stage-windows-package.bat" -ForegroundColor Yellow
    Write-Host "  cd gui && npm run release:build" -ForegroundColor Yellow
    Write-Host "(release:build, not 'tauri build' -- only release:build re-runs this check.)" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "[preflight] OK -- staging binaries match workspace v$WorkspaceVersion" -ForegroundColor Green
exit 0

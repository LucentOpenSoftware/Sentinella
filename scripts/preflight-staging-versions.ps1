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
# Wired into npm run tauri:build via gui/package.json prebuild hook.

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
    "sentinella.exe"    # CLI, renamed to sentinella-cli.exe inside the bundle
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

if ($Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "[preflight] FAILED:" -ForegroundColor Red
    foreach ($e in $Errors) { Write-Host $e -ForegroundColor Red }
    Write-Host ""
    Write-Host "If you're packaging a new release, the standard recipe is:" -ForegroundColor Yellow
    Write-Host "  cargo build --release -p sentinelld -p argusd -p sentinella-cli" -ForegroundColor Yellow
    Write-Host "  scripts\stage-windows-package.bat" -ForegroundColor Yellow
    Write-Host "  cd gui && npm run tauri -- build" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "[preflight] OK -- staging binaries match workspace v$WorkspaceVersion" -ForegroundColor Green
exit 0

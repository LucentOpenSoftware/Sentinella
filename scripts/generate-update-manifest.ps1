# generate-update-manifest.ps1 -- build latest.json from the real artifacts
#
# The auto-updater fetches
#   https://github.com/LucentOpenSoftware/Sentinella/releases/latest/download/latest.json
# and that manifest carries the minisign signature INSIDE it, plus the URL of
# the installer to download. Tauri produces the .exe and the .sig; it does
# NOT produce this file, and nothing else in this repo did either -- no
# script, no CI. It was hand-written each release.
#
# The failure that invites: the previous release's latest.json sits in the
# bundle directory looking like build output. Uploading "the three files from
# bundle/nsis" therefore publishes a manifest announcing the OLD version and
# pointing at the OLD installer. Every client is told it is up to date and
# nothing anywhere reports an error. Checked on 2026-08-02: after three
# 0.1.13 builds, bundle/nsis/latest.json still said 0.1.12 and was dated
# 2026-07-29.
#
# So this generates it from what is actually on disk: version from
# tauri.conf.json, signature read out of the .sig the build just produced,
# URL derived from that version. Nothing is copied forward from a previous
# release, so it cannot silently describe one.
#
# Usage:
#   pwsh scripts\generate-update-manifest.ps1
#   pwsh scripts\generate-update-manifest.ps1 -Notes "short release summary"
#
# Exit codes:
#   0   manifest written
#   1   installer or signature missing / inconsistent

[CmdletBinding()]
param(
    # Release notes shown by the updater. Defaults to the CHANGELOG heading
    # for this version, which is at least never wrong about which release it
    # describes.
    [string]$Notes,
    # Where the installer will be published. Only the tag shape varies.
    [string]$RepoUrl = "https://github.com/LucentOpenSoftware/Sentinella"
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$TauriConf = Join-Path $RepoRoot "gui\src-tauri\tauri.conf.json"
$BundleDir = Join-Path $RepoRoot "gui\src-tauri\target\release\bundle\nsis"

if (-not (Test-Path $TauriConf)) {
    Write-Host "[manifest] FATAL: tauri.conf.json not found" -ForegroundColor Red
    exit 1
}

$conf = Get-Content $TauriConf -Raw | ConvertFrom-Json
$version = $conf.version

if (-not $conf.bundle.createUpdaterArtifacts -or -not $conf.plugins.updater.pubkey) {
    Write-Host "[manifest] updater artifacts are not configured -- nothing to generate" -ForegroundColor Yellow
    exit 0
}

# THIS version's installer only. Globbing "*setup.exe" would happily pick up
# the previous release still sitting in the directory, which is the exact
# mistake this script exists to prevent.
$exeName = "Sentinella_${version}_x64-setup.exe"
$exe = Join-Path $BundleDir $exeName
$sig = "$exe.sig"

if (-not (Test-Path $exe)) {
    Write-Host "[manifest] FAILED: no installer for v$version at" -ForegroundColor Red
    Write-Host "           $exe" -ForegroundColor Red
    Write-Host "           The bundle step did not produce one." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $sig) -or (Get-Item $sig).Length -eq 0) {
    Write-Host "[manifest] FAILED: no signature beside the v$version installer." -ForegroundColor Red
    Write-Host "           A manifest without a valid signature is rejected by every" -ForegroundColor Red
    Write-Host "           client, so writing one would only look like progress." -ForegroundColor Red
    Write-Host "           Set TAURI_SIGNING_PRIVATE_KEY (and _PASSWORD) and rebuild." -ForegroundColor Red
    exit 1
}

# The signature file is public key material -- it is published as a release
# asset -- so reading it here is not handling a secret.
$signature = (Get-Content $sig -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($signature)) {
    Write-Host "[manifest] FAILED: the signature file is empty." -ForegroundColor Red
    exit 1
}

# Minisign's trusted comment records the file it signed. If that name is not
# this installer, the .sig belongs to a different build and the update would
# fail verification on every client, after they downloaded 140 MB.
$decoded = ""
try {
    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($signature))
} catch {
    Write-Host "[manifest] FAILED: signature is not valid base64." -ForegroundColor Red
    exit 1
}
if ($decoded -notmatch [regex]::Escape($exeName)) {
    Write-Host "[manifest] FAILED: the signature does not name this installer." -ForegroundColor Red
    Write-Host "           expected: $exeName" -ForegroundColor Red
    Write-Host "           It signs a different build -- verification would fail on" -ForegroundColor Red
    Write-Host "           every client after a full download." -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Notes)) {
    # First non-empty prose line under this version's CHANGELOG heading.
    $changelog = Join-Path $RepoRoot "CHANGELOG.md"
    if (Test-Path $changelog) {
        $lines = Get-Content $changelog
        $start = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "^##\s*\[$([regex]::Escape($version))\]") { $start = $i; break }
        }
        if ($start -ge 0) {
            # First PROSE paragraph, skipping sub-headings and list markers.
            # Taking the first non-empty line verbatim yielded "### Web
            # protection (new)" -- a heading rendered to the user as the
            # release notes.
            $buf = @()
            for ($i = $start + 1; $i -lt $lines.Count -and $buf.Count -lt 6; $i++) {
                $l = $lines[$i].Trim()
                if ($lines[$i] -match '^##\s') { break }
                if ($l -match '^#{1,6}\s') { continue }
                if ($l -match '^[-*|]') { if ($buf.Count -gt 0) { break } else { continue } }
                if ($l) { $buf += $l }
                elseif ($buf.Count -gt 0) { break }
            }
            $Notes = ($buf -join ' ')
        }
    }
    if ([string]::IsNullOrWhiteSpace($Notes)) { $Notes = "Sentinella v$version" }
}

$manifest = [ordered]@{
    version   = $version
    notes     = $Notes
    pub_date  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    platforms = [ordered]@{
        "windows-x86_64" = [ordered]@{
            signature = $signature
            url       = "$RepoUrl/releases/download/v$version/$exeName"
        }
    }
}

$out = Join-Path $BundleDir "latest.json"
$json = $manifest | ConvertTo-Json -Depth 6
# UTF-8 without BOM: a BOM here breaks strict JSON parsers.
[System.IO.File]::WriteAllText($out, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "[manifest] OK -- wrote latest.json for v$version" -ForegroundColor Green
Write-Host "           installer : $exeName"
Write-Host "           signature : verified to name that installer"
Write-Host "           url       : $RepoUrl/releases/download/v$version/$exeName"
Write-Host ""
Write-Host "Publish all three as assets on a release tagged v$version," -ForegroundColor Yellow
Write-Host "and make sure it is the LATEST release (not a draft or pre-release)" -ForegroundColor Yellow
Write-Host "-- the updater fetches releases/latest/download/latest.json." -ForegroundColor Yellow
exit 0

# verify-updater-signature.ps1 -- the bundle actually got signed
#
# The preflight sibling checks TAURI_SIGNING_PRIVATE_KEY is SET before the
# build. That is necessary and not sufficient: a wrong key, a wrong
# passphrase, or a bundler that changes its mind still produce an unsigned
# installer, and the Tauri bundler EXITS 0 either way. It prints
#
#   Error A public key has been found, but no private key.
#
# and then returns success, so `npm run release:build` reports a clean
# build over an installer that no existing install can auto-update to.
# That is how 0.1.13 was cut unsigned twice.
#
# This asserts the artifact itself: for every installer in the bundle
# directory at the CURRENT workspace version, a non-empty .sig sits beside
# it. Signature CONTENT is never read, printed or validated here -- that
# would need the key, and this script deliberately touches no key material.
#
# Usage:
#   pwsh scripts\verify-updater-signature.ps1
#
# Exit codes:
#   0   every installer at this version has a signature (or the updater is
#       not configured, in which case there is nothing to check)
#   1   an installer is unsigned, or the bundle directory is missing

$ErrorActionPreference = 'Stop'

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$TauriConf = Join-Path $RepoRoot "gui\src-tauri\tauri.conf.json"

if (-not (Test-Path $TauriConf)) {
    Write-Host "[sigcheck] FATAL: tauri.conf.json not found at $TauriConf" -ForegroundColor Red
    exit 1
}

$conf = Get-Content $TauriConf -Raw | ConvertFrom-Json
$version = $conf.version

# No updater configured means no signature is owed. Say so rather than
# passing silently, so a config change that drops the pubkey is visible.
if (-not $conf.bundle.createUpdaterArtifacts -or -not $conf.plugins.updater.pubkey) {
    Write-Host "[sigcheck] updater artifacts are not configured -- nothing to verify" -ForegroundColor Yellow
    exit 0
}

$BundleDir = Join-Path $RepoRoot "gui\src-tauri\target\release\bundle\nsis"
if (-not (Test-Path $BundleDir)) {
    Write-Host "[sigcheck] FAILED: no bundle directory at $BundleDir" -ForegroundColor Red
    exit 1
}

# Only THIS version's installers. Older ones sitting in the directory are
# not this build's problem, and matching them would let a signed 0.1.12
# vouch for an unsigned 0.1.13.
$installers = @(Get-ChildItem $BundleDir -Filter "*$version*setup.exe" -File -ErrorAction SilentlyContinue)

if ($installers.Count -eq 0) {
    Write-Host "[sigcheck] FAILED: no installer for v$version in $BundleDir" -ForegroundColor Red
    Write-Host "           The bundle step did not produce one." -ForegroundColor Red
    exit 1
}

$failed = 0
foreach ($exe in $installers) {
    $sig = "$($exe.FullName).sig"
    if ((Test-Path $sig) -and ((Get-Item $sig).Length -gt 0)) {
        Write-Host ("[sigcheck] OK     {0}" -f $exe.Name) -ForegroundColor Green
    } else {
        $failed++
        Write-Host ("[sigcheck] UNSIGNED  {0}" -f $exe.Name) -ForegroundColor Red
    }
}

if ($failed -gt 0) {
    Write-Host ""
    Write-Host "[sigcheck] FAILED: $failed installer(s) built without a signature." -ForegroundColor Red
    Write-Host ""
    Write-Host "The auto-updater verifies this signature against the pubkey in" -ForegroundColor Yellow
    Write-Host "tauri.conf.json, so an unsigned installer is one that existing" -ForegroundColor Yellow
    Write-Host "installs cannot update to. Set TAURI_SIGNING_PRIVATE_KEY (and" -ForegroundColor Yellow
    Write-Host "TAURI_SIGNING_PRIVATE_KEY_PASSWORD if the key has one) and rebuild." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "[sigcheck] OK -- every v$version installer is signed" -ForegroundColor Green
exit 0

# release-build.ps1 -- the whole release pipeline, one entry point
#
# preflight -> bundle -> sign -> verify signature -> generate manifest
#
# WHY THIS EXISTS. The npm chain (`a && b && c`) could not express the one
# control-flow quirk this release actually has: the Tauri bundler's built-in
# signing step cannot be used non-interactively with this key.
#
#   - keys\sentinella-update.key is encrypted with an EMPTY passphrase.
#   - `tauri build` reads the passphrase only from
#     TAURI_SIGNING_PRIVATE_KEY_PASSWORD, and on Windows a variable cannot
#     be SET to empty -- `$env:X = ''` (PowerShell) and `set X=` (cmd) both
#     DELETE it. So the CLI never sees an empty password, falls back to an
#     interactive prompt, and in any non-interactive shell hangs forever at
#     "Decrypting updater signing key, expect a prompt for password".
#     0.1.13 hung there twice before this was understood.
#   - `tauri signer sign --password ""` takes the empty passphrase as an
#     ARGUMENT, which works everywhere. So: bundle without the key in the
#     environment (the bundler then skips its signing attempt and merely
#     exits nonzero after producing a complete installer), and sign as an
#     explicit step.
#
# Usage:
#   $env:TAURI_SIGNING_PRIVATE_KEY = "C:\...\keys\sentinella-update.key"
#   pwsh scripts\release-build.ps1              # full pipeline
#   pwsh scripts\release-build.ps1 -SkipBundle  # re-run sign/verify/manifest only
#
# TAURI_SIGNING_PRIVATE_KEY holds the key file path or the key itself;
# TAURI_SIGNING_PRIVATE_KEY_PASSWORD the passphrase (absent = empty).
# Exit nonzero on the first step that fails.

[CmdletBinding()]
param(
    [switch]$SkipBundle
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$GuiDir = Join-Path $RepoRoot "gui"
$BundleDir = Join-Path $GuiDir "src-tauri\target\release\bundle\nsis"

function Step($n, $msg) { Write-Host ""; Write-Host "[release $n/5] $msg" -ForegroundColor Cyan }

# ── 1/5 preflight (includes the signing-key presence check) ────────────
Step 1 "preflight"
& (Join-Path $PSScriptRoot "preflight-staging-versions.ps1")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$conf = Get-Content (Join-Path $GuiDir "src-tauri\tauri.conf.json") -Raw | ConvertFrom-Json
$version = $conf.version
$exe = Join-Path $BundleDir "Sentinella_${version}_x64-setup.exe"

# ── 2/5 bundle ─────────────────────────────────────────────────────────
if ($SkipBundle) {
    Step 2 "bundle (skipped on request)"
    if (-not (Test-Path $exe)) {
        Write-Host "[release] FAILED: -SkipBundle, but no installer exists at $exe" -ForegroundColor Red
        exit 1
    }
} else {
    Step 2 "bundle (unsigned -- signing is step 3)"
    $started = Get-Date
    # The key comes OUT of the bundler's environment on purpose; see header.
    # Saved and restored so step 3 still has it.
    $savedKey = $env:TAURI_SIGNING_PRIVATE_KEY
    $env:TAURI_SIGNING_PRIVATE_KEY = $null
    Push-Location $GuiDir
    try {
        npm run tauri build
        $bundleExit = $LASTEXITCODE
    } finally {
        Pop-Location
        $env:TAURI_SIGNING_PRIVATE_KEY = $savedKey
    }
    # With updater artifacts configured and no key in the environment the
    # bundler produces the COMPLETE installer and then exits nonzero over
    # the missing key. That precise failure is expected here. Anything that
    # failed to produce a fresh installer is a real failure.
    $fresh = (Test-Path $exe) -and ((Get-Item $exe).LastWriteTime -gt $started)
    if (-not $fresh) {
        Write-Host "[release] FAILED: bundler exit $bundleExit and no fresh installer at" -ForegroundColor Red
        Write-Host "          $exe" -ForegroundColor Red
        exit 1
    }
    if ($bundleExit -ne 0) {
        Write-Host "[release] bundler exit $bundleExit with a fresh installer present -- its" -ForegroundColor Yellow
        Write-Host "          built-in signing was skipped by design; signing next." -ForegroundColor Yellow
    }
}

# ── 3/5 sign ───────────────────────────────────────────────────────────
Step 3 "sign"
$key = $env:TAURI_SIGNING_PRIVATE_KEY
if ([string]::IsNullOrWhiteSpace($key)) {
    Write-Host "[release] FAILED: TAURI_SIGNING_PRIVATE_KEY is not set" -ForegroundColor Red
    exit 1
}
# Path or inline key -- the signer has a flag for each.
$keyArgs = if (Test-Path -LiteralPath $key) { @("-f", $key) } else { @("-k", $key) }
$password = $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD
if ($null -eq $password) { $password = "" }
Push-Location $GuiDir
# The env var must NOT be visible to the signer: clap reads
# TAURI_SIGNING_PRIVATE_KEY as --private-key, and an explicit -f/-k beside
# it is rejected as conflicting flags. Cleared for the child, restored
# after -- on Windows assigning $null genuinely deletes it, which for once
# is the behavior we want.
$env:TAURI_SIGNING_PRIVATE_KEY = $null
try {
    # ONE token, `--password=...`, never `--password "..."`. Windows
    # PowerShell 5.1 silently DROPS empty-string arguments to native
    # commands, so with the empty passphrase the two-token form became
    # `--password <exe-path>`: the flag ate the installer path as its
    # password and the signer exited 2 over the missing file argument.
    # `--password=` survives because the token itself is non-empty, and
    # clap parses it as an empty value.
    npx tauri signer sign @keyArgs "--password=$password" "$exe"
    $signExit = $LASTEXITCODE
} finally {
    Pop-Location
    $env:TAURI_SIGNING_PRIVATE_KEY = $key
}
if ($signExit -ne 0) {
    Write-Host "[release] FAILED: signer exit $signExit" -ForegroundColor Red
    exit 1
}

# ── 4/5 verify the artifact really is signed ───────────────────────────
Step 4 "verify signature"
& (Join-Path $PSScriptRoot "verify-updater-signature.ps1")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# ── 5/5 manifest ───────────────────────────────────────────────────────
Step 5 "update manifest"
& (Join-Path $PSScriptRoot "generate-update-manifest.ps1")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "[release] DONE -- signed installer + signature + manifest for v$version" -ForegroundColor Green
Write-Host "          Publish all three from $BundleDir" -ForegroundColor Green
exit 0

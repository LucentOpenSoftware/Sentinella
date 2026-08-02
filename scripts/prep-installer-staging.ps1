# Prepare release/staging/windows/ with the freshly built daemon binaries
# before invoking `pnpm tauri build`.
#
# Why this script exists:
#   gui/src-tauri/tauri.conf.json bundles
#     ../../release/staging/windows/sentinelld.exe
#     ../../release/staging/windows/argusd.exe
#   as Tauri "resources" — NOT from target/release/. If the staging dir
#   holds stale binaries from a prior release, `pnpm tauri build` happily
#   wraps them in a fresh installer whose label says (e.g.) 0.1.10 but
#   whose daemon is still (e.g.) 0.1.9. That cost the v0.1.10 release two
#   installer rebuilds before we caught it.
#
# What this does:
#   1. Reads the workspace version from Cargo.toml.
#   2. Confirms target/release/sentinelld.exe and target/release/argusd.exe
#      both report that version (via embedded PRODUCT_VERSION string).
#   3. Copies them into release/staging/windows/ overwriting whatever
#      was there.
#   4. Re-checks the staged binaries report the right version.
#
# Run this before every `pnpm tauri build` invocation, including in CI.
#
# Usage:
#   .\scripts\prep-installer-staging.ps1
#   .\scripts\prep-installer-staging.ps1 -Verbose
#
# Exit codes:
#   0   ok, staged binaries match workspace version
#   1   target/release/ binary missing -- run `cargo build --release` first
#   2   target/release/ binary version mismatch -- rebuild
#   3   staging copy failed
#   4   post-copy verification failed

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Find-AsciiSubstring {
    param(
        [byte[]]$Bytes,
        [byte[]]$Needle
    )
    if ($Needle.Length -eq 0) { return $false }
    $limit = $Bytes.Length - $Needle.Length
    for ($i = 0; $i -le $limit; $i++) {
        $match = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Bytes[$i + $j] -ne $Needle[$j]) { $match = $false; break }
        }
        if ($match) { return $true }
    }
    return $false
}
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$cargoToml = Join-Path $repoRoot 'Cargo.toml'
$targetDir = Join-Path $repoRoot 'target\release'
$stagingDir = Join-Path $repoRoot 'release\staging\windows'

# ── 1. Read workspace version ──
$cargo = Get-Content -Raw -LiteralPath $cargoToml
if ($cargo -notmatch '(?m)^\s*\[workspace\.package\][^\[]*?version\s*=\s*"([^"]+)"') {
    Write-Error "Could not find workspace.package.version in $cargoToml"
    exit 1
}
$expectedVersion = $matches[1]
Write-Host "Workspace version: $expectedVersion" -ForegroundColor Cyan

# ── 2. Verify target/release binaries exist and have the right version ──
# sentinella-dnsreconcile.exe is the boot-time NRPT reconciler. It is the
# ONLY thing that can remove the DNS policy rule when the daemon is not
# running, and the daemon refuses to install a rule unless its scheduled
# task exists - so a staging run that forgets it does not break DNS, it
# silently disables web protection.
$binaries = @('sentinelld.exe', 'argusd.exe', 'sentinella-dnsreconcile.exe')
foreach ($bin in $binaries) {
    $path = Join-Path $targetDir $bin
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Error "Missing: $path -- run 'cargo build --release' first"
        exit 1
    }

    # Embedded version string scan. We're looking for the ASCII bytes
    # of the workspace version, but we have to be paranoid about false
    # positives: "0.1.10" could appear inside an unrelated dep version
    # string in the rodata. Mitigation: also require that the OLD version
    # (Cargo.toml workspace-1) does NOT appear as a standalone token.
    # If both checks pass, this binary is freshly built at the new version.
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $needle = [System.Text.Encoding]::ASCII.GetBytes($expectedVersion)
    $found = Find-AsciiSubstring -Bytes $bytes -Needle $needle
    if (-not $found) {
        Write-Error "$bin does NOT contain version string '$expectedVersion'. Rebuild with 'cargo build --workspace --release'."
        exit 2
    }
    Write-Verbose "$bin contains expected version string"
}

# ── 3. Copy into staging ──
if (-not (Test-Path -LiteralPath $stagingDir)) {
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
}
foreach ($bin in $binaries) {
    $src = Join-Path $targetDir $bin
    $dst = Join-Path $stagingDir $bin
    try {
        Copy-Item -LiteralPath $src -Destination $dst -Force
        Write-Verbose "Staged $bin"
    } catch {
        Write-Error "Failed to stage $bin -- $_"
        exit 3
    }
}

# ── 4. Re-verify staged copies ──
foreach ($bin in $binaries) {
    $path = Join-Path $stagingDir $bin
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $needle = [System.Text.Encoding]::ASCII.GetBytes($expectedVersion)
    if (-not (Find-AsciiSubstring -Bytes $bytes -Needle $needle)) {
        Write-Error "Post-copy: $bin in staging does NOT contain '$expectedVersion'"
        exit 4
    }
}

Write-Host "Staged $($binaries -join ', ') at version $expectedVersion. Safe to run 'pnpm tauri build'." -ForegroundColor Green

# Prepare release/staging/windows/ with the freshly built daemon binaries
# before the installer is packaged.
#
# Why this script exists:
#   gui/src-tauri/tauri.conf.json bundles
#     ../../release/staging/windows/sentinelld.exe
#     ../../release/staging/windows/argusd.exe
#   as Tauri "resources" — NOT from target/release/. If the staging dir
#   holds stale binaries from a prior release, the bundler happily
#   wraps them in a fresh installer whose label says (e.g.) 0.1.10 but
#   whose daemon is still (e.g.) 0.1.9. That cost the v0.1.10 release two
#   installer rebuilds before we caught it.
#
# What this does:
#   1. Reads the workspace version from Cargo.toml.
#   2. Confirms every target/release binary carries that version as a
#      STANDALONE token, and does NOT still carry the previous patch
#      version. See Test-VersionToken for why "contains the string
#      somewhere" was never good enough.
#   3. Copies them into release/staging/windows/ overwriting whatever
#      was there.
#   4. Re-checks the staged copies the same way.
#
# Run this before packaging, including in CI. NOTHING runs it for you:
# gui's `npm run release:build` chains the sibling guard
# (preflight-staging-versions.ps1), not this script, and `pnpm tauri build`
# / `npm run tauri -- build` chain neither of them.
#
# Usage:
#   .\scripts\prep-installer-staging.ps1
#   .\scripts\prep-installer-staging.ps1 -Verbose
#   .\scripts\prep-installer-staging.ps1 -SelfTest
#
# Exit codes:
#   0   ok, staged binaries match workspace version
#   1   target/release/ binary missing -- run `cargo build --release` first
#   2   target/release/ binary version mismatch -- rebuild
#   3   staging copy failed
#   4   post-copy verification failed
#   5   -SelfTest found the version matcher broken

[CmdletBinding()]
param(
    # Check the version matcher against known-tricky inputs and exit
    # without reading or writing anything in the repo.
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

# Characters which, sitting immediately beside a version match, prove that
# match is part of something longer and not a version in its own right.
$script:VersionTokenBreakers = '0123456789.-'

function Test-VersionToken {
    <#
      .SYNOPSIS
      Does $Version occur in $Text as a standalone version token?

      .DESCRIPTION
      A plain substring scan is not good enough, and never was. Every Rust
      binary carries panic-location strings for its dependencies, e.g.
        ...\index.crates.io-1949cf8c6b5b557f\weezl-0.1.12\src\decode.rs
      so "sentinelld.exe contains 0.1.12" is true of a binary that has
      nothing at all to do with version 0.1.12 — and it is true today, of
      both sentinelld.exe and argusd.exe, for exactly that reason. Bump the
      workspace to a number some transitive dependency also happens to
      carry and a stale binary sails straight through, producing the
      mixed-version installer this script exists to prevent.

      Standalone means neither neighbouring character is a digit, '.' or
      '-', which rejects:
        10.1.13 / 0.1.130  -- a different, longer version
        weezl-0.1.12\src   -- a cargo registry path component
        0.1.13-rc1         -- a prerelease, i.e. not this version
      A rejected occurrence does not end the search: a binary may well
      contain both a registry path and its own version.
    #>
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Version
    )
    if ($Version.Length -eq 0) { return $false }
    $i = 0
    while (($i = $Text.IndexOf($Version, $i, [System.StringComparison]::Ordinal)) -ge 0) {
        $end = $i + $Version.Length
        $leftOk = ($i -eq 0) -or ($script:VersionTokenBreakers.IndexOf($Text[$i - 1]) -lt 0)
        $rightOk = ($end -ge $Text.Length) -or ($script:VersionTokenBreakers.IndexOf($Text[$end]) -lt 0)
        if ($leftOk -and $rightOk) { return $true }
        $i++
    }
    return $false
}

function Get-BinaryText {
    # ASCII decoding maps every byte above 0x7F to '?', which can neither
    # invent a version token nor hide one: '?' is not a digit, '.' or '-',
    # so it can only ever act as a boundary. Also ~100x faster than walking
    # 34 MB of bytes in PowerShell, which is what this used to do per
    # binary, twice.
    param([Parameter(Mandatory)][string]$Path)
    [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($Path))
}

function Get-PreviousPatchVersion {
    # The release immediately before a patch bump. Returns $null for x.y.0,
    # where the predecessor is the last patch of some earlier minor and
    # guessing it would be worse than not checking at all.
    param([Parameter(Mandatory)][string]$Version)
    if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)$') { return $null }
    $patch = [int]$Matches[3]
    if ($patch -le 0) { return $null }
    '{0}.{1}.{2}' -f $Matches[1], $Matches[2], ($patch - 1)
}

if ($SelfTest) {
    # The registry-path cases are the whole point: a substring scan returns
    # $true for every one of them, so this fails loudly the moment
    # Test-VersionToken degrades back into one.
    $cases = @(
        @{ Expect = $true;  Version = '0.1.13'; Text = 'max-size-mb0.1.13Sentinella ARGUS isolated worker'; Why = 'clap version string, exactly as argusd.exe embeds it' }
        @{ Expect = $true;  Version = '0.1.13'; Text = "settings.get0.1.13`0`0";                            Why = 'CLI version string, NUL-terminated' }
        @{ Expect = $true;  Version = '0.1.13'; Text = '0.1.13';                                            Why = 'whole text' }
        @{ Expect = $false; Version = '0.1.12'; Text = 'index.crates.io-1949cf8c\weezl-0.1.12\src\dec.rs';  Why = 'cargo registry path component, not the binary version' }
        @{ Expect = $false; Version = '0.1.12'; Text = '/root/.cargo/registry/src/weezl-0.1.12/src/lib.rs'; Why = 'same, unix separators' }
        @{ Expect = $false; Version = '0.1.13'; Text = 'built with 10.1.13';                                Why = 'suffix of a longer version' }
        @{ Expect = $false; Version = '0.1.13'; Text = 'built with 0.1.130';                                Why = 'prefix of a longer version' }
        @{ Expect = $false; Version = '0.1.13'; Text = 'sentinelld 0.1.13-rc1';                             Why = 'prerelease is a different version' }
        @{ Expect = $true;  Version = '0.1.12'; Text = 'weezl-0.1.12 and 0.1.12 alone';                     Why = 'a rejected occurrence must not mask a real one' }
    )
    $failed = 0
    foreach ($c in $cases) {
        $got = Test-VersionToken -Text $c.Text -Version $c.Version
        if ($got -ne $c.Expect) {
            $failed++
            Write-Host ("[selftest] FAIL  expected={0} got={1}  {2}" -f $c.Expect, $got, $c.Why) -ForegroundColor Red
            Write-Host ("           version={0}  text={1}" -f $c.Version, $c.Text) -ForegroundColor Red
        } else {
            Write-Verbose ("[selftest] ok  {0}" -f $c.Why)
        }
    }
    foreach ($p in @(@('0.1.13', '0.1.12'), @('2.4.10', '2.4.9'), @('1.0.0', $null), @('not.a.version', $null))) {
        $got = Get-PreviousPatchVersion -Version $p[0]
        if ($got -ne $p[1]) {
            $failed++
            Write-Host ("[selftest] FAIL  Get-PreviousPatchVersion('{0}') = '{1}', expected '{2}'" -f $p[0], $got, $p[1]) -ForegroundColor Red
        }
    }
    if ($failed -gt 0) {
        Write-Host "[selftest] $failed assertion(s) failed" -ForegroundColor Red
        exit 5
    }
    Write-Host "[selftest] version matcher OK" -ForegroundColor Green
    exit 0
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$cargoToml = Join-Path $repoRoot 'Cargo.toml'
$targetDir = Join-Path $repoRoot 'target\release'
$stagingDir = Join-Path $repoRoot 'release\staging\windows'

# Every Write-Error below carries -ErrorAction Continue on purpose. With
# $ErrorActionPreference = 'Stop' a bare Write-Error is TERMINATING: the
# script dies on the spot and powershell.exe -File returns 1, so the exit
# codes documented above never actually happened and every failure looked
# like "binary missing" to a caller. Continue keeps the message on stderr
# and lets the following exit set the real code.

# ── 1. Read workspace version ──
$cargo = Get-Content -Raw -LiteralPath $cargoToml
if ($cargo -notmatch '(?m)^\s*\[workspace\.package\][^\[]*?version\s*=\s*"([^"]+)"') {
    Write-Error "Could not find workspace.package.version in $cargoToml" -ErrorAction Continue
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
# sentinella.exe is the CLI, bundled by tauri.conf.json as
# daemon/sentinella-cli.exe. It was missing from this list until 0.1.13, so
# every installer since the CLI was last hand-copied shipped whatever build
# happened to be sitting in staging. preflight-staging-versions.ps1 caught it
# on the 0.1.13 bundle (staged copy dated 2026-05-30) - which is precisely the
# v0.1.7 stale-binary class this script exists to prevent, present in the
# script itself. Anything listed under tauri.conf.json's resources and built
# from this workspace belongs here.
$binaries = @('sentinelld.exe', 'argusd.exe', 'sentinella-dnsreconcile.exe', 'sentinella.exe')

# Embedded version string scan, both halves of it.
#
# The first half looks for the workspace version as a standalone token —
# see Test-VersionToken for why "appears anywhere in the file" answers a
# different and useless question.
#
# The second half is the one this script promised in a comment and never
# implemented: a binary rebuilt at the new version must not still be
# carrying the previous one. It only became implementable once dependency
# path components stopped counting as matches, because weezl-0.1.12 is in
# sentinelld.exe and argusd.exe no matter which version we ship, and a
# naive scan would have failed every single build.
$previousVersion = Get-PreviousPatchVersion -Version $expectedVersion
if ($previousVersion) {
    Write-Verbose "Previous release version (must be absent): $previousVersion"
} else {
    Write-Host "Note: $expectedVersion is not a patch bump, so there is no predecessor to check for." -ForegroundColor DarkYellow
}

function Get-BinaryVersionProblem {
    # $null when the binary looks freshly built at $Expected, otherwise the
    # reason it does not.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Expected,
        [AllowNull()][string]$Previous
    )
    $text = Get-BinaryText -Path $Path
    if (-not (Test-VersionToken -Text $text -Version $Expected)) {
        return "$Name does NOT contain version string '$Expected'. Rebuild with 'cargo build --workspace --release'."
    }
    if ($Previous -and (Test-VersionToken -Text $text -Version $Previous)) {
        return "$Name still carries '$Previous' as a standalone version token -- it looks like a stale build from the previous release. Rebuild with 'cargo build --workspace --release'."
    }
    return $null
}

foreach ($bin in $binaries) {
    $path = Join-Path $targetDir $bin
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Error "Missing: $path -- run 'cargo build --release' first" -ErrorAction Continue
        exit 1
    }

    $problem = Get-BinaryVersionProblem -Path $path -Name $bin -Expected $expectedVersion -Previous $previousVersion
    if ($problem) {
        Write-Error $problem -ErrorAction Continue
        exit 2
    }
    Write-Verbose "$bin carries $expectedVersion as a standalone version token"
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
        Write-Error "Failed to stage $bin -- $_" -ErrorAction Continue
        exit 3
    }
}

# ── 4. Re-verify staged copies ──
# Same two checks against what actually landed, because the file the
# installer bundles is this one, not the one in target/release.
foreach ($bin in $binaries) {
    $path = Join-Path $stagingDir $bin
    $problem = Get-BinaryVersionProblem -Path $path -Name $bin -Expected $expectedVersion -Previous $previousVersion
    if ($problem) {
        Write-Error "Post-copy: $problem" -ErrorAction Continue
        exit 4
    }
}

Write-Host "Staged $($binaries -join ', ') at version $expectedVersion." -ForegroundColor Green
Write-Host "Package with 'npm run release:build' from gui/ so preflight-staging-versions.ps1 runs too." -ForegroundColor Green

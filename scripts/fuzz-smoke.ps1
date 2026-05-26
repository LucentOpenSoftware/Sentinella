# fuzz-smoke.ps1 — Run 15-minute smoke fuzz on each target.
# Usage: .\scripts\fuzz-smoke.ps1 [-Duration 900] [-Target fuzz_convergence]
#
# Requires: rustup nightly, cargo-fuzz
# Install: rustup toolchain install nightly; cargo install cargo-fuzz

param(
    [int]$Duration = 900,        # seconds per target
    [string]$Target = "",        # specific target, or "" for all
    [switch]$Quick               # 60-second quick smoke
)

$ErrorActionPreference = "Continue"

# Ensure rustup-managed cargo is used (not standalone Rust install).
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

Set-Location "$PSScriptRoot\..\fuzz"

if ($Quick) { $Duration = 60 }

$targets = @(
    "fuzz_convergence",
    "fuzz_ipc_frame",
    "fuzz_argus_pe",
    "fuzz_etw_parser",
    "fuzz_paths"
)

if ($Target -ne "") {
    $targets = @($Target)
}

$results = @()
$crashCount = 0

Write-Host "=== Sentinella Fuzz Smoke Test ===" -ForegroundColor Cyan
Write-Host "Duration per target: ${Duration}s"
Write-Host "Targets: $($targets -join ', ')"
Write-Host ""

foreach ($t in $targets) {
    Write-Host "--- Running $t (${Duration}s) ---" -ForegroundColor Yellow
    $start = Get-Date

    # Windows: use GNU target + no sanitizer (MSVC doesn't support SanCov symbols).
    # For full sanitizer support, use WSL2 or Linux.
    $output = cargo fuzz run $t --sanitizer none --target x86_64-pc-windows-gnu -- -max_total_time=$Duration 2>&1 | Out-String

    $elapsed = ((Get-Date) - $start).TotalSeconds
    $crashed = $output -match "SUMMARY.*BINGO\!|panicked|ERROR|ABORTING"
    $timeout = $output -match "Done.*iterations"

    if ($crashed) {
        Write-Host "  CRASH FOUND in $t!" -ForegroundColor Red
        $crashCount++
        $results += [PSCustomObject]@{
            Target = $t
            Status = "CRASH"
            Duration = [math]::Round($elapsed, 1)
        }

        # Save crash artifacts
        $crashDir = "corpus\$($t.Replace('fuzz_',''))\crashes"
        if (-not (Test-Path $crashDir)) {
            New-Item -ItemType Directory -Force $crashDir | Out-Null
        }

        # Copy crash files from fuzz artifacts directory
        $artifactDir = "artifacts\$t"
        if (Test-Path $artifactDir) {
            Get-ChildItem $artifactDir -Filter "crash-*" | ForEach-Object {
                Copy-Item $_.FullName "$crashDir\$($_.Name)"
                Write-Host "  Saved: $crashDir\$($_.Name)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  Clean ($([math]::Round($elapsed, 1))s)" -ForegroundColor Green
        $results += [PSCustomObject]@{
            Target = $t
            Status = "CLEAN"
            Duration = [math]::Round($elapsed, 1)
        }
    }
}

Write-Host ""
Write-Host "=== Smoke Results ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

if ($crashCount -gt 0) {
    Write-Host "$crashCount target(s) had crashes — fix before release!" -ForegroundColor Red
    exit 1
} else {
    Write-Host "All targets clean." -ForegroundColor Green
    exit 0
}

# fuzz-regression.ps1 — Replay known corpus + crash reproductions.
# CI-safe: runs each input through the target once (no fuzzing).
# If any input crashes, exits with code 1.
#
# Usage: .\scripts\fuzz-regression.ps1

$ErrorActionPreference = "Continue"
Set-Location "$PSScriptRoot\..\fuzz"

$targets = @(
    "fuzz_convergence",
    "fuzz_ipc_frame",
    "fuzz_argus_pe",
    "fuzz_etw_parser",
    "fuzz_paths"
)

$failed = 0

Write-Host "=== Sentinella Fuzz Regression ===" -ForegroundColor Cyan
Write-Host ""

foreach ($t in $targets) {
    $corpusName = $t.Replace("fuzz_", "")
    $corpusDir = "corpus\$corpusName"

    if (-not (Test-Path $corpusDir)) {
        Write-Host "  SKIP $t (no corpus at $corpusDir)" -ForegroundColor DarkGray
        continue
    }

    $fileCount = (Get-ChildItem $corpusDir -File -Recurse | Measure-Object).Count
    if ($fileCount -eq 0) {
        Write-Host "  SKIP $t (empty corpus)" -ForegroundColor DarkGray
        continue
    }

    Write-Host "--- $t ($fileCount inputs) ---" -ForegroundColor Yellow

    # -runs=0 means "process corpus, don't generate new inputs"
    $output = cargo +nightly fuzz run $t $corpusDir -- -runs=0 2>&1 | Out-String

    if ($output -match "panicked|ERROR|ABORTING|SUMMARY.*BINGO") {
        Write-Host "  REGRESSION FAILURE in $t!" -ForegroundColor Red
        $failed++
    } else {
        Write-Host "  OK" -ForegroundColor Green
    }
}

Write-Host ""
if ($failed -gt 0) {
    Write-Host "$failed regression failure(s)!" -ForegroundColor Red
    exit 1
} else {
    Write-Host "All regressions pass." -ForegroundColor Green
    exit 0
}

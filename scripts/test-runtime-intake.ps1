# Sentinella ASTRA Runtime Intake Validation
# Tests the runtime scan pipeline against a corpus of safe script samples.
#
# Prerequisites:
#   - sentinelld running (dev-run.bat or service)
#   - sentinella CLI built (target\release\sentinella.exe)
#   - SENTINELLA_IPC_SECRET env var set
#
# Usage:
#   $env:SENTINELLA_IPC_SECRET = Get-Content runtime\state\ipc_secret
#   .\scripts\test-runtime-intake.ps1

param(
    [string]$CliPath = "target\release\sentinella.exe",
    [string]$CorpusDir = "runtime\test_runtime"
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  ====================================" -ForegroundColor Cyan
Write-Host "  ASTRA Runtime Intake Validation" -ForegroundColor Cyan
Write-Host "  ====================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $CliPath)) {
    Write-Host "  [ERR] CLI not found: $CliPath" -ForegroundColor Red
    Write-Host "  Build with: cargo build --workspace --release"
    exit 1
}

if (-not $env:SENTINELLA_IPC_SECRET) {
    $secretPath = "runtime\state\ipc_secret"
    if (Test-Path $secretPath) {
        $env:SENTINELLA_IPC_SECRET = (Get-Content $secretPath -Raw).Trim()
        Write-Host "  [OK] Loaded IPC secret from $secretPath" -ForegroundColor Green
    } else {
        Write-Host "  [ERR] Set SENTINELLA_IPC_SECRET or ensure $secretPath exists" -ForegroundColor Red
        exit 1
    }
}

$results = @()
$pass = 0
$fail = 0

function Test-RuntimeScan {
    param(
        [string]$File,
        [string]$Category,
        [int]$MinScore,
        [int]$MaxScore
    )

    $json = & $CliPath runtime-scan $File --language powershell --json 2>&1
    try {
        $r = $json | ConvertFrom-Json
        $score = if ($r.score) { $r.score } else { 0 }
        $findings = if ($r.findings_count) { $r.findings_count } else { 0 }
        $block = if ($r.should_block) { "BLOCK" } else { "OBSERVE" }
        $name = Split-Path $File -Leaf

        $ok = ($score -ge $MinScore -and $score -le $MaxScore)
        $status = if ($ok) { "PASS" } else { "FAIL" }
        $color = if ($ok) { "Green" } else { "Red" }

        Write-Host ("  [{0}] {1,-35} score={2,3}  findings={3}  {4}  (expected {5}-{6})" -f $status, $name, $score, $findings, $block, $MinScore, $MaxScore) -ForegroundColor $color

        if ($ok) { $script:pass++ } else { $script:fail++ }

        $script:results += [PSCustomObject]@{
            File = $name
            Category = $Category
            Score = $score
            Findings = $findings
            Verdict = $block
            Expected = "$MinScore-$MaxScore"
            Status = $status
        }
    } catch {
        Write-Host "  [ERR] $File : $json" -ForegroundColor Red
        $script:fail++
    }
}

Write-Host "  Category: BENIGN (expected low scores)" -ForegroundColor DarkGray
Write-Host ""
Test-RuntimeScan "$CorpusDir\benign\hello.ps1" "benign" 0 25
Test-RuntimeScan "$CorpusDir\benign\admin_script.ps1" "benign" 0 30
Test-RuntimeScan "$CorpusDir\benign\web_request.ps1" "benign" 0 30

Write-Host ""
Write-Host "  Category: SUSPICIOUS (expected medium scores)" -ForegroundColor DarkGray
Write-Host ""
Test-RuntimeScan "$CorpusDir\suspicious\encoded_command.ps1" "suspicious" 10 70
Test-RuntimeScan "$CorpusDir\suspicious\base64_blob.ps1" "suspicious" 10 70
Test-RuntimeScan "$CorpusDir\suspicious\lolbin_launch.ps1" "suspicious" 15 75

Write-Host ""
Write-Host "  Category: MALICIOUS SIMULATED (expected high scores)" -ForegroundColor DarkGray
Write-Host ""
Test-RuntimeScan "$CorpusDir\malicious_simulated\download_cradle.ps1" "malicious" 20 100
Test-RuntimeScan "$CorpusDir\malicious_simulated\amsi_bypass.ps1" "malicious" 15 100
Test-RuntimeScan "$CorpusDir\malicious_simulated\credential_access.ps1" "malicious" 15 100

Write-Host ""
Write-Host "  ====================================" -ForegroundColor Cyan
Write-Host "  Results: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
Write-Host "  ====================================" -ForegroundColor Cyan
Write-Host ""

if ($fail -gt 0) {
    Write-Host "  Failed tests:" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq "FAIL" } | Format-Table -AutoSize
}

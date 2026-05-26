# cold-scan-benchmark.ps1 — Phase 2Z.9: Cold scan recovery benchmark
#
# Measures scan latency and working set regrowth after post-compile trim.
# Tests: cold scan (pages evicted) vs warm scan (pages resident).
#
# Requirements: sentinelld running with file-backed mpool + WS trim active.

$ErrorActionPreference = "Continue"
Set-Location "$PSScriptRoot\.."

function Get-DaemonMemory {
    $p = Get-Process -Name "sentinelld" -ErrorAction SilentlyContinue
    if (-not $p) { return $null }
    return [PSCustomObject]@{
        WS_MB = [math]::Round($p.WorkingSet64 / 1MB, 1)
        Private_MB = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
        PageFaults = $p.PageFaultCount
    }
}

function Invoke-IPC {
    param([string]$Method, [hashtable]$Params = @{})
    $body = @{ jsonrpc = "2.0"; id = 1; method = $Method; params = $Params } | ConvertTo-Json -Compress
    # Use the CLI tool or direct pipe — for now, use the scan file API via Tauri
    # Fallback: measure by watching the daemon process
    return $null
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Phase 2Z.9: Cold Scan Recovery Benchmark"
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$daemon = Get-Process -Name "sentinelld" -ErrorAction SilentlyContinue
if (-not $daemon) {
    Write-Host "[ERR] sentinelld not running" -ForegroundColor Red
    exit 1
}

# Baseline
$baseline = Get-DaemonMemory
Write-Host "=== BASELINE (post-trim idle) ==="
Write-Host "  WS: $($baseline.WS_MB) MB  Private: $($baseline.Private_MB) MB  PageFaults: $($baseline.PageFaults)"
Write-Host ""

# Prepare test files
$testDir = "runtime\diagnostics\benchmark_files"
New-Item -ItemType Directory -Force $testDir | Out-Null

# Create test files of various types
# 1. Small text file
$textFile = "$testDir\small_text.txt"
"This is a clean text file for benchmark purposes." | Out-File -FilePath $textFile -Encoding utf8

# 2. Copy a real PE (use sentinelld.exe itself — known clean)
$peFile = "$testDir\test_pe.exe"
Copy-Item "target\debug\sentinelld.exe" $peFile -Force -ErrorAction SilentlyContinue

# 3. Create a small ZIP
$zipFile = "$testDir\test_archive.zip"
if (-not (Test-Path $zipFile)) {
    Compress-Archive -Path $textFile -DestinationPath $zipFile -Force
}

$testFiles = @(
    @{ Name = "Small text (100B)"; Path = $textFile },
    @{ Name = "PE executable (sentinelld)"; Path = $peFile },
    @{ Name = "ZIP archive"; Path = $zipFile }
)

# Filter to existing files
$testFiles = $testFiles | Where-Object { Test-Path $_.Path }

Write-Host "=== COLD SCAN (first scan after trim) ==="
Write-Host ""

$results = @()
foreach ($test in $testFiles) {
    $before = Get-DaemonMemory

    # Trigger scan via CLI
    $scanStart = Get-Date
    $scanOutput = & "target\debug\sentinella.exe" scan-file $test.Path 2>&1 | Out-String
    $scanEnd = Get-Date
    $scanMs = [math]::Round(($scanEnd - $scanStart).TotalMilliseconds, 0)

    $after = Get-DaemonMemory
    $faultDelta = if ($before -and $after) { $after.PageFaults - $before.PageFaults } else { 0 }
    $wsGrowth = if ($before -and $after) { $after.WS_MB - $before.WS_MB } else { 0 }

    Write-Host "  $($test.Name):"
    Write-Host "    Scan time:     ${scanMs}ms"
    Write-Host "    WS before:     $($before.WS_MB) MB"
    Write-Host "    WS after:      $($after.WS_MB) MB  (growth: ${wsGrowth} MB)"
    Write-Host "    Page faults:   $faultDelta"
    Write-Host ""

    $results += [PSCustomObject]@{
        File = $test.Name
        ColdScanMs = $scanMs
        WS_Before = $before.WS_MB
        WS_After = $after.WS_MB
        WS_Growth = $wsGrowth
        PageFaults = $faultDelta
    }
}

# Warm scan: repeat the same files
Write-Host "=== WARM SCAN (pages now resident) ==="
Write-Host ""

$warmResults = @()
foreach ($test in $testFiles) {
    $before = Get-DaemonMemory

    $scanStart = Get-Date
    $scanOutput = & "target\debug\sentinella.exe" scan-file $test.Path 2>&1 | Out-String
    $scanEnd = Get-Date
    $scanMs = [math]::Round(($scanEnd - $scanStart).TotalMilliseconds, 0)

    $after = Get-DaemonMemory
    $faultDelta = if ($before -and $after) { $after.PageFaults - $before.PageFaults } else { 0 }

    Write-Host "  $($test.Name):"
    Write-Host "    Scan time:     ${scanMs}ms"
    Write-Host "    Page faults:   $faultDelta"
    Write-Host ""

    $warmResults += [PSCustomObject]@{
        File = $test.Name
        WarmScanMs = $scanMs
        PageFaults = $faultDelta
    }
}

# Final state
$final = Get-DaemonMemory
Write-Host "=== FINAL STATE ==="
Write-Host "  WS: $($final.WS_MB) MB  Private: $($final.Private_MB) MB"
Write-Host ""

# Comparison table
Write-Host "=== COMPARISON ==="
Write-Host ""
Write-Host "File                        Cold(ms)  Warm(ms)  WS Growth  Faults(cold)"
Write-Host "---                         --------  --------  ---------  ------------"
for ($i = 0; $i -lt $results.Count; $i++) {
    $c = $results[$i]
    $w = if ($i -lt $warmResults.Count) { $warmResults[$i] } else { $null }
    $warmMs = if ($w) { $w.WarmScanMs } else { "N/A" }
    Write-Host ("  {0,-26} {1,8}  {2,8}  {3,9}  {4,12}" -f $c.File, $c.ColdScanMs, $warmMs, "$($c.WS_Growth) MB", $c.PageFaults)
}

Write-Host ""
Write-Host "Baseline WS: $($baseline.WS_MB) MB  Final WS: $($final.WS_MB) MB  Regrowth: $([math]::Round($final.WS_MB - $baseline.WS_MB, 1)) MB"

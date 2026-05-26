# pressure-test.ps1 — Phase 2C: Memory pressure validation for file-backed mpool
#
# Measures how sentinelld's working set behaves under memory pressure.
# File-backed mpool pages should be cheaply reclaimable by the OS.
#
# Usage: .\scripts\pressure-test.ps1
#
# Requirements: sentinelld must be running with file-backed mpool DLL.

param(
    [int]$PressureMB = 4096,    # MB of pressure to create
    [int]$HoldSeconds = 15      # How long to hold pressure
)

$ErrorActionPreference = "Continue"

function Get-SentinellaMemory {
    $p = Get-Process -Name "sentinelld" -ErrorAction SilentlyContinue
    if (-not $p) { return $null }
    return [PSCustomObject]@{
        PID = $p.Id
        WorkingSetMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
        PrivateMB = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
        VirtualMB = [math]::Round($p.VirtualMemorySize64 / 1MB, 1)
        PageFaults = $p.PageFaultCount
        Threads = $p.Threads.Count
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Phase 2C: Memory Pressure Validation"
Write-Host " File-backed mpool residency test"
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check sentinelld is running
$initial = Get-SentinellaMemory
if (-not $initial) {
    Write-Host "[ERR] sentinelld not running. Start daemon first." -ForegroundColor Red
    exit 1
}

# Check cache file
$cacheFile = "runtime\cache\clamav-engine-mpool.cache"
$cacheExists = Test-Path $cacheFile
$cacheSize = if ($cacheExists) { [math]::Round((Get-Item $cacheFile).Length / 1MB, 1) } else { 0 }

Write-Host "Cache file: $(if ($cacheExists) { "${cacheSize} MB (FILE-BACKED)" } else { 'NOT FOUND (anonymous)' })"
Write-Host ""

# Phase 1: Baseline
Write-Host "--- Phase 1: Baseline (idle) ---" -ForegroundColor Yellow
Write-Host "  Working Set:  $($initial.WorkingSetMB) MB"
Write-Host "  Private:      $($initial.PrivateMB) MB"
Write-Host "  Page Faults:  $($initial.PageFaults)"
Write-Host ""

$baseline_ws = $initial.WorkingSetMB
$baseline_pf = $initial.PageFaults

# Phase 2: Wait for idle (let OS naturally trim if it wants)
Write-Host "--- Phase 2: Waiting 30s for idle trim ---" -ForegroundColor Yellow
Start-Sleep -Seconds 30
$after_idle = Get-SentinellaMemory
Write-Host "  Working Set:  $($after_idle.WorkingSetMB) MB (delta: $($after_idle.WorkingSetMB - $baseline_ws))"
Write-Host "  Private:      $($after_idle.PrivateMB) MB"
Write-Host ""

# Phase 3: Apply memory pressure
Write-Host "--- Phase 3: Applying ${PressureMB}MB memory pressure for ${HoldSeconds}s ---" -ForegroundColor Yellow
Write-Host "  (Allocating large arrays to force page eviction...)"

# Allocate memory to create pressure
$arrays = @()
$chunkMB = 512
$chunks = [math]::Floor($PressureMB / $chunkMB)

for ($i = 0; $i -lt $chunks; $i++) {
    try {
        $arr = New-Object byte[] ($chunkMB * 1MB)
        # Touch all pages to force them into working set
        for ($j = 0; $j -lt $arr.Length; $j += 4096) {
            $arr[$j] = [byte]($j % 256)
        }
        $arrays += $arr
        Write-Host "    Allocated chunk $($i+1)/$chunks (${chunkMB}MB)" -ForegroundColor DarkGray
    } catch {
        Write-Host "    Allocation failed at chunk $($i+1) — system under pressure" -ForegroundColor DarkGray
        break
    }
}

$during_pressure = Get-SentinellaMemory
Write-Host ""
Write-Host "  Working Set during pressure: $($during_pressure.WorkingSetMB) MB" -ForegroundColor $(if ($during_pressure.WorkingSetMB -lt $baseline_ws * 0.5) { "Green" } else { "Yellow" })
Write-Host "  Private during pressure:     $($during_pressure.PrivateMB) MB"
Write-Host "  Page Faults:                 $($during_pressure.PageFaults) (delta: $($during_pressure.PageFaults - $baseline_pf))"
Write-Host ""

$pressure_ws = $during_pressure.WorkingSetMB
$ws_reduction = $baseline_ws - $pressure_ws
$ws_pct = if ($baseline_ws -gt 0) { [math]::Round($ws_reduction / $baseline_ws * 100, 1) } else { 0 }

Write-Host "  Working Set reduction: ${ws_reduction} MB (${ws_pct} percent)" -ForegroundColor $(if ($ws_pct -gt 50) { "Green" } elseif ($ws_pct -gt 20) { "Yellow" } else { "Red" })

# Hold pressure
Write-Host ""
Write-Host "  Holding pressure for ${HoldSeconds}s..."
Start-Sleep -Seconds $HoldSeconds

$after_hold = Get-SentinellaMemory
Write-Host "  Working Set after hold: $($after_hold.WorkingSetMB) MB"

# Phase 4: Release pressure
Write-Host ""
Write-Host "--- Phase 4: Releasing pressure ---" -ForegroundColor Yellow
$arrays = $null
[GC]::Collect()
[GC]::WaitForPendingFinalizers()
Start-Sleep -Seconds 5

$after_release = Get-SentinellaMemory
Write-Host "  Working Set after release: $($after_release.WorkingSetMB) MB"
Write-Host "  Private after release:     $($after_release.PrivateMB) MB"
Write-Host "  Page Faults:               $($after_release.PageFaults) (total delta: $($after_release.PageFaults - $baseline_pf))"
Write-Host ""

# Phase 5: Summary
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " RESULTS"
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  File-backed mpool:    $(if ($cacheExists) { 'YES' } else { 'NO' })"
Write-Host "  Cache file size:      ${cacheSize} MB"
Write-Host ""
Write-Host "  Baseline WS:          ${baseline_ws} MB"
Write-Host "  Idle trim WS:         $($after_idle.WorkingSetMB) MB"
Write-Host "  Under pressure WS:    ${pressure_ws} MB" -ForegroundColor $(if ($pressure_ws -lt 400) { "Green" } elseif ($pressure_ws -lt 700) { "Yellow" } else { "Red" })
Write-Host "  After release WS:     $($after_release.WorkingSetMB) MB"
Write-Host ""
Write-Host "  Private Bytes:        $($after_release.PrivateMB) MB" -ForegroundColor $(if ($after_release.PrivateMB -lt 50) { "Green" } else { "Yellow" })
Write-Host "  WS reduction:         ${ws_reduction} MB (${ws_pct} percent)"
Write-Host "  Page faults (total):  $($after_release.PageFaults - $baseline_pf)"
Write-Host ""

if ($pressure_ws -lt 400) {
    Write-Host "  VERDICT: EXCELLENT — file-backed pages reclaimed under pressure" -ForegroundColor Green
} elseif ($pressure_ws -lt 700) {
    Write-Host "  VERDICT: GOOD — significant WS reduction under pressure" -ForegroundColor Yellow
} else {
    Write-Host "  VERDICT: POOR — pages not reclaimed (check if mpool is file-backed)" -ForegroundColor Red
}
Write-Host ""

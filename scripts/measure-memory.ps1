# measure-memory.ps1 — Measure sentinelld memory metrics
#
# Usage:
#   .\scripts\measure-memory.ps1 [-ProcessName sentinelld] [-Interval 5] [-Duration 60]
#
# Captures:
#   - Working Set (physical RAM)
#   - Private Bytes (committed virtual memory)
#   - Virtual Size (total address space)
#   - Page Faults/sec
#   - Handle Count
#
# Output: CSV-format to stdout + summary

param(
    [string]$ProcessName = "sentinelld",
    [int]$Interval = 5,        # seconds between samples
    [int]$Duration = 60,       # total capture duration
    [switch]$PressureTest      # simulate memory pressure during capture
)

$ErrorActionPreference = "Continue"

Write-Host "=== Sentinella Memory Measurement ===" -ForegroundColor Cyan
Write-Host "Process: $ProcessName"
Write-Host "Interval: ${Interval}s, Duration: ${Duration}s"
Write-Host ""

# Find process
$proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
if (-not $proc) {
    Write-Host "[ERR] Process '$ProcessName' not found. Start the daemon first." -ForegroundColor Red
    exit 1
}

$pid = $proc.Id
Write-Host "PID: $pid"
Write-Host ""

# CSV header
Write-Host "timestamp,working_set_mb,private_bytes_mb,virtual_size_mb,page_faults,handle_count,thread_count"

$samples = @()
$iterations = [math]::Floor($Duration / $Interval)

for ($i = 0; $i -lt $iterations; $i++) {
    $p = Get-Process -Id $pid -ErrorAction SilentlyContinue
    if (-not $p) {
        Write-Host "[WARN] Process exited during measurement" -ForegroundColor Yellow
        break
    }

    $ts = Get-Date -Format "HH:mm:ss"
    $ws_mb = [math]::Round($p.WorkingSet64 / 1MB, 1)
    $pb_mb = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
    $vs_mb = [math]::Round($p.VirtualMemorySize64 / 1MB, 1)
    $pf = $p.PageFaultCount  # Note: this is cumulative, not per-second
    $handles = $p.HandleCount
    $threads = $p.Threads.Count

    $line = "$ts,$ws_mb,$pb_mb,$vs_mb,$pf,$handles,$threads"
    Write-Host $line

    $samples += [PSCustomObject]@{
        Timestamp = $ts
        WorkingSetMB = $ws_mb
        PrivateMB = $pb_mb
        VirtualMB = $vs_mb
        PageFaults = $pf
        Handles = $handles
        Threads = $threads
    }

    Start-Sleep -Seconds $Interval
}

# Summary
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan

if ($samples.Count -gt 0) {
    $ws_values = $samples | ForEach-Object { $_.WorkingSetMB }
    $pb_values = $samples | ForEach-Object { $_.PrivateMB }

    $ws_min = ($ws_values | Measure-Object -Minimum).Minimum
    $ws_max = ($ws_values | Measure-Object -Maximum).Maximum
    $ws_avg = [math]::Round(($ws_values | Measure-Object -Average).Average, 1)

    $pb_min = ($pb_values | Measure-Object -Minimum).Minimum
    $pb_max = ($pb_values | Measure-Object -Maximum).Maximum
    $pb_avg = [math]::Round(($pb_values | Measure-Object -Average).Average, 1)

    Write-Host "Working Set:   min=${ws_min}MB  avg=${ws_avg}MB  max=${ws_max}MB"
    Write-Host "Private Bytes: min=${pb_min}MB  avg=${pb_avg}MB  max=${pb_max}MB"
    Write-Host "Samples: $($samples.Count)"

    # Check for file-backed mpool cache
    $cacheFile = "runtime\cache\clamav-engine-mpool.cache"
    if (Test-Path $cacheFile) {
        $cacheSize = [math]::Round((Get-Item $cacheFile).Length / 1MB, 1)
        Write-Host "mpool cache file: ${cacheSize}MB" -ForegroundColor Green
    } else {
        Write-Host "mpool cache file: NOT FOUND (vanilla anonymous mpool)" -ForegroundColor Yellow
    }
}

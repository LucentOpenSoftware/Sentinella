# baseline-memory.ps1 — Capture baseline memory metrics for sentinelld
#
# Run this BEFORE swapping to the file-backed DLL to establish baseline.
# Then run again AFTER to compare.
#
# Usage: .\scripts\baseline-memory.ps1 [-Label "vanilla"]

param(
    [string]$Label = "measurement"
)

$proc = Get-Process -Name "sentinelld" -ErrorAction SilentlyContinue
if (-not $proc) {
    Write-Host "sentinelld not running. Start the daemon first." -ForegroundColor Red
    exit 1
}

$ws = [math]::Round($proc.WorkingSet64 / 1MB, 1)
$pb = [math]::Round($proc.PrivateMemorySize64 / 1MB, 1)
$vs = [math]::Round($proc.VirtualMemorySize64 / 1MB, 1)
$pf = $proc.PageFaultCount
$handles = $proc.HandleCount
$threads = $proc.Threads.Count
$uptime = [math]::Round(((Get-Date) - $proc.StartTime).TotalSeconds, 0)

$cacheExists = Test-Path "runtime\cache\clamav-engine-mpool.cache"
$cacheSize = if ($cacheExists) { [math]::Round((Get-Item "runtime\cache\clamav-engine-mpool.cache").Length / 1MB, 1) } else { 0 }

Write-Host ""
Write-Host "=== sentinelld Memory Baseline [$Label] ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  PID:              $($proc.Id)"
Write-Host "  Uptime:           ${uptime}s"
Write-Host "  Working Set:      ${ws} MB" -ForegroundColor $(if ($ws -lt 400) { "Green" } elseif ($ws -lt 800) { "Yellow" } else { "Red" })
Write-Host "  Private Bytes:    ${pb} MB"
Write-Host "  Virtual Size:     ${vs} MB"
Write-Host "  Page Faults:      $pf (cumulative)"
Write-Host "  Handles:          $handles"
Write-Host "  Threads:          $threads"
Write-Host "  mpool cache:      $(if ($cacheExists) { "${cacheSize} MB (FILE-BACKED)" } else { "N/A (anonymous)" })"
Write-Host ""

# Output as JSON for easy comparison
$json = @{
    label = $Label
    timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    pid = $proc.Id
    uptime_secs = $uptime
    working_set_mb = $ws
    private_bytes_mb = $pb
    virtual_size_mb = $vs
    page_faults = $pf
    handles = $handles
    threads = $threads
    mpool_file_backed = $cacheExists
    mpool_cache_size_mb = $cacheSize
} | ConvertTo-Json

$outDir = "runtime\diagnostics"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force $outDir | Out-Null }
$outFile = "$outDir\memory_baseline_${Label}.json"
$json | Out-File -FilePath $outFile -Encoding utf8
Write-Host "  Saved to: $outFile" -ForegroundColor DarkGray

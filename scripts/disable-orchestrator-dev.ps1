# Sentinella — Disable All Orchestrator Pilots
# Restores legacy scan paths. Restart daemon after running.

$configPath = Join-Path (Split-Path $PSScriptRoot -Parent) "runtime\config\sentinelld.toml"

if (!(Test-Path $configPath)) {
    Write-Host "[ERR] Config not found: $configPath" -ForegroundColor Red
    exit 1
}

$content = Get-Content $configPath -Raw -Encoding utf8
$content = $content -replace '(?m)^orchestrator_\w+_scan_enabled\s*=.*\r?\n', ''

# Ensure flags are explicitly false.
if ($content -notmatch '\[scan\]') {
    $content += "`n[scan]`n"
}

$disableBlock = @"
orchestrator_file_scan_enabled = false
orchestrator_folder_scan_enabled = false
orchestrator_quick_scan_enabled = false
"@

$content = $content -replace '(\[scan\])', "`$1`n$disableBlock"

Set-Content $configPath $content -Encoding utf8 -NoNewline

Write-Host ""
Write-Host "  All orchestrator pilots DISABLED."
Write-Host "  Legacy scan paths restored."
Write-Host "  Restart daemon to apply."
Write-Host ""

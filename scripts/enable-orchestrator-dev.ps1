# Sentinella — Enable Orchestrator File Scan Pilot (Dev Testing)
# Modifies runtime/config/sentinelld.toml to enable file scan pilot only.
# Restart daemon after running this script.

param(
    [ValidateSet("file", "folder", "quick", "all")]
    [string]$Pilot = "file"
)

$configPath = Join-Path (Split-Path $PSScriptRoot -Parent) "runtime\config\sentinelld.toml"

if (!(Test-Path $configPath)) {
    Write-Host "[ERR] Config not found: $configPath" -ForegroundColor Red
    Write-Host "      Start daemon once to create default config."
    exit 1
}

$content = Get-Content $configPath -Raw -Encoding utf8

# Remove existing orchestrator lines.
$content = $content -replace '(?m)^orchestrator_\w+_scan_enabled\s*=.*\r?\n', ''

# Add [scan] section if missing.
if ($content -notmatch '\[scan\]') {
    $content += "`n[scan]`n"
}

# Determine flags.
$file = if ($Pilot -eq "file" -or $Pilot -eq "all") { "true" } else { "false" }
$folder = if ($Pilot -eq "folder" -or $Pilot -eq "all") { "true" } else { "false" }
$quick = if ($Pilot -eq "quick" -or $Pilot -eq "all") { "true" } else { "false" }

$scanBlock = @"
orchestrator_file_scan_enabled = $file
orchestrator_folder_scan_enabled = $folder
orchestrator_quick_scan_enabled = $quick
"@

# Append after [scan].
$content = $content -replace '(\[scan\])', "`$1`n$scanBlock"

Set-Content $configPath $content -Encoding utf8 -NoNewline

Write-Host ""
Write-Host "  Orchestrator Pilot: $Pilot"
Write-Host "  =========================="
Write-Host "  File:   $file"
Write-Host "  Folder: $folder"
Write-Host "  Quick:  $quick"
Write-Host ""
Write-Host "  Config: $configPath"
Write-Host "  Restart daemon to apply."
Write-Host ""

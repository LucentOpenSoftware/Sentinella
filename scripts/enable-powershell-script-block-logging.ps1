# Enable PowerShell Script Block Logging (requires admin).
# This allows Sentinella's PsBridge to capture deobfuscated script content.
#Requires -RunAsAdministrator

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Write-Host "[OK] Script Block Logging enabled." -ForegroundColor Green
Write-Host "     PowerShell will now log script blocks to:"
Write-Host "     Event Log: Microsoft-Windows-PowerShell/Operational"
Write-Host "     Event ID: 4104"

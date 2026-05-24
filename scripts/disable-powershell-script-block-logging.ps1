# Disable PowerShell Script Block Logging (requires admin).
#Requires -RunAsAdministrator

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (Test-Path $regPath) {
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 0 -Type DWord
    Write-Host "[OK] Script Block Logging disabled." -ForegroundColor Yellow
} else {
    Write-Host "[OK] Script Block Logging was not configured." -ForegroundColor Gray
}

# Benign PowerShell — should score 0-10.
Write-Host "Hello from Sentinella runtime test"
Get-Date
Get-Process | Select-Object -First 5 | Format-Table Name, CPU

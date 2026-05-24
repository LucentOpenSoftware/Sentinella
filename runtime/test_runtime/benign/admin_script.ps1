# Benign admin script — should score 0-15.
$services = Get-Service | Where-Object { $_.Status -eq 'Running' }
Write-Host "Running services: $($services.Count)"
Get-EventLog -LogName System -Newest 5 | Format-Table TimeGenerated, Source, Message -AutoSize
Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber

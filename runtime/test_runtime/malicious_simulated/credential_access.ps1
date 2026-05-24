# Simulated malicious: credential access patterns.
# SAMPLE ONLY — NOT EXECUTED. Should score 40-70+.
$cred = Get-Credential
$password = $cred.GetNetworkCredential().Password
# Mimikatz-style command patterns
sekurlsa::logonpasswords
lsadump::sam
# Browser credential paths
$chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
$edge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
Copy-Item $chrome "$env:TEMP\chrome_creds.db"
Copy-Item $edge "$env:TEMP\edge_creds.db"

# Benign web request — should score 0-20.
# Uses a well-known safe URL. NOT executed during testing.
$response = Invoke-WebRequest -Uri "https://httpbin.org/get" -UseBasicParsing
Write-Host "Status: $($response.StatusCode)"
Write-Host "Content length: $($response.Content.Length)"

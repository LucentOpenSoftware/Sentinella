# Suspicious: large base64 blob with decode+execute pattern.
# SAMPLE ONLY — not real payload. Should score 25-50.
$data = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
$bytes = [System.Convert]::FromBase64String($data)
[System.Reflection.Assembly]::Load($bytes)

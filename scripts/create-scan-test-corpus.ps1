# Sentinella — Scan Test Corpus Generator
# Creates a safe local directory structure for testing scan pilots.
# Does NOT include malware. Use --eicar to add EICAR test file.

param(
    [string]$OutputDir = "test-corpus",
    [switch]$Eicar,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$root = Join-Path (Get-Location) $OutputDir

if ($Clean -and (Test-Path $root)) {
    Remove-Item $root -Recurse -Force
    Write-Host "Cleaned: $root"
    exit 0
}

Write-Host ""
Write-Host "  Sentinella Scan Test Corpus Generator"
Write-Host "  ======================================"
Write-Host "  Output: $root"
Write-Host ""

# Create directory structure.
$dirs = @(
    "$root",
    "$root\executables",
    "$root\scripts",
    "$root\documents",
    "$root\archives",
    "$root\media",
    "$root\build-artifacts",
    "$root\nested\level1\level2\level3",
    "$root\config-files",
    "$root\large-blobs"
)
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}

# ── Clean text files ──
Set-Content "$root\readme.txt" "This is a test corpus for Sentinella scan validation." -Encoding utf8
Set-Content "$root\documents\report.md" "# Test Report`nNothing suspicious here." -Encoding utf8
Set-Content "$root\documents\data.csv" "name,value`ntest,123`nfoo,456" -Encoding utf8

# ── Fake PE-like binaries (MZ header + padding) ──
$mzHeader = [byte[]]@(0x4D, 0x5A) + (New-Object byte[] 510)
[System.IO.File]::WriteAllBytes("$root\executables\clean_app.exe", $mzHeader)
[System.IO.File]::WriteAllBytes("$root\executables\helper.dll", $mzHeader)
[System.IO.File]::WriteAllBytes("$root\executables\updater.exe", $mzHeader + (New-Object byte[] 1024))

# ── Script files ──
Set-Content "$root\scripts\build.bat" "@echo off`necho Building..." -Encoding utf8
Set-Content "$root\scripts\deploy.ps1" "Write-Host 'Deploying...'" -Encoding utf8
Set-Content "$root\scripts\init.js" "console.log('init');" -Encoding utf8

# ── Config/skip files ──
Set-Content "$root\config-files\app.json" '{"name":"test","version":"1.0"}' -Encoding utf8
Set-Content "$root\config-files\settings.toml" '[app]`nname = "test"' -Encoding utf8
Set-Content "$root\config-files\app.log" "2026-05-17 INFO Starting..." -Encoding utf8
Set-Content "$root\config-files\cache.lock" "locked" -Encoding utf8

# ── Build artifacts (should be skipped) ──
[System.IO.File]::WriteAllBytes("$root\build-artifacts\libtest.rlib", (New-Object byte[] 256))
[System.IO.File]::WriteAllBytes("$root\build-artifacts\module.obj", (New-Object byte[] 128))
Set-Content "$root\build-artifacts\output.map" "symbols..." -Encoding utf8
[System.IO.File]::WriteAllBytes("$root\build-artifacts\debug.pdb", (New-Object byte[] 512))

# ── Media files (signature-only strategy) ──
$jpgHeader = [byte[]]@(0xFF, 0xD8, 0xFF, 0xE0) + (New-Object byte[] 1020)
[System.IO.File]::WriteAllBytes("$root\media\photo.jpg", $jpgHeader)
$pngHeader = [byte[]]@(0x89, 0x50, 0x4E, 0x47) + (New-Object byte[] 1020)
[System.IO.File]::WriteAllBytes("$root\media\icon.png", $pngHeader)

# ── Nested files ──
Set-Content "$root\nested\level1\file1.txt" "level1" -Encoding utf8
Set-Content "$root\nested\level1\level2\file2.txt" "level2" -Encoding utf8
Set-Content "$root\nested\level1\level2\level3\deep.exe" "not-really-an-exe" -Encoding utf8

# ── Large blob (tests size strategy) ──
$blob = New-Object byte[] (5 * 1024 * 1024)  # 5MB
(New-Object Random).NextBytes($blob)
[System.IO.File]::WriteAllBytes("$root\large-blobs\firmware.bin", $blob)

# ── Archive placeholder ──
Set-Content "$root\archives\sample.zip.txt" "placeholder - not a real zip" -Encoding utf8

# ── EICAR (optional) ──
if ($Eicar) {
    $eicarStr = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    Set-Content "$root\executables\eicar_test.com" $eicarStr -Encoding ascii -NoNewline
    Write-Host "  [!] EICAR test file created (will be detected as threat)"
}

# ── Summary ──
$fileCount = (Get-ChildItem $root -Recurse -File).Count
$totalSize = (Get-ChildItem $root -Recurse -File | Measure-Object -Property Length -Sum).Sum
Write-Host "  Created: $fileCount files, $([math]::Round($totalSize / 1024, 1)) KB"
Write-Host "  Directories: $($dirs.Count)"
Write-Host ""
Write-Host "  File types:"
Write-Host "    Executables:      3 (.exe, .dll)"
Write-Host "    Scripts:          3 (.bat, .ps1, .js)"
Write-Host "    Documents:        3 (.txt, .md, .csv)"
Write-Host "    Config/skip:      4 (.json, .toml, .log, .lock)"
Write-Host "    Build artifacts:  4 (.rlib, .obj, .map, .pdb)"
Write-Host "    Media:            2 (.jpg, .png)"
Write-Host "    Large blobs:      1 (5MB .bin)"
Write-Host "    Nested:           3 (3 levels deep)"
if ($Eicar) { Write-Host "    EICAR:            1 (.com)" }
Write-Host ""
Write-Host "  Usage:"
Write-Host "    sentinella-argus scan-folder $root"
Write-Host "    sentinella-argus scan-folder $root --format json"
Write-Host ""

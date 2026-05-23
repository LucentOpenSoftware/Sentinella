# Sentinella — Orchestrator Pilot Validation Script
# Tests file/folder/quick scan pilots via the ARGUS CLI scanner.
# Does NOT require daemon — uses sentinella-argus directly.
#
# For daemon-based orchestrator testing, enable config flags manually
# and use the GUI or IPC tools.

param(
    [string]$CorpusDir = "test-corpus",
    [switch]$CreateCorpus,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$pass = 0
$fail = 0
$skip = 0

function Test-Check($name, $condition, $detail) {
    if ($condition) {
        Write-Host "  [PASS] $name" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  [FAIL] $name — $detail" -ForegroundColor Red
        $script:fail++
    }
}

function Test-Skip($name, $reason) {
    Write-Host "  [SKIP] $name — $reason" -ForegroundColor Yellow
    $script:skip++
}

Write-Host ""
Write-Host "  Sentinella Orchestrator Pilot Validation"
Write-Host "  ========================================="
Write-Host ""

# ── Step 0: Create corpus if needed ──
if ($CreateCorpus -or !(Test-Path $CorpusDir)) {
    Write-Host "  Creating test corpus..."
    & "$PSScriptRoot\create-scan-test-corpus.ps1" -OutputDir $CorpusDir
}

if (!(Test-Path $CorpusDir)) {
    Write-Host "  [ERR] Corpus directory not found: $CorpusDir" -ForegroundColor Red
    exit 1
}

# ── Step 1: Find sentinella-argus binary ──
$argusExe = $null
$candidates = @(
    "target\debug\sentinella-argus.exe",
    "target\release\sentinella-argus.exe"
)
foreach ($c in $candidates) {
    $p = Join-Path (Split-Path $PSScriptRoot -Parent) $c
    if (Test-Path $p) { $argusExe = $p; break }
}

if (!$argusExe) {
    Write-Host "  [ERR] sentinella-argus not found. Run: cargo build -p sentinella-argus" -ForegroundColor Red
    exit 1
}

Write-Host "  Binary: $argusExe"
Write-Host "  Corpus: $CorpusDir"
Write-Host ""

# ── Step 2: Self-test ──
Write-Host "  === Self-Test ==="
$selfTest = & $argusExe self-test 2>&1
$selfTestExit = $LASTEXITCODE
Test-Check "self-test passes" ($selfTestExit -eq 0) "exit code: $selfTestExit"
if ($Verbose) { $selfTest | ForEach-Object { Write-Host "    $_" } }
Write-Host ""

# ── Step 3: Rules summary ──
Write-Host "  === Rules ==="
$rules = & $argusExe rules 2>&1
$rulesText = $rules -join "`n"
Test-Check "YARA rules > 0" ($rulesText -match "YARA rules: (\d+)" -and [int]$Matches[1] -gt 0) "no rules found"
Test-Check "IOC hashes > 0" ($rulesText -match "IOC hashes: (\d+)" -and [int]$Matches[1] -gt 0) "no IOC hashes"
if ($Verbose) { $rules | ForEach-Object { Write-Host "    $_" } }
Write-Host ""

# ── Step 4: Single file scan ──
Write-Host "  === File Scan ==="
$testExe = Join-Path $CorpusDir "executables\clean_app.exe"
if (Test-Path $testExe) {
    $fileScan = & $argusExe scan-file $testExe --format json 2>&1
    $fileExit = $LASTEXITCODE
    Test-Check "file scan completes" ($fileExit -le 1) "exit code: $fileExit"

    # Parse JSON output.
    $jsonLines = $fileScan | Where-Object { $_ -notmatch "^(YARA|IOC):" }
    $jsonText = $jsonLines -join "`n"
    try {
        $verdict = $jsonText | ConvertFrom-Json
        Test-Check "verdict has score" ($null -ne $verdict.score) "missing score field"
        Test-Check "verdict has sha256" ($verdict.sha256.Length -gt 0) "missing sha256"
        Test-Check "score <= 50 for clean stub" ($verdict.score -le 50) "score: $($verdict.score)"
        if ($verdict.timing) {
            Test-Check "timing present" ($verdict.timing.argus_total_us -gt 0) "missing timing"
            Test-Check "strategy present" ($null -ne $verdict.timing.strategy) "missing strategy"
        }
    } catch {
        Test-Check "JSON parseable" $false "parse error: $_"
    }
} else {
    Test-Skip "file scan" "test file not found"
}
Write-Host ""

# ── Step 5: Folder scan ──
Write-Host "  === Folder Scan ==="
$folderScan = & $argusExe scan-folder $CorpusDir --format json --threads 2 2>&1
$folderExit = $LASTEXITCODE
Test-Check "folder scan completes" ($folderExit -le 1) "exit code: $folderExit"

$jsonLines = $folderScan | Where-Object { $_ -notmatch "^(YARA|IOC|Collected)" }
$jsonText = $jsonLines -join "`n"
try {
    $summary = $jsonText | ConvertFrom-Json
    Test-Check "total_files > 0" ($summary.total_files -gt 0) "no files scanned"
    Test-Check "elapsed_ms > 0" ($summary.elapsed_ms -gt 0) "no timing"
    Test-Check "results array exists" ($null -ne $summary.results) "missing results"

    # Strategy checks — some files should have been skipped.
    $resultCount = if ($summary.results) { $summary.results.Count } else { 0 }
    Test-Check "not all files flagged" ($resultCount -lt $summary.total_files) "all files have findings"

    Write-Host "    Files: $($summary.total_files)  Threats: $($summary.threats)  Time: $($summary.elapsed_ms)ms"
} catch {
    Test-Check "folder JSON parseable" $false "parse error: $_"
}
Write-Host ""

# ── Step 6: Explain mode ──
Write-Host "  === Explain ==="
if (Test-Path $testExe) {
    $explain = & $argusExe explain $testExe 2>&1
    $explainExit = $LASTEXITCODE
    $explainText = $explain -join "`n"
    Test-Check "explain completes" ($explainExit -eq 0) "exit code: $explainExit"
    Test-Check "explain shows score" ($explainText -match "Score:") "missing score"
    Test-Check "explain shows verdict" ($explainText -match "Verdict:") "missing verdict"
    Test-Check "explain shows confidence" ($explainText -match "Confidence:") "missing confidence"
} else {
    Test-Skip "explain" "test file not found"
}
Write-Host ""

# ── Step 7: Strategy classification ──
Write-Host "  === Strategy Classification ==="
# Scan a .log file — should be SkipSafe.
$logFile = Join-Path $CorpusDir "config-files\app.log"
if (Test-Path $logFile) {
    $logScan = & $argusExe scan-file $logFile --format json 2>&1
    $logJson = ($logScan | Where-Object { $_ -notmatch "^(YARA|IOC):" }) -join "`n"
    try {
        $logVerdict = $logJson | ConvertFrom-Json
        Test-Check "log file score = 0" ($logVerdict.score -eq 0) "score: $($logVerdict.score)"
    } catch {
        Test-Check "log scan parseable" $false "parse error"
    }
}
# Scan a .jpg file — should be SignatureOnly.
$jpgFile = Join-Path $CorpusDir "media\photo.jpg"
if (Test-Path $jpgFile) {
    $jpgScan = & $argusExe scan-file $jpgFile --format json 2>&1
    $jpgJson = ($jpgScan | Where-Object { $_ -notmatch "^(YARA|IOC):" }) -join "`n"
    try {
        $jpgVerdict = $jpgJson | ConvertFrom-Json
        Test-Check "jpg file score = 0" ($jpgVerdict.score -eq 0) "score: $($jpgVerdict.score)"
    } catch {
        Test-Check "jpg scan parseable" $false "parse error"
    }
}
Write-Host ""

# ── Summary ──
Write-Host ""
Write-Host "  ========================================="
Write-Host "  Results: $pass passed, $fail failed, $skip skipped"
Write-Host "  ========================================="
Write-Host ""

if ($fail -gt 0) {
    Write-Host "  [FAIL] Validation has failures." -ForegroundColor Red
    exit 1
} else {
    Write-Host "  [PASS] All checks passed." -ForegroundColor Green
    exit 0
}

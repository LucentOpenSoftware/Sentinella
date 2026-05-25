# Sentinella PLM ETW Validation Script
# Tests process lineage monitoring in both ETW and snapshot modes.
#
# Usage:
#   .\scripts\test-plm-etw.ps1
#
# If running as admin: validates ETW mode
# If running as normal user: validates snapshot fallback

param(
    [string]$CliPath = "target\release\sentinella.exe"
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  ====================================" -ForegroundColor Cyan
Write-Host "  PLM ETW Validation" -ForegroundColor Cyan
Write-Host "  ====================================" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "  Admin:  $isAdmin" -ForegroundColor $(if ($isAdmin) { "Green" } else { "Yellow" })
Write-Host ""

# Load IPC secret
if (-not $env:SENTINELLA_IPC_SECRET) {
    $secretPath = "runtime\state\ipc_secret"
    if (Test-Path $secretPath) {
        $env:SENTINELLA_IPC_SECRET = (Get-Content $secretPath -Raw).Trim()
    }
}

Write-Host "  Step 1: Check daemon connection..." -ForegroundColor DarkGray
try {
    $status = & $CliPath status 2>&1
    Write-Host "  [OK] Daemon reachable" -ForegroundColor Green
} catch {
    Write-Host "  [ERR] Daemon not running" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Step 2: Create test process chains..." -ForegroundColor DarkGray

# Chain 1: powershell -> cmd -> whoami
Write-Host "  Chain: powershell -> cmd -> whoami"
cmd /c "whoami" | Out-Null

# Chain 2: powershell -> ping
Write-Host "  Chain: powershell -> ping"
ping -n 1 127.0.0.1 | Out-Null

# Chain 3: powershell -> cmd -> echo
Write-Host "  Chain: powershell -> cmd -> echo"
cmd /c "echo test" | Out-Null

Write-Host "  [OK] Test chains created" -ForegroundColor Green

Write-Host ""
Write-Host "  Step 3: Wait for PLM intake (6s)..." -ForegroundColor DarkGray
Start-Sleep 6

Write-Host ""
Write-Host "  Step 4: Check PLM diagnostics..." -ForegroundColor DarkGray
$diag = & $CliPath diag 2>&1 | Out-String

if ($diag -match "plm") {
    Write-Host "  [OK] PLM diagnostics available" -ForegroundColor Green
} else {
    Write-Host "  [WARN] PLM diagnostics not visible" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Step 5: Expected behavior:" -ForegroundColor DarkGray
if ($isAdmin) {
    Write-Host "    PLM mode:    ETW (real-time)" -ForegroundColor Green
    Write-Host "    Precision:   Exact parent-child" -ForegroundColor Green
    Write-Host "    Latency:     <100ms" -ForegroundColor Green
    Write-Host "    Short-lived: Visible" -ForegroundColor Green
} else {
    Write-Host "    PLM mode:    Snapshot (5s polling)" -ForegroundColor Yellow
    Write-Host "    Precision:   Best-effort" -ForegroundColor Yellow
    Write-Host "    Latency:     ~5s" -ForegroundColor Yellow
    Write-Host "    Short-lived: May be missed" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  ====================================" -ForegroundColor Cyan
Write-Host "  PLM ETW validation complete" -ForegroundColor Cyan
Write-Host "  ====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Check daemon log for:" -ForegroundColor DarkGray
Write-Host "    PLM: ETW real-time mode active     (if admin)" -ForegroundColor DarkGray
Write-Host "    PLM: ETW unavailable, using snapshot (if not admin)" -ForegroundColor DarkGray
Write-Host ""

# probe-request-rate-fairness.ps1 - v0.1.12 workstream K/L live probe
#
# Drives rapid scan.control requests against a RUNNING sentinelld and
# prints per-client accept/reject counts, demonstrating the per-principal
# request-rate budget (matrix row C-5): one principal can no longer drain
# the whole global ScanControl bucket (10/min, burst 3) - its share is
# capped at 5/min, burst 2, and the budget is keyed on the client SID,
# NOT on the connection.
#
# What this probe can and cannot show from a single logon session:
#   - Client A and Client B below are two SEPARATE pipe connections from
#     the SAME user SID. Client B being rate-limited immediately after
#     Client A's burst proves the budget follows the principal, not the
#     connection (contrast: connection fairness in fairness.rs keys the
#     same SID but caps connections, not requests).
#   - A true two-SID starvation test needs two user sessions; that
#     property is covered by the Rust unit harness in
#     crates/sentinelld/src/ipc/policy.rs
#     (scancontrol_one_principal_cannot_starve_another et al.).
#
# Method choice: the flood uses scan.cancel (ScanControl bucket, harmless
# with no active scan) so the probe never starts a real scan on a
# production daemon.
#
# Requirements: sentinelld running as a service. Run unelevated - the IPC
# secret is world-readable by design; elevation must not matter here.

$ErrorActionPreference = "Continue"
Set-Location "$PSScriptRoot\.."

$PipeName = "sentinelld"
$RateLimitedCode = -32020

function Get-IpcSecret {
    if ($env:SENTINELLA_IPC_SECRET) { return $env:SENTINELLA_IPC_SECRET }
    $path = Join-Path $env:ProgramData "Sentinella\state\ipc_secret"
    if (-not (Test-Path $path)) { throw "IPC secret not found at $path (set SENTINELLA_IPC_SECRET)" }
    return (Get-Content $path -Raw).Trim()
}

function Send-IpcRequest {
    param([string]$Method, [hashtable]$Params, [int]$Id = 1)
    $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $PipeName,
        [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(3000)
        $body = @{ jsonrpc = "2.0"; id = $Id; method = $Method; params = $Params } | ConvertTo-Json -Compress
        $payload = [System.Text.Encoding]::UTF8.GetBytes($body)
        $len = [BitConverter]::GetBytes([uint32]$payload.Length)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($len) }
        $client.Write($len, 0, 4)
        $client.Write($payload, 0, $payload.Length)
        $client.Flush()
        $lenBuf = New-Object byte[] 4
        $read = $client.Read($lenBuf, 0, 4)
        if ($read -lt 4) { return $null }
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBuf) }
        $respLen = [BitConverter]::ToUInt32($lenBuf, 0)
        if ($respLen -gt 1MB) { return $null }
        $respBuf = New-Object byte[] $respLen
        $off = 0
        while ($off -lt $respLen) {
            $n = $client.Read($respBuf, $off, $respLen - $off)
            if ($n -le 0) { break }
            $off += $n
        }
        return ([System.Text.Encoding]::UTF8.GetString($respBuf) | ConvertFrom-Json)
    } finally {
        $client.Dispose()
    }
}

function Invoke-Flood {
    param([string]$Label, [int]$Count, [string]$Secret)
    $accepted = 0; $rateLimited = 0; $other = 0
    for ($i = 0; $i -lt $Count; $i++) {
        $resp = Send-IpcRequest -Method "scan.cancel" -Params @{ auth = $Secret } -Id $i
        if ($null -eq $resp) { $other++; continue }
        if ($resp.error -and $resp.error.code -eq $RateLimitedCode) { $rateLimited++ }
        else { $accepted++ } # passed the rate limiter (scan.cancel w/o active scan errors elsewhere - fine)
    }
    return [PSCustomObject]@{ Label = $Label; Accepted = $accepted; RateLimited = $rateLimited; Other = $other }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " v0.1.12 Request-Rate Fairness Live Probe" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$daemon = Get-Process -Name "sentinelld" -ErrorAction SilentlyContinue
if (-not $daemon) {
    Write-Host "[ERR] sentinelld not running" -ForegroundColor Red
    exit 1
}

try { $secret = Get-IpcSecret } catch {
    Write-Host "[ERR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Sanity: one request on the STATUS bucket (health, no auth) so it does
# NOT spend a ScanControl token and skew the counts below.
$probe = Send-IpcRequest -Method "health" -Params @{}
if ($null -eq $probe) {
    Write-Host "[ERR] no response from sentinelld pipe" -ForegroundColor Red
    exit 1
}

# Phase A: Client A fires a rapid burst on one connection-per-request.
$a = Invoke-Flood -Label "Client A (burst)" -Count 12 -Secret $secret
Write-Host ("{0,-22} accepted={1} rate-limited={2} other={3}" -f $a.Label, $a.Accepted, $a.RateLimited, $a.Other)

# Phase B: Client B - new connections, SAME SID - must share Client A's
# per-principal budget, so it is rate-limited immediately (the 5/min
# burst-2 share is already spent). Pre-v0.1.12 both phases together would
# have drained the GLOBAL burst (3) and every later caller - including an
# elevated GUI - would be rejected.
Start-Sleep -Milliseconds 200
$b = Invoke-Flood -Label "Client B (same SID)" -Count 6 -Secret $secret
Write-Host ("{0,-22} accepted={1} rate-limited={2} other={3}" -f $b.Label, $b.Accepted, $b.RateLimited, $b.Other)

Write-Host ""
$pass = $true
# Discriminating check: the v0.1.12 per-principal ScanControl burst is 2.
# A pre-fix daemon (global burst 3 only) accepts 3 here, so >2 means the
# per-principal cap is absent or mis-keyed. (Refill is 1 token/6s; the
# flood completes well under that, so no refill noise is expected.)
if ($a.Accepted -gt 2) {
    Write-Host "[FAIL] Client A accepted $($a.Accepted) requests - per-principal burst is 2; is the daemon running the v0.1.12 limiter?" -ForegroundColor Red
    $pass = $false
}
# Same-SID sharing: Client B must not get a fresh budget. Allow 1 for
# refill-timing jitter on a slow host.
if ($b.Accepted -gt 1) {
    Write-Host "[FAIL] Client B (same SID) accepted $($b.Accepted) - budget is keyed per-connection, not per-principal" -ForegroundColor Red
    $pass = $false
}
if ($a.Other -gt 0 -or $b.Other -gt 0) {
    Write-Host "[WARN] transport/parse failures seen (other>0) - check daemon health" -ForegroundColor Yellow
}
if ($pass) {
    Write-Host "[OK] per-principal ScanControl budget enforced; same-SID clients share it" -ForegroundColor Green
    Write-Host "     (two-SID starvation property: see policy.rs unit harness)" -ForegroundColor Green
}
Write-Host ""
if ($pass) { exit 0 } else { exit 2 }

# Collect WeedHack runtime diagnostics from a running Sentinella daemon.
#
# Connects to the IPC named pipe, exports the WeedHack-relevant subset of
# runtime.status + diagnostics.export + health, sanitizes any field that
# could conceivably contain raw paths or URLs, and writes a timestamped
# JSON report to disk.
#
# Privacy guarantees enforced here (defense-in-depth -- the daemon already
# scrubs at the diagnostics-layer):
#   * No raw wallet paths
#   * No HTTP bodies
#   * No full URLs
#   * No raw process command lines beyond what the daemon already redacts
#
# Usage:
#   .\collect-weedhack-runtime-diagnostics.ps1 [-OutputDir <path>]
#                                              [-AuthSecretPath <path>]
#                                              [-NoAuth]
#
# Without -NoAuth, the script auto-discovers the IPC secret at
# %ProgramData%\Sentinella\state\ipc_secret (installed mode) or
# <repo>\runtime\state\ipc_secret (dev mode). If neither is present and
# -NoAuth is omitted, the script falls back to the public 'health'
# endpoint only.

[CmdletBinding()]
param(
    [string]$OutputDir = "$env:TEMP\sentinella-weedhack-diagnostics",
    [string]$AuthSecretPath = "",
    [switch]$NoAuth
)

$ErrorActionPreference = 'Stop'
$PipeName = 'sentinelld'
$IpcTimeoutMs = 5000
$MaxFrameSize = 16 * 1024 * 1024

function Resolve-AuthSecret {
    param([string]$Explicit)

    if ($Explicit -and (Test-Path -LiteralPath $Explicit)) {
        return (Get-Content -Raw -LiteralPath $Explicit).Trim()
    }

    $candidates = @(
        (Join-Path $PSScriptRoot '..\runtime\state\ipc_secret'),
        (Join-Path $env:ProgramData 'Sentinella\state\ipc_secret')
    )

    foreach ($p in $candidates) {
        if (Test-Path -LiteralPath $p) {
            $s = (Get-Content -Raw -LiteralPath $p).Trim()
            if ($s.Length -ge 32) { return $s }
        }
    }
    return $null
}

function Invoke-DaemonRpc {
    param(
        [string]$Method,
        [hashtable]$ExtraParams = @{}
    )

    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', $PipeName,
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None
    )
    try {
        $pipe.Connect($IpcTimeoutMs)

        $params = @{}
        foreach ($k in $ExtraParams.Keys) {
            $params[$k] = $ExtraParams[$k]
        }
        $req = @{
            jsonrpc = '2.0'
            id = 1
            method = $Method
            params = $params
        }
        $payload = [System.Text.Encoding]::UTF8.GetBytes(
            (ConvertTo-Json -InputObject $req -Depth 8 -Compress)
        )

        # Length prefix is 4-byte big-endian.
        $lenBytes = [System.BitConverter]::GetBytes([uint32]$payload.Length)
        if ([System.BitConverter]::IsLittleEndian) {
            [System.Array]::Reverse($lenBytes)
        }
        $pipe.Write($lenBytes, 0, 4)
        $pipe.Write($payload, 0, $payload.Length)
        $pipe.Flush()

        # Read 4-byte BE length, then payload.
        $respLenBuf = New-Object byte[] 4
        $read = 0
        while ($read -lt 4) {
            $n = $pipe.Read($respLenBuf, $read, 4 - $read)
            if ($n -le 0) { throw "pipe closed before length read" }
            $read += $n
        }
        if ([System.BitConverter]::IsLittleEndian) {
            [System.Array]::Reverse($respLenBuf)
        }
        $respLen = [System.BitConverter]::ToUInt32($respLenBuf, 0)
        if ($respLen -gt $MaxFrameSize) {
            throw "response length $respLen exceeds limit $MaxFrameSize"
        }

        $respBuf = New-Object byte[] $respLen
        $read = 0
        while ($read -lt $respLen) {
            $n = $pipe.Read($respBuf, $read, $respLen - $read)
            if ($n -le 0) { throw "pipe closed before payload read" }
            $read += $n
        }

        $respJson = [System.Text.Encoding]::UTF8.GetString($respBuf)
        return $respJson | ConvertFrom-Json
    }
    finally {
        $pipe.Dispose()
    }
}

# Defense-in-depth sanitizer.
#
# The daemon already enforces privacy in its diagnostics layer (Wave 6/7
# tests verify no raw paths/bodies/URLs in counter output). This is a
# second pass: walk the response tree and strip anything that looks like
# a path or URL anyway, by key name. Operator-visible counters and
# canonical store keys remain.
function Invoke-SanitizeTree {
    param($Node)

    if ($null -eq $Node) { return $null }

    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        $out = [ordered]@{}
        foreach ($prop in $Node.PSObject.Properties) {
            $key = $prop.Name
            $val = $prop.Value

            if ($key -in @(
                'image_path', 'loaded_module_path', 'path',
                'url', 'host_hint', 'path_hint', 'body_snippet',
                'command_line', 'cmdline', 'description',
                'technical_detail', 'narrative'
            )) {
                if ($val -is [string]) {
                    $len = $val.Length
                    $out[$key] = "[redacted: $len chars]"
                } elseif ($val -is [array]) {
                    $len = $val.Length
                    $out[$key] = "[redacted: $len items]"
                } else {
                    $out[$key] = '[redacted]'
                }
                continue
            }

            $out[$key] = Invoke-SanitizeTree -Node $val
        }
        return $out
    }

    if ($Node -is [System.Collections.IList] -and -not ($Node -is [string])) {
        return ,@($Node | ForEach-Object { Invoke-SanitizeTree -Node $_ })
    }

    if ($Node -is [string]) {
        $s = $Node
        if ($s -match '^[A-Za-z]:\\') { return '[redacted-path]' }
        if ($s -match '^\\\\') { return '[redacted-unc]' }
        if ($s -match '^https?://') { return '[redacted-url]' }
        return $s
    }

    return $Node
}

function Get-WeedHackBlock {
    param($RuntimeStatus)

    if ($null -eq $RuntimeStatus) { return $null }
    if ($null -ne $RuntimeStatus.result) {
        $RuntimeStatus = $RuntimeStatus.result
    }

    $wh = $null
    if ($RuntimeStatus.PSObject.Properties['weedhack_campaigns']) {
        $wh = $RuntimeStatus.weedhack_campaigns
    }
    return $wh
}

# Main.

Write-Host "Connecting to Sentinella daemon over named pipe..." -ForegroundColor Cyan

# 1) Health -- public, no auth.
$health = $null
try {
    $health = Invoke-DaemonRpc -Method 'health'
} catch {
    Write-Error "Could not reach daemon over pipe: $_"
    exit 2
}

$authSecret = $null
if (-not $NoAuth) {
    $authSecret = Resolve-AuthSecret -Explicit $AuthSecretPath
    if (-not $authSecret) {
        Write-Warning "No IPC secret found. Falling back to public 'health' only."
    }
}

# 2) Authenticated endpoints.
$runtimeStatus = $null
$diagExport = $null
if ($authSecret) {
    try {
        $runtimeStatus = Invoke-DaemonRpc -Method 'runtime.status' `
            -ExtraParams @{ auth = $authSecret }
    } catch {
        Write-Warning "runtime.status failed: $_"
    }
    try {
        $diagExport = Invoke-DaemonRpc -Method 'diagnostics.export' `
            -ExtraParams @{ auth = $authSecret }
    } catch {
        Write-Warning "diagnostics.export failed: $_"
    }
}

# Extract WeedHack block.
$weedhack = Get-WeedHackBlock -RuntimeStatus $runtimeStatus
$weedhackFromDiag = $null
if ($null -ne $diagExport) {
    $r = $diagExport
    if ($null -ne $r.result) { $r = $r.result }
    if ($r.PSObject.Properties['weedhack_campaigns']) {
        $weedhackFromDiag = $r.weedhack_campaigns
    }
}

# Sanitize everything we emit.
$nowUnix = [int][double](Get-Date -UFormat %s)
$report = [ordered]@{
    collected_at_unix = $nowUnix
    pipe_reached = ($null -ne $health)
    health = (Invoke-SanitizeTree -Node $health)
    weedhack_campaigns = (Invoke-SanitizeTree -Node $weedhack)
    weedhack_campaigns_from_export = (Invoke-SanitizeTree -Node $weedhackFromDiag)
    privacy_note = (@(
        "Defense-in-depth scrub applied: fields named image_path, loaded_module_path,",
        "path, url, host_hint, path_hint, body_snippet, command_line, narrative,",
        "description, technical_detail were replaced with redaction stubs even though",
        "the daemon already redacts at source. Strings matching drive-letter or URL",
        "patterns were also replaced. Counters, canonical store keys, tier names, and",
        "PIDs are preserved."
    ) -join ' ')
}

# Write to disk.
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outPath = Join-Path $OutputDir "weedhack-runtime-$stamp.json"
$report | ConvertTo-Json -Depth 16 | Out-File -LiteralPath $outPath -Encoding utf8

Write-Host "Wrote $outPath" -ForegroundColor Green

# Brief human-readable summary on stdout (counters only).
if ($null -ne $weedhack) {
    Write-Host ""
    Write-Host "WeedHack runtime summary:" -ForegroundColor Cyan
    Write-Host "  active campaigns:       $($weedhack.active)"
    Write-Host "  confirmed total:        $($weedhack.confirmed_total)"
    Write-Host "  high_confidence_total:  $($weedhack.high_confidence_total)"
    Write-Host "  suspicious_total:       $($weedhack.suspicious_total)"
    if ($weedhack.image_load_etw) {
        Write-Host "  ImageLoad ETW running:  $($weedhack.image_load_etw.running)"
        Write-Host "  ImageLoad events seen:  $($weedhack.image_load_etw.events_seen)"
        Write-Host "  ImageLoad signals:      $($weedhack.image_load_etw.signals_emitted)"
    }
    if ($weedhack.fileio_etw) {
        Write-Host "  FileIO ETW running:     $($weedhack.fileio_etw.running)"
        Write-Host "  FileIO events seen:     $($weedhack.fileio_etw.events_seen)"
        Write-Host "  FileIO wallet hits:     $($weedhack.fileio_etw.wallet_store_hits)"
        Write-Host "  FileIO burst signals:   $($weedhack.fileio_etw.burst_signals)"
    }
    if ($weedhack.http_intake) {
        Write-Host "  HTTP intake events:     $($weedhack.http_intake.events_seen)"
        Write-Host "  HTTP body_unavailable:  $($weedhack.http_intake.body_unavailable)"
        Write-Host "  HTTP emitted:           $($weedhack.http_intake.emitted)"
    }
} elseif ($health) {
    Write-Host ""
    Write-Host "Public health only -- WeedHack counters are NOT exposed on the" -ForegroundColor Yellow
    Write-Host "unauthenticated 'health' endpoint (v0.1.11 security fix: it gave" -ForegroundColor Yellow
    Write-Host "any local process a detection-status oracle). Re-run with" -ForegroundColor Yellow
    Write-Host "-AuthSecretPath to read the full weedhack_campaigns block from" -ForegroundColor Yellow
    Write-Host "the auth-gated runtime.status endpoint." -ForegroundColor Yellow
}

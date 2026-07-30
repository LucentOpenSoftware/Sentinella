# check-threshold-docs.ps1 — regression guard for the 76/85 threshold split.
#
# The engine's Malicious *label* starts at score 76 (argus Verdict::from_score),
# but the daemon's ARGUS-only auto-quarantine bar is 85
# (sentinelld/src/ipc/state.rs unify_detection_filtered). Documentation must
# never present 76 as THE quarantine threshold without naming the 85 bar.
#
# Exits 1 if any doc line claims quarantine at 76 without mentioning 85.
# Run after editing any threshold-related doc or comment.

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$targets = @()
$targets += Get-ChildItem -Path (Join-Path $repo 'docs') -Filter '*.md' -Recurse
$targets += Get-Item (Join-Path $repo 'CHANGELOG.md'), (Join-Path $repo 'README.md')

$bad = @()
foreach ($file in $targets) {
    $n = 0
    foreach ($line in Get-Content $file.FullName) {
        $n++
        # Forbidden: a line tying quarantine to 76 with no mention of 85.
        if ($line -match '(?i)quarantin' -and $line -match '\b76\b' -and $line -notmatch '\b85\b') {
            $bad += "{0}:{1}: {2}" -f $file.FullName, $n, $line.Trim()
        }
    }
}

if ($bad.Count -gt 0) {
    Write-Host "FAIL: lines presenting 76 as the quarantine threshold without the 85 ARGUS-only bar:"
    $bad | ForEach-Object { Write-Host "  $_" }
    exit 1
}
Write-Host "OK: no doc presents 76 as the universal quarantine threshold ($($targets.Count) files checked)."
exit 0

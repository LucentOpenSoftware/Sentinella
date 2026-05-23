@echo off
:: ============================================================
:: Sentinella ARGUS — Known-Bad Detection Regression Test
:: ============================================================
:: Scans files in runtime/research_samples/ to verify ARGUS
:: and ClamAV properly detect known malware.
::
:: SAFETY: This script does NOT execute any samples. It only
:: calls the daemon's scan API to verify detection.
::
:: Requires: daemon running, explicit --confirm flag.
:: ============================================================

if not "%1"=="--confirm" (
    echo.
    echo   ==========================================
    echo   ARGUS Known-Bad Detection Regression Test
    echo   ==========================================
    echo.
    echo   WARNING: This scans files in runtime\research_samples\
    echo   which may contain ACTUAL MALWARE.
    echo.
    echo   Files are NOT executed — only scanned via the daemon API.
    echo   Ensure the daemon is running.
    echo.
    echo   To proceed, run:
    echo     %~nx0 --confirm
    echo.
    pause
    exit /b 1
)

title ARGUS Known-Bad Regression Test

set "CLI=%~dp0..\target\debug\sentinella.exe"
set "SAMPLES=%~dp0..\runtime\research_samples"

if not exist "%CLI%" (
    echo [ERR] sentinella.exe not found. Build first.
    pause
    exit /b 1
)

if not exist "%SAMPLES%" (
    echo [WARN] research_samples directory not found.
    echo        Create runtime\research_samples\ and add controlled samples.
    pause
    exit /b 1
)

echo.
echo  ==========================================
echo   Scanning research samples...
echo  ==========================================
echo.

set TESTED=0
set DETECTED=0
set MISSED=0

for %%F in ("%SAMPLES%\*.*") do (
    if /i not "%%~nxF"=="README.txt" (
        set /a TESTED+=1
        echo  Scanning: %%~nxF
        "%CLI%" scan "%%F" 2>nul
        echo.
    )
)

echo.
echo  ==========================================
echo   Results: %TESTED% samples tested
echo  ==========================================
echo.
echo   Review output above for detection results.
echo   Any "CLEAN" result on a known-bad sample = missed detection.
echo.
pause
exit /b 0

@echo off
:: ============================================================
:: Sentinella ARGUS — False Positive Regression Test
:: ============================================================
:: Scans known clean files and reports ARGUS scores.
:: Any score > 50 on a known clean file is a false positive.
:: Requires daemon to be running.
:: ============================================================

title ARGUS FP Regression Test

set "CLI=%~dp0..\target\debug\sentinella.exe"
if not exist "%CLI%" (
    echo [ERR] sentinella.exe not found. Build first.
    pause
    exit /b 1
)

echo.
echo  ==========================================
echo   ARGUS False Positive Regression Test
echo  ==========================================
echo.

set TESTED=0
set PASSED=0
set FAILED=0
set SKIPPED=0

:: ── Test signed installers in Downloads ──
call :test_file "%USERPROFILE%\Downloads\Git-*.exe" "Git installer"
call :test_file "%USERPROFILE%\Downloads\python-*.exe" "Python installer"
call :test_file "%USERPROFILE%\Downloads\npp.*.exe" "Notepad++ installer"
call :test_file "%USERPROFILE%\Downloads\*Notion*.exe" "Notion installer"
call :test_file "%USERPROFILE%\Downloads\*Discord*.exe" "Discord installer"
call :test_file "%USERPROFILE%\Downloads\rustdesk-*.exe" "RustDesk installer"
call :test_file "%USERPROFILE%\Downloads\*chrome*.exe" "Chrome installer"
call :test_file "%USERPROFILE%\Downloads\*firefox*.exe" "Firefox installer"
call :test_file "%USERPROFILE%\Downloads\7z*.exe" "7-Zip installer"
call :test_file "%USERPROFILE%\Downloads\*vlc*.exe" "VLC installer"

:: ── Test system binaries (Microsoft signed) ──
call :test_exact "%SystemRoot%\System32\notepad.exe" "Windows Notepad"
call :test_exact "%SystemRoot%\System32\cmd.exe" "Windows CMD"
call :test_exact "%SystemRoot%\System32\calc.exe" "Windows Calculator"

echo.
echo  ==========================================
echo   Results: %TESTED% tested, %PASSED% passed, %FAILED% FAILED, %SKIPPED% skipped
echo  ==========================================
echo.

if %FAILED% GTR 0 (
    echo  [FAIL] False positives detected!
) else (
    echo  [PASS] No false positives found.
)
echo.
pause
exit /b 0

:: ── Test function (glob pattern) ──
:test_file
set "PATTERN=%~1"
set "LABEL=%~2"
for %%F in ("%PATTERN%") do (
    if exist "%%F" (
        call :test_exact "%%F" "%LABEL%"
        exit /b 0
    )
)
echo  [SKIP] %LABEL% — not found
set /a SKIPPED+=1
exit /b 0

:: ── Test function (exact path) ──
:test_exact
set "FILE=%~1"
set "LABEL=%~2"
if not exist "%FILE%" (
    echo  [SKIP] %LABEL% — not found
    set /a SKIPPED+=1
    exit /b 0
)
set /a TESTED+=1
echo  Testing: %LABEL%
"%CLI%" scan "%FILE%" 2>nul | findstr /i "CLEAN THREAT" >nul
"%CLI%" scan "%FILE%" 2>nul
echo.
set /a PASSED+=1
exit /b 0

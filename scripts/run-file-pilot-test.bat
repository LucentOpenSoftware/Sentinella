@echo off
:: ============================================================
:: Sentinella — File Orchestrator Pilot Field Test
:: ============================================================
:: Run this script to execute the complete file pilot test.
:: It will:
::   1. Enable the file pilot config
::   2. Start the daemon
::   3. Wait for you to test via GUI
::   4. Offer to disable the pilot
:: ============================================================

title Sentinella File Pilot Test

cd /d %~dp0..

echo.
echo  ==========================================
echo   Sentinella File Pilot Field Test
echo  ==========================================
echo.

:: Step 1: Enable file pilot.
echo  [1/4] Enabling file orchestrator pilot...
powershell -ExecutionPolicy Bypass -Command "& scripts\enable-orchestrator-dev.ps1 -Pilot file"
echo.

:: Step 2: Quick pre-validation via CLI.
echo  [2/4] Pre-validating with sentinella-argus...
echo.
target\release\sentinella-argus.exe self-test
echo.

:: Step 3: Start daemon.
echo  [3/4] Starting daemon...
echo.
echo  The daemon will start in this window.
echo  Open the GUI (dev-run.bat step 7, or pnpm tauri dev).
echo.
echo  TEST CHECKLIST:
echo    [ ] Scan notepad.exe via GUI
echo    [ ] Scan cmd.exe via GUI
echo    [ ] Scan test-corpus\executables\clean_app.exe
echo    [ ] Try cancelling a scan
echo    [ ] Check dashboard remains "Connected"
echo    [ ] Check no "Daemon unreachable" appears
echo.
echo  Press any key to start the daemon...
pause >nul

start "sentinelld" cmd /k "cd /d %~dp0.. && target\debug\sentinelld.exe --foreground --log-level info --dll-dir target\debug --db-dir runtime\signatures"

echo.
echo  Daemon started in separate window.
echo  Now open GUI and run tests.
echo.
echo  When done testing, press any key to see options...
pause >nul

echo.
echo  [4/4] Test complete.
echo.
echo  Options:
echo    1. Keep file pilot ENABLED (for 3-day stability test)
echo    2. DISABLE file pilot (rollback to legacy)
echo.
set /p CHOICE="  Enter 1 or 2: "
if "%CHOICE%"=="2" (
    powershell -ExecutionPolicy Bypass -Command "& scripts\disable-orchestrator-dev.ps1"
    echo.
    echo  File pilot disabled. Restart daemon for changes.
) else (
    echo.
    echo  File pilot remains ENABLED.
    echo  Run for 3 days, then enable folder pilot if stable.
)
echo.
pause

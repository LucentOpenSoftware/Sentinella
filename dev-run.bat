@echo off
setlocal enabledelayedexpansion
cd /d %~dp0

:: ============================================================
:: Sentinella Development Runner
:: ============================================================
::
:: Single command to bring the full dev environment online:
::   daemon (named pipe) + Tauri GUI (hot-reload)
::
:: Safe to re-run: kills previous instances first.
:: ============================================================

title Sentinella Dev Runner

echo.
echo  ======================================
echo   Sentinella Development Runner
echo  ======================================
echo.

:: ── [0/6] Resolve tool paths ────────────────────────────────

set "PNPM_CMD="
for /f "delims=" %%P in ('where pnpm.cmd 2^>nul') do (
    if not defined PNPM_CMD set "PNPM_CMD=%%P"
)
if not defined PNPM_CMD (
    if exist "%APPDATA%\npm\pnpm.cmd" set "PNPM_CMD=%APPDATA%\npm\pnpm.cmd"
)
if not defined PNPM_CMD (
    echo  [ERR] pnpm not found. Install with: npm install -g pnpm
    pause
    exit /b 1
)

where cargo >nul 2>&1
if errorlevel 1 (
    echo  [ERR] cargo not found. Install Rust: https://rustup.rs
    pause
    exit /b 1
)

echo  pnpm: !PNPM_CMD!
echo  cargo: OK
echo.

:: ── [1/6] Kill previous Sentinella processes ────────────────

echo [1/6] Cleaning up previous processes...

taskkill /F /IM sentinelld.exe >nul 2>&1
taskkill /F /IM Sentinella.exe >nul 2>&1

:: Kill stale Vite dev servers on port 1420.
for /f "tokens=5" %%A in ('netstat -aon 2^>nul ^| findstr ":1420 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%A >nul 2>&1
)

:: Brief pause for OS to release file locks and pipes.
timeout /t 2 /nobreak >nul
echo        Done.
echo.

:: ── [2/6] Build Rust workspace ──────────────────────────────

echo [2/6] Building Rust workspace...
echo.

cargo build --workspace
if errorlevel 1 (
    echo.
    echo  [ERR] Rust build FAILED. Fix errors above.
    pause
    exit /b 1
)

echo.
echo        Rust build OK.
echo.

:: ── [3/6] Ensure frontend dependencies ──────────────────────

echo [3/6] Checking frontend dependencies...

if not exist "gui\node_modules\" (
    echo        Installing...
    pushd gui
    call "!PNPM_CMD!" install
    if errorlevel 1 (
        echo  [ERR] pnpm install FAILED.
        popd
        pause
        exit /b 1
    )
    popd
    echo        Installed.
) else (
    echo        node_modules OK.
)
echo.

:: ── [4/6] TypeScript check ──────────────────────────────────

echo [4/6] TypeScript type-check...

pushd gui
call "!PNPM_CMD!" exec tsc --noEmit
if errorlevel 1 (
    echo.
    echo  [ERR] TypeScript errors. Fix before continuing.
    popd
    pause
    exit /b 1
)
popd
echo        Types OK.
echo.

:: ── [5/6] Start daemon ──────────────────────────────────────

echo [5/6] Starting sentinelld daemon...

set "DAEMON_BIN=%~dp0target\debug\sentinelld.exe"
if not exist "!DAEMON_BIN!" (
    echo  [WARN] Binary not found, falling back to cargo run
    set "DAEMON_BIN=cargo run -p sentinelld --"
)

start "sentinelld" cmd /k "title sentinelld && cd /d %~dp0 && !DAEMON_BIN! --foreground --log-level debug"

echo        Waiting for pipe...
timeout /t 3 /nobreak >nul

tasklist /FI "IMAGENAME eq sentinelld.exe" /FO CSV /NH 2>nul | findstr /I "sentinelld" >nul
if errorlevel 1 (
    echo  [WARN] Daemon not detected. Check its window.
) else (
    echo        Daemon running.
)
echo.

:: ── [6/6] Launch Tauri GUI ──────────────────────────────────
::
:: Write a small .bat launcher to %TEMP% to avoid nested-quote
:: issues with start + cmd /k + paths containing spaces.
::
:: The > redirection builds the file line by line. Each line
:: uses >> to append after the first.

echo [6/6] Launching Tauri GUI...

set "LAUNCHER=%TEMP%\sentinella-dev-gui.bat"

> "!LAUNCHER!" echo @echo off
>> "!LAUNCHER!" echo title Sentinella GUI Dev
>> "!LAUNCHER!" echo cd /d "%~dp0gui"
>> "!LAUNCHER!" echo call "!PNPM_CMD!" tauri dev
>> "!LAUNCHER!" echo echo.
>> "!LAUNCHER!" echo echo GUI exited. Press any key to close.
>> "!LAUNCHER!" echo pause

:: Verify the launcher was written.
if not exist "!LAUNCHER!" (
    echo  [ERR] Could not create GUI launcher at !LAUNCHER!
    echo        Trying direct launch instead...
    pushd gui
    start "Sentinella GUI" cmd /k "call "!PNPM_CMD!" tauri dev"
    popd
    goto :summary
)

start "Sentinella GUI" cmd /c "call "!LAUNCHER!""

:summary
echo        Waiting for Vite + Tauri...
timeout /t 5 /nobreak >nul

echo.
echo  ======================================
echo   Sentinella dev environment ready
echo  ======================================
echo.
echo   Daemon:  sentinelld.exe
echo            Pipe \\.\pipe\sentinelld
echo            Logs in "sentinelld" window
echo.
echo   GUI:     Tauri + Vite on http://localhost:1420
echo            Hot-reload active
echo            Logs in "Sentinella GUI" window
echo.
echo   Re-run:  dev-run.bat  (kills previous automatically)
echo.

pause
exit /b 0

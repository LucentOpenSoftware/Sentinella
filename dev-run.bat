@echo off
setlocal enabledelayedexpansion
cd /d %~dp0

:: ============================================================
:: Sentinella Development Runner
:: ============================================================
::
:: Single command: build + setup DLLs + start daemon + launch GUI.
:: Safe to re-run: kills previous instances first.
:: ============================================================

title Sentinella Dev Runner

echo.
echo  ======================================
echo   Sentinella Development Runner
echo  ======================================
echo.

:: ── [0/7] Resolve tool paths ────────────────────────────────

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

:: ── [1/7] Kill previous Sentinella processes ────────────────

echo [1/7] Cleaning up previous processes...

taskkill /F /IM sentinelld.exe >nul 2>&1
taskkill /F /IM Sentinella.exe >nul 2>&1

:: Kill stale Vite dev servers on port 1420.
for /f "tokens=5" %%A in ('netstat -aon 2^>nul ^| findstr ":1420 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%A >nul 2>&1
)

:: Kill stale cargo processes holding target/ locks.
taskkill /F /IM cargo.exe >nul 2>&1
taskkill /F /IM rustc.exe >nul 2>&1

timeout /t 2 /nobreak >nul
echo        Done.
echo.

:: ── [2/7] Build Rust workspace ──────────────────────────────

echo [2/7] Building Rust workspace (release)...
echo.

cargo build --workspace --release
if errorlevel 1 (
    echo.
    echo  [ERR] Rust build FAILED. Fix errors above.
    pause
    exit /b 1
)

echo.
echo        Rust build OK (release).
echo.

:: ── [3/7] Setup runtime (DLLs, certs, dirs) ────────────────

echo [3/7] Setting up runtime environment...

set "ROOT=%~dp0"
set "TARGET=%ROOT%target\release"
set "BUILD=%ROOT%build\clamav"

:: Create runtime directories.
if not exist "%ROOT%runtime\signatures" mkdir "%ROOT%runtime\signatures"
if not exist "%ROOT%runtime\config" mkdir "%ROOT%runtime\config"
if not exist "%ROOT%runtime\logs" mkdir "%ROOT%runtime\logs"
if not exist "%ROOT%runtime\state" mkdir "%ROOT%runtime\state"
if not exist "%ROOT%runtime\quarantine" mkdir "%ROOT%runtime\quarantine"
if not exist "%ROOT%runtime\rules" mkdir "%ROOT%runtime\rules"
if not exist "%ROOT%runtime\argus\rules\yara" mkdir "%ROOT%runtime\argus\rules\yara"
if not exist "%ROOT%runtime\argus\compiled" mkdir "%ROOT%runtime\argus\compiled"
if not exist "%ROOT%runtime\argus\manifests" mkdir "%ROOT%runtime\argus\manifests"

:: Copy ClamAV DLLs to target\debug (if ClamAV was built).
if exist "%BUILD%\libclamav\Release\libclamav.dll" (
    for %%D in (libclamav\Release libclammspack\Release libfreshclam\Release) do (
        for %%F in ("%BUILD%\%%D\*.dll") do (
            if not exist "%TARGET%\%%~nxF" copy /Y "%%F" "%TARGET%\" >nul 2>&1
        )
    )
    echo        DLLs copied.
) else (
    echo  [WARN] ClamAV not built. Daemon will start without scanning.
    echo         Run: scripts\build-clamav-windows.bat
)

:: Copy certs.
if not exist "%TARGET%\certs" (
    if exist "%ROOT%third_party\clamav\certs" (
        xcopy /E /I /Q "%ROOT%third_party\clamav\certs" "%TARGET%\certs" >nul 2>&1
        echo        Certs copied.
    )
)

:: Copy freshclam.
if not exist "%TARGET%\freshclam.exe" (
    if exist "%BUILD%\freshclam\Release\freshclam.exe" (
        copy /Y "%BUILD%\freshclam\Release\freshclam.exe" "%TARGET%\" >nul 2>&1
        echo        freshclam.exe copied.
    )
)

echo        Runtime OK.
echo.

:: ── [4/7] Ensure frontend dependencies ──────────────────────

echo [4/7] Checking frontend dependencies...

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

:: ── [5/7] TypeScript check ──────────────────────────────────

echo [5/7] TypeScript type-check...

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

:: ── [6/7] Start daemon with ClamAV engine ───────────────────

echo [6/7] Starting sentinelld daemon (release)...

set "DAEMON_BIN=%TARGET%\sentinelld.exe"
if not exist "!DAEMON_BIN!" (
    echo  [WARN] Release binary not found, falling back to cargo run --release
    set "DAEMON_CMD=cargo run --release -p sentinelld -- --foreground --log-level info --dll-dir "%TARGET%" --db-dir "%ROOT%runtime\signatures""
) else (
    echo        Binary: !DAEMON_BIN!
    set "DAEMON_CMD=!DAEMON_BIN! --foreground --log-level info --dll-dir "%TARGET%" --db-dir "%ROOT%runtime\signatures""
)

start "sentinelld" cmd /k "title sentinelld && cd /d %~dp0 && !DAEMON_CMD!"

echo        Waiting for engine to load (this takes ~15 seconds)...
timeout /t 5 /nobreak >nul

tasklist /FI "IMAGENAME eq sentinelld.exe" /FO CSV /NH 2>nul | findstr /I "sentinelld" >nul
if errorlevel 1 (
    echo  [WARN] Daemon not detected. Check its window for errors.
) else (
    echo        Daemon running.
    echo        Pipe: \\.\pipe\sentinelld
)
echo.

:: ── [7/7] Launch Tauri GUI ──────────────────────────────────

echo [7/7] Launching Tauri GUI...

set "LAUNCHER=%TEMP%\sentinella-dev-gui.bat"

> "!LAUNCHER!" echo @echo off
>> "!LAUNCHER!" echo title Sentinella GUI Dev
>> "!LAUNCHER!" echo cd /d "%~dp0gui"
>> "!LAUNCHER!" echo call "!PNPM_CMD!" tauri dev
>> "!LAUNCHER!" echo echo.
>> "!LAUNCHER!" echo echo GUI exited. Press any key to close.
>> "!LAUNCHER!" echo pause

if not exist "!LAUNCHER!" (
    echo  [ERR] Could not create GUI launcher.
    pushd gui
    start "Sentinella GUI" cmd /k "call "!PNPM_CMD!" tauri dev"
    popd
    goto :summary
)

start "Sentinella GUI" cmd /c "call "!LAUNCHER!""

:summary
echo        Waiting for Vite + Tauri to compile...
timeout /t 5 /nobreak >nul

echo.
echo  ======================================
echo   Sentinella dev environment ready
echo  ======================================
echo.
echo   Daemon:  sentinelld.exe (release build)
echo            --dll-dir %TARGET%
echo            --db-dir  %ROOT%runtime\signatures
echo            Pipe: \\.\pipe\sentinelld
echo            Logs: "sentinelld" console window
echo            Log level: info
echo.
echo   GUI:     Tauri + Vite on http://localhost:1420
echo            Hot-reload active
echo            Logs: "Sentinella GUI" console window
echo.
echo   Re-run:  dev-run.bat  (kills previous automatically)
echo.
echo   Tip: If Tauri build fails with "os error 32",
echo        close all Sentinella windows and re-run.
echo.

pause
exit /b 0

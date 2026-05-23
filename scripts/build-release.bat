@echo off
setlocal
cd /d %~dp0..

:: ============================================================
:: Sentinella — Release Build
:: ============================================================
::
:: Builds everything in release mode and gathers artifacts.
::
:: Output: build/release/
:: ============================================================

set "ROOT=%cd%"
set "OUT=%ROOT%\build\release"

echo.
echo  ======================================
echo   Sentinella Release Build
echo  ======================================
echo.

:: Clean output
if exist "%OUT%" rd /s /q "%OUT%"
mkdir "%OUT%"

:: ── Step 1: Build Rust workspace (release) ──
echo [1/4] Building Rust workspace (release)...
cargo build --workspace --release
if errorlevel 1 (
    echo  [ERR] Rust build failed.
    exit /b 1
)
echo        OK.
echo.

:: ── Step 2: Build Tauri GUI (release) ──
echo [2/4] Building Tauri GUI (release)...
pushd gui
call pnpm tauri build
if errorlevel 1 (
    echo  [ERR] Tauri build failed.
    popd
    exit /b 1
)
popd
echo        OK.
echo.

:: ── Step 3: Gather artifacts ──
echo [3/4] Gathering artifacts...

:: Daemon + CLI
copy /Y "%ROOT%\target\release\sentinelld.exe" "%OUT%\" >nul
copy /Y "%ROOT%\target\release\sentinella.exe" "%OUT%\" >nul
copy /Y "%ROOT%\target\release\argusd.exe" "%OUT%\" >nul

:: ClamAV DLLs
for %%D in (libclamav\Release libclammspack\Release libfreshclam\Release) do (
    for %%F in ("%ROOT%\build\clamav\%%D\*.dll") do (
        copy /Y "%%F" "%OUT%\" >nul 2>&1
    )
)

:: Freshclam
copy /Y "%ROOT%\build\clamav\freshclam\Release\freshclam.exe" "%OUT%\" >nul 2>&1

:: Certs
xcopy /E /I /Q "%ROOT%\third_party\clamav\certs" "%OUT%\certs" >nul 2>&1

:: Config
mkdir "%OUT%\config" 2>nul
if exist "%ROOT%\installer\windows\freshclam.conf.template" (
    copy /Y "%ROOT%\installer\windows\freshclam.conf.template" "%OUT%\config\freshclam.conf" >nul 2>&1
) else (
    echo DatabaseDirectory C:\ProgramData\Sentinella\signatures > "%OUT%\config\freshclam.conf"
    echo UpdateLogFile C:\ProgramData\Sentinella\logs\freshclam.log >> "%OUT%\config\freshclam.conf"
)

echo        Artifacts gathered in: %OUT%
echo.

:: ── Step 4: Report ──
echo [4/4] Release artifacts:
dir /b "%OUT%\*.exe" "%OUT%\*.dll" 2>nul
echo.
echo  Build complete.
echo.

exit /b 0

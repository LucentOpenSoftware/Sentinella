@echo off
:: ============================================================
:: Sentinella — Package Source Code (clean zip)
:: ============================================================
:: Creates a clean source archive excluding build artifacts,
:: signatures, samples, and machine-specific data.
:: ============================================================

set "ROOT=%~dp0.."
set "OUT=%ROOT%\release\sentinella-source.zip"

echo.
echo  Sentinella Source Packaging
echo  ===========================
echo.

where tar >nul 2>&1
if errorlevel 1 (
    echo  [ERR] tar not found. Windows 10+ should have it built in.
    pause
    exit /b 1
)

:: Use tar with exclusions (available on Windows 10+).
cd /d "%ROOT%"

if exist "%OUT%" del "%OUT%"

tar -czf "%OUT%" ^
    --exclude="target" ^
    --exclude="node_modules" ^
    --exclude="dist" ^
    --exclude="build" ^
    --exclude="third_party/vcpkg" ^
    --exclude="third_party/clamav/build" ^
    --exclude="runtime/signatures" ^
    --exclude="runtime/state" ^
    --exclude="runtime/logs" ^
    --exclude="runtime/quarantine" ^
    --exclude="runtime/research_samples" ^
    --exclude="runtime/compiled" ^
    --exclude="graphify-out" ^
    --exclude=".graphify_*" ^
    --exclude="*.db-wal" ^
    --exclude="*.db-shm" ^
    --exclude="*.pdb" ^
    --exclude="release/staging" ^
    -C "%ROOT%\.." "sentinella"

if exist "%OUT%" (
    echo.
    echo  Source package created: %OUT%
    for %%A in ("%OUT%") do echo  Size: %%~zA bytes
    set "PKG_OK=1"
) else (
    echo  [ERR] Failed to create source package.
    set "PKG_OK=0"
)

echo.
if "%1"=="" pause
if "%PKG_OK%"=="1" exit /b 0
exit /b 1

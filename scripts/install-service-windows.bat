@echo off
:: ============================================================
:: Sentinella — Install Windows Service
:: ============================================================
:: Registers sentinelld as a Windows service so it starts
:: automatically and restarts on failure.
::
:: REQUIRES: Administrator privileges.
:: ============================================================

net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo   [ERR] This script requires Administrator privileges.
    echo         Right-click and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

set "SERVICE_NAME=SentinellaDaemon"
set "DISPLAY_NAME=Sentinella Protection Service"
set "DESCRIPTION=Sentinella antivirus daemon — ClamAV signatures + ARGUS heuristic intelligence engine."

:: Locate sentinelld.exe
set "DAEMON=%~dp0..\target\release\sentinelld.exe"
if not exist "%DAEMON%" set "DAEMON=%~dp0..\target\debug\sentinelld.exe"
if not exist "%DAEMON%" set "DAEMON=%ProgramFiles%\Sentinella\sentinelld.exe"
if not exist "%DAEMON%" (
    echo   [ERR] sentinelld.exe not found.
    echo         Build first: cargo build --release -p sentinelld
    pause
    exit /b 1
)

for %%F in ("%DAEMON%") do set "DAEMON=%%~fF"

echo.
echo   ==========================================
echo   Sentinella Service Installation
echo   ==========================================
echo.
echo   Binary:  %DAEMON%
echo   Service: %SERVICE_NAME%
echo.

:: Check if already installed.
sc query "%SERVICE_NAME%" >nul 2>&1
if not errorlevel 1 (
    echo   [WARN] Service already exists. Stopping and removing...
    sc stop "%SERVICE_NAME%" >nul 2>&1
    timeout /t 3 /nobreak >nul
    sc delete "%SERVICE_NAME%" >nul 2>&1
    timeout /t 2 /nobreak >nul
)

:: Create service — auto start, runs as LocalSystem.
sc create "%SERVICE_NAME%" ^
    binPath= "\"%DAEMON%\" --foreground --log-level info" ^
    DisplayName= "%DISPLAY_NAME%" ^
    start= delayed-auto ^
    obj= "LocalSystem"

if errorlevel 1 (
    echo   [ERR] Failed to create service.
    pause
    exit /b 1
)

:: Set description.
sc description "%SERVICE_NAME%" "%DESCRIPTION%"

:: Configure failure recovery: restart on 1st, 2nd, 3rd failure.
:: Reset failure count after 1 day (86400 seconds).
sc failure "%SERVICE_NAME%" ^
    reset= 86400 ^
    actions= restart/5000/restart/10000/restart/30000

echo.
echo   [OK] Service installed successfully.
echo.
echo   To start:   net start %SERVICE_NAME%
echo   To stop:    net stop %SERVICE_NAME%
echo   To remove:  scripts\uninstall-service-windows.bat
echo.
echo   The service will auto-start on next boot.
echo.
pause
exit /b 0

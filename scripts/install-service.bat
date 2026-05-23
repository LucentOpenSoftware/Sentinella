@echo off
setlocal
cd /d %~dp0..

:: ============================================================
:: Sentinella — Install/Uninstall Windows Service
:: ============================================================
::
:: Usage:
::   install-service.bat install    — registers sentinelld as a service
::   install-service.bat uninstall  — removes the service
::   install-service.bat start      — starts the service
::   install-service.bat stop       — stops the service
::   install-service.bat status     — shows service status
::
:: Requires: Administrator privileges
:: ============================================================

set "ROOT=%cd%"
set "DAEMON=%ROOT%\target\release\sentinelld.exe"
set "SERVICE_NAME=sentinelld"
set "DISPLAY_NAME=Sentinella Antivirus Daemon"
set "DLL_DIR=%ROOT%\target\release"
set "DB_DIR=%ROOT%\runtime\signatures"
set "STATE_DB=%ROOT%\runtime\state\sentinella.db"

if "%~1"=="" goto :usage

if /I "%~1"=="install" (
    echo Installing %SERVICE_NAME%...
    if not exist "%DAEMON%" (
        echo [ERR] %DAEMON% not found. Build release first.
        exit /b 1
    )
    sc create %SERVICE_NAME% binPath= "\"%DAEMON%\" --dll-dir \"%DLL_DIR%\" --db-dir \"%DB_DIR%\" --state-db \"%STATE_DB%\"" start= auto DisplayName= "%DISPLAY_NAME%"
    sc description %SERVICE_NAME% "Background antivirus protection daemon for Sentinella."
    echo Service installed. Start with: install-service.bat start
    exit /b 0
)

if /I "%~1"=="uninstall" (
    echo Stopping and removing %SERVICE_NAME%...
    sc stop %SERVICE_NAME% >nul 2>&1
    timeout /t 3 /nobreak >nul
    sc delete %SERVICE_NAME%
    echo Service removed.
    exit /b 0
)

if /I "%~1"=="start" (
    sc start %SERVICE_NAME%
    exit /b %errorlevel%
)

if /I "%~1"=="stop" (
    sc stop %SERVICE_NAME%
    exit /b %errorlevel%
)

if /I "%~1"=="status" (
    sc query %SERVICE_NAME%
    exit /b 0
)

:usage
echo Usage: install-service.bat [install^|uninstall^|start^|stop^|status]
exit /b 1

@echo off
:: Sentinella — Uninstall Windows Service. Requires Administrator.
net session >nul 2>&1
if errorlevel 1 ( echo [ERR] Run as Administrator. & pause & exit /b 1 )
set "SVC=SentinellaDaemon"
echo Stopping %SVC%...
sc stop "%SVC%" >nul 2>&1
timeout /t 3 /nobreak >nul
echo Removing %SVC%...
sc delete "%SVC%"
echo Done.
pause

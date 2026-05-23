@echo off
net session >nul 2>&1
if errorlevel 1 ( echo [ERR] Run as Administrator. & pause & exit /b 1 )
net start SentinellaDaemon
pause

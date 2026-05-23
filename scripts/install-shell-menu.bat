@echo off
:: ============================================================
:: Sentinella — Install "Scan with Sentinella" context menu
:: ============================================================
:: Adds a right-click context menu entry for files and folders
:: in Windows Explorer. Requires Administrator privileges.
::
:: Usage: Run as Administrator.
:: Uninstall: Run with /uninstall flag.
:: ============================================================

if "%1"=="/uninstall" goto :uninstall

echo.
echo   Sentinella Shell Integration
echo   ============================
echo.
echo   Installing "Scan with Sentinella" context menu...
echo.

:: Determine sentinella.exe path.
set "SENTINELLA_EXE=%~dp0..\target\debug\sentinella.exe"
if not exist "%SENTINELLA_EXE%" (
    set "SENTINELLA_EXE=%~dp0..\target\release\sentinella.exe"
)
if not exist "%SENTINELLA_EXE%" (
    :: Try installed location.
    set "SENTINELLA_EXE=%ProgramFiles%\Sentinella\sentinella.exe"
)
if not exist "%SENTINELLA_EXE%" (
    echo   [ERR] sentinella.exe not found.
    echo         Build the project first: cargo build --workspace
    pause
    exit /b 1
)

:: Resolve to absolute path.
for %%F in ("%SENTINELLA_EXE%") do set "SENTINELLA_EXE=%%~fF"

echo   Using: %SENTINELLA_EXE%

:: Get icon path.
set "ICON_PATH=%~dp0..\gui\src-tauri\icons\icon.ico"
for %%F in ("%ICON_PATH%") do set "ICON_PATH=%%~fF"

:: Add context menu for files.
reg add "HKCU\Software\Classes\*\shell\SentinellaScan" /ve /d "Scan with Sentinella" /f >nul 2>&1
reg add "HKCU\Software\Classes\*\shell\SentinellaScan" /v "Icon" /d "\"%ICON_PATH%\"" /f >nul 2>&1
reg add "HKCU\Software\Classes\*\shell\SentinellaScan\command" /ve /d "\"%SENTINELLA_EXE%\" scan \"%%1\"" /f >nul 2>&1

:: Add context menu for folders.
reg add "HKCU\Software\Classes\Directory\shell\SentinellaScan" /ve /d "Scan with Sentinella" /f >nul 2>&1
reg add "HKCU\Software\Classes\Directory\shell\SentinellaScan" /v "Icon" /d "\"%ICON_PATH%\"" /f >nul 2>&1
reg add "HKCU\Software\Classes\Directory\shell\SentinellaScan\command" /ve /d "\"%SENTINELLA_EXE%\" scan \"%%1\"" /f >nul 2>&1

:: Add context menu for folder background (right-click inside folder).
reg add "HKCU\Software\Classes\Directory\Background\shell\SentinellaScan" /ve /d "Scan folder with Sentinella" /f >nul 2>&1
reg add "HKCU\Software\Classes\Directory\Background\shell\SentinellaScan" /v "Icon" /d "\"%ICON_PATH%\"" /f >nul 2>&1
reg add "HKCU\Software\Classes\Directory\Background\shell\SentinellaScan\command" /ve /d "\"%SENTINELLA_EXE%\" scan \"%%V\"" /f >nul 2>&1

echo.
echo   Done! "Scan with Sentinella" now appears in right-click menus.
echo.
echo   To uninstall: %~nx0 /uninstall
echo.
pause
exit /b 0

:uninstall
echo.
echo   Removing "Scan with Sentinella" context menu...
echo.
reg delete "HKCU\Software\Classes\*\shell\SentinellaScan" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Directory\shell\SentinellaScan" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Directory\Background\shell\SentinellaScan" /f >nul 2>&1
echo   Done! Context menu entries removed.
echo.
pause
exit /b 0

@echo off
setlocal
cd /d %~dp0..

:: ============================================================
:: Sentinella — Signature Database Update
:: ============================================================
::
:: Downloads ClamAV signature databases using freshclam.
::
:: Prerequisites:
::   - ClamAV built (run scripts\build-clamav-windows.bat first)
::   - Internet connection
::
:: Output:
::   runtime\signatures\main.cvd
::   runtime\signatures\daily.cvd
::   runtime\signatures\bytecode.cvd
::
:: ============================================================

set "ROOT=%cd%"
set "BUILD=%ROOT%\build\clamav"
set "FRESHCLAM=%BUILD%\freshclam\Release\freshclam.exe"
set "CONFIG=%ROOT%\runtime\config\freshclam.conf"
set "SIGDIR=%ROOT%\runtime\signatures"
set "LOGDIR=%ROOT%\runtime\logs"
set "CERTS_SRC=%ROOT%\third_party\clamav\certs"

echo.
echo  ======================================
echo   Sentinella Signature Update
echo  ======================================
echo.

:: Check freshclam exists
if not exist "%FRESHCLAM%" (
    echo  [ERR] freshclam.exe not found.
    echo        Build ClamAV first: scripts\build-clamav-windows.bat
    exit /b 1
)

:: Ensure directories exist
if not exist "%SIGDIR%" mkdir "%SIGDIR%"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

:: Ensure DLLs are next to freshclam
echo  Checking DLL dependencies...
for %%D in (libfreshclam\Release libclamav\Release libclammspack\Release) do (
    for %%F in ("%BUILD%\%%D\*.dll") do (
        if not exist "%BUILD%\freshclam\Release\%%~nxF" (
            copy /Y "%%F" "%BUILD%\freshclam\Release\" >nul 2>&1
        )
    )
)

:: Ensure certs directory exists next to freshclam
if not exist "%BUILD%\freshclam\Release\certs\" (
    echo  Copying ClamAV CA certificates...
    xcopy /E /I /Q "%CERTS_SRC%" "%BUILD%\freshclam\Release\certs" >nul
)

echo  freshclam: %FRESHCLAM%
echo  config:    %CONFIG%
echo  database:  %SIGDIR%
echo  log:       %LOGDIR%\freshclam.log
echo.
echo  Downloading signatures from database.clamav.net...
echo  (main.cvd is ~160 MB, first download takes a few minutes)
echo.

"%FRESHCLAM%" --config-file="%CONFIG%"

if errorlevel 1 (
    echo.
    echo  [WARN] freshclam exited with errors.
    echo         Check %LOGDIR%\freshclam.log for details.
) else (
    echo.
    echo  Signatures updated successfully.
)

:: Report what was downloaded
echo.
echo  Database files:
for %%F in ("%SIGDIR%\*.cvd" "%SIGDIR%\*.cld") do (
    if exist "%%F" echo    %%~nxF  (%%~zF bytes)
)

echo.
exit /b 0

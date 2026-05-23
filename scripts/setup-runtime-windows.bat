@echo off
setlocal
cd /d %~dp0..

:: ============================================================
:: Sentinella — Setup Runtime Environment (Development)
:: ============================================================
::
:: Copies ClamAV DLLs and certs next to sentinelld.exe so the
:: daemon can find libclamav.dll at runtime.
::
:: ============================================================

set "ROOT=%cd%"
set "BUILD=%ROOT%\build\clamav"
set "TARGET=%ROOT%\target\debug"

echo.
echo  Setting up runtime environment...
echo.

if not exist "%BUILD%\libclamav\Release\libclamav.dll" (
    echo  [ERR] ClamAV not built. Run scripts\build-clamav-windows.bat first.
    exit /b 1
)

:: Copy DLLs to target\debug (where sentinelld.exe lives)
echo  Copying DLLs to %TARGET%...
for %%D in (libclamav\Release libclammspack\Release libfreshclam\Release) do (
    for %%F in ("%BUILD%\%%D\*.dll") do (
        copy /Y "%%F" "%TARGET%\" >nul 2>&1
    )
)

:: Copy certs
if not exist "%TARGET%\certs" (
    echo  Copying ClamAV certificates...
    xcopy /E /I /Q "%ROOT%\third_party\clamav\certs" "%TARGET%\certs" >nul
)

:: Report
echo.
echo  DLLs in target\debug:
dir /b "%TARGET%\*.dll" 2>nul
echo.
echo  Certs:
dir /b "%TARGET%\certs\*" 2>nul
echo.
echo  Done. You can now run:
echo    cargo run -p sentinelld -- --dll-dir "%TARGET%" --db-dir "%ROOT%\runtime\signatures" --log-level debug
echo.

exit /b 0

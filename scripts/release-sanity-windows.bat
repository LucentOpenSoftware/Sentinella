@echo off
:: ============================================================
:: Sentinella — Release Sanity Check
:: ============================================================
:: Verifies release/staging/windows/ has everything needed.
:: ============================================================

set "STAGE=%~dp0..\release\staging\windows"
set PASS=0
set FAIL=0

echo.
echo  Sentinella Release Sanity Check
echo  ================================
echo.

:: Check binaries.
call :check "%STAGE%\sentinelld.exe" "Daemon binary"
call :check "%STAGE%\sentinella.exe" "CLI binary"
call :check "%STAGE%\argusd.exe" "ARGUS worker binary"

:: Check ClamAV DLLs.
call :check "%STAGE%\libclamav.dll" "ClamAV engine DLL"

:: Check ARGUS rules.
call :check_dir "%STAGE%\runtime\argus\rules\yara" "YARA rules directory"
call :check "%STAGE%\runtime\argus\manifests\pack_manifest.json" "Pack manifest"
call :check "%STAGE%\runtime\rules\ioc_hashes.txt" "IOC hashes"

:: Check config.
call :check_dir "%STAGE%\runtime\config" "Config directory"
call :check "%STAGE%\runtime\config\freshclam.conf" "Freshclam config"

:: Check legal.
call :check "%STAGE%\LICENSE" "LICENSE file"
call :check_notice

:: Reject developer-local paths in staged config.
findstr /I /C:"C:\Users\\" "%STAGE%\runtime\config\freshclam.conf" >nul 2>&1
if errorlevel 1 ( echo  [OK]   Freshclam config has no user-profile path & set /a PASS+=1 ) else ( echo  [FAIL] Freshclam config contains user-profile path & set /a FAIL+=1 )
findstr /I /C:"C:\ProgramData\Sentinella" "%STAGE%\runtime\config\freshclam.conf" >nul 2>&1
if errorlevel 1 ( echo  [FAIL] Freshclam config missing ProgramData path & set /a FAIL+=1 ) else ( echo  [OK]   Freshclam config uses ProgramData & set /a PASS+=1 )

:: Check icon.
call :check "%STAGE%\sentinella.ico" "Application icon"

:: Safety checks — these should NOT exist.
call :reject "%STAGE%\runtime\signatures" "Signature databases should download at runtime"
call :reject "%STAGE%\runtime\quarantine" "Quarantine vault"
call :reject "%STAGE%\runtime\research_samples" "Research samples"
call :reject "%STAGE%\runtime\state" "State database"
call :reject "%STAGE%\runtime\logs" "Log files"

echo.
echo  ==========================================
echo   Results: %PASS% passed, %FAIL% FAILED
echo  ==========================================
echo.
if %FAIL% GTR 0 ( echo  [FAIL] Release has issues! ) else ( echo  [PASS] Release looks good. )
echo.
if "%1"=="" pause
if %FAIL% GTR 0 exit /b 1
exit /b 0

:check
if exist "%~1" ( echo  [OK]   %~2 & set /a PASS+=1 ) else ( echo  [FAIL] %~2 NOT FOUND & set /a FAIL+=1 )
exit /b

:check_dir
if exist "%~1\" ( echo  [OK]   %~2 & set /a PASS+=1 ) else ( echo  [FAIL] %~2 NOT FOUND & set /a FAIL+=1 )
exit /b

:check_notice
if exist "%STAGE%\NOTICE" ( echo  [OK]   NOTICE attribution & set /a PASS+=1 ) else if exist "%STAGE%\NOTICE.md" ( echo  [OK]   NOTICE.md attribution & set /a PASS+=1 ) else ( echo  [FAIL] NOTICE attribution NOT FOUND & set /a FAIL+=1 )
exit /b

:reject
if exist "%~1" ( echo  [FAIL] %~2 should NOT be bundled! & set /a FAIL+=1 ) else ( echo  [OK]   %~2 correctly excluded & set /a PASS+=1 )
exit /b

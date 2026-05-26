@echo off
setlocal enabledelayedexpansion

:: ============================================================
:: Build ClamAV with Sentinella file-backed mpool (Phase 2A)
:: ============================================================
::
:: This builds libclamav.dll with SENTINELLA_FILEBACKED_MPOOL enabled.
:: The compiled engine's memory pool uses CreateFileMapping + MapViewOfFile
:: instead of VirtualAlloc, making pages file-backed (cheaper to evict).
::
:: Usage:
::   scripts\build-clamav-filebacked.bat
::
:: Output:
::   build\clamav-filebacked\libclamav\Release\libclamav.dll
::
:: ============================================================

set "ROOT=%~dp0.."
set "CLAMAV_SRC=%ROOT%\third_party\clamav"
set "BUILD_DIR=%ROOT%\build\clamav-filebacked"
set "VCPKG_ROOT=%ROOT%\third_party\vcpkg"
set "VCPKG_TOOLCHAIN=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"

echo.
echo  ======================================
echo   ClamAV File-Backed mpool Build
echo   Phase 2A: Performance Research
echo  ======================================
echo.

:: ── Validate prerequisites ──────────────────────────────────

if not exist "%CLAMAV_SRC%\CMakeLists.txt" (
    echo  [ERR] ClamAV source not found at %CLAMAV_SRC%
    exit /b 1
)

if not exist "%VCPKG_TOOLCHAIN%" (
    echo  [ERR] vcpkg toolchain not found
    exit /b 1
)

:: ── Set up MSVC environment ─────────────────────────────────

set "VCVARS="
for /f "delims=" %%V in ('dir /b /s "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" 2^>nul') do (
    set "VCVARS=%%V"
)
if not defined VCVARS (
    echo  [ERR] vcvarsall.bat not found. Install VS 2022 Build Tools.
    exit /b 1
)

call "!VCVARS!" x64 >nul 2>&1
echo  MSVC ready.

:: ── Configure with file-backed mpool flag ───────────────────

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo.
echo  [1/2] Configuring ClamAV with SENTINELLA_FILEBACKED_MPOOL...
echo.

cmake -S "%CLAMAV_SRC%" -B "%BUILD_DIR%" ^
    -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_TOOLCHAIN_FILE="%VCPKG_TOOLCHAIN%" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_C_FLAGS="/DSENTINELLA_FILEBACKED_MPOOL" ^
    -DENABLE_LIBCLAMAV_ONLY=OFF ^
    -DENABLE_STATIC_LIB=OFF ^
    -DENABLE_SHARED_LIB=ON ^
    -DENABLE_APP=ON ^
    -DENABLE_UNRAR=OFF ^
    -DENABLE_MILTER=OFF ^
    -DENABLE_CLAMONACC=OFF ^
    -DENABLE_EXAMPLES=OFF ^
    -DENABLE_TESTS=OFF ^
    -DENABLE_MAN_PAGES=OFF ^
    -DENABLE_DOXYGEN=OFF ^
    -DBYTECODE_RUNTIME=interpreter

if errorlevel 1 (
    echo  [ERR] CMake configure FAILED.
    exit /b 1
)

echo  Configure OK.

:: ── Build ───────────────────────────────────────────────────

echo.
echo  [2/2] Building ClamAV (file-backed mpool)...
echo.

cmake --build "%BUILD_DIR%" --config Release --parallel

if errorlevel 1 (
    echo  [ERR] Build FAILED.
    exit /b 1
)

echo.
echo  ======================================
echo   ClamAV file-backed mpool build DONE
echo  ======================================
echo.
echo  DLL: %BUILD_DIR%\libclamav\Release\libclamav.dll
echo.
echo  To test: copy to target\debug\ and run sentinelld
echo  To revert: copy from build\clamav\libclamav\Release\
echo.

exit /b 0

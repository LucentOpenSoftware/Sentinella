@echo off
setlocal enabledelayedexpansion

:: ============================================================
:: Build upstream ClamAV (libclamav) on Windows
:: ============================================================
::
:: Prerequisites:
::   - Visual Studio 2022 Build Tools (MSVC)
::   - CMake 3.16+
::   - Rust toolchain (MSVC target)
::   - vcpkg with: openssl zlib bzip2 libxml2 pcre2 json-c curl pthreads
::
:: Output:
::   sentinella/build/clamav/  (out-of-tree build)
::
:: Usage:
::   scripts\build-clamav-windows.bat [configure|build|clean]
::
:: ============================================================

set "ROOT=%~dp0.."
set "CLAMAV_SRC=%ROOT%\third_party\clamav"
set "BUILD_DIR=%ROOT%\build\clamav"
set "VCPKG_ROOT=%ROOT%\third_party\vcpkg"
set "VCPKG_TOOLCHAIN=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"

:: Default action
set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=build"

echo.
echo  ======================================
echo   ClamAV Windows Build
echo  ======================================
echo.
echo  Source:  %CLAMAV_SRC%
echo  Build:   %BUILD_DIR%
echo  vcpkg:   %VCPKG_ROOT%
echo  Action:  %ACTION%
echo.

:: ── Validate prerequisites ──────────────────────────────────

if not exist "%CLAMAV_SRC%\CMakeLists.txt" (
    echo  [ERR] ClamAV source not found at %CLAMAV_SRC%
    exit /b 1
)

if not exist "%VCPKG_TOOLCHAIN%" (
    echo  [ERR] vcpkg toolchain not found at %VCPKG_TOOLCHAIN%
    echo       Run: third_party\vcpkg\bootstrap-vcpkg.bat
    exit /b 1
)

where cmake >nul 2>&1
if errorlevel 1 (
    echo  [ERR] cmake not found on PATH
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

echo  Setting up MSVC x64 environment...
call "!VCVARS!" x64 >nul 2>&1
echo  MSVC ready.
echo.

:: ── Handle action ───────────────────────────────────────────

if /I "%ACTION%"=="clean" (
    echo  Cleaning build directory...
    if exist "%BUILD_DIR%" rd /s /q "%BUILD_DIR%"
    echo  Done.
    exit /b 0
)

:: ── Configure ───────────────────────────────────────────────

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo  [1/2] Configuring ClamAV with CMake...
echo.

cmake -S "%CLAMAV_SRC%" -B "%BUILD_DIR%" ^
    -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_TOOLCHAIN_FILE="%VCPKG_TOOLCHAIN%" ^
    -DCMAKE_BUILD_TYPE=Release ^
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
    echo.
    echo  [ERR] CMake configure FAILED. Check errors above.
    exit /b 1
)

echo.
echo  Configure OK.
echo.

if /I "%ACTION%"=="configure" (
    echo  Configure-only mode. Exiting.
    exit /b 0
)

:: ── Build ───────────────────────────────────────────────────

echo  [2/2] Building ClamAV...
echo.

cmake --build "%BUILD_DIR%" --config Release --parallel

if errorlevel 1 (
    echo.
    echo  [ERR] Build FAILED. Check errors above.
    exit /b 1
)

echo.
echo  ======================================
echo   ClamAV build complete
echo  ======================================
echo.

:: ── Report binaries ─────────────────────────────────────────

echo  Checking for expected binaries...
for %%B in (clamscan.exe freshclam.exe clamd.exe clamdscan.exe sigtool.exe) do (
    for /f "delims=" %%F in ('dir /b /s "%BUILD_DIR%\Release\%%B" 2^>nul') do (
        echo    FOUND: %%F
    )
    if errorlevel 1 (
        for /f "delims=" %%F in ('dir /b /s "%BUILD_DIR%\%%B" 2^>nul') do (
            echo    FOUND: %%F
        )
    )
)

echo.
echo  Build directory: %BUILD_DIR%
echo.

exit /b 0

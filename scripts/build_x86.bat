@echo off
REM Build script for 32-bit version
REM Usage: build_x86.bat [Debug|Release]

setlocal enabledelayedexpansion

set BUILD_TYPE=%1
if "%BUILD_TYPE%"=="" set BUILD_TYPE=Release

echo ============================================
echo Building MiniProxifier x86 (%BUILD_TYPE%)
echo ============================================

REM Check for vcpkg
if not defined VCPKG_ROOT (
    if exist "C:\vcpkg" (
        set VCPKG_ROOT=C:\vcpkg
    ) else (
        echo ERROR: VCPKG_ROOT not set and vcpkg not found at C:\vcpkg
        exit /b 1
    )
)

echo Using vcpkg at: %VCPKG_ROOT%

REM Create build directory
if not exist "build_x86" mkdir build_x86

REM Configure with CMake
echo Configuring CMake...
cmake -B build_x86 -A Win32 ^
    -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake ^
    -DVCPKG_TARGET_TRIPLET=x86-windows

if errorlevel 1 (
    echo CMake configuration failed!
    exit /b 1
)

REM Build
echo Building...
cmake --build build_x86 --config %BUILD_TYPE%

if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo ============================================
echo Build completed successfully!
echo Output: build_x86\bin\%BUILD_TYPE%\
echo ============================================

endlocal

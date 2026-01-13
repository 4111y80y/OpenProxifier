@echo off
REM Setup vcpkg and install dependencies
REM Run this script once before building

setlocal enabledelayedexpansion

echo ============================================
echo Setting up vcpkg for MiniProxifier
echo ============================================

REM Check if vcpkg exists
if exist "C:\vcpkg" (
    echo vcpkg found at C:\vcpkg
    set VCPKG_ROOT=C:\vcpkg
) else (
    echo Installing vcpkg to C:\vcpkg...
    cd /d C:\
    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg
    call bootstrap-vcpkg.bat
    set VCPKG_ROOT=C:\vcpkg
)

cd /d %VCPKG_ROOT%

REM Install Detours for both architectures
echo Installing Microsoft Detours...
vcpkg install detours:x86-windows
vcpkg install detours:x64-windows

if errorlevel 1 (
    echo Failed to install dependencies!
    exit /b 1
)

REM Integrate with MSBuild
echo Integrating vcpkg...
vcpkg integrate install

echo ============================================
echo Setup completed!
echo
echo VCPKG_ROOT=%VCPKG_ROOT%
echo
echo You can now build the project using:
echo   scripts\build_x64.bat
echo   scripts\build_x86.bat
echo ============================================

endlocal

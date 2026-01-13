@echo off
REM Install IFEO rule for curl.exe - Run as Administrator!

set INJECTOR_PATH=D:\5118\OpenProxifier\build_x64\bin\Debug\ProxifierInjector_x64.exe

echo Installing IFEO rule for curl.exe...
echo Injector path: %INJECTOR_PATH%

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\curl.exe" /v Debugger /t REG_SZ /d "%INJECTOR_PATH%" /f

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] IFEO rule installed for curl.exe
    echo.
    echo Now test by running curl from any command prompt:
    echo   curl https://httpbin.org/ip
    echo.
    echo Expected result: Should show VPN IP (205.198.72.66) instead of local IP
) else (
    echo [ERROR] Failed to install IFEO rule. Make sure you run this as Administrator!
)

pause

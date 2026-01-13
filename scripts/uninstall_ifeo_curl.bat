@echo off
REM Uninstall IFEO rule for curl.exe - Run as Administrator!

echo Removing IFEO rule for curl.exe...

reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\curl.exe" /v Debugger /f 2>nul

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] IFEO rule removed for curl.exe
) else (
    echo [INFO] No IFEO rule found for curl.exe or failed to remove
)

pause

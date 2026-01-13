@echo off
REM OpenProxifier Launcher - Creates a proxified shortcut for any executable
REM Usage: create_shortcut.bat "C:\Path\To\App.exe" "Shortcut Name"

setlocal enabledelayedexpansion

set INJECTOR_PATH=%~dp0..\build_x64\bin\Debug\ProxifierInjector_x64.exe
set TARGET_EXE=%~1
set SHORTCUT_NAME=%~2

if "%TARGET_EXE%"=="" (
    echo Usage: create_shortcut.bat "C:\Path\To\App.exe" "Shortcut Name"
    echo.
    echo Example: create_shortcut.bat "C:\Windows\System32\curl.exe" "Proxified Curl"
    pause
    exit /b 1
)

if "%SHORTCUT_NAME%"=="" (
    for %%F in ("%TARGET_EXE%") do set SHORTCUT_NAME=Proxified %%~nF
)

set DESKTOP=%USERPROFILE%\Desktop
set SHORTCUT_PATH=%DESKTOP%\%SHORTCUT_NAME%.lnk

echo Creating shortcut: %SHORTCUT_PATH%
echo Target: %TARGET_EXE%
echo Injector: %INJECTOR_PATH%

powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT_PATH%'); $s.TargetPath = '%INJECTOR_PATH%'; $s.Arguments = '\"%TARGET_EXE%\"'; $s.WorkingDirectory = '%~dp1'; $s.Description = 'Launches %~nx1 through SOCKS5 proxy'; $s.Save()"

if exist "%SHORTCUT_PATH%" (
    echo [SUCCESS] Shortcut created on Desktop: %SHORTCUT_NAME%.lnk
) else (
    echo [ERROR] Failed to create shortcut
)

pause

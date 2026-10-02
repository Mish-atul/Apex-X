@echo off
echo ================================================
echo   APEX-X Android Emulator Launcher
echo ================================================
echo.
echo Cleaning up old emulator instances...
taskkill /IM qemu-system-x86_64.exe /F >nul 2>&1

echo Launching Android Emulator (this takes 30-60 seconds)...
echo DO NOT close this window!
echo.

"%LOCALAPPDATA%\Android\Sdk\emulator\emulator.exe" -avd ApexX_Sandbox -no-audio -no-snapshot-save -gpu auto

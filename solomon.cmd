@echo off
setlocal
set "PYTHONUTF8=1"
if not exist "%~dp0.venv\Scripts\python.exe" goto missing
pushd "%~dp0"
"%~dp0.venv\Scripts\python.exe" -m solomon %*
set "SOLOMON_EXIT=%ERRORLEVEL%"
popd
exit /b %SOLOMON_EXIT%
:missing
echo Execute primeiro: powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup-windows.ps1"
exit /b 2

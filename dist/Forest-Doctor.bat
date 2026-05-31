@echo off
title Forest Doctor
echo Running Forest Doctor... (this may take ~5 seconds)
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Forest-Doctor.ps1"
echo.
pause

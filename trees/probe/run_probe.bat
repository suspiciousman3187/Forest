@echo off
rem Right-click -> Run as administrator, BEFORE starting POL.
rem Waits for the next new pol.exe, injects the read-only PolProbe.dll and
rem keeps the POL window visible. Already-running characters are not touched.
rem Log: probe\out\polprobe_<pid>.log

if not exist "%~dp0out\PolProbe.dll" (echo Build first: probe\build_probe.bat & pause & exit /b 1)
"%~dp0out\waitinject.exe" "%~dp0out\PolProbe.dll" "" "" nohide
echo.
echo Injected. You can close this window now; the probe keeps going inside POL.
pause

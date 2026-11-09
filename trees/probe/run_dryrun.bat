@echo off
rem Dry run of the real Trees.dll: it follows the POL login screens and logs
rem every step it WOULD take, but never selects, types, clicks or closes POL.
rem
rem Right-click -> Run as administrator, BEFORE starting POL.
rem Log: probe\out\dryrun\trees.log

setlocal
set "OUT=%~dp0out\dryrun"
if not exist "%~dp0..\Trees.dll" (echo Build first: trees\build.bat & pause & exit /b 1)
if not exist "%OUT%" mkdir "%OUT%"
copy /y "%~dp0..\Trees.dll" "%OUT%\" >nul
copy /y "%~dp0..\waitinject.exe" "%OUT%\" >nul
echo 1> "%OUT%\forest_debug.txt"
echo 1> "%OUT%\forest_dryrun.txt"
if exist "%OUT%\trees.log" del /q "%OUT%\trees.log"

rem Arguments: dll, POL member slot (1 = first row, only logged), no creds, keep window visible.
"%OUT%\waitinject.exe" "%OUT%\Trees.dll" 1 "" nohide
echo.
echo Injected. You can close this window now; the dry run keeps going inside POL.
pause

@echo off
rem Builds PolProbe.dll (x86) into probe\out\ alongside a copy of waitinject.exe.
rem Test run (admin terminal, POL not yet started):
rem   probe\out\waitinject.exe probe\out\PolProbe.dll "" "" nohide
rem then launch POL via Windower and step through the login screens by hand.

setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSDIR="
if exist "%VSWHERE%" for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%I"
if not defined VSDIR (echo ERROR: no Visual Studio with C++ tools found. & exit /b 1)
call "%VSDIR%\VC\Auxiliary\Build\vcvars32.bat" >nul 2>nul
cd /d "%~dp0"
if not exist out mkdir out

cl /nologo /LD /O2 /MT /EHsc /W3 /DNDEBUG PolProbe.cpp /Fe:out\PolProbe.dll /Fo:out\PolProbe.obj /link /SUBSYSTEM:WINDOWS
if errorlevel 1 (echo PROBE BUILD FAILED. & exit /b 1)

cl /nologo /O2 /MT /EHsc /W3 /DNDEBUG ..\waitinject.cpp /Fe:out\waitinject.exe /Fo:out\waitinject.obj
if errorlevel 1 (echo waitinject BUILD FAILED. & exit /b 1)

del out\*.obj out\*.exp out\*.lib >nul 2>nul
echo === PROBE BUILD OK ===
dir /b out

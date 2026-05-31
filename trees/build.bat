@echo off

setlocal EnableDelayedExpansion

set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
if not exist %VCVARS% goto :no_vcvars
call %VCVARS% >nul
cd /d "%~dp0"

echo === Compiling version resource ===
rc /nologo /fo Trees.res Trees.rc
if errorlevel 1 goto :trees_fail

echo === Building Trees.new.dll (x86) ===
cl /nologo /LD /O2 /MT /EHsc /W3 /DNDEBUG Trees.cpp Trees.res /Fe:Trees.new.dll /Fo:Trees.obj /link /SUBSYSTEM:WINDOWS
if errorlevel 1 goto :trees_fail

for %%F in (Trees.old*.dll) do del /q "%%F" >nul 2>nul

if not exist Trees.dll goto :promote

set "OLD=Trees.old.dll"
if exist "!OLD!" set "OLD=Trees.old-!RANDOM!.dll"
ren Trees.dll "!OLD!"
if errorlevel 1 goto :sideline_fail

:promote
ren Trees.new.dll Trees.dll
if errorlevel 1 goto :promote_fail
echo Hot-swap OK: Trees.dll updated. Running pol.exes keep their mapping.

echo === Building waitinject.exe (x86, PID-safe auto-capture) ===
cl /nologo /O2 /MT /EHsc /W3 /DNDEBUG waitinject.cpp /Fe:waitinject.exe /Fo:waitinject.obj
if errorlevel 1 goto :wait_fail

del *.obj *.exp *.lib *.res >nul 2>nul
echo === BUILD OK ===
dir /b Trees.dll waitinject.exe
exit /b 0

:no_vcvars
echo ERROR: vcvars32.bat not found.
exit /b 1

:trees_fail
echo Trees BUILD FAILED.
exit /b 1

:wait_fail
echo waitinject.exe BUILD FAILED.
exit /b 1

:sideline_fail
echo *** Could not sideline Trees.dll. Fresh build is at Trees.new.dll. ***
exit /b 2

:promote_fail
echo *** Could not promote Trees.new.dll into Trees.dll. ***
exit /b 2

@echo off
rem Builds and runs the native unit tests (x86, same compiler as build.bat).
rem   run_tests.bat                    synthetic tests only
rem   run_tests.bat <path\appEU.dll>   also checks a real POL UI module

setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSDIR="
if exist "%VSWHERE%" for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%I"
if not defined VSDIR (echo ERROR: no Visual Studio with C++ tools found. & exit /b 1)
call "%VSDIR%\VC\Auxiliary\Build\vcvars32.bat" >nul 2>nul
cd /d "%~dp0"
if not exist out mkdir out

cl /nologo /O2 /MT /EHsc /W3 rtti_test.cpp /Fe:out\rtti_test.exe /Fo:out\rtti_test.obj
if errorlevel 1 (echo TEST BUILD FAILED. & exit /b 1)

out\rtti_test.exe %*

@echo off
REM ============================================================================
REM  Build script for the SAML & OAuth2.0 Auto Tester Burp extension.
REM  Requires only a JDK (no Maven/Gradle). Produces dist\saml-oauth-tester.jar
REM ============================================================================
setlocal

REM --- locate the JDK ---
set "JDK=C:\Program Files\Java\jdk-21"
if not exist "%JDK%\bin\javac.exe" (
  echo [!] JDK not found at "%JDK%". Edit JDK in build.bat to point at your JDK.
  exit /b 1
)

set "ROOT=%~dp0"
set "OUT=%ROOT%build\classes"
set "DIST=%ROOT%dist"
set "API=%ROOT%lib\montoya-api-2026.4.jar"

if not exist "%API%" (
  echo [!] Montoya API jar missing at "%API%".
  exit /b 1
)

echo [*] Cleaning...
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%"
if not exist "%DIST%" mkdir "%DIST%"

echo [*] Collecting sources...
REM The project folder may contain spaces, so each path must be quoted in the javac @argfile.
REM javac argfiles also treat backslash as an escape, so we emit forward slashes (valid on Windows).
dir /s /b "%ROOT%src\main\java\*.java" > "%ROOT%build\sources_raw.txt"
if exist "%ROOT%build\sources.txt" del "%ROOT%build\sources.txt"
setlocal enabledelayedexpansion
for /f "usebackq delims=" %%F in ("%ROOT%build\sources_raw.txt") do (
  set "p=%%F"
  set "p=!p:\=/!"
  echo "!p!">> "%ROOT%build\sources.txt"
)
endlocal

echo [*] Compiling...
"%JDK%\bin\javac.exe" -encoding UTF-8 -cp "%API%" -d "%OUT%" @"%ROOT%build\sources.txt"
if errorlevel 1 (
  echo [!] Compilation failed.
  exit /b 1
)

echo [*] Adding resources...
xcopy /s /e /y /i "%ROOT%src\main\resources\*" "%OUT%" >nul

echo [*] Packaging jar...
"%JDK%\bin\jar.exe" --create --file "%DIST%\saml-oauth-tester.jar" -C "%OUT%" .
if errorlevel 1 (
  echo [!] Packaging failed.
  exit /b 1
)

echo.
echo [+] Build OK  ->  %DIST%\saml-oauth-tester.jar
echo     Load it in Burp: Extensions ^> Installed ^> Add ^> Extension type: Java ^> select the jar.
endlocal

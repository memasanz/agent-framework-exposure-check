@echo off
setlocal DisableDelayedExpansion
title Agent Framework - Quick Exposure Check

echo Agent Framework - Quick Exposure Check
echo.
echo This checks suspicious filenames under your Windows user profile only.
echo It does not scan all drives, run Python, delete files, or upload results.
echo Large profiles can take time. Please leave this window open.
echo.

if not defined USERPROFILE (
    echo ERROR: Your Windows user-profile folder could not be determined.
    pause
    exit /b 1
)

if not exist "%~dp0Test-AgentFrameworkExposure.ps1" (
    echo ERROR: The scanner script is missing.
    echo Extract all files from the ZIP into the same folder, then try again.
    pause
    exit /b 1
)

set "REPORT=%USERPROFILE%\AgentFramework-QuickReport-%RANDOM%-%RANDOM%.json"
set "HTML_REPORT=%REPORT:.json=.html%"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -File "%~dp0Test-AgentFrameworkExposure.ps1" -Mode Quick -Scope UserProfile -ReportPath "%REPORT%"
set "SCAN_EXIT=%ERRORLEVEL%"

echo.
if "%SCAN_EXIT%"=="0" goto reports
if "%SCAN_EXIT%"=="2" (
    echo WARNING: Reports saved, but coverage is incomplete. Ask IT to review access and skipped locations.
    goto reports
)
if "%SCAN_EXIT%"=="3" (
    echo ALERT: Reports saved with indicators. Avoid suspect Python environments and contact IT.
    goto reports
)
if "%SCAN_EXIT%"=="4" (
    echo ALERT: Reports saved with indicators AND incomplete coverage. Contact IT.
    goto reports
)
echo ERROR: The scanner failed. A report pair may be missing or partial.
echo If Windows or your organization blocks the script, contact IT.
echo Do not disable security controls or change execution policy.
goto finish

:reports
echo Open this report in a browser:
echo "%HTML_REPORT%"
echo JSON companion: "%REPORT%"
echo Send both reports to your security or IT contact.
echo A completed scan does NOT establish that the machine is safe.

:finish
echo.
pause
endlocal & exit /b %SCAN_EXIT%

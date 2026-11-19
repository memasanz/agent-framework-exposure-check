@echo off
setlocal DisableDelayedExpansion
title Agent Framework - Full Exposure Check

echo Agent Framework - Full Exposure Check
echo.
echo This performs DEEP checks across ALL accessible local fixed drives.
echo It checks filenames, package metadata, dependency files, and archives.
echo This can take much longer than Quick scanning and may encounter access errors.
echo Obtain authorization before inspecting other users' or system folders.
echo Do NOT run as administrator unless your IT team approves.
echo Python is never started. Files are not deleted and results are not uploaded.
echo Hidden folders and .git are included. Link targets and cloud placeholders are not followed.
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

"%SystemRoot%\System32\choice.exe" /C YN /N /M "Start the full scan? [Y/N]: "
if errorlevel 2 goto cancelled
if errorlevel 1 goto scan
goto cancelled

:scan
set "REPORT=%USERPROFILE%\AgentFramework-FullReport-%RANDOM%-%RANDOM%.json"
set "HTML_REPORT=%REPORT:.json=.html%"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -File "%~dp0Test-AgentFrameworkExposure.ps1" -Mode Deep -Scope FixedDrives -ReportPath "%REPORT%"
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

:cancelled
echo.
echo Cancelled. No scan was started and no report was created.
pause
endlocal & exit /b 0

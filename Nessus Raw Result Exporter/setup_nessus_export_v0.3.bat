@echo off
setlocal EnableExtensions
title Nessus Exporter Setup

echo ============================================================
echo              Nessus Scan Report Exporter Setup
echo ============================================================
echo.
echo This setup will:
echo   1. Check for nessus_export_v0.5.3.ps1 in this folder
echo   2. Save your Nessus API keys as USER environment variables
echo   3. Create the Nessus Exports folder in the current directory
echo   4. Check whether TCP port 8834 is reachable locally
echo.
echo Environment variables created:
echo   NESSUS_ACCESS_KEY
echo   NESSUS_SECRET_KEY
echo.
echo NOTE:
echo   The API keys are stored in your Windows user environment.
echo   They are persistent, but are not a password-vault mechanism.
echo.
pause
echo.

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%nessus_export_v0.5.3.ps1"
set "EXPORT_DIR=%CD%\Nessus Exports"

echo [1/4] Checking PowerShell script...
if exist "%PS_SCRIPT%" (
    echo [OK] Found:
    echo      %PS_SCRIPT%
) else (
    echo [WARNING] nessus_export_v0.5.3.ps1 was not found beside this BAT file.
    echo           You can still configure the API keys now.
    echo           Put both files in the same folder before using the exporter.
)
echo.

echo [2/4] Configuring Nessus API credentials...
echo       Your key entries will be hidden while you type.
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; function Get-PlainText([Security.SecureString]$s){$p=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); try{[Runtime.InteropServices.Marshal]::PtrToStringBSTR($p)} finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p)}}; try{$a=Get-PlainText (Read-Host 'Enter Nessus Access Key' -AsSecureString); $s=Get-PlainText (Read-Host 'Enter Nessus Secret Key' -AsSecureString); if([string]::IsNullOrWhiteSpace($a)){throw 'Access Key cannot be blank.'}; if([string]::IsNullOrWhiteSpace($s)){throw 'Secret Key cannot be blank.'}; [Environment]::SetEnvironmentVariable('NESSUS_ACCESS_KEY',$a,'User'); [Environment]::SetEnvironmentVariable('NESSUS_SECRET_KEY',$s,'User'); if([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('NESSUS_ACCESS_KEY','User')) -or [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('NESSUS_SECRET_KEY','User'))){throw 'Credential environment variables could not be verified.'}; Write-Host '[OK] Nessus API credentials saved for the current Windows user.' -ForegroundColor Green; exit 0}catch{Write-Host ('[ERROR] '+$_.Exception.Message) -ForegroundColor Red; exit 1}"

if errorlevel 1 (
    echo.
    echo Setup stopped because the API credentials could not be saved.
    echo.
    pause
    exit /b 1
)
echo.

echo [3/4] Creating current-directory export folder...
if not exist "%EXPORT_DIR%" mkdir "%EXPORT_DIR%" >nul 2>&1

if exist "%EXPORT_DIR%" (
    echo [OK] %EXPORT_DIR%
) else (
    echo [WARNING] Could not create:
    echo           %EXPORT_DIR%
)
echo.

echo [4/4] Checking local Nessus port 8834...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$r=Test-NetConnection -ComputerName 127.0.0.1 -Port 8834 -WarningAction SilentlyContinue; if($r.TcpTestSucceeded){Write-Host '[OK] Nessus is reachable on https://127.0.0.1:8834' -ForegroundColor Green}else{Write-Host '[WARNING] Port 8834 is not currently reachable.' -ForegroundColor Yellow; Write-Host '          Start Nessus before running the exporter.' -ForegroundColor Yellow}"

echo.
echo ============================================================
echo                       Setup complete
echo ============================================================
echo.
echo IMPORTANT:
echo   Close and reopen PowerShell before running the exporter.
echo   New PowerShell sessions will receive the saved API keys.
echo.
echo OUTPUT LOCATION:
echo   Reports are saved relative to the directory where you run the PS1:
echo     .\Nessus Exports\^<FolderName^>\^<DateRange^>\
echo.
echo Example commands:
echo.
echo   Help:
echo     .\nessus_export_v0.5.3.ps1 -h
echo.
echo   Export all latest/current scans:
echo     .\nessus_export_v0.5.3.ps1 -All
echo.
echo   Export one folder:
echo     .\nessus_export_v0.5.3.ps1 -FolderName "Windows Servers"
echo.
echo   Export initial-assessment history by scan end date:
echo     .\nessus_export_v0.5.3.ps1 -FolderName "Windows Servers" -StartDate "2026-08-01" -EndDate "2026-09-15"
echo.
echo   Export all completed runs up to a cut-off date:
echo     .\nessus_export_v0.5.3.ps1 -FolderName "Windows Servers" -EndDate "2026-09-15"
echo.
pause
endlocal

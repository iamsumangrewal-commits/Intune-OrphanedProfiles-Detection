<#
.SYNOPSIS
    Detects whether the SYSTEM setup for SecurePrint has completed.
.DESCRIPTION
    This script is intended for the Intune Win32 app that runs as SYSTEM.
    It checks whether the logon task and setup marker were created.
#>

$ErrorActionPreference = "Stop"

$MarkerPath = "C:\ProgramData\SecurePrint\SystemSetupComplete.txt"

if (Test-Path -LiteralPath $MarkerPath) {
    Write-Output "SecurePrint SYSTEM setup complete."
    exit 0
}

Write-Output "SecurePrint SYSTEM setup not complete."
exit 1

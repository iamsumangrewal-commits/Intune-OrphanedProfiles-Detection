<#
.SYNOPSIS
    Configures SecurePrint installation for users on an Autopilot device.
.DESCRIPTION
    Run this setup script as SYSTEM from an Intune Win32 app. It copies the
    user-context printer script to ProgramData and creates a scheduled task
    that runs it at logon for each interactive user.

    SYSTEM cannot authenticate to the on-premises print shares on some
    Entra-joined Autopilot devices, so Add-Printer must run as the logged-on
    user. Sign out and sign in after deployment to trigger the task.
#>

$ErrorActionPreference = "Stop"

$TaskName = "Install SecurePrint Printers"
$InstallDirectory = "C:\ProgramData\SecurePrint"
$SourceUserScript = Join-Path $PSScriptRoot "Install-SecurePrint-User.ps1"
$UserScript = Join-Path $InstallDirectory "Install-SecurePrint-User.ps1"
$SystemLog = Join-Path $InstallDirectory "SystemSetup.log"
$Marker = Join-Path $InstallDirectory "SystemSetupComplete.txt"

New-Item -Path $InstallDirectory -ItemType Directory -Force | Out-Null

function Write-SystemLog {
    param([string]$Message)

    Add-Content -Path $SystemLog -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
}

try {
    Write-SystemLog "Starting SecurePrint SYSTEM setup. Identity: $(whoami)"

    if (-not (Test-Path -LiteralPath $SourceUserScript)) {
        throw "User script was not found: $SourceUserScript"
    }

    Copy-Item `
        -LiteralPath $SourceUserScript `
        -Destination $UserScript `
        -Force

    # Ensure standard users can read and execute the copied script.
    $Acl = Get-Acl -Path $UserScript
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Users",
        "ReadAndExecute",
        "Allow"
    )
    $Acl.SetAccessRule($Rule)
    Set-Acl -Path $UserScript -AclObject $Acl

    $Action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$UserScript`""

    $Trigger = New-ScheduledTaskTrigger -AtLogOn

    $Principal = New-ScheduledTaskPrincipal `
        -GroupId "Users" `
        -LogonType InteractiveToken `
        -RunLevel Limited

    $Settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Principal $Principal `
        -Settings $Settings `
        -Description "Installs SecurePrint printers in the logged-on user's context." `
        -Force | Out-Null

    Set-Content `
        -Path $Marker `
        -Value "Configured: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" `
        -Force

    Write-SystemLog "Scheduled task created successfully."
    Write-SystemLog "The user script will run when each user logs on."
    exit 0
}
catch {
    Write-SystemLog "Setup failed: $($_.Exception.Message)"
    exit 1
}

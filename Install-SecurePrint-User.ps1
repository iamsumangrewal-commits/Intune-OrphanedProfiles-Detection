<#
.SYNOPSIS
    Installs the SecurePrint shared printers for the logged-on user.
.DESCRIPTION
    Designed to run in the logged-on user context. The printer shares are
    intentionally installed with Add-Printer rather than PrintUIEntry /ga,
    because Autopilot/Entra-joined devices may not allow the SYSTEM account
    to authenticate to on-premises print servers.
#>

$ErrorActionPreference = "Continue"

$LogDirectory = Join-Path $env:LOCALAPPDATA "SecurePrint"
$LogPath = Join-Path $LogDirectory "Install.log"

$Printers = @(
    "\\p-print1\SecurePrint_PS",
    "\\p-print1\SecurePrint_PCL",
    "\\p-print2\SecurePrint_PS",
    "\\p-print2\SecurePrint_PCL"
)

New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Add-Content -Path $LogPath -Value $Line
    Write-Output $Line
}

Write-Log "Starting SecurePrint installation for user $env:USERNAME."

try {
    $Spooler = Get-Service -Name Spooler -ErrorAction Stop

    if ($Spooler.Status -ne 'Running') {
        Write-Log "Print Spooler is not running. Attempting to start it."
        Start-Service -Name Spooler -ErrorAction Stop
    }
}
catch {
    Write-Log "Could not verify or start the Print Spooler: $($_.Exception.Message)"
}

$InstalledCount = 0
$FailedCount = 0

foreach ($Printer in $Printers) {
    try {
        $ExistingPrinter = Get-Printer -Name $Printer -ErrorAction SilentlyContinue

        if ($null -ne $ExistingPrinter) {
            Write-Log "Already installed: $Printer"
            $InstalledCount++
            continue
        }

        Write-Log "Installing: $Printer"
        Add-Printer -ConnectionName $Printer -ErrorAction Stop

        Start-Sleep -Seconds 2

        if ($null -ne (Get-Printer -Name $Printer -ErrorAction SilentlyContinue)) {
            Write-Log "Successfully installed: $Printer"
            $InstalledCount++
        }
        else {
            Write-Log "Installation could not be verified: $Printer"
            $FailedCount++
        }
    }
    catch {
        Write-Log "Failed to install $Printer: $($_.Exception.Message)"
        $FailedCount++
    }
}

Write-Log "Completed. Installed/already present: $InstalledCount. Failed: $FailedCount."

if ($FailedCount -gt 0) {
    exit 1
}

exit 0

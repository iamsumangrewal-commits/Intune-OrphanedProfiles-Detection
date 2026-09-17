<#
.SYNOPSIS
    Win32 app detection script for SecurePrint shared printers.
.DESCRIPTION
    Runs in the logged-on user context and returns exit code 0 only when all
    four required printer connections are installed for that user.
#>

$ErrorActionPreference = "SilentlyContinue"

$RequiredPrinters = @(
    "\\p-print1\SecurePrint_PS",
    "\\p-print1\SecurePrint_PCL",
    "\\p-print2\SecurePrint_PS",
    "\\p-print2\SecurePrint_PCL"
)

$MissingPrinters = @(
    foreach ($Printer in $RequiredPrinters) {
        $InstalledPrinter = Get-Printer -Name $Printer -ErrorAction SilentlyContinue

        if ($null -eq $InstalledPrinter) {
            $Printer
        }
    }
)

if ($MissingPrinters.Count -eq 0) {
    Write-Output "All SecurePrint printers are installed for $env:USERNAME."
    exit 0
}

Write-Output "Missing SecurePrint printers for $env:USERNAME:"
$MissingPrinters | ForEach-Object { Write-Output "- $_" }
exit 1

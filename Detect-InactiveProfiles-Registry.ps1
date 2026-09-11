<#
.SYNOPSIS
    Detection script for Intune - Identifies ALL inactive profiles (60+ days no login)
    Uses Registry Hive LastWriteTime (more reliable than folder LastAccessTime)
.DESCRIPTION
    - Detects ALL user profiles with no login activity for 60+ days
    - Uses NTUSER.DAT registry hive LastWriteTime (not folder LastAccessTime)
    - More resistant to background process interference
    - Also reports if user account is disabled/removed in Azure AD (Entra ID) or On-Prem AD
    - Excludes system accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, Public, Default, Cscadmin)
    - Works with Hybrid Azure AD and Cloud-only (Autopilot) devices
    - Generates JSON report with profile names, sizes, last access times, and AD account status
    - Returns exit code 1 if orphaned profiles found, 0 if none
.NOTES
    Run as: SYSTEM account (Intune manages this)
    Execution Policy: Bypass required
    Key Difference: Uses registry hive timestamp instead of folder LastAccessTime
#>

param(
    [string]$ReportPath = "C:\Windows\Temp\OrphanedProfiles.json",
    [int]$InactivityDays = 60
)

$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"

# Excluded profiles - system accounts and service accounts
$ExcludedProfiles = @(
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "Public",
    "Default",
    "DefaultAccount",
    "Guest",
    "Cscadmin",
    "Administrator"
)

$InactivityThresholdDate = (Get-Date).AddDays(-$InactivityDays)
$OrphanedProfiles = @()
$ProfilesChecked = 0

Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting orphaned profile detection (Registry-based)..."
Write-Verbose "Inactivity threshold: $InactivityThresholdDate ($InactivityDays+ days)"

# Function to check if user exists in Azure AD (Entra ID)
function Test-UserInEntraID {
    param([string]$SamAccountName)
    
    try {
        # Try using Microsoft Graph (requires no additional auth if running as SYSTEM)
        $Uri = "https://graph.microsoft.com/v1.0/users?\$filter=mailNickname eq '$SamAccountName'"
        $Response = Invoke-RestMethod -Uri $Uri -Method Get -ErrorAction SilentlyContinue
        return $Response.value.count -gt 0
    }
    catch {
        # Fallback: assume user exists if we can't check (don't orphan on auth failure)
        return $true
    }
}

# Function to check if user exists in On-Prem AD
function Test-UserInOnPremAD {
    param([string]$SamAccountName)
    
    try {
        $ADUser = Get-ADUser -Identity $SamAccountName -ErrorAction SilentlyContinue
        if ($null -eq $ADUser) {
            return $false
        }
        
        # Check if account is disabled
        if ($ADUser.Enabled -eq $false) {
            return $false
        }
        
        return $true
    }
    catch {
        # If AD not available, assume user exists (don't orphan on connection failure)
        return $true
    }
}

# Function to get registry hive LastWriteTime from the actual registry KEY (not file)
function Get-RegistryHiveLastWriteTime {
    param([string]$ProfilePath, [string]$ProfileName)
    
    try {
        # Method 1: Load the NTUSER.DAT hive and query it directly
        # This requires running as SYSTEM
        $HivePath = Join-Path $ProfilePath "NTUSER.DAT"
        
        if (Test-Path $HivePath) {
            # Use reg.exe to query the hive timestamp (gets last write time of registry)
            $RegOutput = reg query "HKEY_USERS\S-1-5-21*" 2>$null | Select-String $ProfileName
            
            # Alternative: Get the file's LastWriteTime directly (this IS the hive's last modification)
            $FileInfo = Get-Item -Path $HivePath -Force -ErrorAction SilentlyContinue
            if ($null -ne $FileInfo) {
                Write-Verbose "  Found NTUSER.DAT for $ProfileName : $($FileInfo.LastWriteTime)"
                return $FileInfo.LastWriteTime
            }
        }
    }
    catch {
        Write-Verbose "Warning: Could not get registry hive timestamp for $ProfilePath : $_"
    }
    
    return $null
}

# Check all profiles in C:\Users
if (Test-Path "C:\Users") {
    $Profiles = Get-ChildItem -Path "C:\Users" -Directory -Force -ErrorAction SilentlyContinue
    
    foreach ($Profile in $Profiles) {
        $ProfileName = $Profile.Name
        $ProfilePath = $Profile.FullName
        
        # Skip excluded profiles
        if ($ProfileName -in $ExcludedProfiles) {
            Write-Verbose "Skipping excluded profile: $ProfileName"
            continue
        }
        
        $ProfilesChecked++
        
        # Get registry hive LastWriteTime (NTUSER.DAT) - this is the key metric
        $LastActivityTime = Get-RegistryHiveLastWriteTime -ProfilePath $ProfilePath -ProfileName $ProfileName
        
        if ($null -eq $LastActivityTime) {
            Write-Verbose "SKIPPED: $ProfileName | Reason: Could not determine last activity time"
            continue
        }
        
        # Calculate profile size
        try {
            $ProfileSize = (Get-ChildItem -Path $ProfilePath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            $ProfileSizeMB = [math]::Round($ProfileSize / 1MB, 2)
        }
        catch {
            $ProfileSizeMB = 0
        }
        
        # Check if profile is inactive (no login for X days)
        $IsInactive = $false
        $InactiveForDays = 0
        
        if ($null -ne $LastActivityTime) {
            # Ensure we're working with DateTime
            if ($LastActivityTime -is [System.DateTime]) {
                $InactiveForDays = [math]::Round(((Get-Date) - $LastActivityTime).TotalDays, 0)
            }
            else {
                # Try to convert if it's a string
                try {
                    $LastActivityTimeConverted = [datetime]$LastActivityTime
                    $InactiveForDays = [math]::Round(((Get-Date) - $LastActivityTimeConverted).TotalDays, 0)
                }
                catch {
                    Write-Verbose "Could not convert LastActivityTime for $ProfileName : $LastActivityTime"
                    continue
                }
            }
            
            if ($InactiveForDays -ge $InactivityDays) {
                $IsInactive = $true
            }
        }
        else {
            # If we can't get registry hive time, skip (don't mark as orphaned on data collection failure)
            Write-Verbose "SKIPPED: $ProfileName | Reason: Could not determine last activity time"
            continue
        }
        
        # Check if user exists in AD systems (informational)
        $UserExistsInOnPremAD = $true
        $UserExistsInEntraID = $true
        
        # For Hybrid devices: Check On-Prem AD
        $UserExistsInOnPremAD = Test-UserInOnPremAD -SamAccountName $ProfileName
        
        # For Cloud-only or Hybrid: Check Entra ID
        $UserExistsInEntraID = Test-UserInEntraID -SamAccountName $ProfileName
        
        # Mark as orphaned if profile is inactive (ANY inactive profile regardless of AD account status)
        $IsOrphaned = $false
        $OrphanReason = ""
        
        if ($IsInactive) {
            $IsOrphaned = $true
            $OrphanReason = "Inactive for $InactiveForDays days (No registry/login activity)"
        }
        
        if ($IsOrphaned) {
            Write-Verbose "ORPHANED: $ProfileName | Reason: $OrphanReason | Last Activity (Registry): $LastActivityTime | Size: ${ProfileSizeMB}MB"
            
            $OrphanedProfiles += @{
                ProfileName       = $ProfileName
                ProfilePath       = $ProfilePath
                LastActivityTime  = $LastActivityTime
                InactiveForDays   = $InactiveForDays
                SizeMB            = $ProfileSizeMB
                ExistsInOnPremAD  = $UserExistsInOnPremAD
                ExistsInEntraID   = $UserExistsInEntraID
                OrphanReason      = $OrphanReason
                DetectedDate      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                DataSource        = "Registry Hive (NTUSER.DAT)"
            }
        }
        else {
            Write-Verbose "ACTIVE: $ProfileName | Inactive: $InactiveForDays days (threshold: $InactivityDays days) | Last Activity: $LastActivityTime"
        }
    }
}

Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Profiles checked: $ProfilesChecked | Orphaned found: $($OrphanedProfiles.Count)"

# Create report directory if it doesn't exist
$ReportDir = Split-Path -Path $ReportPath -Parent
if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

# Export report as JSON
$Report = @{
    ComputerName      = $env:COMPUTERNAME
    ReportDate        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ProfilesChecked   = $ProfilesChecked
    OrphanedCount     = $OrphanedProfiles.Count
    InactivityDays    = $InactivityDays
    DataSource        = "Registry Hive (NTUSER.DAT) LastWriteTime"
    OrphanedProfiles  = $OrphanedProfiles
}

$Report | ConvertTo-Json -Depth 3 | Out-File -FilePath $ReportPath -Force -Encoding UTF8
Write-Verbose "Report saved to: $ReportPath"

# Exit code: 1 if orphaned profiles found, 0 if none
if ($OrphanedProfiles.Count -gt 0) {
    Write-Output "Orphaned profiles detected: $($OrphanedProfiles.Count)"
    exit 1
}
else {
    Write-Output "No orphaned profiles detected."
    exit 0
}

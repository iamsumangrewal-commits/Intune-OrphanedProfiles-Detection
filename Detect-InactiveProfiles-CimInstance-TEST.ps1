<#
.SYNOPSIS
    TEST: Detection script using Get-CimInstance (Win32_UserProfile) for comparison
.DESCRIPTION
    - This is a TEST script to compare Get-CimInstance vs Registry Hive approach
    - Uses Win32_UserProfile.LastUseTime instead of NTUSER.DAT LastWriteTime
    - Detects ALL user profiles with no login activity for 60+ days
    - Also reports if user account is disabled/removed in Azure AD (Entra ID) or On-Prem AD
    - Excludes system accounts
    - Generates JSON report for easy comparison with Registry-based version
    - Returns exit code 1 if orphaned profiles found, 0 if none
.NOTES
    Run as: SYSTEM account or Administrator
    Execution Policy: Bypass required
    Purpose: Compare Get-CimInstance accuracy vs Registry Hive method
#>

param(
    [string]$ReportPath = "C:\Windows\Temp\OrphanedProfiles_CIM.json",
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

Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting orphaned profile detection (Get-CimInstance method)..."
Write-Verbose "Inactivity threshold: $InactivityThresholdDate ($InactivityDays+ days)"

# Function to check if user exists in Azure AD (Entra ID)
function Test-UserInEntraID {
    param([string]$SamAccountName)
    
    try {
        $Uri = "https://graph.microsoft.com/v1.0/users?\$filter=mailNickname eq '$SamAccountName'"
        $Response = Invoke-RestMethod -Uri $Uri -Method Get -ErrorAction SilentlyContinue
        return $Response.value.count -gt 0
    }
    catch {
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
        
        if ($ADUser.Enabled -eq $false) {
            return $false
        }
        
        return $true
    }
    catch {
        return $true
    }
}

# Get all user profiles using Get-CimInstance
try {
    $UserProfiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue
    Write-Verbose "Retrieved $($UserProfiles.Count) profiles from WMI"
}
catch {
    Write-Verbose "Error retrieving profiles from WMI: $_"
    Write-Output "Error: Could not retrieve user profiles from WMI"
    exit 1
}

if ($null -eq $UserProfiles) {
    Write-Verbose "No profiles found"
    exit 0
}

# Process each profile
foreach ($Profile in $UserProfiles) {
    $ProfileSID = $Profile.SID
    $ProfilePath = $Profile.LocalPath
    
    # Extract username from path
    if ($ProfilePath) {
        $ProfileName = Split-Path -Leaf $ProfilePath
    }
    else {
        $ProfileName = $ProfileSID
    }
    
    # Skip excluded profiles
    if ($ProfileName -in $ExcludedProfiles) {
        Write-Verbose "Skipping excluded profile: $ProfileName"
        continue
    }
    
    # Skip profiles without valid paths
    if (-not $ProfilePath -or -not (Test-Path $ProfilePath)) {
        Write-Verbose "Skipping profile with invalid path: $ProfileName ($ProfilePath)"
        continue
    }
    
    $ProfilesChecked++
    
    # Get LastUseTime from CIM instance
    $LastUseTime = $Profile.LastUseTime
    
    Write-Verbose "Profile: $ProfileName | Path: $ProfilePath | LastUseTime: $LastUseTime"
    
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
    
    if ($null -ne $LastUseTime) {
        # Convert CIM datetime to PowerShell datetime
        $LastUseTimeConverted = [System.Management.ManagementDateTimeConverter]::ToDateTime($LastUseTime)
        $InactiveForDays = [math]::Round(((Get-Date) - $LastUseTimeConverted).TotalDays, 0)
        
        if ($InactiveForDays -ge $InactivityDays) {
            $IsInactive = $true
        }
        
        Write-Verbose "  Inactive for: $InactiveForDays days (threshold: $InactivityDays)"
    }
    else {
        Write-Verbose "  LastUseTime is NULL - cannot determine activity"
        $LastUseTimeConverted = $null
    }
    
    # Check if user exists in AD systems (informational)
    $UserExistsInOnPremAD = $true
    $UserExistsInEntraID = $true
    
    # Only check AD if we have a valid profile name (not SID)
    if ($ProfileName -ne $ProfileSID) {
        $UserExistsInOnPremAD = Test-UserInOnPremAD -SamAccountName $ProfileName
        $UserExistsInEntraID = Test-UserInEntraID -SamAccountName $ProfileName
    }
    
    # Mark as orphaned if profile is inactive
    $IsOrphaned = $false
    $OrphanReason = ""
    
    if ($IsInactive) {
        $IsOrphaned = $true
        $OrphanReason = "Inactive for $InactiveForDays days (No login activity per WMI)"
    }
    
    if ($IsOrphaned) {
        Write-Verbose "ORPHANED: $ProfileName | Reason: $OrphanReason | Last Use: $LastUseTimeConverted | Size: ${ProfileSizeMB}MB"
        
        $OrphanedProfiles += @{
            ProfileName       = $ProfileName
            ProfileSID        = $ProfileSID
            ProfilePath       = $ProfilePath
            LastUseTime       = $LastUseTimeConverted
            InactiveForDays   = $InactiveForDays
            SizeMB            = $ProfileSizeMB
            ExistsInOnPremAD  = $UserExistsInOnPremAD
            ExistsInEntraID   = $UserExistsInEntraID
            OrphanReason      = $OrphanReason
            DetectedDate      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            DataSource        = "WMI (Win32_UserProfile.LastUseTime)"
            Loaded            = $Profile.Loaded
            RoamingProfile    = $Profile.RoamingProfile
        }
    }
    else {
        Write-Verbose "ACTIVE: $ProfileName | Inactive: $InactiveForDays days (threshold: $InactivityDays)"
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
    DataSource        = "WMI (Win32_UserProfile.LastUseTime)"
    TestMethod        = "Get-CimInstance Comparison"
    OrphanedProfiles  = $OrphanedProfiles
}

$Report | ConvertTo-Json -Depth 3 | Out-File -FilePath $ReportPath -Force -Encoding UTF8
Write-Verbose "Report saved to: $ReportPath"

# Exit code: 1 if orphaned profiles found, 0 if none
if ($OrphanedProfiles.Count -gt 0) {
    Write-Output "Orphaned profiles detected (CIM method): $($OrphanedProfiles.Count)"
    exit 1
}
else {
    Write-Output "No orphaned profiles detected (CIM method)."
    exit 0
}

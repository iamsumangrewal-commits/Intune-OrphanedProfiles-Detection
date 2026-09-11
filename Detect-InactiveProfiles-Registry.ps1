<#
.SYNOPSIS
    Detection script for Intune - Identifies ALL inactive profiles (60+ days no login)
    Uses BOTH WMI (Win32_UserProfile.LastUseTime) AND folder access time for comparison
.DESCRIPTION
    - Detects ALL user profiles with no login activity for 60+ days
    - PRIMARY METHOD: Win32_UserProfile.LastUseTime from WMI (only updates on actual login)
    - COMPARISON METHOD: Folder LastAccessTime (most recent file/folder activity)
    - Marks as orphaned if EITHER:
      * WMI LastUseTime is 60+ days old, OR
      * Folder last access is 60+ days old
    - This dual approach catches profiles that may have stale WMI data
    - Excludes system accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, Public, Default, Cscadmin)
    - Works with Hybrid Azure AD and Cloud-only (Autopilot) devices
    - Generates JSON report with both timestamps for comparison
    - Returns exit code 1 if orphaned profiles found, 0 if none
.NOTES
    Run as: SYSTEM account (Intune manages this)
    Execution Policy: Bypass required
    Methods: WMI LastUseTime + Folder LastAccessTime
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

Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting orphaned profile detection (WMI + Folder Access)..."
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
        return $true  # Assume exists if we can't check
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
        return $true  # Assume exists if AD unavailable
    }
}

# Function to get folder's most recent access time (recursively)
function Get-FolderLastAccessTime {
    param([string]$FolderPath)
    
    try {
        # Get the most recent LastAccessTime from all files in the profile
        $MostRecentTime = (Get-ChildItem -Path $FolderPath -Recurse -Force -ErrorAction SilentlyContinue | 
                           Measure-Object -Property LastAccessTime -Maximum).Maximum
        
        if ($null -eq $MostRecentTime) {
            # If no files, get folder's own LastAccessTime
            $FolderItem = Get-Item -Path $FolderPath -Force -ErrorAction SilentlyContinue
            if ($null -ne $FolderItem) {
                return $FolderItem.LastAccessTime
            }
        }
        
        return $MostRecentTime
    }
    catch {
        Write-Verbose "Warning: Could not get folder access time for $FolderPath : $_"
        return $null
    }
}

# Get all user profiles using WMI
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
        continue
    }
    
    # Skip excluded profiles
    if ($ProfileName -in $ExcludedProfiles) {
        Write-Verbose "Skipping excluded profile: $ProfileName"
        continue
    }
    
    # Skip profiles without valid paths
    if (-not $ProfilePath -or -not (Test-Path $ProfilePath)) {
        Write-Verbose "Skipping profile with invalid path: $ProfileName"
        continue
    }
    
    $ProfilesChecked++
    
    # METHOD 1: Get LastUseTime from WMI (only updates on actual login)
    $WmiLastUseTime = $null
    $WmiInactiveForDays = 0
    $LastUseTime = $Profile.LastUseTime
    
    if ($null -ne $LastUseTime) {
        try {
            $WmiLastUseTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($LastUseTime)
            $WmiInactiveForDays = [math]::Round(((Get-Date) - $WmiLastUseTime).TotalDays, 0)
            Write-Verbose "Profile: $ProfileName | WMI LastUseTime: $WmiLastUseTime (Inactive: $WmiInactiveForDays days)"
        }
        catch {
            Write-Verbose "Warning: Could not convert WMI LastUseTime for $ProfileName"
            $WmiLastUseTime = $null
        }
    }
    else {
        Write-Verbose "Profile: $ProfileName | WMI LastUseTime: NULL"
    }
    
    # METHOD 2: Get folder's most recent access time
    $FolderLastAccessTime = Get-FolderLastAccessTime -FolderPath $ProfilePath
    $FolderInactiveForDays = 0
    
    if ($null -ne $FolderLastAccessTime) {
        $FolderInactiveForDays = [math]::Round(((Get-Date) - $FolderLastAccessTime).TotalDays, 0)
        Write-Verbose "Profile: $ProfileName | Folder LastAccessTime: $FolderLastAccessTime (Inactive: $FolderInactiveForDays days)"
    }
    else {
        Write-Verbose "Profile: $ProfileName | Folder LastAccessTime: NULL"
    }
    
    # Calculate profile size
    try {
        $ProfileSize = (Get-ChildItem -Path $ProfilePath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        $ProfileSizeMB = [math]::Round($ProfileSize / 1MB, 2)
    }
    catch {
        $ProfileSizeMB = 0
    }
    
    # Determine if orphaned: Mark as orphaned if EITHER condition is true
    $IsOrphaned = $false
    $OrphanReason = @()
    $InactiveForDays = 0
    $LastActivityTime = $null
    
    # Check WMI method
    if ($null -ne $WmiLastUseTime -and $WmiInactiveForDays -ge $InactivityDays) {
        $OrphanReason += "WMI: $WmiInactiveForDays days inactive"
        $IsOrphaned = $true
        if ($null -eq $LastActivityTime) { $LastActivityTime = $WmiLastUseTime; $InactiveForDays = $WmiInactiveForDays }
    }
    elseif ($null -ne $WmiLastUseTime) {
        Write-Verbose "Profile: $ProfileName | WMI Active (only $WmiInactiveForDays days)"
    }
    
    # Check Folder method
    if ($null -ne $FolderLastAccessTime -and $FolderInactiveForDays -ge $InactivityDays) {
        $OrphanReason += "Folder: $FolderInactiveForDays days inactive"
        $IsOrphaned = $true
        if ($null -eq $LastActivityTime) { $LastActivityTime = $FolderLastAccessTime; $InactiveForDays = $FolderInactiveForDays }
    }
    elseif ($null -ne $FolderLastAccessTime) {
        Write-Verbose "Profile: $ProfileName | Folder Active (only $FolderInactiveForDays days)"
    }
    
    # If both methods returned nothing, skip
    if ($null -eq $WmiLastUseTime -and $null -eq $FolderLastAccessTime) {
        Write-Verbose "SKIPPED: $ProfileName | Reason: Could not determine activity from either method"
        continue
    }
    
    # Use most recent timestamp if we have both
    if ($null -ne $WmiLastUseTime -and $null -ne $FolderLastAccessTime) {
        if ($WmiLastUseTime -gt $FolderLastAccessTime) {
            $LastActivityTime = $WmiLastUseTime
            $InactiveForDays = $WmiInactiveForDays
        }
        else {
            $LastActivityTime = $FolderLastAccessTime
            $InactiveForDays = $FolderInactiveForDays
        }
    }
    
    # Check if user exists in AD systems
    $UserExistsInOnPremAD = Test-UserInOnPremAD -SamAccountName $ProfileName
    $UserExistsInEntraID = Test-UserInEntraID -SamAccountName $ProfileName
    
    if ($IsOrphaned) {
        $ReasonText = $OrphanReason -join " | "
        Write-Verbose "ORPHANED: $ProfileName | Reason: $ReasonText | Last Activity: $LastActivityTime | Size: ${ProfileSizeMB}MB"
        
        $OrphanedProfiles += @{
            ProfileName         = $ProfileName
            ProfilePath         = $ProfilePath
            ProfileSID          = $ProfileSID
            WmiLastUseTime      = $WmiLastUseTime
            FolderLastAccessTime = $FolderLastAccessTime
            LastActivityTime    = $LastActivityTime
            InactiveForDays     = $InactiveForDays
            WmiInactiveForDays  = $WmiInactiveForDays
            FolderInactiveForDays = $FolderInactiveForDays
            SizeMB              = $ProfileSizeMB
            ExistsInOnPremAD    = $UserExistsInOnPremAD
            ExistsInEntraID     = $UserExistsInEntraID
            OrphanReason        = $ReasonText
            DetectedDate        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            DataSource          = "WMI (LastUseTime) + Folder (LastAccessTime)"
        }
    }
    else {
        Write-Verbose "ACTIVE: $ProfileName | WMI Inactive: $WmiInactiveForDays days | Folder Inactive: $FolderInactiveForDays days | (threshold: $InactivityDays days)"
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
    DataSource        = "WMI (Win32_UserProfile.LastUseTime) + Folder (LastAccessTime)"
    DetectionMethod   = "Dual Method: Orphaned if EITHER WMI OR Folder is 60+ days inactive"
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

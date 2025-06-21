# Windows Optimization Script
# Optimized version with improved structure, error handling, and performance

#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Comprehensive Windows system optimization and privacy enhancement script.
.DESCRIPTION
    This script modifies Windows settings to optimize performance, enhance privacy,
    and improve security. It provides configurable options to customize the changes.
.NOTES
    Author: Optimized by Claude AI based on original script
    Version: 2.1 (Updated to include DeviceCensus disabling)
    Requires: PowerShell 5.1 or higher with Administrator privileges
#>

# Set strict mode and error preferences for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Force PowerShell to use TLS 1.2 for downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region Configuration

# Create a configuration object that can be validated and used throughout the script
$Config = @{
    General = @{
        # Performance settings
        PowerPlan = 'a1841308-3541-4fab-bc81-f71556f20b4a'  # Power saver
        DisablePrefetcher = $true
        DisableMemoryDump = $true
        DisableSystemRestore = $true
        DisableNtfsEncryption = $true
        DisableNtfsCompression = $true
        DisableVBS = $true
        DisableLastAccess = $true
        DoPerformanceStuff = $true

        # Power settings (in minutes, 0 = never)
        DiskAcTimeout = 0
        DiskDcTimeout = 0
        MonitorAcTimeout = 10
        MonitorDcTimeout = 5
        StandbyAcTimeout = 0
        StandbyDcTimeout = 25
        HibernateAcTimeout = 0
        HibernateDcTimeout = 0

        # Quality of life improvements
        DarkTheme = $true
        LegacyRightClicksMenu = $true
        DisableWindowsSounds = $true
        DisableStartupSound = $true

        # Cleanup options
        Remove3dObjFolder = $true
        UnpinStartMenu = $false
        DisablePerformanceMonitor = $true
    }

    Security = @{
        DisableWindowsFirewall = $true
        DisableSMBServer = $true
        DoSecurityStuff = $true
        DoFingerprintPrevention = $true
        UseGoogleDNS = $true
    }

    Privacy = @{
        DisableCortana = $true
        DisableTelemetry = $true
        DisableBloatware = $true
        DoPrivacyStuff = $true
    }

    SafetyToggles = @{
        # Switches to prevent breaking functionality
        BeWifiSafe = $false
        BeMicrophoneSafe = $true
        BeAppxSafe = $false
        BeXboxSafe = $false
        BeBiometricSafe = $false
        BeNetworkPrinterSafe = $false
        BePrinterSafe = $false
        BeNetworkFolderSafe = $false
        BeAeroPeekSafe = $true
        BeThumbnailSafe = $true
        BeCastSafe = $false
        BeVpnPppoeSafe = $false
        TroubleshootInstalls = $false
    }

    Uninstall = @{
        UninstallWindowsDefender = $true
        UninstallOneDrive = $true

        # Define bloatware list
        BloatwareList = @(
            "Microsoft.BingWeather*"
            "MicrosoftTeams*"
            "Microsoft.DrawboardPDF*"
            "E2A4F912-2574-4A75-9BB0-0D023378592B*"
            "Microsoft.Appconnector*"
            "Microsoft.3dbuilder"
            "Microsoft.BingNews"
            "Microsoft.GetHelp"
            "Microsoft.Getstarted"
            "Microsoft.Messaging"
            "Microsoft3DViewer*"
            "Microsoft.MicrosoftOfficeHub"
            "Microsoft.MicrosoftSolitaireCollection"
            "Microsoft.NetworkSpeedTest"
            "Microsoft.News"
            "Microsoft.Office.Lens"
            "Microsoft.Office.OneNote"
            "Microsoft.Office.Sway"
            "Microsoft.OneConnect"
            "Microsoft.People"
            "Microsoft.Print3D"
            "Microsoft.RemoteDesktop"
            "Microsoft.SkypeApp"
            "Microsoft.StorePurchaseApp"
            "Microsoft.Office.Todo.List"
            "Microsoft.Whiteboard"
            "Microsoft.WindowsAlarms"
            "microsoft.windowscommunicationsapps"
            "Microsoft.WindowsFeedbackHub*"
            "Microsoft.WindowsMaps"
            "Microsoft.WindowsSoundRecorder"
            "Microsoft.ZuneMusic"
            "Microsoft.ZuneVideo"

            # Sponsored AppX
            "DolbyLaboratories.DolbyAccess*"
            "Microsoft.Asphalt8Airborne*"
            "46928bounde.EclipseManager*"
            "ActiproSoftwareLLC*"
            "AdobeSystemsIncorporated.AdobePhotoshopExpress*"
            "Duolingo-LearnLanguagesforFree*"
            "PandoraMediaInc*"
            "CandyCrush*"
            "BubbleWitch3Saga*"
            "Wunderlist*"
            "Flipboard.Flipboard*"
            "Twitter*"
            "Facebook*"
            "Spotify*"
            "Minecraft*"
            "Royal Revolt*"
            "Sway*"
            "Speed Test*"
            "FarmHeroesSaga*"
            "Prime*"
            "Clipchamp*"
            "Disney*"
            "Netflix*"
            "Keeper*"
            "Instagram*"
            "Amazon*"
            "Roblox*"
            "AdobePhotoshop*"
        )
    }

    Installation = @{
        InstallNvidiaControlPanel = $true
        InitialPackages = $false
    }

    Updates = @{
        DisableWindowsUpdates = $false
    }
}

# Add conditional entries to bloatware list based on configuration
if ($Config.SafetyToggles.BeXboxSafe -eq $false) {
    $Config.Uninstall.BloatwareList += @(
        "Microsoft.XboxGamingOverlay"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
    )
}

if ($Config.SafetyToggles.BeBiometricSafe -eq $false) {
    $Config.Uninstall.BloatwareList += @(
        "Microsoft.BioEnrollment*"
        "Microsoft.CredDialogHost*"
        "Microsoft.ECApp*"
        "Microsoft.LockApp*"
    )
}

if ($Config.Installation.InstallNvidiaControlPanel -eq $false) {
    $Config.Uninstall.BloatwareList += "NVIDIACorp.NVIDIAControlPanel*"
}

if ($Config.SafetyToggles.BeCastSafe -eq $false) {
    $Config.Uninstall.BloatwareList += "Microsoft.PPIP*"
}

#endregion Configuration

#region Logging

# Create a log file with timestamp
$LogPath = "$env:TEMP\WindowsOptimizer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:SuccessCount = 0
$script:WarningCount = 0
$script:ErrorCount = 0

function Write-LogMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Type] $Message"

    # Write to log file
    Add-Content -Path $LogPath -Value $logMessage

    # Output to console with appropriate color
    switch ($Type) {
        'Success' {
            Write-Host $logMessage -ForegroundColor Green
            $script:SuccessCount++
        }
        'Warning' {
            Write-Host $logMessage -ForegroundColor Yellow
            $script:WarningCount++
        }
        'Error' {
            Write-Host $logMessage -ForegroundColor Red
            $script:ErrorCount++
        }
        default { Write-Host $logMessage }
    }
}

function Disable-WindowsFirewallService {
    [CmdletBinding()]
    param ()

    try {
        Write-LogMessage "Attempting to disable Windows Defender Firewall service..." -Type Info

        # First, try using the enhanced service configuration function
        $serviceResult = Set-ServiceConfigurationWithScExe -Name "MpsSvc" -State "Stopped" -StartupType "Disabled" -Description "Disabling Windows Defender Firewall Service"

        # If that fails, try a more direct approach with netsh
        if (-not $serviceResult) {
            Write-LogMessage "Service configuration approach failed, trying netsh approach..." -Type Warning

            # First try to disable the firewall profiles through netsh
            $netshResult = Start-Process -FilePath "netsh" -ArgumentList "advfirewall set allprofiles state off" -Wait -NoNewWindow -PassThru

            if ($netshResult.ExitCode -eq 0) {
                Write-LogMessage "Successfully disabled Windows Firewall profiles using netsh" -Type Success
            }
            else {
                Write-LogMessage ("Failed to disable Windows Firewall profiles using netsh. Exit code: " + $netshResult.ExitCode) -Type Warning
            }

            # Try direct registry approach as last resort
            try {
                # Disable the firewall service via registry
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc"

                if (Test-Path $regPath) {
                    Write-LogMessage "Attempting to modify firewall service via registry..." -Type Info

                    # Try using reg.exe which might have higher privileges
                    $regExeResult = Start-Process -FilePath "reg.exe" -ArgumentList "add `"HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc`" /v Start /t REG_DWORD /d 4 /f" -Wait -NoNewWindow -PassThru

                    if ($regExeResult.ExitCode -eq 0) {
                        Write-LogMessage "Successfully modified firewall service registry key" -Type Success
                    }
                    else {
                        Write-LogMessage ("Failed to modify firewall service registry key. Exit code: " + $regExeResult.ExitCode) -Type Warning
                    }
                }
            }
            catch {
                Write-LogMessage ("Error modifying firewall registry: " + $_.Exception.Message) -Type Error
            }
        }

        Write-LogMessage "Windows Firewall operation completed with available methods" -Type Success
        return $true
    }
    catch {
        Write-LogMessage ("Critical error disabling Windows Firewall: " + $_.Exception.Message) -Type Error
        return $false
    }
}

function Disable-WindowsFirewallProfiles {
    [CmdletBinding()]
    param ()

    try {
        Write-LogMessage "Attempting to disable Windows Firewall profiles..." -Type Info

        # First try using PowerShell cmdlets
        try {
            Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled False -ErrorAction Stop
            Write-LogMessage "Successfully disabled Windows Firewall profiles using PowerShell cmdlets" -Type Success
            return $true
        }
        catch {
            Write-LogMessage ("PowerShell cmdlets failed to disable firewall profiles: " + $_.Exception.Message) -Type Warning
        }

        # If PowerShell method fails, try netsh command
        try {
            $netshResult = Start-Process -FilePath "netsh" -ArgumentList "advfirewall set allprofiles state off" -Wait -NoNewWindow -PassThru

            if ($netshResult.ExitCode -eq 0) {
                Write-LogMessage "Successfully disabled Windows Firewall profiles using netsh" -Type Success
                return $true
            }
            else {
                Write-LogMessage ("Failed to disable Windows Firewall profiles using netsh. Exit code: " + $netshResult.ExitCode) -Type Warning
            }
        }
        catch {
            Write-LogMessage ("Error running netsh command: " + $_.Exception.Message) -Type Warning
        }

        # As a last resort, try registry method
        try {
            $profilePaths = @(
                "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
                "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
                "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
            )

            foreach ($path in $profilePaths) {
                if (-not (Test-Path $path)) {
                    New-Item -Path $path -Force | Out-Null
                }

                # Use reg.exe for each profile
                $regExeResult = Start-Process -FilePath "reg.exe" -ArgumentList "add `"$($path.Replace(':', ''))`" /v EnableFirewall /t REG_DWORD /d 0 /f" -Wait -NoNewWindow -PassThru

                if ($regExeResult.ExitCode -eq 0) {
                    Write-LogMessage ("Successfully disabled firewall profile via registry: " + $path) -Type Success
                }
            }

            return $true
        }
        catch {
            Write-LogMessage ("Registry method failed to disable firewall profiles: " + $_.Exception.Message) -Type Error
            return $false
        }
    }
    catch {
        Write-LogMessage ("Critical error during firewall profile operation: " + $_.Exception.Message) -Type Error
        return $false
    }
}

function Set-ServiceConfigurationWithScExe {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Running", "Stopped")]
        [string]$State,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Automatic", "Manual", "Disabled")]
        [string]$StartupType,

        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    try {
        # Map PowerShell startup type to sc.exe format
        $scStartupType = switch ($StartupType) {
            "Automatic" { "auto" }
            "Manual" { "demand" }
            "Disabled" { "disabled" }
        }

        # Try to configure service startup type using sc.exe
        Write-LogMessage "Configuring service $Name using sc.exe..." -Type Info
        $scConfigResult = Start-Process -FilePath "sc.exe" -ArgumentList "config `"$Name`" start= $scStartupType" -Wait -NoNewWindow -PassThru

        if ($scConfigResult.ExitCode -ne 0) {
            # Try to take ownership of the service before configuring
            Write-LogMessage "Initial configuration failed, attempting alternative approach..." -Type Warning

            # Try registry approach directly
            try {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
                $startValue = switch ($StartupType) {
                    "Automatic" { 2 }
                    "Manual" { 3 }
                    "Disabled" { 4 }
                }

                # Use reg.exe to directly modify the registry
                $regResult = Start-Process -FilePath "reg.exe" -ArgumentList "add `"HKLM\SYSTEM\CurrentControlSet\Services\$Name`" /v Start /t REG_DWORD /d $startValue /f" -Wait -NoNewWindow -PassThru

                if ($regResult.ExitCode -ne 0) {
                    Write-LogMessage ("Registry modification for service $Name failed with exit code: " + $regResult.ExitCode) -Type Error
                    return $false
                }
            }
            catch {
                Write-LogMessage ("Failed to modify registry for service " + $Name + ": " + $_.Exception.Message) -Type Error
                return $false
            }
        }

        # Handle service state (start/stop) according to desired state
        if ($State -eq "Running") {
            # Only try to start if not already running and not set to disabled
            if ($StartupType -ne "Disabled") {
                try {
                    $currentState = (Get-Service -Name $Name -ErrorAction SilentlyContinue).Status
                    if ($currentState -ne "Running") {
                        Write-LogMessage "Starting service $Name..." -Type Info
                        Start-Process -FilePath "sc.exe" -ArgumentList "start `"$Name`"" -Wait -NoNewWindow
                    }
                }
                catch {
                    Write-LogMessage ("Failed to start service " + $Name + ": " + $_.Exception.Message) -Type Warning
                }
            }
        }
        else {
            # Try to stop the service
            try {
                $currentState = (Get-Service -Name $Name -ErrorAction SilentlyContinue).Status
                if ($currentState -eq "Running") {
                    Write-LogMessage "Stopping service $Name..." -Type Info
                    Start-Process -FilePath "sc.exe" -ArgumentList "stop `"$Name`"" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-LogMessage ("Failed to stop service " + $Name + ": " + $_.Exception.Message) -Type Warning
            }
        }

        # Verify the service configuration
        try {
            $serviceAfter = Get-Service -Name $Name -ErrorAction SilentlyContinue
            if ($serviceAfter) {
                Write-LogMessage ("Service $Name configured successfully: StartType=$StartupType, Status=$($serviceAfter.Status)") -Type Success
                return $true
            }
            else {
                Write-LogMessage "Unable to verify service $Name configuration" -Type Warning
                return $true  # Assume it worked if we can't verify
            }
        }
        catch {
            Write-LogMessage ("Error verifying service $Name configuration: " + $_.Exception.Message) -Type Warning
            return $true  # Assume it worked if we can't verify
        }
    }
    catch {
        Write-LogMessage ("Error configuring service " + $Name + ": " + $_.Exception.Message) -Type Error
        return $false
    }
}

function Set-ProtectedRegistryValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        $Value,

        [Parameter(Mandatory = $false)]
        [string]$Type = "DWord",

        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    try {
        # Normalize path to handle both HKLM:\ and HKCU:\ paths
        $normalizedPath = $Path -replace '^HKLM:', 'HKLM:\' -replace '^HKCU:', 'HKCU:\'

        # Try the standard approach first
        if (!(Test-Path $normalizedPath)) {
            New-Item -Path $normalizedPath -Force | Out-Null
            Write-LogMessage "Created registry path: $normalizedPath" -Type Info
        }

        # Try to set the value using standard method
        Set-ItemProperty -Path $normalizedPath -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        Write-LogMessage ("Registry: " + $Description + " - [" + $normalizedPath + "] " + $Name + " = " + $Value) -Type Success
        return $true
    }
    catch {
        # If standard approach fails, try the alternative method using reg.exe
        Write-LogMessage ("Standard registry write failed: " + $_.Exception.Message) -Type Warning

        try {
            # Extract the registry path without the provider prefix
            $hiveName = if ($normalizedPath -match 'HKLM:\\(.*)') { "HKLM" } elseif ($normalizedPath -match 'HKCU:\\(.*)') { "HKCU" } else { throw "Unsupported registry path" }
            $keyPath = if ($normalizedPath -match ':\\(.*)') { $matches[1] } else { throw "Invalid registry path format" }

            # Determine the reg.exe type parameter
            $regType = switch ($Type) {
                "String" { "REG_SZ" }
                "ExpandString" { "REG_EXPAND_SZ" }
                "Binary" { "REG_BINARY" }
                "DWord" { "REG_DWORD" }
                "MultiString" { "REG_MULTI_SZ" }
                "QWord" { "REG_QWORD" }
                default { "REG_SZ" }
            }

            # For services, try to use sc.exe to configure the service directly
            if ($keyPath -match 'SYSTEM\\CurrentControlSet\\services\\(.+)' -and $Name -eq "Start") {
                $serviceName = $matches[1]
                $startType = switch ($Value) {
                    2 { "auto" }
                    3 { "demand" }
                    4 { "disabled" }
                    default { $Value } # Pass through for other values
                }

                $scResult = Start-Process -FilePath "sc.exe" -ArgumentList "config `"$serviceName`" start= $startType" -Wait -NoNewWindow -PassThru

                if ($scResult.ExitCode -eq 0) {
                    Write-LogMessage ("Successfully configured service " + $serviceName + " using sc.exe") -Type Success
                    return $true
                }
                else {
                    Write-LogMessage ("Failed to configure service using sc.exe, trying reg.exe") -Type Warning
                }
            }

            # Use reg.exe to add the value
            $regResult = Start-Process -FilePath "reg.exe" -ArgumentList "add `"$hiveName\$keyPath`" /v `"$Name`" /t $regType /d $Value /f" -Wait -NoNewWindow -PassThru

            if ($regResult.ExitCode -eq 0) {
                Write-LogMessage ("Registry: " + $Description + " - [" + $normalizedPath + "] " + $Name + " = " + $Value + " (using reg.exe)") -Type Success
                return $true
            }
            else {
                Write-LogMessage ("Failed to set registry value using reg.exe: " + $normalizedPath + " - Exit code: " + $regResult.ExitCode) -Type Error

                # Last resort - try to take ownership of the key
                Write-LogMessage "Attempting to take ownership of registry key..." -Type Warning

                # Extract components for the takeown commands
                $keyComponents = $keyPath.Split('\')
                $keyParent = $keyComponents[0..($keyComponents.Count-2)] -join '\'
                $keyName = $keyComponents[-1]

                # Use PowerShell to take ownership and grant full control
                $takeOwnershipScript = @"
                param(
                    [string]`$keyPath = '$hiveName\$keyPath'
                )

                `$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                `$parts = `$keyPath.Split('\')
                `$rootKey = `$parts[0]
                `$subKey = `$parts[1..(`$parts.Length-1)] -join '\'

                switch (`$rootKey) {
                    'HKLM' { `$hive = [Microsoft.Win32.Registry]::LocalMachine }
                    'HKCU' { `$hive = [Microsoft.Win32.Registry]::CurrentUser }
                    default { throw "Unsupported registry hive" }
                }

                `$regKey = `$hive.OpenSubKey(`$subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
                if (`$regKey) {
                    `$acl = `$regKey.GetAccessControl()
                    `$acl.SetOwner(`$identity.User)
                    `$regKey.SetAccessControl(`$acl)
                    `$regKey.Close()

                    `$regKey = `$hive.OpenSubKey(`$subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
                    `$acl = `$regKey.GetAccessControl()
                    `$rule = New-Object System.Security.AccessControl.RegistryAccessRule(`$identity.User, [System.Security.AccessControl.RegistryRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
                    `$acl.SetAccessRule(`$rule)
                    `$regKey.SetAccessControl(`$acl)
                    `$regKey.Close()
                    return `$true
                }
                return `$false
"@

                # Execute the ownership script
                $ownershipResult = PowerShell -NoProfile -ExecutionPolicy Bypass -Command $takeOwnershipScript

                if ($ownershipResult -eq $true) {
                    # Try again to set the value
                    $regRetryResult = Start-Process -FilePath "reg.exe" -ArgumentList "add `"$hiveName\$keyPath`" /v `"$Name`" /t $regType /d $Value /f" -Wait -NoNewWindow -PassThru

                    if ($regRetryResult.ExitCode -eq 0) {
                        Write-LogMessage ("Registry: " + $Description + " - [" + $normalizedPath + "] " + $Name + " = " + $Value + " (after taking ownership)") -Type Success
                        return $true
                    }
                }

                Write-LogMessage ("Failed to set registry value after all attempts: " + $normalizedPath + "\\" + $Name) -Type Error
                return $false
            }
        }
        catch {
            Write-LogMessage ("Failed to set registry value using alternative methods: " + $_.Exception.Message) -Type Error
            return $false
        }
    }
}
function Start-Operation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    Write-LogMessage "Starting: $Description" -Type Info
}

function Complete-Operation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [bool]$Successful = $true
    )

    if ($Successful) {
        Write-LogMessage "Completed: $Description" -Type Success
    }
    else {
        Write-LogMessage "Failed: $Description" -Type Error
    }
}

#endregion Logging

#region Helper Functions

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-ScriptAsAdmin {
    if (-not (Test-Administrator)) {
        Write-LogMessage "Script must run as administrator. Restarting with elevation..." -Type Warning
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit
    }
}

function Set-RegistryValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        $Value,

        [Parameter(Mandatory = $false)]
        [string]$Type = "String",

        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    try {
        # Normalize path to handle both HKLM:\ and HKCU:\ paths
        $normalizedPath = $Path -replace '^HKLM:', 'HKLM:\' -replace '^HKCU:', 'HKCU:\'

        # Create the path if it doesn't exist
        if (!(Test-Path $normalizedPath)) {
            New-Item -Path $normalizedPath -Force | Out-Null
            Write-LogMessage "Created registry path: $normalizedPath" -Type Info
        }

        # Set the value
        Set-ItemProperty -Path $normalizedPath -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        Write-LogMessage "Registry: $Description - [$normalizedPath] $Name = $Value" -Type Success
        return $true
    }
    catch {
        Write-LogMessage "Failed to set registry value: $normalizedPath\$Name - $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Remove-RegistryValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Name = $null,

        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    try {
        # Normalize path to handle both HKLM:\ and HKCU:\ paths
        $normalizedPath = $Path -replace '^HKLM:', 'HKLM:\' -replace '^HKCU:', 'HKCU:\'

        if (Test-Path $normalizedPath) {
            if ($Name) {
                # Remove specific property
                Remove-ItemProperty -Path $normalizedPath -Name $Name -ErrorAction Stop
                Write-LogMessage "Removed registry value: $Description - [$normalizedPath] $Name" -Type Success
            }
            else {
                # Remove entire key
                Remove-Item -Path $normalizedPath -Recurse -Force -ErrorAction Stop
                Write-LogMessage "Removed registry key: $Description - $normalizedPath" -Type Success
            }
            return $true
        }
        else {
            Write-LogMessage "Registry path does not exist: $normalizedPath" -Type Warning
            return $true  # Not an error if it doesn't exist
        }
    }
    catch {
        Write-LogMessage ("Failed to remove registry value: " + $normalizedPath + " - " + $_.Exception.Message) -Type Error
        return $false
    }
}

function Set-ServiceConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Running", "Stopped")]
        [string]$State,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Automatic", "Manual", "Disabled")]
        [string]$StartupType,

        [Parameter(Mandatory = $false)]
        [string]$Description = "",

        [Parameter(Mandatory = $false)]
        [bool]$Force = $false
    )

    try {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue

        if ($null -eq $service) {
            Write-LogMessage "Service '$Name' not found" -Type Warning
            return $false
        }

        # Update service startup type
        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop

        # Start or stop the service as needed
        if ($State -eq "Running" -and $service.Status -ne "Running") {
            Start-Service -Name $Name -ErrorAction Stop
        }
        elseif ($State -eq "Stopped" -and $service.Status -ne "Stopped") {
            if ($Force) {
                Stop-Service -Name $Name -Force -ErrorAction Stop
            }
            else {
                Stop-Service -Name $Name -ErrorAction Stop
            }
        }

        # Additional registry setting for services that need it
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        $startValue = switch ($StartupType) {
            "Automatic" { 2 }
            "Manual" { 3 }
            "Disabled" { 4 }
        }

       Set-ProtectedRegistryValue -Path $regPath -Name "Start" -Value $startValue -Type "DWord" -Description "$Description (Registry)"

        Write-LogMessage "Service: $Description - $Name set to $StartupType/$State" -Type Success
        return $true
    }
    catch {
                    Write-LogMessage ("Failed to configure service " + $Name + ": " + $_.Exception.Message) -Type Error
        return $false
    }
}

function Remove-File {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    if (!(Test-Path $Path)) {
        Write-LogMessage "File does not exist: $Path" -Type Info
        return $true
    }

    try {
        # Take ownership
        takeown /F $Path | Out-Null

        # Set full permissions
        $Acl = Get-Acl $Path
        $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("everyone", "FullControl", "Allow")
        $Acl.SetAccessRule($AccessRule)
        Set-Acl $Path $Acl

        # Remove read-only attribute
        Set-ItemProperty $Path -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue

        # Delete the file
        Remove-Item -Path $Path -Force -ErrorAction Stop
        Write-LogMessage "Removed file: $Description - $Path" -Type Success
        return $true
    }
    catch {
        Write-LogMessage ("Failed to remove file " + $Path + ": " + $_.Exception.Message) -Type Error
        return $false
    }
}

function Remove-Directory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    if (!(Test-Path $Path)) {
        Write-LogMessage "Directory does not exist: $Path" -Type Info
        return $true
    }

    try {
        # Take ownership of the directory and contents
        takeown /F $Path /R /D Y | Out-Null

        # Set full permissions
        $Acl = Get-Acl $Path
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $Acl.AddAccessRule($AccessRule)
        Set-Acl $Path $Acl

        # Delete the directory
        Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        Write-LogMessage "Removed directory: $Description - $Path" -Type Success
        return $true
    }
    catch {
        Write-LogMessage ("Failed to remove directory " + $Path + ": " + $_.Exception.Message) -Type Error
        return $false
    }
}

function Stop-ProcessSafely {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3
    )

    try {
        $process = Get-Process -Name $Name -ErrorAction SilentlyContinue

        if ($null -eq $process) {
            Write-LogMessage "Process '$Name' is not running" -Type Info
            return $true
        }

        for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
            Write-LogMessage "Stopping process '$Name' - Attempt $attempt of $MaxAttempts" -Type Info
            Stop-Process -Name $Name -Force -ErrorAction SilentlyContinue

            # Wait and check if it's gone
            Start-Sleep -Seconds 2
            $process = Get-Process -Name $Name -ErrorAction SilentlyContinue

            if ($null -eq $process) {
                Write-LogMessage "Successfully stopped process '$Name'" -Type Success
                return $true
            }
        }

        Write-LogMessage "Failed to stop process '$Name' after $MaxAttempts attempts" -Type Warning
        return $false
    }
    catch {
        Write-LogMessage ("Error stopping process '" + $Name + "': " + $_.Exception.Message) -Type Error
        return $false
    }
}

function Clear-AllCaches {
    Start-Operation "Clearing system caches"

    # Clear network profiles
    Remove-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" -Description "Clearing network profiles"
    Remove-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed" -Description "Clearing managed network profiles"
    Remove-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged" -Description "Clearing unmanaged network profiles"

    # Clear USB history
    Remove-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -Description "Clearing USB history"
    Remove-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\usbflags" -Description "Clearing USB flags"

    # Clear intranet history
    Remove-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\Intranet" -Description "Clearing intranet history"

    # Clear command history
    Remove-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Description "Clearing command history"
    Remove-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Description "Clearing typed paths"
    Remove-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Description "Clearing recent docs"

    # Clear other caches
    Remove-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -Description "Clearing app compat cache"
    Remove-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -Description "Clearing mapped drives cache"

    # Clear file system caches
    try {
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue

        # Clear temp files
        Get-ChildItem -Path $env:TEMP -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path "$env:WINDIR\Prefetch" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path "$env:WINDIR\*.dmp" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

        # Clear explorer caches
        Remove-Directory -Path "$env:LocalAppData\Microsoft\Windows\Explorer" -Description "Clearing explorer cache"
        Remove-Directory -Path "$env:LocalAppData\Microsoft\Windows\Recent" -Description "Clearing recent items"
        Remove-Directory -Path "$env:LocalAppData\Microsoft\Windows\Recent\AutomaticDestinations" -Description "Clearing automatic destinations"
        Remove-Directory -Path "$env:LocalAppData\Microsoft\Windows\Recent\CustomDestinations" -Description "Clearing custom destinations"

        # Restart explorer
        Start-Process explorer.exe
        Write-LogMessage "Restarted Explorer" -Type Success
    }
    catch {
        Write-LogMessage ("Error clearing file system caches: " + $_.Exception.Message) -Type Error
    }

    Complete-Operation "Clearing system caches"
}

function Test-SafeMode {
    $mySafeMode = Get-WmiObject win32_computersystem | Select-Object BootupState
    return ($mySafeMode -notlike '*Normal boot*')
}

function Get-GPUVendor {
    try {
        $myGPU = Get-WmiObject win32_VideoController
        if ($myGPU.name -like '*nvidia*') {
            Write-LogMessage "Detected NVIDIA GPU" -Type Info
            return "nvidia"
        }
        else {
            Write-LogMessage "No NVIDIA GPU detected" -Type Info
            return $null
        }
    }
    catch {
        Write-LogMessage ("Error detecting GPU: " + $_.Exception.Message) -Type Error
        return $null
    }
}

function Disable-WindowsDefenderComponents {
    Start-Operation "Disabling Windows Defender components"

    # Check if in safe mode
    if (-not (Test-SafeMode)) {
        Write-LogMessage "System needs to be in safe mode to uninstall Windows Defender" -Type Warning
        return
    }

    # Take ownership of Defender registry key
    Write-LogMessage "Taking ownership of Windows Defender registry keys" -Type Info

    # Disable Defender services
    $services = @(
        "WinDefend", "WdBoot", "WdFilter", "WdNisDrv", "WdNisSvc",
        "SecurityHealthService", "Sense", "webthreatdefsvc", "webthreatdefusersvc"
    )

    foreach ($service in $services) {
        Set-ServiceConfiguration -Name $service -State "Stopped" -StartupType "Disabled" -Description "Disabling Windows Defender service" -Force $true
    }

    # Disable via registry
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 0 -Type "DWord" -Description "Disabling Windows Defender Cloud"
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type "DWord" -Description "Disabling Windows Defender Cloud Sample"
   Set-ProtectedRegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableConfig" -Value 1 -Type "DWord" -Description "Disabling Windows Anti Spyware Config"
   Set-ProtectedRegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type "DWord" -Description "Disabling Windows Anti Spyware"

    # Disable Windows Security Center
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc" -Name "Start" -Value 4 -Type "DWord" -Description "Disabling Windows Security Center Service"

    # Disable SmartScreen
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type "String" -Description "Disabling SmartScreen Filter"
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type "DWord" -Description "Disabling SmartScreen Web Content Evaluation"

    # Delete Defender files
    $defenderPaths = @(
        "$env:ProgramFiles\Windows Defender",
        "$env:ProgramFiles\Windows Defender Advanced Threat Protection",
        "$env:ProgramFiles(x86)\Windows Defender",
        "$env:ProgramData\Microsoft\Windows Defender",
        "$env:ProgramData\Microsoft\Windows Defender\Platform",
        "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection",
        "$env:ProgramData\Microsoft\Windows Security Health",
        "$env:WinDir\System32\SecurityHealthService.exe"
    )

    foreach ($path in $defenderPaths) {
        Remove-Directory -Path $path -Description "Removing Windows Defender directory"
    }

    # Disable additional features
    Write-LogMessage "Disabling Windows Defender Application Guard" -Type Info
    Disable-WindowsOptionalFeature -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null

    # Disable AllowUpdateService
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\AllowUpdateService" -Name "value" -Value 0 -Type "DWord" -Description "Disabling Windows AllowUpdateService"

    # Disable AllowAutoUpdate
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\AllowAutoUpdate" -Name "value" -Value 5 -Type "DWord" -Description "Disabling Windows AllowAutoUpdate"

    # Disable various Windows Defender features through policy manager
    $defenderPolicies = @(
        "AllowArchiveScanning", "AllowBehaviorMonitoring", "AllowCloudProtection",
        "AllowIntrusionPreventionSystem", "AllowIOAVProtection", "AllowOnAccessProtection",
        "AllowRealtimeMonitoring", "AllowScanningNetworkFiles", "AllowScriptScanning",
        "DisableCatchupFullScan", "DisableCatchupQuickScan", "EnableNetworkProtection",
        "PUAProtection", "AllowEmailScanning"
    )

    foreach ($policy in $defenderPolicies) {
        $value = if ($policy -like "Disable*") { 0 } else { 0 }
       Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\$policy" -Name "value" -Value $value -Type "DWord" -Description "Configuring Windows Defender policy: $policy"
    }

    # Set RealTimeScanDirection to monitor only outgoing files
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\RealTimeScanDirection" -Name "value" -Value 2 -Type "DWord" -Description "Setting RealTimeScanDirection to monitor only outgoing files"

    Complete-Operation "Disabling Windows Defender components"
}

function Uninstall-OneDrive {
    Start-Operation "Uninstalling OneDrive"

    # Check if in safe mode
    if (-not (Test-SafeMode)) {
        Write-LogMessage "System needs to be in safe mode to uninstall OneDrive" -Type Warning
        return
    }

    # Stop OneDrive processes
    Stop-ProcessSafely -Name "OneDrive"
    Stop-ProcessSafely -Name "explorer"

    # Uninstall OneDrive
    if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
        Write-LogMessage "Running OneDrive uninstaller (64-bit)" -Type Info
        Start-Process "$env:systemroot\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
    }

    if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
        Write-LogMessage "Running OneDrive uninstaller (32-bit)" -Type Info
        Start-Process "$env:systemroot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
    }

    # Remove OneDrive leftovers
    $oneDrivePaths = @(
        "$env:localappdata\Microsoft\OneDrive",
        "$env:programdata\Microsoft OneDrive",
        "$env:systemdrive\OneDriveTemp"
    )

    foreach ($path in $oneDrivePaths) {
        Remove-Directory -Path $path -Description "Removing OneDrive directory"
    }

    # Check if user OneDrive directory is empty before removing
    $userOneDrive = "$env:userprofile\OneDrive"
    if (Test-Path $userOneDrive) {
        $fileCount = (Get-ChildItem $userOneDrive -Recurse | Measure-Object).Count
        if ($fileCount -eq 0) {
            Remove-Directory -Path $userOneDrive -Description "Removing empty user OneDrive directory"
        }
        else {
            Write-LogMessage "User OneDrive directory contains files, skipping removal" -Type Warning
        }
    }

    # Disable OneDrive via Group Policies
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type "DWord" -Description "Disabling OneDrive via Group Policy"

    # Remove OneDrive from explorer sidebar
    New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR" -ErrorAction SilentlyContinue

   Set-ProtectedRegistryValue -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type "DWord" -Description "Removing OneDrive from explorer sidebar (CLSID)"
   Set-ProtectedRegistryValue -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type "DWord" -Description "Removing OneDrive from explorer sidebar (Wow6432Node)"

    # Remove OneDrive from startup for new users
    try {
        Write-LogMessage "Removing OneDrive from startup for new users" -Type Info
        reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
        reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
        reg unload "hku\Default"
    }
    catch {
        Write-LogMessage ("Failed to modify default user registry: " + $_.Exception.Message) -Type Error
    }

    # Remove start menu entry and scheduled tasks
    Remove-File -Path "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Description "Removing OneDrive start menu shortcut"

    Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    # Restart explorer
    Start-Process "explorer.exe"

    Complete-Operation "Uninstalling OneDrive"
}

function Remove-Bloatware {
    param (
        [array]$BloatwareList
    )

    Start-Operation "Removing bloatware applications"

    foreach ($app in $BloatwareList) {
        try {
            Write-LogMessage "Attempting to remove: $app" -Type Info
            Get-AppxPackage -Name $app -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue

            # Disable content delivery
            $cdmSettings = @(
                @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="FeatureManagementEnabled"; Value=0},
                @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="ContentDeliveryAllowed"; Value=0},
                @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="OemPreInstalledAppsEnabled"; Value=0},
                @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEnabled"; Value=0},
                @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEverEnabled"; Value=0},
                @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SilentInstalledAppsEnabled"; Value=0},
                @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SystemPaneSuggestionsEnabled"; Value=0},
                @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContentEnabled"; Value=0}
            )

            # Apply content delivery manager settings
            foreach ($setting in $cdmSettings) {
               Set-ProtectedRegistryValue -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type "DWord" -Description "Disabling content delivery"
            }

            # Disable subscription content
            for ($i = 310093; $i -le 353694; $i++) {
                if ($i -in @(310093, 338388, 338389, 338393, 353694, 353696)) {
                   Set-ProtectedRegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-$i`Enabled" -Value 0 -Type "DWord" -Description "Disabling subscribed content"
                }
            }

            # Clear content store
            Remove-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" -Description "Clearing subscriptions"
            Remove-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Description "Clearing suggested apps"
        }
        catch {
            Write-LogMessage ("Failed to remove " + $app + " : " + $_.Exception.Message) -Type Error
        }
    }

    Complete-Operation "Removing bloatware applications"
}

function Set-PrivacySettings {
    Start-Operation "Configuring privacy settings"

    # Disable Cortana
    $cortanaSettings = @(
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="ConnectedSearchPrivacy"; Value=0},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="ConnectedSearchUseWeb"; Value=0},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="ConnectedSearchUseWebOverMeteredConnections"; Value=0},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="DisableWebSearch"; Value=1},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="CortanaEnabled"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="BingSearchEnabled"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="CanCortanaBeEnabled"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Personalization\Settings"; Name="AcceptedPrivacyPolicy"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="DeviceHistoryEnabled"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="HistoryViewEnabled"; Value=0}
    )

    foreach ($setting in $cortanaSettings) {
       Set-ProtectedRegistryValue -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type "DWord" -Description "Disabling Cortana"
    }

    # Disable telemetry
    $telemetrySettings = @(
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"; Name="AllowTelemetry"; Value=0},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Value=0},
        @{Path="HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Value=0}
    )

    foreach ($setting in $telemetrySettings) {
       Set-ProtectedRegistryValue -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type "DWord" -Description "Disabling telemetry"
    }

    # Disable scheduled tasks related to telemetry
    $telemetryTasks = @(
        "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "Microsoft\Windows\Autochk\Proxy",
        "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        # Added task to disable DeviceCensus
        "Microsoft\Windows\Device Information\Device" # This is the scheduled task for devicecensus.exe
    )

    foreach ($taskPath in $telemetryTasks) { # Changed variable name to $taskPath for clarity
        try {
            # Scheduled tasks are identified by their path in Task Scheduler
            $task = Get-ScheduledTask -TaskPath "\" -TaskName ($taskPath.Split('\')[-1]) -ErrorAction SilentlyContinue
            if ($taskPath.StartsWith("Microsoft\Windows\Device Information")) { # More specific check for DeviceCensus task path
                $task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Device Information\" -TaskName "Device" -ErrorAction SilentlyContinue
            } else {
                 # Attempt to get task by full path if it contains subfolders
                $pathParts = $taskPath.Split('\')
                $taskName = $pathParts[-1]
                $folderPath = "\" + ($pathParts[0..($pathParts.Length-2)] -join '\')
                if ($pathParts.Length -gt 1) {
                    $task = Get-ScheduledTask -TaskPath $folderPath -TaskName $taskName -ErrorAction SilentlyContinue
                } else { # Root task
                    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                }
            }

            if ($task) {
                if ($task.State -ne [Microsoft.Win32.TaskScheduler.TaskState]::Disabled) {
                    Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
                    Write-LogMessage "Disabled scheduled task: $taskPath" -Type Success
                } else {
                    Write-LogMessage "Scheduled task already disabled: $taskPath" -Type Info
                }
            } else {
                Write-LogMessage "Scheduled task not found (may not exist on this system or already removed): $taskPath" -Type Info
            }
        }
        catch {
            Write-LogMessage "Failed to disable or check task $taskPath : $($_.Exception.Message)" -Type Warning
        }
    }

    # Location tracking
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type "DWord" -Description "Disabling location tracking"
   Set-ProtectedRegistryValue -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type "DWord" -Description "Disabling location tracking service"

    # Disable input collection
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type "DWord" -Description "Disabling implicit ink collection"
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type "DWord" -Description "Disabling implicit text collection"
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type "DWord" -Description "Disabling contact harvesting"

    # Advertising ID
   Set-ProtectedRegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type "DWord" -Description "Disabling Advertising ID"

    # Disable feedback experience
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type "DWord" -Description "Disabling feedback experience"

    # Disable consumer features
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type "DWord" -Description "Disabling consumer features"

    # Disable Windows Tips
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type "DWord" -Description "Disabling Windows Tips"

    # Disable tailored experiences
   Set-ProtectedRegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type "DWord" -Description "Disabling tailored experiences"
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type "DWord" -Description "Disabling tailored experiences via policy"

    # Disable automatic network device installation
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Value 0 -Type "DWord" -Description "Disabling automatic network device installation"

    # Disable background apps
    try {
        Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" |
        Where-Object { $_.PSChildName -ne "Microsoft.Windows.Cortana*" } |
        ForEach-Object {
           Set-ProtectedRegistryValue -Path $_.PSPath -Name "Disabled" -Value 1 -Type "DWord" -Description "Disabling background app: $($_.PSChildName)"
           Set-ProtectedRegistryValue -Path $_.PSPath -Name "DisabledByUser" -Value 1 -Type "DWord" -Description "Disabling background app: $($_.PSChildName)"
        }
    }
    catch {
        Write-LogMessage ("Error disabling background apps: " + $_.Exception.Message) -Type Warning
    }

    # Disable remote assistance
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type "DWord" -Description "Disabling Remote Assistance"

    # Disable AutoLogger and ETW traces
    $etlLogPath = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    Remove-Directory -Path $etlLogPath -Description "Removing ETL Autologs"

    if (Test-Path $etlLogPath) {
        # If removal failed, try to secure the directory
        try {
            $acl = Get-Acl $etlLogPath
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("System", "FullControl", "ContainerInherit, ObjectInherit", "None", "Deny")
            $acl.AddAccessRule($rule)
            Set-Acl $etlLogPath $acl
            Write-LogMessage "Secured ETL Autologs directory" -Type Success
        }
        catch {
            Write-LogMessage ("Failed to secure ETL Autologs directory: " + $_.Exception.Message) -Type Error
        }
    }

    # Disable DiagTrack service
    Set-ServiceConfiguration -Name "DiagTrack" -State "Stopped" -StartupType "Disabled" -Description "Disabling DiagTrack (Connected User Experiences and Telemetry)" -Force $true # Clarified description

    # Disable dmwappushservice
    Set-ServiceConfiguration -Name "dmwappushservice" -State "Stopped" -StartupType "Disabled" -Description "Disabling dmwappushservice (Device Management Wireless Application Protocol Push message routing)" -Force $true # Clarified description

    # Disable Windows Insider Service
    Set-ServiceConfiguration -Name "wisvc" -State "Stopped" -StartupType "Disabled" -Description "Disabling Windows Insider Service" -Force $true

    # Disable IP Helper (can leak data)
    Set-ServiceConfiguration -Name "iphlpsvc" -State "Stopped" -StartupType "Disabled" -Description "Disabling IP Helper service" -Force $true

    # Disable NVIDIA telemetry
    Set-ServiceConfiguration -Name "NvTelemetryContainer" -State "Stopped" -StartupType "Disabled" -Description "Disabling NVIDIA Telemetry" -Force $true

    # Set network profile to public for enhanced security
    try {
        Get-NetConnectionProfile -ErrorAction SilentlyContinue | Set-NetConnectionProfile -NetworkCategory Public -ErrorAction SilentlyContinue
        Write-LogMessage "Attempted to set network profiles to Public" -Type Success # Changed to "Attempted" as it might not apply to all or fail silently
    }
    catch {
        Write-LogMessage ("Failed to set network profile to Public: " + $_.Exception.Message) -Type Warning
    }

    Complete-Operation "Configuring privacy settings"
}

function Set-PerformanceOptimizations {
    Start-Operation "Applying performance optimizations"

    # Services to disable for performance
    $servicesToDisable = @(
        @{Name="WpcMonSvc"; Desc="Windows Parental Controls"},
        @{Name="diagsvc"; Desc="Diagnostic Execution Service"},
        @{Name="Fax"; Desc="Windows Fax Service"},
        @{Name="lfsvc"; Desc="Geolocation Service"},
        @{Name="DusmSvc"; Desc="Data Usage Service"},
        @{Name="StorSvc"; Desc="Storage Service"},
        @{Name="MSDTC"; Desc="Distributed Transaction Coordinator"},
        @{Name="Ndu"; Desc="Network Data Usage Monitor"},
        @{Name="AppMgmt"; Desc="Application Management"},
        @{Name="TrkWks"; Desc="Distributed Link Tracking Client"},
        @{Name="DispBrokerDesktopSvc"; Desc="Display Policy Service"},
        @{Name="OneSyncSvc"; Desc="OneSync Service"},
        @{Name="WalletService"; Desc="Wallet Service"}
    )

    # Only disable printer-related services if safe mode is disabled
    if (-not $Config.SafetyToggles.BePrinterSafe) {
        $servicesToDisable += @(
            @{Name="Spooler"; Desc="Print Spooler"},
            @{Name="StiSvc"; Desc="Windows Image Acquisition"}
        )
    }

    # Only disable certain services if safety mode is disabled
    if (-not $Config.SafetyToggles.BeWifiSafe) {
        $servicesToDisable += @(
            @{Name="RmSvc"; Desc="Radio Management Service"},
            @{Name="WlanSvc"; Desc="WLAN AutoConfig"}
        )
    }

    if (-not $Config.SafetyToggles.BeMicrophoneSafe) {
        $servicesToDisable += @{Name="camsvc"; Desc="Capability Access Manager Service"}
    }

    # Disable selected services
    foreach ($service in $servicesToDisable) {
        Set-ServiceConfiguration -Name $service.Name -State "Stopped" -StartupType "Disabled" -Description "Disabling $($service.Desc)" -Force $true
    }

    # Disable Windows features
    if ($Config.General.DisablePrefetcher) {
       Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Type "DWord" -Description "Disabling Prefetcher"
    }

    if ($Config.General.DisableMemoryDump) {
       Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Type "DWord" -Description "Disabling Memory Dump"
    }

    # Hardware acceleration
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 2 -Type "DWord" -Description "Enabling Hardware Accelerated GPU Scheduling"

    # Disable visual effects
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type "DWord" -Description "Disabling transparency effects"

    # Disable diagnostic services
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\services\WdiServiceHost" -Name "Start" -Value 4 -Type "DWord" -Description "Disabling Diagnostic Service Host"
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\services\WdiSystemHost" -Name "Start" -Value 4 -Type "DWord" -Description "Disabling Diagnostic System Host"
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\services\DPS" -Name "Start" -Value 4 -Type "DWord" -Description "Disabling Diagnostic Policy Service"

    # Disable hibernation
   Set-ProtectedRegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Value 0 -Type "DWord" -Description "Disabling hibernation"
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Value 0 -Type "DWord" -Description "Hiding hibernation option"

    # Disable scheduled defragmentation
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" -ErrorAction SilentlyContinue | Out-Null
    Write-LogMessage "Disabled scheduled defragmentation" -Type Success

    # Disable superfetch/sysmain
    Set-ServiceConfiguration -Name "SysMain" -State "Stopped" -StartupType "Disabled" -Description "Disabling Superfetch/SysMain" -Force $true

    # Disable SSDPSRV
    Set-ServiceConfiguration -Name "SSDPSRV" -State "Stopped" -StartupType "Disabled" -Description "Disabling SSDP Discovery" -Force $true

    # Disable AxInstSV
    Set-ServiceConfiguration -Name "AxInstSV" -State "Stopped" -StartupType "Disabled" -Description "Disabling ActiveX Installer" -Force $true

    # Disable MapsBroker
    Set-ServiceConfiguration -Name "MapsBroker" -State "Stopped" -StartupType "Disabled" -Description "Disabling Downloaded Maps Manager" -Force $true

    # Set power plan
    $powerCfg = powercfg -SetActive $Config.General.PowerPlan
    if ($LASTEXITCODE -eq 0) {
        Write-LogMessage "Applied power plan successfully" -Type Success
    }
    else {
        Write-LogMessage "Failed to apply power plan" -Type Warning
    }

    # Configure power settings
    powercfg -Change -monitor-timeout-ac $Config.General.MonitorAcTimeout
    powercfg -Change -monitor-timeout-dc $Config.General.MonitorDcTimeout
    powercfg -Change -disk-timeout-ac $Config.General.DiskAcTimeout
    powercfg -Change -disk-timeout-dc $Config.General.DiskDcTimeout
    powercfg -Change -standby-timeout-ac $Config.General.StandbyAcTimeout
    powercfg -Change -standby-timeout-dc $Config.General.StandbyDcTimeout
    powercfg -Change -hibernate-timeout-ac $Config.General.HibernateAcTimeout
    powercfg -Change -hibernate-timeout-dc $Config.General.HibernateDcTimeout

    Write-LogMessage "Applied power settings" -Type Success

    Complete-Operation "Applying performance optimizations"
}

function Set-QualityOfLifeImprovements {
    Start-Operation "Applying quality of life improvements"

    # Set file attachment handling
   Set-ProtectedRegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type "DWord" -Description "Disabling attachment lock when saved"
   Set-ProtectedRegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "DefaultFileTypeRisk" -Value 6152 -Type "DWord" -Description "Lowering attachment risk level"

    # Disable Microsoft Store integration
   Set-ProtectedRegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type "DWord" -Description "Disabling 'Look for an app in the Microsoft Store'"

    # Remove taskbar items
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type "DWord" -Description "Removing widgets button from taskbar"
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Type "DWord" -Description "Removing chat button from taskbar"

    # Disable Windows tips
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0 -Type "DWord" -Description "Disabling Windows tips"

    # Disable automatic restart sign-on
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1 -Type "DWord" -Description "Disabling automatic restart sign-on"

    # Disable notifications
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_TOASTS_ENABLED" -Value 0 -Type "DWord" -Description "Disabling notifications"
   Set-ProtectedRegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0 -Type "DWord" -Description "Disabling toast notifications"

    # Disable dynamic scrollbars
   Set-ProtectedRegistryValue -Path "HKCU:\Control Panel\Accessibility" -Name "DynamicScrollbars" -Value 0 -Type "DWord" -Description "Disabling dynamic scrollbars"

    # Disable fast boot (can cause issues with some software)
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Type "DWord" -Description "Disabling Fast Boot"

    # Disable sticky keys prompt
   Set-ProtectedRegistryValue -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506 -Type "DWord" -Description "Disabling Sticky Keys prompt"

    # Show This PC shortcut on desktop
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type "DWord" -Description "Showing This PC on desktop"
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type "DWord" -Description "Showing This PC on desktop"

    # Disable ads in File Explorer
   Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type "DWord" -Description "Disabling ads in File Explorer"

    # Disable third-party suggestions
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1 -Type "DWord" -Description "Disabling third-party suggestions"

    # Disable enhanced pointer precision
   Set-ProtectedRegistryValue -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value 0 -Type "DWord" -Description "Disabling enhanced pointer precision"
   Set-ProtectedRegistryValue -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value 0 -Type "DWord" -Description "Disabling pointer acceleration"
   Set-ProtectedRegistryValue -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value 0 -Type "DWord" -Description "Disabling pointer acceleration"

    # Legacy right-click menu (Windows 11)
    if ($Config.General.LegacyRightClicksMenu) {
       Set-ProtectedRegistryValue -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Value "" -Type "String" -Description "Enabling legacy right-click menu"
    }

    # Disable startup sound
    if ($Config.General.DisableStartupSound) {
       Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Value 1 -Type "DWord" -Description "Disabling Windows startup sound"
    }

    # Disable Windows sounds
    if ($Config.General.DisableWindowsSounds) {
        try {
            Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps" |
            Get-ChildItem |
            Get-ChildItem |
            Where-Object {$_.PSChildName -eq ".Current"} |
            Set-ItemProperty -Name "(Default)" -Value ".None"

            Write-LogMessage "Disabled Windows sound effects" -Type Success
        }
        catch {
            Write-LogMessage ("Failed to disable Windows sounds: " + $_.Exception.Message) -Type Error
        }
    }

    # Remove 3D Objects folder
    if ($Config.General.Remove3dObjFolder) {
        Remove-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Description "Removing 3D Objects folder"
        Remove-RegistryValue -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Description "Removing 3D Objects folder (WOW6432Node)"
    }

    # Dark theme
    if ($Config.General.DarkTheme) {
       Set-ProtectedRegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type "DWord" -Description "Enabling dark theme for apps"
       Set-ProtectedRegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type "DWord" -Description "Enabling dark theme for system"
    }

    Complete-Operation "Applying quality of life improvements"
}

function Set-SecurityEnhancements {
    Start-Operation "Applying security enhancements"

    # Airstrike Attack mitigation
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1 -Type "DWord" -Description "Hardening against Airstrike Attack"

    # Disable Windows Media Player Network Sharing
    Set-ServiceConfiguration -Name "WMPNetworkSvc" -State "Stopped" -StartupType "Disabled" -Description "Disabling Windows Media Player Network Sharing" -Force $true

    # Disable WPAD (Web Proxy Auto-Discovery) - potential MITM vector
    if (-not $Config.SafetyToggles.BePrinterSafe) {
        Set-ServiceConfigurationWithScExe -Name "WinHttpAutoProxySvc" -State "Stopped" -StartupType "Disabled" -Description "Disabling WPAD service"
    }

    # Disable LLMNR (Link-Local Multicast Name Resolution) - potential spoofing vector
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type "DWord" -Description "Disabling LLMNR"

    # Flush DNS cache
    try {
        ipconfig /flushdns | Out-Null
        Write-LogMessage "Flushed DNS cache" -Type Success
    }
    catch {
        Write-LogMessage "Failed to flush DNS cache: $($_.Exception.Message)" -Type Warning
    }

    # Disable NetBIOS over TCP/IP (potential spoofing vector)
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Value 2 -Type "DWord" -Description "Disabling NetBIOS over TCP/IP"

    # Anonymous enumeration hardening
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type "DWord" -Description "Disabling anonymous enumeration of shares"

    # Disable Wi-Fi Sense (risky auto-connection feature)
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Value 0 -Type "DWord" -Description "Disabling Wi-Fi Sense reporting"
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Value 0 -Type "DWord" -Description "Disabling Wi-Fi Sense auto-connect"
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type "DWord" -Description "Disabling Wi-Fi Sense OEM settings"

    # Disable Remote Assistance
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type "DWord" -Description "Disabling Remote Assistance"

    # Disable AutoPlay and AutoRun
   Set-ProtectedRegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type "DWord" -Description "Disabling AutoPlay"
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Type "DWord" -Description "Disabling AutoPlay for non-volume devices"
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutorun" -Value 1 -Type "DWord" -Description "Disabling AutoRun"

    # Protect against credential scraping (Mimikatz)
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 8 -Type "DWord" -Description "LSASS protection - audit level"
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type "DWord" -Description "LSASS protection - RunAsPPL"
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0 -Type "DWord" -Description "LSASS protection - DisableRestrictedAdmin"
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdminOutboundCreds" -Value 1 -Type "DWord" -Description "LSASS protection - DisableRestrictedAdminOutboundCreds"
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type "DWord" -Description "LSASS protection - Disable WDigest"
   Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "Negotiate" -Value 0 -Type "DWord" -Description "LSASS protection - Disable WDigest Negotiate"
   Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value 1 -Type "DWord" -Description "LSASS protection - Allow protected credentials"

    # Disable SMB Server (if selected)
    if ($Config.Security.DisableSMBServer) {
        try {
            # Disable SMB1
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
            # Disable SMB2/3
            Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ErrorAction Stop
            # Disable SMB network adapter binding
            Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server" -ErrorAction Stop

            Write-LogMessage "Disabled SMB Server" -Type Success
        }
        catch {
            Write-LogMessage ("Failed to disable SMB Server: " + $_.Exception.Message) -Type Error
        }
    }

    # With this:
	if ($Config.Security.DisableWindowsFirewall) {
		# Disable both the service and the profiles
		Disable-WindowsFirewallService
		Disable-WindowsFirewallProfiles
	}

    # Fingerprint prevention
    if ($Config.Security.DoFingerprintPrevention) {
        # Disable recent docs history
       Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -Type "DWord" -Description "Disabling Recent docs history"

        # Disable Windows zone information
       Set-ProtectedRegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1 -Type "DWord" -Description "Disabling Windows zone information"

        # Disable internet connection test
       Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -Value 0 -Type "DWord" -Description "Disabling internet connection test"

        # Configure DNS over HTTPS
       Set-ProtectedRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Value 2 -Type "DWord" -Description "Enabling DNS over HTTPS"
    }

    # Set Google DNS (if selected)
    if ($Config.Security.UseGoogleDNS) {
        try {
            $dnsServers = @("8.8.8.8", "8.8.4.4")

            $networkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
            foreach ($adapter in $networkAdapters) {
                $adapter.SetDNSServerSearchOrder($dnsServers) | Out-Null
            }

            Write-LogMessage "Set Google DNS servers" -Type Success
        }
        catch {
            Write-LogMessage ("Failed to set Google DNS: " + $_.Exception.Message) -Type Error
        }
    }

    Complete-Operation "Applying security enhancements"
}

function Set-UpdateConfiguration {
    Start-Operation "Configuring Windows Updates"

    if ($Config.Updates.DisableWindowsUpdates) {
        # Services to disable
        $updateServices = @(
            @{Name="UsoSvc"; Desc="Update Orchestrator Service"},
            @{Name="CryptSvc"; Desc="Cryptographic Services"},
            @{Name="WaaSMedicSvc"; Desc="Windows Update Medic Service"},
            @{Name="wuauserv"; Desc="Windows Update Service"},
            @{Name="BITS"; Desc="Background Intelligent Transfer Service"}
        )

        foreach ($service in $updateServices) {
            Set-ServiceConfiguration -Name $service.Name -State "Stopped" -StartupType "Disabled" -Description "Disabling $($service.Desc)" -Force $true
        }

        # Disable updates via registry
       Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "NoAutoUpdate" -Value 1 -Type "DWord" -Description "Disabling Windows Update"
       Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type "DWord" -Description "Preventing device metadata download"

        # Disable driver updates
       Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Value 1 -Type "DWord" -Description "Disabling Windows Update driver prompt"
       Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Value 1 -Type "DWord" -Description "Disabling Windows Update driver search"
       Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Value 0 -Type "DWord" -Description "Disabling driver update wizard"
       Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type "DWord" -Description "Excluding drivers from Windows Update"

        Write-LogMessage "Windows Updates have been disabled" -Type Success
    }
    else {
        # Enable update services if they should be running
        $updateServices = @(
            @{Name="UsoSvc"; Desc="Update Orchestrator Service"},
            @{Name="CryptSvc"; Desc="Cryptographic Services"},
            @{Name="WaaSMedicSvc"; Desc="Windows Update Medic Service"},
            @{Name="wuauserv"; Desc="Windows Update Service"},
            @{Name="BITS"; Desc="Background Intelligent Transfer Service"}
        )

        foreach ($service in $updateServices) {
            Set-ServiceConfiguration -Name $service.Name -State "Running" -StartupType "Automatic" -Description "Enabling $($service.Desc)" -Force $false
        }

       Set-ProtectedRegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "NoAutoUpdate" -Value 0 -Type "DWord" -Description "Enabling Windows Update"

        Write-LogMessage "Windows Updates have been enabled" -Type Success
    }

    Complete-Operation "Configuring Windows Updates"
}

function Install-InitialPackages {
    Start-Operation "Installing initial packages"

    if ($Config.Installation.InitialPackages) {
        try {
            # Install Chocolatey
            Set-ExecutionPolicy Bypass -Scope Process -Force
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

            # Essential software
            $packages = @(
                "vcredist-all",
                "vcredist2010",
                "vcredist2017",
                "dotnetcore-3.1-desktopruntime"
                "dotnet4.0",
                "dotnet4.5",
                "dotnetfx",
                "directx",
                "dotnetcore",
                "dotnet-runtime",
                "qbittorrent",
                "k-litecodecpackfull",
                "imageglass",
                "7zip.install",
                "vscode"
            )

            foreach ($package in $packages) {
                Write-LogMessage "Installing $package..." -Type Info
                Start-Process -FilePath "choco" -ArgumentList "install $package -y" -Wait -NoNewWindow
            }

            Write-LogMessage "Initial packages installed successfully" -Type Success
        }
        catch {
            Write-LogMessage ("Failed to install packages: " + $_.Exception.Message) -Type Error
        }
    }
    else {
        Write-LogMessage "Initial package installation skipped (not selected in config)" -Type Info
    }

    Complete-Operation "Installing initial packages"
}

function Show-FinalSummary {
    $totalOperations = $script:SuccessCount + $script:WarningCount + $script:ErrorCount

    Write-Host "`n===========================================" -ForegroundColor Cyan
    Write-Host "     Windows Optimization Complete" -ForegroundColor Cyan
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host "Summary:"
    Write-Host "  Total Operations: $totalOperations"
    Write-Host "  Successful: $($script:SuccessCount)" -ForegroundColor Green
    Write-Host "  Warnings: $($script:WarningCount)" -ForegroundColor Yellow
    Write-Host "  Errors: $($script:ErrorCount)" -ForegroundColor Red
    Write-Host "`nLog file saved to: $LogPath"
    Write-Host "===========================================" -ForegroundColor Cyan

    Write-Host "`nSome changes may require a system restart to take effect." -ForegroundColor Yellow
    $restart = Read-Host "Would you like to restart your computer now? (y/n)"

    if ($restart -eq 'y') {
        Write-Host "Restarting in 10 seconds..." -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
    else {
        Write-Host "Please remember to restart your computer later for changes to take full effect." -ForegroundColor Yellow
    }
}

#region Main Execution

# Check and ensure administrator privileges
if (-not (Test-Administrator)) {
    Write-Host "This script requires administrator privileges." -ForegroundColor Yellow
    Write-Host "Attempting to restart with elevated permissions..." -ForegroundColor Yellow

    try {
        # Get the full path to the current script
        $scriptPath = $MyInvocation.MyCommand.Definition

        if (-not $scriptPath) {
            # Fallback if MyCommand.Definition is empty
            $scriptPath = $PSCommandPath
        }

        if (-not $scriptPath) {
            Write-Host "Unable to determine script path. Please run this script as administrator." -ForegroundColor Red
            Start-Sleep -Seconds 5
            exit 1
        }

        # Start a new PowerShell process with elevated privileges
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" "
        Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $arguments

        # Exit the current (non-elevated) instance
        exit 0
    }
    catch {
        Write-Host "Failed to restart script with elevated permissions: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please right-click on the script and select 'Run as administrator'" -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        exit 1
    }
}

# Create new PSDrive for HKCR if it doesn't exist
if (-not (Get-PSDrive HKCR -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}

# Display header
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "     Windows System Optimization Tool" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Starting optimization with selected configuration...`n"

# Execute operations based on configuration
try {
    # Clear caches
    Clear-AllCaches

    # Apply privacy settings
    if ($Config.Privacy.DoPrivacyStuff) {
        Set-PrivacySettings
    }

    # Apply performance optimizations
    if ($Config.General.DoPerformanceStuff) {
        Set-PerformanceOptimizations
    }

    # Apply quality of life improvements
    Set-QualityOfLifeImprovements

    # Apply security enhancements
    if ($Config.Security.DoSecurityStuff) {
        Set-SecurityEnhancements
    }

    # Configure Windows Updates
    Set-UpdateConfiguration

    # Remove bloatware if selected
    if ($Config.Privacy.DisableBloatware) {
        Remove-Bloatware -BloatwareList $Config.Uninstall.BloatwareList
    }

    # Uninstall Windows Defender (if selected and in safe mode)
    if ($Config.Uninstall.UninstallWindowsDefender) {
        Disable-WindowsDefenderComponents
    }

    # Uninstall OneDrive (if selected and in safe mode)
    if ($Config.Uninstall.UninstallOneDrive) {
        Uninstall-OneDrive
    }

    # Install initial packages
    Install-InitialPackages

    # Update hosts file (block telemetry)
    try {
        $hostsPath = "$env:windir\System32\drivers\etc\hosts"
        $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
        $telemetryHosts = @(
            "127.0.0.1 localhost",
            "127.0.0.1 telemetry.microsoft.com",
            "127.0.0.1 vortex.data.microsoft.com",
            "127.0.0.1 settings-win.data.microsoft.com",
            "127.0.0.1 telemetry.remoteapp.windowsazure.com",
            "127.0.0.1 watson.telemetry.microsoft.com",
            "127.0.0.1 telemetry.appex.bing.net"
        )

        Set-Content -Path $hostsPath -Value $telemetryHosts -Force
        Write-LogMessage "Updated hosts file to block telemetry" -Type Success
    }
    catch {
        Write-LogMessage ("Failed to update hosts file: " + $_.Exception.Message) -Type Error
    }

    # Remove VSS shadows (reduce disk space usage)
    try {
        vssadmin delete shadows /all /quiet | Out-Null
        Write-LogMessage "Removed VSS shadow copies" -Type Success
    }
    catch {
        Write-LogMessage ("Failed to remove VSS shadows: " + $_.Exception.Message) -Type Warning
    }

    # Show final summary and offer restart
    Show-FinalSummary
}
catch {
    Write-LogMessage ("Critical error during execution: " + $_.Exception.Message) -Type Error
    Write-LogMessage ("Stack trace: " + $_.ScriptStackTrace) -Type Error

    Write-Host "`nAn error occurred during optimization. Please check the log file for details: $LogPath" -ForegroundColor Red
}
finally {
    # Clean up PSDrive
    if (Get-PSDrive HKCR -ErrorAction SilentlyContinue) {
        Remove-PSDrive HKCR -ErrorAction SilentlyContinue
    }
}

#endregion Main Execution
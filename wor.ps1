$ErrorActionPreference = "SilentlyContinue"
Set-ExecutionPolicy unrestricted
Write-Host "Creating PSDrive 'HKCR' (HKEY_CLASSES_ROOT). This will be used for the duration of the script as it is necessary for the removal and modification of specific registry keys."
New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

#This will self elevate the script so with a UAC prompt since this script needs to be run as an Administrator in order to function properly.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Write-Host "                                               3"
    Start-Sleep 1
    Write-Host "                                               2"
    Start-Sleep 1
    Write-Host "                                               1"
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

Function DebloatBlack {
    $Bloatware = @(

        #Unnecessary Windows 10 AppX Apps
        "Microsoft.BingNews"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
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
        #"Microsoft.WindowsCamera"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Spotify*"
        "*Minecraft*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
             
        #Optional: Typically not removed but you can if you need to for some reason
        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
        #"*Microsoft.BingWeather*"
        #"*Microsoft.MSPaint*"
        #"*Microsoft.MicrosoftStickyNotes*"
        #"*Microsoft.Windows.Photos*"
        #"*Microsoft.WindowsCalculator*"
        #"*Microsoft.WindowsStore*"
    )
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Output "Trying to remove $Bloat."
    }
}

Function DebloatAll {
	# REMOVE GARBAGE BY BULK
	Get-AppxPackage -AllUsers | Remove-AppxPackage; Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
}

Function Remove-Keys {
        
    #These are the registry keys that it will delete.
            
    $Keys = @(
            
        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
               
        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
        
    #This writes the output of each key it is removing and also removes the keys listed above.
    ForEach ($Key in $Keys) {
        Write-Output "Removing $Key from registry"
        Remove-Item $Key -Recurse
    }
}

Function DisableUAC {
	New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force -EA SilentlyContinue | Out-Null
	if($?){   write-Host -ForegroundColor Green "Windows UAC disabled"  }else{   write-Host -ForegroundColor green "Windows UAC not disabled" } 
	# REMOVE ONE DRIVE
	rd "%UserProfile%\OneDrive" /q /s > nul 2>&1
	rd "%SystemDrive%\OneDriveTemp" /q /s > nul 2>&1
	rd "%LocalAppData%\Microsoft\OneDrive" /q /s > nul 2>&1
	rd "%ProgramData%\Microsoft OneDrive" /q /s > nul 2>&1
	reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
	reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f > nul
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d 1 /f > nul
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d 1 /f > nul
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d 1 /f > nul
	reg add "HKCU\SOFTWARE\Microsoft\OneDrive" /v "DisablePersonalSync" /t REG_DWORD /d 1 /f > nul
}


Function Protect-Privacy {

    Write-Output "Disabling Windows Feedback Experience program / Advertising ID"
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising Enabled -Value 0 
    }
            
    Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    If (Test-Path $Search) {
        Set-ItemProperty $Search AllowCortana -Value 0 
    }

    #Disables Web Search in Start Menu
    Write-Output "Disabling Bing Search in Start Menu"
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 
    If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch
    }
    Set-ItemProperty $WebSearch DisableWebSearch -Value 1 
            
    #Stops the Windows Feedback Experience from sending anonymous data
    Write-Output "Stopping the Windows Feedback Experience program"
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) { 
        New-Item $Period
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 

    #Prevents bloatware applications from returning and removes Start Menu suggestions               
    Write-Output "Adding Registry key to prevent bloatware apps from returning"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 

    If (!(Test-Path $registryOEM)) {
        New-Item $registryOEM
    }
    Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0 
    Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0 
    Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0          
    
    #Preping mixed Reality Portal for removal    
    Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
    $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
    If (Test-Path $Holo) {
        Set-ItemProperty $Holo  FirstRunSucceeded -Value 0 
    }

    #Disables Wi-fi Sense
    Write-Output "Disabling Wi-Fi Sense"
    $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    If (!(Test-Path $WifiSense1)) {
        New-Item $WifiSense1
    }
    Set-ItemProperty $WifiSense1  Value -Value 0 
    If (!(Test-Path $WifiSense2)) {
        New-Item $WifiSense2
    }
    Set-ItemProperty $WifiSense2  Value -Value 0 
    Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
        
    #Disables live tiles
    Write-Output "Disabling live tiles"
    $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
    If (!(Test-Path $Live)) {      
        New-Item $Live
    }
    Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 
        
    #Turns off Data Collection via the AllowTelemtry key by changing it to 0
    Write-Output "Turning off Data Collection"
    $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
    If (Test-Path $DataCollection1) {
        Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection2) {
        Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection3) {
        Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0 
    }
    
    #Disabling Location Tracking
    Write-Output "Disabling Location Tracking"
    $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
    If (!(Test-Path $SensorState)) {
        New-Item $SensorState
    }
    Set-ItemProperty $SensorState SensorPermissionState -Value 0 
    If (!(Test-Path $LocationConfig)) {
        New-Item $LocationConfig
    }
    Set-ItemProperty $LocationConfig Status -Value 0 
        
    #Disables People icon on Taskbar
    Write-Output "Disabling People icon on Taskbar"
    $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
    If (Test-Path $People) {
        Set-ItemProperty $People -Name PeopleBand -Value 0
    }
        
    #Disables scheduled tasks that are considered unnecessary 
    Write-Output "Disabling scheduled tasks"
    Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask
    Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask
    Get-ScheduledTask  Consolidator | Disable-ScheduledTask
    Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
    Get-ScheduledTask  DmClient | Disable-ScheduledTask
    Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask

    Write-Output "Stopping and disabling Diagnostics Tracking Service"
    #Disabling the Diagnostics Tracking Service
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled

    
    Write-Output "Removing CloudStore from registry if it exists"
    $CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
    If (Test-Path $CloudStore) {
        Stop-Process Explorer.exe -Force
        Remove-Item $CloudStore -Recurse -Force
        Start-Process Explorer.exe -Wait
    }
}

Function DisableCortana {
	Write-Host "Disabling Cortana..."	
	Write-Output "Disabling AllowSearchToUseLocation"
    $AllowSearchToUseLocation = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    If (Test-Path $AllowSearchToUseLocation) {
        Set-ItemProperty $AllowSearchToUseLocation Enabled -Value 0 
    }

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchPrivacy" -Type DWord -Value 3
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "DeviceHistoryEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Type DWord -Value 0
}

Function UnpinStart {
    #https://superuser.com/questions/1068382/how-to-remove-all-the-tiles-in-the-windows-10-start-menu
    #Unpins all tiles from the Start Menu
    Write-Host "Unpinning all tiles from the start menu"
    (New-Object -Com Shell.Application).
    NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').
    Items() |
        % { $_.Verbs() } |
        ? {$_.Name -match 'Un.*pin from Start'} |
        % {$_.DoIt()}
}

Function Remove3dObjects {
    #Removes 3D Objects from the 'My Computer' submenu in explorer
    Write-Host "Removing 3D Objects from explorer 'My Computer' submenu"
    $Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    $Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    If (Test-Path $Objects32) {
        Remove-Item $Objects32 -Recurse 
    }
    If (Test-Path $Objects64) {
        Remove-Item $Objects64 -Recurse 
    }
}

$reverse = Read-Host "Reverse mode? (use if having some troubles) (y/n)"

while("y","n" -notcontains $reverse)
{
	$reverse = Read-Host "y or n?"
}


$visual = Read-Host "Install Initial Packages? (y/n)"

while("y","n" -notcontains $visual)
{
	$visual = Read-Host "y or n?"
}


$windowsdefender = Read-Host "Disable windows defender? (y/n)"

while("y","n" -notcontains $windowsdefender)
{
	$windowsdefender = Read-Host "y or n?"
}

$windowsfirewall = Read-Host "Disable windows firewall? (y/n)"

while("y","n" -notcontains $windowsfirewall)
{
	$windowsfirewall = Read-Host "y or n?"
}

$windowsupdate = Read-Host "Disable windows updates? (y/n)"

while("y","n" -notcontains $windowsupdate)
{
	$windowsupdate = Read-Host "y or n?"
}

$showhidden = Read-Host "Show hidden files and extensions (y/n)"
while("y","n" -notcontains $showhidden)
{
	$showhidden = Read-Host "y or n?"
}


$disableuac = Read-Host "Disable UAC and remove windows apps (y/n)"
switch ($disableuac) {
	y {
	DisableUAC
	}
}


$ink = Read-Host "Disable Windows INK (y/n)"
while("y","n" -notcontains $ink)
{
	$ink = Read-Host "y or n?"
}


if ($windowsdefender -like "y") { 
#DISABLE WINDOWS DEFENDER

sc.exe config WinDefend start=disabled | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Updates Service Disabled"  }else{   write-Host -ForegroundColor red "Windows Updates Service Not Disabled" }

Set-MpPreference -DisableRealtimeMonitoring $true -EA SilentlyContinue
if($?){   write-Host -ForegroundColor Green "Windows Defender Current Session Disabled"  }else{   write-Host -ForegroundColor Green "Windows Defender Current Session not running" }

Set-ItemProperty -Path "HKLM:Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
if($?){   write-Host -ForegroundColor Green "Windows Anti Spyware Disabled"  }else{   write-Host -ForegroundColor red "Windows Anti Spyware not Disabled" }

Set-ItemProperty -Path "HKLM:Software\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Type DWord -Value 1
if($?){   write-Host -ForegroundColor Green "Windows Defender DisableRoutinelyTakingAction Disabled"  }else{   write-Host -ForegroundColor red "Windows Defender DisableRoutinelyTakingAction Not Disabled" }

Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Type DWord -Value 1
if($?){   write-Host -ForegroundColor Green "Windows DisableBehaviorMonitoring Disabled"  }else{   write-Host -ForegroundColor red "Windows DisableBehaviorMonitoring not Disabled" }

Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableAntiSpywareRealtimeProtection" -Type DWord -Value 1
if($?){   write-Host -ForegroundColor Green "Windows DisableAntiSpywareRealtimeProtection Disabled"  }else{   write-Host -ForegroundColor red "Windows DisableAntiSpywareRealtimeProtection not Disabled" }

Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Type DWord -Value 1
if($?){   write-Host -ForegroundColor Green "Windows On Access Protection Disabled"  }else{   write-Host -ForegroundColor red "Windows On Access Protection not Disabled" }

Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Type DWord -Value 1
if($?){   write-Host -ForegroundColor Green "Windows Real Time Protection Disabled"  }else{   write-Host -ForegroundColor red "Windows Real Time Protection not Disabled" }

Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\WinDefend" -Name "Start" -Type DWord -Value 4
if($?){   write-Host -ForegroundColor Green "Windows Defender Startup Disabled"  }else{   write-Host -ForegroundColor red "Windows Defender Startup not Disabled" } 

# Disable AllowUpdateService
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\AllowUpdateService")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\AllowUpdateService" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\AllowUpdateService" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows AllowUpdateService disabled"  }else{   write-Host -ForegroundColor red "Windows AllowUpdateService not disabled" } 

# Disable AllowAutoUpdate
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\AllowAutoUpdate")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\AllowAutoUpdate" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\AllowAutoUpdate" -Name "value" -Type DWord -Value 5
if($?){   write-Host -ForegroundColor Green "Windows AllowAutoUpdate disabled"  }else{   write-Host -ForegroundColor red "Windows AllowAutoUpdate not disabled" } 

# Disable Windows Defender AllowArchiveScanning
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender AllowArchiveScanning disabled"  }else{   write-Host -ForegroundColor red "Windows Defender AllowArchiveScanning not disabled" } 

# Disable Windows Defender AllowBehaviorMonitoring
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender AllowBehaviorMonitoring disabled"  }else{   write-Host -ForegroundColor red "Windows Defender AllowBehaviorMonitoring not disabled" } 

# Disable Windows Defender AllowCloudProtection
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowCloudProtection")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowCloudProtection" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowCloudProtection" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender AllowCloudProtection disabled"  }else{   write-Host -ForegroundColor red "Windows Defender AllowCloudProtection not disabled" } 

# Disable Windows Defender AllowIntrusionPreventionSystem
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender AllowIntrusionPreventionSystem disabled"  }else{   write-Host -ForegroundColor red "Windows Defender AllowIntrusionPreventionSystem not disabled" } 

# Disable Windows Defender AllowIOAVProtection
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender AllowIOAVProtection disabled"  }else{   write-Host -ForegroundColor red "Windows Defender AllowIOAVProtection not disabled" } 

# Disable Windows Defender AllowOnAccessProtection
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender AllowOnAccessProtection disabled"  }else{   write-Host -ForegroundColor red "Windows Defender AllowOnAccessProtection not disabled" } 

# Disable Windows Defender AllowRealtimeMonitoring
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender AllowRealtimeMonitoring disabled"  }else{   write-Host -ForegroundColor red "Windows Defender AllowRealtimeMonitoring not disabled" } 

# Disable Windows Defender AllowScanningNetworkFiles
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScanningNetworkFiles")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScanningNetworkFiles" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScanningNetworkFiles" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender AllowScanningNetworkFiles disabled"  }else{   write-Host -ForegroundColor red "Windows Defender AllowScanningNetworkFiles not disabled" } 

# Disable Windows Defender AllowScriptScanning
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScriptScanning")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScriptScanning" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScriptScanning" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender AllowScriptScanning disabled"  }else{   write-Host -ForegroundColor red "Windows Defender AllowScriptScanning not disabled" } 

# Disable Windows Defender DisableCatchupFullScan
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupFullScan")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupFullScan" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupFullScan" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender DisableCatchupFullScan disabled"  }else{   write-Host -ForegroundColor red "Windows Defender DisableCatchupFullScan not disabled" } 

# Disable Windows Defender DisableCatchupQuickScan
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupQuickScan")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupQuickScan" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupQuickScan" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender DisableCatchupQuickScan disabled"  }else{   write-Host -ForegroundColor red "Windows Defender DisableCatchupQuickScan not disabled" } 

# Disable Windows Defender EnableControlledFolderAccess
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableControlledFolderAccess")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableControlledFolderAccess" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableControlledFolderAccess" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender EnableControlledFolderAccess disabled"  }else{   write-Host -ForegroundColor red "Windows Defender EnableControlledFolderAccess not disabled" } 

# Disable Windows Defender EnableNetworkProtection
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableNetworkProtection")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableNetworkProtection" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableNetworkProtection" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender EnableNetworkProtection disabled"  }else{   write-Host -ForegroundColor red "Windows Defender EnableNetworkProtection not disabled" } 

# Disable Windows Defender PUAProtection
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\PUAProtection")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\PUAProtection" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\PUAProtection" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender PUAProtection disabled"  }else{   write-Host -ForegroundColor red "Windows Defender PUAProtection not disabled" } 

# Change Windows Defender RealTimeScanDirection to monitor only outgoing files
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\RealTimeScanDirection")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\RealTimeScanDirection" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\RealTimeScanDirection" -Name "value" -Type DWord -Value 2
if($?){   write-Host -ForegroundColor Green "Changed Windows Defender RealTimeScanDirection to monitor only outgoing files"  }else{   write-Host -ForegroundColor red "Windows RealTimeScanDirection not changed" } 

# Disable Windows Defender SubmitSamplesConsent
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent" -Name "value" -Type DWord -Value 2
if($?){   write-Host -ForegroundColor Green "Windows Defender SubmitSamplesConsent disabled"  }else{   write-Host -ForegroundColor red "Windows Defender SubmitSamplesConsent not disabled" } 


# Disable Windows Defender AllowEmailScanning
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowEmailScanning")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowEmailScanning" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowEmailScanning" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Windows Defender AllowEmailScanning disabled"  }else{   write-Host -ForegroundColor red "Windows Defender AllowEmailScanning not disabled" } 


}

if ($windowsfirewall -like "y") {
#DISABLE WINDOWS FIREWALL
Get-Service MpsSvc | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "Windows Firewall service disabled"  } else {   write-Host -ForegroundColor red "Windows Firewall service not disabled" } 
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False
if($?){   write-Host -ForegroundColor Green "Windows Firewall Disabled"  }else{   write-Host -ForegroundColor red "Windows Firewall not Disabled" }
# USELESS WINDOWS FIREWALL
New-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\MpsSvc -Name Start -PropertyType DWord -Value 4 -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "MpsSvc service disabled"  }else{   write-Host -ForegroundColor red "MpsSvc service not disabled" } 

}


if ($showhidden -like "y") { 
#SHOW HIDDEN FILES AND EXTENSIONS

$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $key Hidden 1
if($?){   write-Host -ForegroundColor Green "Windows Hidden Files Disabled"  }else{   write-Host -ForegroundColor red "Windows Hidden Files not Disabled" }

Set-ItemProperty $key HideFileExt 0
if($?){   write-Host -ForegroundColor Green "Windows Hidden Extensions Disabled"  }else{   write-Host -ForegroundColor red "Windows Hidden Extensions Options not Disabled" }

}


if ($ink -like "y") { 
#Disable INK
New-ItemProperty -Path HKLM:SOFTWARE\Policies\Microsoft -Name WindowsInkWorkspace -PropertyType DWord -Value 0 -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows INK disabled"  }else{   write-Host -ForegroundColor red "Windows INK not disabled" } 
}

if ($visual -like "y") { 

Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco install vcredist-all -y 
choco install vcredist2010 -y
choco install vcredist2017 -y
choco install dotnet3.5 -y 
choco install dotnet4.0 -y 
choco install dotnet4.5 -y 
choco install dotnetfx -y

choco install notepadplusplus -y
choco install 7zip -y
choco install nomacs

#FIREFOX
choco install firefox -y 
choco install ublockorigin-firefox -y

choco install qbittorrent -y 
choco install k-litecodecpackfull -y 
choco install steam -y
choco install virtualbox -y

}

if ($windowsupdate -like "y") { 
#DISABLE WINDOWS UPDATES

sc.exe stop wuauserv | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Updates Service Stoped"  }else{   write-Host -ForegroundColor red "Windows Updates Service Not Stoped" }

sc.exe config wuauserv start=disabled | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Updates Service Disabled"  }else{   write-Host -ForegroundColor red "Windows Updates Service Not Disabled" }

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v NoAutoUpdate /t REG_DWORD /d 1 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Updates Registry Disabled"  }else{   write-Host -ForegroundColor red "Windows Updates Registry not Disabled" }

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Updates Registry Disabled"  }else{   write-Host -ForegroundColor red "Windows Updates Registry not Disabled" }

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Updates Registry Options Disabled"  }else{   write-Host -ForegroundColor red "Windows Updates Registry Options not Disabled" }

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" /v Start /t REG_DWORD /d 4 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Updates Registry Start Disabled"  }else{   write-Host -ForegroundColor red "Windows Updates Registry Start not Disabled" }

}


#DISABLE USELESS SERVICES
Get-Service diagtrack | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "Windows Diagnostics Tracking Service Disabled"  }else{   write-Host -ForegroundColor red "Windows Diagnostics Tracking Service not Disabled" }
Get-Service DiagTrack | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "Windows Diagnostics Tracking Service Disabled"  }else{   write-Host -ForegroundColor red "Windows Diagnostics Tracking Service not Disabled" } 

Get-Service dmwappushservice | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "Windows Keylogger Disabled"  }else{   write-Host -ForegroundColor red "Windows Keylogger not Disabled" }

Get-Service DcpSvc | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "DcpSvc Disabled"  }else{   write-Host -ForegroundColor red "DcpSvc not Disabled" }

Get-Service OneSyncSvc | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "OneSyncSvc Disabled"  }else{   write-Host -ForegroundColor red "OneSyncSvc not Disabled" }

Get-Service WalletService | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "WalletService Disabled"  }else{   write-Host -ForegroundColor red "WalletService not Disabled" }

Get-Service diagnosticshub.standardcollector.service | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "diagnosticshub Disabled"  }else{   write-Host -ForegroundColor red "diagnosticshub not Disabled" }

#DISABLE USELESS SERVICES BY REGISTRY
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Telemetry Disabled"  }else{   write-Host -ForegroundColor red "Windows Telemetry not Disabled" } 

# REMOVE ONEDRIVE
kill -processname OneDrive, aaa -Force -Verbose -EA SilentlyContinue
if($?){   write-Host -ForegroundColor Green "One Drive process has been stoped"  }else{   write-Host -ForegroundColor Green "One Drive process is not running" } 

if (Test-Path "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe") {
"$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe /uninstall" | Out-Null
if($?){   write-Host -ForegroundColor Green "One Drive has been uninstalled"  }else{   write-Host -ForegroundColor red "One Drive uninstaller failed!" } 
}Else{
write-Host -ForegroundColor yellow "One Drive unnistaller is not present on the system"
}

Remove-Item "$env:USERPROFILE\OneDrive\*.*" -Force -ErrorAction SilentlyContinue
if($?){   write-Host -ForegroundColor Green "One Drive files removed"  }else{   write-Host -ForegroundColor red "One Drive files not Removed" } 

Remove-Item "C:\OneDriveTemp\*.*" -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "One Drive temp files Removed (Step 2)"  }else{   write-Host -ForegroundColor green "One Drive temp files not present" } 

Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive\" -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "One Drive appdata folder removed"  }else{   write-Host -ForegroundColor green "One Drive appdata folder not present" } 


Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -recurse -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows recent folder cleared"  }else{   write-Host -ForegroundColor red "Windows recent folder not cleared" } 

Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -recurse -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows automatic destinations folder cleared"  }else{   write-Host -ForegroundColor green "Windows automatic destinations folder not found" } 

Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*" -recurse -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows custom destinations folder cleared"  }else{   write-Host -ForegroundColor green "Windows custom destinations not found" } 

# Disable ShadowCopy
vssadmin delete shadows /all /quiet | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Shadowcopy removed"  }else{   write-Host -ForegroundColor green "Windows Shadowcopy already disabled" } 

# Disable SystemRestore
Disable-ScheduledTask -TaskName "Microsoft\Windows\SystemRestore\SR" -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows system restore disabled"  }else{   write-Host -ForegroundColor green "Windows system restore already disabled" } 

Get-Service swprv | Stop-Service -PassThru | Set-Service -StartupType disabled
Get-Service VSS | Stop-Service -PassThru | Set-Service -StartupType disabled

# Disable BITS service due still download windows updates even if the user does not want it
Get-Service BITS | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "BITS service disabled"  }else{   write-Host -ForegroundColor red "BITS service not disabled" } 
Get-Service netsvcs | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "BITS service disabled"  }else{   write-Host -ForegroundColor red "BITS service not disabled" } 

# Disable Ip helper due transfering a lot of strange data
Get-Service iphlpsvc | Stop-Service -PassThru | Set-Service -StartupType disabled

# Disable Delivery Optimization (DoSvc) due overriding the windows updates disable state
Get-Service DoSvc | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "Windows Delivery Optimization Service Disabled"  }else{   write-Host -ForegroundColor red "Windows Delivery Optimization Service not Disabled" } 
New-ItemProperty -Path 'HKLM:Software\Policies\Microsoft\Windows\DeliveryOptimization' -name DODownloadMode -PropertyType DWord -Value 3 -Force
if($?){   write-Host -ForegroundColor Green "Windows Delivery Optimization Service Disabled by reg"  }else{   write-Host -ForegroundColor red "Windows Delivery Optimization Service not Disabled by reg" } 
New-ItemProperty -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -name DODownloadMode -PropertyType DWord -Value 0 -Force
if($?){   write-Host -ForegroundColor Green "Windows Delivery Optimization Service Disabled by reg"  }else{   write-Host -ForegroundColor red "Windows Delivery Optimization Service not Disabled by reg" } 

New-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\WdBoot' -name Start -PropertyType DWord -Value 4 -Force

# Disable Time Brooker due to huge network usage for spying users
New-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\TimeBrokerSvc' -name Start -PropertyType DWord -Value 4 -Force
if($?){   write-Host -ForegroundColor Green "Windows Time Brooker Service Disabled"  }else{   write-Host -ForegroundColor red "Windows Time Brooker Service not Disabled" } 

# Disable fastboot due conflicts with steam
powercfg /hibernate OFF
New-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Power' -name HiberbootEnabled -PropertyType DWord -Value 0 -Force

# Disable notifications
reg add 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v DisableNotificationCenter /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v EnableBalloonTips /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer /v DisableNotificationCenter /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer /v DisableNotificationCenter /t REG_DWORD /d 1 /f

# Disable Windows Tile Notifications
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Notifications\DisallowTileNotification")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Notifications\DisallowTileNotification" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Notifications\DisallowTileNotification" -Name "value" -Type DWord -Value 1
if($?){   write-Host -ForegroundColor Green "Windows Tile Notifications disabled"  }else{   write-Host -ForegroundColor red "Windows Tile Notifications not disabled" } 

# Disable Windows Defender Enhanced Notifications
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications" -Name "value" -Type DWord -Value 1
if($?){   write-Host -ForegroundColor Green "Windows Defender Enhanced Notifications disabled"  }else{   write-Host -ForegroundColor red "Windows Defender Enhanced Notifications not disabled" } 

# Disable Windows Defender Security Center Notifications
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableNotifications")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableNotifications" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableNotifications" -Name "value" -Type DWord -Value 1
if($?){   write-Host -ForegroundColor Green "Windows Defender Security Center Notifications disabled"  }else{   write-Host -ForegroundColor red "Windows Defender Security Center Notifications not disabled" } 


# Disable AllowSuggestedAppsInWindowsInkWorkspace
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace" -Name "value" -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "AllowSuggestedAppsInWindowsInkWorkspace disabled"  }else{   write-Host -ForegroundColor red "AllowSuggestedAppsInWindowsInkWorkspace not disabled" } 

# Disable SgrmAgent
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SgrmAgent")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SgrmAgent" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SgrmAgent" -Name "Start" -Type DWord -Value 4
if($?){   write-Host -ForegroundColor Green "SgrmAgent disabled"  }else{   write-Host -ForegroundColor red "SgrmAgent not disabled" } 

# Disable SgrmBroker
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SgrmBroker")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SgrmBroker" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SgrmBroker" -Name "Start" -Type DWord -Value 4
if($?){   write-Host -ForegroundColor Green "SgrmBroker disabled"  }else{   write-Host -ForegroundColor red "SgrmBroker not disabled" } 

# Disable SgrmAgent
If (!(Test-Path "HKLM:\SYSTEM\ControlSet001\Services\SgrmAgent")) {
    New-Item -Path "HKLM:\SYSTEM\ControlSet001\Services\SgrmAgent" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\SgrmAgent" -Name "Start" -Type DWord -Value 4
if($?){   write-Host -ForegroundColor Green "SgrmAgent disabled"  }else{   write-Host -ForegroundColor red "SgrmAgent not disabled" } 

# Disable SgrmBroker
If (!(Test-Path "HKLM:\SYSTEM\ControlSet001\Services\SgrmBroker")) {
    New-Item -Path "HKLM:\SYSTEM\ControlSet001\Services\SgrmBroker" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\SgrmBroker" -Name "Start" -Type DWord -Value 4
if($?){   write-Host -ForegroundColor Green "SgrmBroker disabled"  }else{   write-Host -ForegroundColor red "SgrmBroker not disabled" } 

# xbox dvr causing fps issues
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR /v value /t REG_DWORD /d 0 /f

# RAZER THINGS THAT NOBODY USES
Get-Service Razer Chroma SDK Server | Stop-Service -PassThru | Set-Service -StartupType disabled
Get-Service Razer Chroma SDK Service | Stop-Service -PassThru | Set-Service -StartupType disabled


# ANOYING PUSH NOTIFICATIONS
Get-Service WpnService | Stop-Service -PassThru | Set-Service -StartupType disabled

# SUPERFETCH IS KNOWN TO CAUSE SLOW BOOT TIME
Get-Service SysMain | Stop-Service -PassThru | Set-Service -StartupType disabled

# WE DONT NEED TELEMETRY AGENT NVIDIA!
Get-Service NvTelemetryContainer | Stop-Service -PassThru | Set-Service -StartupType disabled

# USELESS FAX
Get-Service Fax | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "Windows Fax service disabled"  }else{   write-Host -ForegroundColor red "Windows Fax service not disabled" } 

# USELESS ADOBE UPDATES
Get-Service AdobeARMservice | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "Adobe Acrobat Update service disabled"  }else{   write-Host -ForegroundColor red "Adobe Acrobat Update service not disabled" } 
Remove-Item -path "${env:ProgramFiles(x86)}/Common Files\Adobe\ARM\" -Force
if($?){   write-Host -ForegroundColor Green "Adobe shit removed"  }else{   write-Host -ForegroundColor red "Adobe shit removed not removed" } 

# USELESS GEO
Get-Service lfsvc | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "Geo service disabled"  }else{   write-Host -ForegroundColor red "Geo service not disabled" } 

Get-Service wlidsvc | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "wlidsvc disabled"  }else{   write-Host -ForegroundColor red "wlidsvc not disabled" } 

# USELESS SecurityHealthService
New-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\SecurityHealthService -Name Start -PropertyType DWord -Value 4 -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "SecurityHealthService service disabled"  }else{   write-Host -ForegroundColor red "SecurityHealthService service not disabled" } 

# USELESS PcaSvc
Get-Service PcaSvc | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "PcaSvc service disabled"  }else{   write-Host -ForegroundColor red "PcaSvc service not disabled" } 

# USELESS DusmSvc
Get-Service DusmSvc | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "DusmSvc service disabled"  }else{   write-Host -ForegroundColor red "DusmSvc service not disabled" } 

# USELESS UsoSvc
Get-Service UsoSvc | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "UsoSvc service disabled"  }else{   write-Host -ForegroundColor red "UsoSvc service not disabled" } 

# Disable SmartScreen Filter
Write-Host "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0

# Disable SecurityHealthService
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Type DWord -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc" -Name "Start" -Type DWord -Value 4

# Disable Location Tracking
Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

Write-Host "Disabling Licence Checking..."
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket " -Type DWord -Value 0
if($?){   write-Host -ForegroundColor Green "Licence checking disabled"  }else{   write-Host -ForegroundColor red "Licence checking not disabled" } 

# Disable Feedback
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
 
# Disable Cortana
Write-Host "Disabling Cortana..."
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0

#Disable Sticky keys prompt
Write-Host "Disabling Sticky keys prompt..." 
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
 
# Show Computer shortcut on desktop
Write-Host "Showing Computer shortcut on desktop..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
  New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
  
 

# Change plan to high performace
$x = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'  
$currScheme = POWERCFG -GETACTIVESCHEME 
$y = $currScheme.Split()


if ($y[3] -eq $x) {

	write-Host -ForegroundColor yellow "You Have correct Settings, Nothing to Do!!! "
	
	} else {						
		PowerCfg -SetActive $x			
		write-Host -ForegroundColor Green "PowerScheme Sucessfully Applied"			
	}


# Disable Error reporting
Function DisableErrorReporting {
	Write-Host "Disabling Error reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}
DisableErrorReporting

Function DisableAutoLogger {
	Write-Host "Removing AutoLogger file and restricting directory..."
	$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
	If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
		Remove-Item -Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
	}
	icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
}
DisableAutoLogger

Function DisableUpdateMSRT {
	Write-Host "Disabling Malicious Software Removal Tool offering..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
}
DisableUpdateMSRT

Function DisableAutoplay {
	Write-Host "Disabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}
DisableAutoplay 

Function DisableAutorun {
	Write-Host "Disabling Autorun for all drives..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}
DisableAutorun

# Disable scheduled defragmentation task
Function DisableDefragmentation {
	Write-Host "Disabling scheduled defragmentation..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}
DisableDefragmentation

Function DisableSuperfetch {
	Write-Host "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
}
DisableSuperfetch

Function DisableHibernation {
	Write-Host "Disabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
}
DisableHibernation

# Disable Action Center
Function DisableActionCenter {
	Write-Host "Disabling Action Center..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" | Out-Null
	}
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" | Out-Null
	}

	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_TOASTS_ENABLED" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
}
DisableActionCenter

# Disable PEOPLE BAR
Function PeopleBar {
    Write-Host "Disabling People Bar..."
    If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Type DWord -Value 1
}
PeopleBar

#DISABLE WINDOWS ARSO
Function WindowsArso {
    Write-Host "Disabling Windows Winlogon Automatic Restart Sign-On..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Type DWord -Value 1
}
WindowsArso

#FIX NOT BEING ABLE TO TYPE ON WINDOWS SEARCH
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v ctfmon /t REG_SZ /d CTFMON.EXE /f | Out-Null

#FIX NOT BEING ABLE TO LINK OUTLOOK 365 ACCOUNT ON OFFICE OUTLOOK 2019
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" -Name "EnableADAL" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" -Name "DisableADALatopWAMOverride" -Type DWord -Value 1

#
#
#CAUTION THINGS
#
#

#CAUTION - DISABLING Winmgmt CAN PREVENT SOME INSTALATIONS DO WORK PROPERLY - LIKE ACAD
# Disable Windows Management Instrumentation due transfering a lot of strange data

#Get-Service Winmgmt | Stop-Service -PassThru | Set-Service -StartupType disabled

#if($?){   write-Host -ForegroundColor Green "Windows Management Instrumentation disabled"  }else{   write-Host -ForegroundColor red "Windows Management Instrumentation not disabled" } 

#New-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Winmgmt' -name Start -PropertyType DWord -Value 4 -Force

#if($?){   write-Host -ForegroundColor Green "Windows Management Instrumentation disabled by registry"  }else{   write-Host -ForegroundColor red "Windows Management Instrumentation not disabled by registry" } 


if ($reverse -like "y") { 

#CAUTION - DISABLING Winmgmt CAN PREVENT SOME INSTALATIONS DO WORK PROPERLY - LIKE ACAD
Get-Service Winmgmt | Stop-Service -PassThru | Set-Service -StartupType automatic
if($?){   write-Host -ForegroundColor DarkYellow "Windows Management Instrumentation enabled"  }else{   write-Host -ForegroundColor red "Windows Management Instrumentation not enabled" } 
New-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Winmgmt' -name Start -PropertyType DWord -Value 2 -Force
if($?){   write-Host -ForegroundColor DarkYellow "Windows Management Instrumentation enabled by registry"  }else{   write-Host -ForegroundColor red "Windows Management Instrumentation not enabled by registry" } 

#CAUTION - DISABLING WIN FIREWALL CAN PREVENT PRINT NETWORK SHARING
New-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\MpsSvc -Name Start -PropertyType DWord -Value 2 -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows firewall service enabled"  }else{   write-Host -ForegroundColor red "Windows firewall service disabled" } 


}


$bloat = Read-Host "Debloat all AppxPackages or just the blacklist (like candy crysh saga, bing news, windows maps...) (all/blacklist)"
switch ($bloat) {
	all {
	DebloatAll
	Remove-Keys
	}
	blacklist {
	DebloatBlack
	Remove-Keys
	}
}

$disablecortana = Read-Host "Disable Cortana? (y/n)"
switch ($disablecortana) {
	y {
	DisableCortana
	}
}

$unpin = Read-Host "Unpin all tiles from the start menu? (y/n)"
switch ($unpin) {
	y {
	UnpinStart	
	}
}

$remove3d = Read-Host "Remove 3D Objects from explorer 'My Computer' submenu? (y/n)"
switch ($remove3d) {
	y {
	Remove3dObjects
	}
}

Protect-Privacy

#THINGS TO DO MANUALLY
#CONFIG FIREFOX
#geo.enabled false
#general.warnOnAboutConfig false
#dom.push.enabled false
#dom.webnotifications.enabled false


## EXTRAS SUBSCRIBE LISTS FOR UBLOCK
## https://filterlists.com/lists/
## AdGuard Social Media filter
## AdGuard Tracking Protection filter
## Block Google Fonts
## Fanboy's Anti-thirdparty Fonts
## Fanboy's problematic-sites

## Credits
##https://github.com/adolfintel/Windows10-Privacy
##https://github.com/Sycnex/Windows10Debloater

Remove-PSDrive HKCR
PAUSE

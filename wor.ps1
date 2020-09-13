# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!                                         !!
# !!           SAFE TO EDIT VALUES           !!
# !!           CONFIGURATION PART            !!
# !!                                         !!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Edit values (Option) to your Choice

# Function = Option
# List of Options

$troubleshootInstalls = 0
# 0 = Do nothing. *Recomended.
# 1 = Enable essential stuff needed for some installations.
# Note: Set to 0 if you are having trouble installing something on you pc.
# Note: Known to fix these installations: windows language pack, Autodesk AutoCad and Appxs.
# Note: Top priority configuration, overrides other settings.

$beXboxSafe = 0
# 0 = Disable Xbox and Windows Live Games related stuff. *Recomended.
# 1 = Enable it.
# Note: Top priority configuration, overrides other settings.

$beBiometricSafe = 0
# 0 = Disable biometric related stuff. *Recomended.
# 1 = Enable it.
# Note: Refers to lockscreen, fingerprint reader, illuminated IR sensor or other biometric sensors.
# Note: Top priority configuration, overrides other settings.

$telemetry = 0
# 0 = Disable Telemetry. *Recomended.
# 1 = Enable Telemetry.
# Note: Microsoft uses telemetry to periodically collect information about Windows systems. It is possible to acquire information as the computer hardware serial number, the connection records for external storage devices, and traces of executed processes.
# Note: This tweak may cause Enterprise edition to stop receiving Windows updates.

$bloatware = 0
# 0 = Remove non commented bloatware in bloatwareList array. *Recomended.
# 1 = Reinstall Windows Bloatware.

$bloatwareList = @(		
	# Non commented lines will be uninstalled	
		
	# Maybe userful AppX       
	#"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
	#"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
	#"*Microsoft.BingWeather*"
	#"*Microsoft.MSPaint*"
	#"*Microsoft.MicrosoftStickyNotes*"
	#"*Microsoft.Windows.Photos*"
	#"*Microsoft.WindowsCalculator*"
	#"*Microsoft.WindowsStore*"
	#"*Microsoft.WindowsCamera*"
	
	# Unnecessary AppX Apps
	"*Microsoft.DrawboardPDF*"
	"*E2A4F912-2574-4A75-9BB0-0D023378592B*"
	"*Microsoft.Appconnector*"
	"Microsoft.3dbuilder"
	"Microsoft.3dbuilder"
	"Microsoft.BingNews"
	"Microsoft.GetHelp"
	"Microsoft.Getstarted"
	"Microsoft.Messaging"
	"*Microsoft3DViewer*"
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
	"*Microsoft.WindowsFeedbackHub*"
	"Microsoft.WindowsMaps"
	"Microsoft.WindowsSoundRecorder"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"

	# Sponsored AppX
	"*DolbyLaboratories.DolbyAccess*"
	"*Microsoft.Asphalt8Airborne*"
	"*46928bounde.EclipseManager*"
	"*ActiproSoftwareLLC*"
	"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
	"*Duolingo-LearnLanguagesforFree*"
	"*PandoraMediaInc*"
	"*CandyCrush*"
	"*BubbleWitch3Saga*"
	"*Wunderlist*"
	"*Flipboard.Flipboard*"
	"*Twitter*"
	"*Facebook*"
	"*Spotify*"
	"*Minecraft*"
	"*Royal Revolt*"
	"*Sway*"
	"*Speed Test*"
	"*FarmHeroesSaga*"   
	
	# Special Cases
	# Dont Touch
	if ($beXboxSafe -eq 0) {	
		"Microsoft.XboxGamingOverlay"
		"Microsoft.Xbox.TCUI"
		"Microsoft.XboxApp"
		"Microsoft.XboxGameOverlay"
		"Microsoft.XboxIdentityProvider"
		"Microsoft.XboxSpeechToTextOverlay"
		
	} 
	
	if ($beBiometricSafe -eq 0) {	
		"*Microsoft.BioEnrollment*"
		"*Microsoft.CredDialogHost*"
		"*Microsoft.ECApp*"
		"*Microsoft.LockApp*"		
	} 
)
		
##########
# Configuration - End
##########
#--------------------------------------------------------------------------

##########
# Global Functions - Start
##########

$ErrorActionPreference = "SilentlyContinue"
Set-ExecutionPolicy unrestricted
Write-Host "Creating PSDrive 'HKCR' (HKEY_CLASSES_ROOT). This will be used for the duration of the script as it is necessary for the removal and modification of specific registry keys."
New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
Set-MpPreference -EnableControlledFolderAccess Enabled



Function RegChange($path, $thing, $value, $desc) {
	Write-Output ($desc)
	
    If (Test-Path ("HKLM:\" + $path)) {
        Set-ItemProperty ("HKLM:\" + $path) $thing -Value $value 
    }
	If (Test-Path ("HKCU:\" + $path)) {
        Set-ItemProperty ("HKCU:\" + $path) $thing -Value $value 
    }

}

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

function serviceStatus{ 
	param($ServiceName)
	$arrService = Get-Service -Name $ServiceName
	if ($arrService.Status -ne "Running"){
		
	}
	if ($arrService.Status -eq "running"){ 
		
	}
}
#serviceStatus("MpsSvc");

Function DarkTheme {
	New-ItemProperty "HKCU:\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Value 0 -PropertyType "DWord"
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

Function ProtectPrivacy {

	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" "0" "Disabling Windows Feedback Experience program / Advertising ID"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" "0" "Stopping Cortana from being used as part of your Windows Search Function" 
	RegChange "Software\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" "0" "Disabling Windows Feedback Experience from sending anonymous data" 
	RegChange "Software\Microsoft\Siuf\Rules" "PeriodInNanoSeconds" "0" "Disabling Windows Feedback"            
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "1" "Adding Registry key to prevent bloatware apps from returning"	
	RegChange "Software\Microsoft\Windows\CurrentVersion\Holographic" "FirstRunSucceeded" "0" "Disabling Reality Portal"    
	RegChange "SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" "Value" "0" "Disabling Wi-Fi Sense"    
	RegChange "SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" "Value" "0" "Disabling Wi-Fi Sense"  
	RegChange "SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" "0" "Disabling Wi-Fi Sense"  
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoTileApplicationNotification" "1" "Disabling live tiles"  
	RegChange "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" "0" "Disabling Location Tracking"
	RegChange "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "Status" "0" "Disabling Location Tracking"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand" "0" "Disabling People icon on Taskbar"
	RegChange "Software\Policies\Microsoft\Windows\Explorer" "HidePeopleBar" "1" "Disabling People Bar"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" "0" "Disabling Activity History Feed"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" "0" "Disabling Activity History Feed"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" "0" "Disabling Activity History Feed"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" "1" "Disabling Tailored Experiences"
	RegChange "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" "0" "Disabling Link-Local Multicast Name Resolution (LLMNR) protocol"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" "AutoSetup" "0" "Disabling automatic installation of network devices"
	RegChange "SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" "0" "Disabling Remote Assistance"
	RegChange "SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" "1" "Disabling Remote Desktop"
	RegChange "SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" "1" "Disabling Remote Desktop"
	
	Set-NetConnectionProfile -NetworkCategory Public
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
   
   Write-Output "Disabling Background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
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
	Get-Service DiagTrack | Stop-Service -PassThru | Set-Service -StartupType disabled
	if($?){   write-Host -ForegroundColor Green "Windows Diagnostics Tracking Service Disabled"  }else{   write-Host -ForegroundColor red "Windows Diagnostics Tracking Service not Disabled" } 
    
	Write-Host "Removing AutoLogger file and restricting directory..."
	$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
	If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
		Remove-Item -Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
	}
	icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
	
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

Function DisablePeek {	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisablePreviewWindow" "1" "Disabling Windows Peek"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisablePreviewDesktop" "1" "Disabling Windows Peek"
	RegChange "SOFTWARE\Microsoft\Windows\DWM" "EnableAeroPeek" "0" "Disabling Windows Peek"
}

Function DisableThumbnail {	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "IconsOnly" "1" "Disabling Windows Thumbnail"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisableThumbnailCache" "1" "Disabling Windows Thumbnail"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisableThumbsDBOnNetworkFolders" "1" "Disabling Windows Thumbnail"
}


##########
# Global Functions - End
##########
#--------------------------------------------------------------------------

##########
# Program - Start
##########

if ($telemetry -eq 0) {	
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "AllowTelemetry" "0" "Disabling data collection through telemetry"  
	RegChange "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "0" "Disabling data collection through telemetry"  
	RegChange "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "0" "Disabling data collection through telemetry"  
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
}

if ($telemetry -eq 1) {	
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "AllowTelemetry" "1" "Disabling data collection through telemetry"  
	RegChange "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "1" "Disabling data collection through telemetry"  
	RegChange "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "1" "Disabling data collection through telemetry"  
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
}

if ($bloatware -eq 0) {			
	foreach ($Bloat in $bloatwareList) {
		Get-AppxPackage -Name $Bloat| Remove-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
		Write-Output "Trying to remove $Bloat."
	}	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" "0" "Adding Registry key to PREVENT bloatware apps from returning"	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" "0" "Adding Registry key to PREVENT bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" "0" "Adding Registry key to PREVENT bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" "0" "Adding Registry key to PREVENT bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" "0" "Adding Registry key to PREVENT bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" "0" "Adding Registry key to PREVENT bloatware apps from returning" 
}	

if ($bloatware -eq 1) {	
	foreach ($Bloat in $bloatwareList) {
		Get-AppxPackage -Name $Bloat| Add-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Add-AppxProvisionedPackage -Online
		Write-Output "Trying to INSTALL $Bloat."
	}	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" "1" "Adding Registry key to ALLOW bloatware apps from returning"	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" "1" "Adding Registry key to ALLOW bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" "1" "Adding Registry key to ALLOW bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" "1" "Adding Registry key to ALLOW bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" "1" "Adding Registry key to ALLOW bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" "1" "Adding Registry key to ALLOW bloatware apps from returning" 
}	

if ($beXboxSafe -eq 1) {
	$safeXboxBloatware = @(	
		"Microsoft.XboxGamingOverlay"
		"Microsoft.Xbox.TCUI"
		"Microsoft.XboxApp"
		"Microsoft.XboxGameOverlay"
		"Microsoft.XboxIdentityProvider"
		"Microsoft.XboxSpeechToTextOverlay"
	)
	foreach ($safeXboxBloatware1 in $safeXboxBloatware) {
		Get-AppxPackage -Name $safeXboxBloatware1| Add-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $safeXboxBloatware1 | Add-AppxProvisionedPackage -Online
		Write-Output "Trying to install $safeXboxBloatware1."
	}
}

if ($beBiometricSafe -eq 1) {
	$safebeBiometricSafe = @(	
		"*Microsoft.BioEnrollment*"
		"*Microsoft.CredDialogHost*"
		"*Microsoft.ECApp*"
		"*Microsoft.LockApp*"
	)
	foreach ($safebeBiometricSafe1 in $safebeBiometricSafe) {
		Get-AppxPackage -Name $safebeBiometricSafe1| Add-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $safebeBiometricSafe1 | Add-AppxProvisionedPackage -Online
		Write-Output "Trying to install $safebeBiometricSafe1."
	}
}

if ($troubleshootInstalls -eq 1) {
	Write-Output "Troubleshoot Install: Windows Management Instrumentation service enabled."
	Get-Service Winmgmt | Stop-Service -PassThru | Set-Service -StartupType automatic
	
	Write-Output "Troubleshoot Install: Windows Management Instrumentation enabled by registry."
	New-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Winmgmt' -name Start -PropertyType DWord -Value 2 -Force
	
	Write-Output "Troubleshoot Install: Windows firewall service enabled by registry."
	New-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\MpsSvc -Name Start -PropertyType DWord -Value 2 -Force -EA SilentlyContinue | Out-Null	
	
	Write-Output "Troubleshoot Install: Windows Firewall enabled by registry."
	RegChange "Software\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" "0" "Enabling Windows Anti Spyware - DisableAntiSpyware - Windows Firewall"
	
	Write-Output "Troubleshoot Install: Windows Firewall enabled by Get-Service."
	Get-Service MpsSvc | Stop-Service -PassThru | Set-Service -StartupType automatic
	
	Write-Output "Troubleshoot Install: Windows Firewall enabled by Get-NetFirewallProfile."
	Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled True
}

##########
# Program - End
##########
#--------------------------------------------------------------------------


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
function Takeown-Registry($key) {
    # TODO does not work for all root keys yet
    switch ($key.split('\')[0]) {
        "HKEY_CLASSES_ROOT" {
            $reg = [Microsoft.Win32.Registry]::ClassesRoot
            $key = $key.substring(18)
        }
        "HKEY_CURRENT_USER" {
            $reg = [Microsoft.Win32.Registry]::CurrentUser
            $key = $key.substring(18)
        }
        "HKEY_LOCAL_MACHINE" {
            $reg = [Microsoft.Win32.Registry]::LocalMachine
            $key = $key.substring(19)
        }
    }

    # get administraor group
    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $admins = $admins.Translate([System.Security.Principal.NTAccount])

    # set owner
    $key = $reg.OpenSubKey($key, "ReadWriteSubTree", "TakeOwnership")
    $acl = $key.GetAccessControl()
    $acl.SetOwner($admins)
    $key.SetAccessControl($acl)

    # set FullControl
    $acl = $key.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admins, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)
}
Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend")

if ($windowsdefender -like "y") { 
#DISABLE WINDOWS DEFENDER
RegChange "Software\Policies\Microsoft\Windows Defender" "DisableConfig" "1" "Disabling Windows Anti Spyware - DisableConfig"
RegChange "Software\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" "1" "Disabling Windows Anti Spyware - DisableAntiSpyware"

RegChange "SYSTEM\CurrentControlSet\Services\WdBoot" "Start" "4" "Disabling WdBoot (Windows Defender)"
RegChange "SYSTEM\CurrentControlSet\Services\WdFilter" "Start" "4" "Disabling WdFilter (Windows Defender)"
RegChange "SYSTEM\CurrentControlSet\Services\WdNisDrv" "Start" "4" "Disabling WdNisDrv (Windows Defender)"
RegChange "SYSTEM\CurrentControlSet\Services\WdNisSvc" "Start" "4" "Disabling WdNisSvc (Windows Defender)"
RegChange "SYSTEM\CurrentControlSet\Services\WinDefend" "Start" "4" "Disabling WinDefend (Windows Defender)"
RegChange "SYSTEM\CurrentControlSet\Services\wscsvc" "Start" "4" "Disabling Windows Security Service Center"
RegChange "SYSTEM\CurrentControlSet\Services\SecurityHealthService" "Start" "4" "Disabling SecurityHealthService (Windows Defender)"
RegChange "SYSTEM\CurrentControlSet\Services\Sense" "Start" "4" "Disabling Sense (Windows Defender)"

RegChange "SYSTEM\ControlSet001\Services\WinDefend" "Start" "4" "Disabling WinDefend (Windows Defender)"

sc.exe config WinDefend start=disabled | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Updates Service Disabled"  }else{   write-Host -ForegroundColor red "Windows Updates Service Not Disabled" }

Set-MpPreference -DisableRealtimeMonitoring $true -EA SilentlyContinue
if($?){   write-Host -ForegroundColor Green "Windows Defender Current Session Disabled"  }else{   write-Host -ForegroundColor Green "Windows Defender Current Session not running" }

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
choco install dotnet4.0 -y 
choco install dotnet4.5 -y 
choco install dotnetfx -y

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

Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
	
	
}


#DISABLE USELESS SERVICES


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

$remove3d = Read-Host "Enable Dark Theme? (y/n)"
switch ($remove3d) {
	y {
	DarkTheme
	}
}

$removePeek = Read-Host "Disable Windows Peek? (y/n)"
switch ($removePeek) {
	y {
	DisablePeek
	}
}

$DisableThumbnail = Read-Host "Disable Windows files thumbnails? (y/n)"
switch ($DisableThumbnail) {
	y {
	DisableThumbnail
	}
}

$DisableBack = Read-Host "Disable Background Access? (y/n)"
switch ($DisableBack) {
	y {
	DisableBackgroundApps
	}
}

ProtectPrivacy

#THINGS TO DO MANUALLY
#CONFIG FIREFOX
#https://addons.mozilla.org/pt-BR/firefox/addon/dark-theme-for-firefox/

#geo.enabled false
#general.warnOnAboutConfig false
#dom.push.enabled false
#dom.webnotifications.enabled false
#app.update.auto false
#identity.fxaccounts.enabled false
#privacy.firstparty.isolate true
#privacy.firstparty.isolate.block_post_message true
#privacy.resistFingerprinting true
#browser.cache.offline.enable false
#browser.send_pings false
#browser.sessionstore.max_tabs_undo 0
#dom.battery.enabled false
#dom.event.clipboardevents.enabled false
#browser.startup.homepage_override.mstone ignore
#browser.cache.disk.smart_size false
#browser.cache.disk.capacity
#dom.event.contextmenu.enabled false


## EXTRAS SUBSCRIBE LISTS FOR UBLOCK
## https://filterlists.com/lists/
## AdGuard Social Media filter
## AdGuard Tracking Protection filter
## Fanboy's Anti-thirdparty Fonts
## ABP Anti-Circumvention Filter List

## NOTES
## DHCP REQUIRED FOR VPN
## TELEPHONY REQUIRED FOR PPOE
## DISABLE wisvc
## DISABLING WIN FIREWALL CAN PREVENT PRINT NETWORK SHARING


## Credits
## https://github.com/builtbybel/debotnet
## https://github.com/Disassembler0/Win10-Initial-Setup-Script
## https://gist.github.com/alirobe/7f3b34ad89a159e6daa1
## https://github.com/adolfintel/Windows10-Privacy
## https://github.com/Sycnex/Windows10Debloater
## http://www.blackviper.com/service-configurations/black-vipers-windows-10-service-configurations/

Remove-PSDrive HKCR
PAUSE

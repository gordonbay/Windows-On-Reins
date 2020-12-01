# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!                                         !!
# !!          SAFE TO EDIT VALUES            !!
# !!          CONFIGURATION START            !!
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
# 0 = Disable Xbox and Windows Live Games related stuff like Game Bar. *Recomended.
# 1 = Enable it.
# Note: Top priority configuration, overrides other settings.

$beBiometricSafe = 0
# 0 = Disable biometric related stuff. *Recomended.
# 1 = Enable it.
# Note: Refers to lockscreen, fingerprint reader, illuminated IR sensor or other biometric sensors.
# Note: Top priority configuration, overrides other settings.

$beAeroPeekSafe = 0
# 0 = Disable Windows Aero Peek. *Recomended.
# 1 = Enable it to Windows deafaults.
# Note: Top priority configuration, overrides other settings.

$beThumbnailSafe = 1
# 0 = Disable Windows Thumbnails. *Recomended.
# 1 = Enable it to Windows deafaults.
# Note: Refers to the use of thumbnails instead of icon to some files.
# Note: Top priority configuration, overrides other settings.

$beCastSafe = 0
# 0 = Disable Casting. *Recomended.
# 1 = Enable it.  
# Note: Refers to the Windows ability to Cast screen to another device and or monitor, PIP (Picture-in-picture), projecting to another device.
# Note: Top priority configuration, overrides other settings.

$beVpnPppoeSafe = 1
# 0 = Will make the system safer against DNS cache poisoning but VPN or PPPOE conns may stop working. *Recomended.
# 1 = This script will not mess with stuff required for VPN or PPPOE to work.  
# Note: Set it to 1 if you pretend to use VPN, PPP conns or having trouble with internet.

$NvidiaControlPanel = 1
# 0 = Remove Nvidia Appx.
# 1 = Install Nvidia control panel. *Recomended.
# Note: The script will check if your GPU vendor is Nvidia
# Note: Refers to the new Nvidia Appx. Nvidia driver install dont cames with control panel anymore.

$darkTheme = 1
# 0 = Use Windows and apps default light theme.
# 1 = Enable dark theme. *Recomended.

$draculaThemeNotepad = 1
# 0 = Disable Dracula theme for Notepad++.
# 1 = Enable Dracula theme for Notepad++. *Recomended.

$telemetry = 0
# 0 = Disable Telemetry. *Recomended.
# 1 = Enable Telemetry.
# Note: Microsoft uses telemetry to periodically collect information about Windows systems. It is possible to acquire information as the computer hardware serial number, the connection records for external storage devices, and traces of executed processes.
# Note: This tweak may cause Enterprise edition to stop receiving Windows updates.

$disableSMBServer = 1
# 0 = Enable SMB Server. 
# 1 = Disable it. *Recomended.
# Note: SMB Server is used for file and printer sharing.

$disablelastaccess = 1
# 0 = Enable it.
# 1 = Disable last file access date. *Recomended.

$doQualityOfLifeStuff = 1
# 0 = Reverse system settings to default.
# 1 = Perform routines to increase quality of life. *Recomended.

$doPerformanceStuff = 1
# 0 = Reverse system settings to default.
# 1 = Perform routines to increase system performance. *Recomended.

$doPrivacyStuff = 1
# 0 = Reverse system settings to default.
# 1 = Perform routines to increase system privacy. *Recomended.

$doSecurityStuff = 1
# 0 = Reverse system settings to default.
# 1 = Perform routines to increase system security. *Recomended.

$disableSystemRestore = 1
# 0 = Enable system restore
# 1 = Disable system restore. *Recomended.

$firefoxSettings = 1
# 0 = Keep Firefox settings unchanged.
# 1 = Apply my Firefox settings. *Recomended.

$disableBloatware = 1
# 0 = Install Windows Bloatware that are not commented in bloatwareList array.
# 1 = Remove non commented bloatware in bloatwareList array. *Recomended.
# Note: On bloatwareList comment the lines on Appxs that you want to keep/install.

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
	
	if ($NvidiaControlPanel -eq 0) {
		"*NVIDIACorp.NVIDIAControlPanel*"
	}
	
	if ($beCastSafe -eq 0) {
		"*Microsoft.PPIP*"
	}
)
		

##########
# Configuration - End
##########
#--------------------------------------------------------------------------

##########
# Global Functions - Start
##########

$env:POWERSHELL_TELEMETRY_OPTOUT = 'yes';
$ErrorActionPreference = "SilentlyContinue"
Set-ExecutionPolicy unrestricted
Write-Host "Creating PSDrive 'HKCR' (HKEY_CLASSES_ROOT). This will be used for the duration of the script as it is necessary for the removal and modification of specific registry keys."
New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

# Enable Controlled Folder Access (Defender Exploit Guard feature) - Applicable since 1709, requires Windows Defender to be enabled
Write-Output "Enabling Controlled Folder Access..."
Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue

Function hardenPath($path, $desc) {
	Write-Output ($desc) 
	$object = "System"
	$permission = "Modify, ChangePermissions"
	
	$FileSystemRights = [System.Security.AccessControl.FileSystemRights]$permission
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]"None"
    $AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
    $Account = New-Object System.Security.Principal.NTAccount($object)
    $FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)
    $DirectorySecurity = Get-ACL $path
    $DirectorySecurity.RemoveAccessRuleAll($FileSystemAccessRule)
    Set-ACL $path -AclObject $DirectorySecurity
		
	$Acl = Get-ACL $path
	$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule("System","FullControl","ContainerInherit,Objectinherit","none","Deny")
	$Acl.AddAccessRule($AccessRule)
	Set-Acl $path $Acl
}

	
Function regDelete($path, $desc) {
	Write-Output ($desc)  	
	
    If (Test-Path ("HKLM:\" + $path)) {
        Remove-Item ("HKLM:\" + $path) -Recurse -Force
    }
	If (Test-Path ("HKCU:\" + $path)) {
        Remove-Item ("HKCU:\" + $path) -Recurse -Force
    }
}	

Function itemDelete($path, $desc) {
	Write-Output ($desc) 
	
	if (!($path | Test-Path)) { 
		write-Host -ForegroundColor Green ($path + " dont exists.")
		return	
	}
	
	takeown /F $path	

	$Acl = Get-ACL $path
	$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","FullControl","ContainerInherit,Objectinherit","none","Allow")
	$Acl.AddAccessRule($AccessRule)
	Set-Acl $path $Acl

	$Acl = Get-ACL $path
	$username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
	$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule($username,"FullControl","ContainerInherit,Objectinherit","none","Allow")
	$Acl.AddAccessRule($AccessRule)
	Set-Acl $path $Acl

	$files = Get-ChildItem $path
	foreach ($file in $files) {
		$Item = $path + "\" + $file.name

		takeown /F $Item

		$Acl = Get-ACL $Item
		$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","FullControl","Allow")
		$Acl.AddAccessRule($AccessRule)
		Set-Acl $Item $Acl

		$Acl = Get-ACL $Item
		$username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
		$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule($username,"FullControl","Allow")
		$Acl.AddAccessRule($AccessRule)
		Set-Acl $Item $Acl

		$whatIs = (Get-Item $Item) -is [System.IO.DirectoryInfo]

		if ($whatIs -eq $False){
			Set-ItemProperty $Item -name IsReadOnly -value $false
			try {
				Remove-Item -Path $Item -Recurse -Force -ErrorAction Stop;
				write-Host -ForegroundColor Green ($file.name + " deleted.")
			}
			catch {			
				write-Host -ForegroundColor red ($file.name + " NOT deleted.") 

			}
		}
	}
}

Function clearCaches {
	regDelete "Software\Microsoft\Windows\CurrentVersion\CloudStore\*" "Clearing all start menu items..." 
	regDelete "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*" "Clearing network profiles..."
	regDelete "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\*" "Clearing managed network profiles..."
	regDelete "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\*" "Clearing managed network profiles..."
	regDelete "SYSTEM\CurrentControlSet\Enum\USBSTOR\*" "Clearing USB history..."
	regDelete "SYSTEM\CurrentControlSet\Control\usbflags\*" "Clearing USB history..."
	regDelete "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\Intranet\*" "Clearing intranet history..."
	regDelete "Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\*" "Clearing commands history..."
	regDelete "Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\*" "Clearing typed paths cache..."
	regDelete "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\*" "Clearing recent docs cache..."
	regDelete "SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\*" "Clearing compat cache..."
	regDelete "Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\*" "Clearing mapped drives cache..."
	
	Stop-Process -ProcessName explorer -Force
	
	Remove-Item $env:TEMP\*.* -confirm:$false -Recurse -Force
	Get-ChildItem $env:TEMP\*.* | Remove-Item -confirm:$false -Recurse -Force
	Remove-Item $env:WINDIR\Prefetch\*.* -confirm:$false -Recurse -Force
	Get-ChildItem $env:WINDIR\Prefetch\*.* | Remove-Item -confirm:$false -Recurse -Force
	Remove-Item $env:WINDIR\*.dmp -confirm:$false -Recurse -Force
	
	
	taskkill /F /IM explorer.exe
	Start-Sleep -Seconds 3
		
	itemDelete "$env:LocalAppData\Microsoft\Windows\Explorer" "Clearing thumbs files cache..."
	itemDelete "$env:LocalAppData\Microsoft\Windows\Recent" "Clearing recent folder cache..."
	itemDelete "$env:LocalAppData\Microsoft\Windows\Recent\AutomaticDestinations" "Clearing automatic destinations folder cache..."
	itemDelete "$env:LocalAppData\Microsoft\Windows\Recent\CustomDestinations" "Clearing custom destinations folder cache..."

	start explorer.exe	
}
	
Function RegChange($path, $thing, $value, $desc, $type) {
	Write-Output ($desc)	
	
   # String: Specifies a null-terminated string. Equivalent to REG_SZ.
   # ExpandString: Specifies a null-terminated string that contains unexpanded references to environment variables that are expanded when the value is retrieved. Equivalent to REG_EXPAND_SZ.
   # Binary: Specifies binary data in any form. Equivalent to REG_BINARY.
   # DWord: Specifies a 32-bit binary number. Equivalent to REG_DWORD.
   # MultiString: Specifies an array of null-terminated strings terminated by two null characters. Equivalent to REG_MULTI_SZ.
   # Qword: Specifies a 64-bit binary number. Equivalent to REG_QWORD.
   # Unknown: Indicates an unsupported registry data type, such as REG_RESOURCE_LIST.

	$type2 = "String"
	if (-not ([string]::IsNullOrEmpty($type)))
	{
		$type2 = $type
	}
	
	If (!(Test-Path ("HKLM:\" + $path))) {
		New-Item -Path ("HKLM:\" + $path) -Force
	}
	If (!(Test-Path ("HKCU:\" + $path))) {
        New-Item -Path ("HKCU:\" + $path) -Force
    }
	
    If (Test-Path ("HKLM:\" + $path)) {
        Set-ItemProperty ("HKLM:\" + $path) $thing -Value $value -Type $type2 -PassThru:$false
    }
	If (Test-Path ("HKCU:\" + $path)) {
        Set-ItemProperty ("HKCU:\" + $path) $thing -Value $value -Type $type2 -PassThru:$false
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
	Write-Output $("Checking service " + $ServiceName + " status...")
	$arrService = Get-Service -Name $ServiceName	
	if ($arrService.Status -eq "Stopped"){
		Write-Output $("Service " + $ServiceName + " is stopped.")
		return "stopped"
	}
}
#serviceStatus("Schedule");

function killProcess{ 
	param($processName)
	Write-Output $("Trying to gracefully close " + $processName + " ...")

	$firefox = Get-Process $processName -ErrorAction SilentlyContinue
	if ($firefox) {
		$firefox.CloseMainWindow()
		Sleep 3
		if (!$firefox.HasExited) {
			Write-Output $("Killing " + $processName + " ...")
			$firefox | Stop-Process -Force
		}
	}
	return
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
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "1" "Adding Registry key to prevent bloatware apps from returning"	
	RegChange "Software\Microsoft\Windows\CurrentVersion\Holographic" "FirstRunSucceeded" "0" "Disabling Reality Portal"	
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoTileApplicationNotification" "1" "Disabling live tiles"  
	RegChange "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" "0" "Disabling Location Tracking"
	RegChange "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "Status" "0" "Disabling Location Tracking"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand" "0" "Disabling People icon on Taskbar"
	RegChange "Software\Policies\Microsoft\Windows\Explorer" "HidePeopleBar" "1" "Disabling People Bar"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" "0" "Disabling Activity History Feed"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" "0" "Disabling Activity History Feed"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" "0" "Disabling Activity History Feed"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" "1" "Disabling Tailored Experiences"	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" "AutoSetup" "0" "Disabling automatic installation of network devices"
	RegChange "SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" "0" "Disabling Remote Assistance"
	RegChange "SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" "1" "Disabling Remote Desktop"
	RegChange "SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" "1" "Disabling Remote Desktop"
	
	Set-NetConnectionProfile -NetworkCategory Public
   
	Write-Output "Disabling Background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
	}	
	
	if ($(serviceStatus("Schedule")) -eq "running") {
		Write-Output "Disabling scheduled tasks, Consolidator, UsbCeip, DmClient..."
		Get-ScheduledTask  Consolidator | Disable-ScheduledTask
		Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
		Get-ScheduledTask  DmClient | Disable-ScheduledTask
		Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask
	}
	
	write-Host "Diagnostics Tracking Service is a Windows keylogger to collect all the speeches, calendar, contacts, typing, inking informations." -ForegroundColor Green -BackgroundColor Black
    Write-Output "Stopping and disabling DiagTrack"
	Get-Service DiagTrack | Stop-Service -PassThru | Set-Service -StartupType disabled
    
	write-Host "dmwappushservice is a Windows keylogger to collect all the speeches, calendar, contacts, typing, inking informations." -ForegroundColor Green -BackgroundColor Black
	Write-Output "Stopping and disabling dmwappushservice"
	Get-Service dmwappushservice | Stop-Service -PassThru | Set-Service -StartupType disabled
	
	$path = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
	itemDelete $path "Clearing ETL Autologs..."
	hardenPath $path "Hardening ETL Autologs folder..."
}

Function unProtectPrivacy {
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" "1" "Enabling Windows Feedback Experience program / Advertising ID"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" "1" "Enabling Cortana from being used as part of your Windows Search Function" 
	RegChange "Software\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" "1" "Enabling Windows Feedback Experience from sending anonymous data"      
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "0" "Adding Registry key to allow bloatware apps from returning"	
	RegChange "Software\Microsoft\Windows\CurrentVersion\Holographic" "FirstRunSucceeded" "1" "Enabling Reality Portal" 
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoTileApplicationNotification" "0" "Enabling live tiles"  
	RegChange "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" "1" "Enabling Location Tracking"
	RegChange "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "Status" "1" "Enabling Location Tracking"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand" "1" "Enabling People icon on Taskbar"
	RegChange "Software\Policies\Microsoft\Windows\Explorer" "HidePeopleBar" "0" "Enabling People Bar"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" "1" "Enabling Activity History Feed"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" "1" "Enabling Activity History Feed"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" "1" "Enabling Activity History Feed"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" "0" "Enabling Tailored Experiences"	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" "AutoSetup" "1" "Enabling automatic installation of network devices"
	RegChange "SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" "1" "Enabling Remote Assistance"
	RegChange "SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" "0" "Enabling Remote Desktop"
	RegChange "SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" "0" "Enabling Remote Desktop"
	
	Write-Output "Setting network to private..."
	Set-NetConnectionProfile -NetworkCategory Private
   
   Write-Output "Enabling Background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 0
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 0
	}
	
	if ($(serviceStatus("Schedule")) -eq "running") {
		Write-Output "Enabling scheduled tasks, Consolidator, UsbCeip, DmClient..."  
		Get-ScheduledTask  Consolidator | Enable-ScheduledTask
		Get-ScheduledTask  UsbCeip | Enable-ScheduledTask
		Get-ScheduledTask  DmClient | Enable-ScheduledTask
		Get-ScheduledTask  DmClientOnScenarioDownload | Enable-ScheduledTask
	}
	
    write-Host "Diagnostics Tracking Service is a Windows keylogger to collect all the speeches, calendar, contacts, typing, inking informations." -ForegroundColor Green -BackgroundColor Black
    Write-Output "Enabling DiagTrack..."
	Get-Service DiagTrack | Stop-Service -PassThru | Set-Service -StartupType automatic
    
	write-Host "dmwappushservice is a Windows keylogger to collect all the speeches, calendar, contacts, typing, inking informations." -ForegroundColor Green -BackgroundColor Black
	Write-Output "Enabling dmwappushservice"
	Get-Service dmwappushservice | Stop-Service -PassThru | Set-Service -StartupType automatic  
}

Function qualityOfLife {
	Get-Service VMwareHostd | Stop-Service -PassThru | Set-Service -StartupType disabled
	RegChange "SYSTEM\CurrentControlSet\services\VMwareHostd" "Start" "4" "Disabling VMware host..." "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" "1" "Disabling Windows Winlogon Automatic Restart Sign-On..." "DWord"	
	RegChange "Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_TOASTS_ENABLED" "0" "Disabling Action Center global toasts..." "DWord"	
	RegChange "SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableNotificationCenter" "1" "Disabling Action Center notification center..." "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" "ToastEnabled" "0" "Disabling Action Center toast push notifications..." "DWord"
	RegChange "Control Panel\Accessibility" "DynamicScrollbars " "0" "Disabling dynamic scrollbars..." "DWord"
	
	write-Host "Fast Boot is known to cause problems with steam" -ForegroundColor Green -BackgroundColor Black 
	RegChange "SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" "0" "Disabling Fast boot..." "DWord"
	powercfg /hibernate OFF
	
	New-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Power' -name HiberbootEnabled -PropertyType DWord -Value 0 -Force
	
	write-Host "RAZER services that allows third party software to ness with your keyboard backlight" -ForegroundColor Green -BackgroundColor Black 	
	Write-Output "Disabling Razer Chroma SDK Server..."
	Get-Service Razer Chroma SDK Server | Stop-Service -PassThru | Set-Service -StartupType disabled
	Write-Output "Disabling Razer Chroma SDK Service..."
	Get-Service Razer Chroma SDK Service | Stop-Service -PassThru | Set-Service -StartupType disabled

	Write-Output "Disabling WpnService, push notification anoyance service..."
	Get-Service WpnService | Stop-Service -PassThru | Set-Service -StartupType disabled
	
	RegChange "System\CurrentControlSet\Services\WpnUserService*" "Start" "4" "Disabling WpnUserService, push notification anoyance service..." "DWord"
	
}

Function qualityOfLifeOff {
	Get-Service VMwareHostd | Set-Service -StartupType automatic
	RegChange "SYSTEM\CurrentControlSet\services\VMwareHostd" "Start" "2" "Enabling VMware host..." "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" "0" "Enabling Windows Winlogon Automatic Restart Sign-On..." "DWord"
	RegChange "Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_TOASTS_ENABLED" "1" "Enabling Action Center toasts..." "DWord"
	RegChange "SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableNotificationCenter" "0" "Enabling Action Center notification center..." "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" "ToastEnabled" "1" "Enabling Action Center toast push notifications..." "DWord"
	RegChange "Control Panel\Accessibility" "DynamicScrollbars " "1" "Enabling dynamic scrollbars..." "DWord"
	
	write-Host "Fast Boot is known to cause problems with steam" -ForegroundColor Green -BackgroundColor Black 
	RegChange "SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" "1" "Enabling Fast boot..." "DWord"
	powercfg /hibernate ON
	
	write-Host "RAZER services that allows third party software to ness with your keyboard backlight" -ForegroundColor Green -BackgroundColor Black 	
	Write-Output "Enabling Razer Chroma SDK Server..."
	Get-Service Razer Chroma SDK Server | Stop-Service -PassThru | Set-Service -StartupType automatic
	Write-Output "Enabling Razer Chroma SDK Service..."
	Get-Service Razer Chroma SDK Service | Stop-Service -PassThru | Set-Service -StartupType automatic

	Write-Output "Enabling WpnService, push notification anoyance service..."
	Get-Service WpnService | Stop-Service -PassThru | Set-Service -StartupType automatic
	
	RegChange "System\CurrentControlSet\Services\WpnUserService*" "Start" "2" "Enabling WpnUserService, push notification anoyance service..." "DWord"
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

Function EnablePeek {	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisablePreviewWindow" "0" "Enabling Windows Peek Thumbnail" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisablePreviewDesktop" "0" "Enabling Windows Peek Desktop Preview" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\DWM" "EnableAeroPeek" "1" "Enabling Windows Peek" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ExtendedUIHoverTime" "0" "Enabling Windows Peek Taskbar Thumbnail" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\DWM" "AlwaysHibernateThumbnails" "1" "Enabling Windows Peek Taskbar Thumbnail Cache" "DWord"
}

Function DisablePeek {	
	if ($beAeroPeekSafe -eq 1) {
		Write-Host "Aero Peek NOT disabled because of the beAeroPeekSafe configuration" -ForegroundColor Yellow -BackgroundColor DarkGreen
		return
	}	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisablePreviewWindow" "1" "Disabling Windows Peek Thumbnail" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisablePreviewDesktop" "1" "Disabling Windows Peek Desktop Preview" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\DWM" "EnableAeroPeek" "0" "Disabling Windows Peek" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ExtendedUIHoverTime" "30000" "Disabling Windows Peek Taskbar Thumbnail" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\DWM" "AlwaysHibernateThumbnails" "0" "Disabling Windows Peek Taskbar Thumbnail Cache" "DWord"
}

Function EnableThumbnail {	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "IconsOnly" "0" "Enabling Windows Thumbnail" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisableThumbnailCache" "0" "Enabling Windows Thumbnail" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisableThumbsDBOnNetworkFolders" "0" "Enabling Windows Thumbnail" "DWord"
}

Function DisableThumbnail {	
	if ($beThumbnailSafe -eq 1) {
		Write-Host "Windows Thumbnails NOT disabled because of the beThumbnailSafe configuration" -ForegroundColor Yellow -BackgroundColor DarkGreen
		return
	}
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "IconsOnly" "1" "Disabling Windows Thumbnail" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisableThumbnailCache" "1" "Disabling Windows Thumbnail" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisableThumbsDBOnNetworkFolders" "1" "Disabling Windows Thumbnail" "DWord"
}

# Disable Xbox features
Function DisableXboxFeatures {
	Write-Output "Disabling Xbox features..."
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	
	if ($(serviceStatus("Schedule")) -eq "running") {
		Write-Output "Disabling Xbox scheduled tasks..."
		Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask
		Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask
	}
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
}

# Prefetch-files contain metadata information about the last run of the program, how many times it was run, which logical drive a program was run and dlls used.
Function EnablePrefetcher {	
	RegChange "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" "3" "Enabling Prefetcher" "DWord"
}
Function DisablePrefetcher {	
	RegChange "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" "0" "Disabling Prefetcher" "DWord"
}

# 
Function DisableDnsCache {
	if ($beVpnPppoeSafe -eq 1) {
		Write-Host "DNS cache NOT disabled because of the beVpnPppoeSafe configuration" -ForegroundColor Yellow -BackgroundColor DarkGreen
		return
	}
	
	Write-Output "Flushing DNS."
	ipconfig /flushDNS
	RegChange "SYSTEM\CurrentControlSet\services\Dnscache" "Start" "4" "Disabling DNS Cache Service" "DWord"
}

Function EnableDnsCache {	
	RegChange "SYSTEM\CurrentControlSet\services\Dnscache" "Start" "2" "Enabling DNS Cache Service" "DWord"
}

Function EnableMemoryDump {
	RegChange "SYSTEM\CurrentControlSet\Control\CrashControl" "CrashDumpEnabled" "1" "Enabling Memory Dump" "DWord"
}

Function DisableMemoryDump {
	RegChange "SYSTEM\CurrentControlSet\Control\CrashControl" "CrashDumpEnabled" "0" "Disabling Memory Dump" "DWord"
}

Function GPUVendor {
	Write-Output "Checking your GPU vendor..."
	$myGPU = Get-WmiObject win32_VideoController
	if ($myGPU.name -like '*nvidia*') {
		write-host 'GPU vendor is Nvidia'
		return "nvidia"				
	}
}


Function installDraculaNotepad {
	Write-Output "Checking internet connection..." 
	
	$HTTP_Request = [System.Net.WebRequest]::Create('http://google.com')
	$HTTP_Response = $HTTP_Request.GetResponse()
	$HTTP_Status = [int]$HTTP_Response.StatusCode

	If ($HTTP_Status -eq 200) {
		Write-Output "Conected to the internet." 
	}
	Else {
		Write-Output "NOT conected to the internet." 
		return
	}

	If ($HTTP_Response -eq $null) { } 
	Else { $HTTP_Response.Close() }

	
	Write-Output "Checking if Notepad++ is running..." 	
	if((get-process "Notepad++" -ea SilentlyContinue) -eq $Null){        
		Write-Output "Notepad++ not running." 
	} else { 
		$restartNeeded = 1
		Write-Host "Notepad++ is running and will be killed. Press any key to continue..." -ForegroundColor Yellow -BackgroundColor DarkGreen
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
		killProcess("notepad++");
	}

	Write-Output "Downloading Dracula Theme for Notepad++..." 
	$url = "https://raw.githubusercontent.com/dracula/notepad-plus-plus/master/Dracula.xml"
	$output = "$Env:USERPROFILE\AppData\Roaming\Notepad++\themes\Dracula.xml"
	$start_time = Get-Date

	$wc = New-Object System.Net.WebClient
	$wc.DownloadFile($url, $output)

	Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)" 

	$file = "$Env:USERPROFILE\AppData\Roaming\Notepad++\config.xml"
	$OpenTag = 'name="stylerTheme" path="'
	$CloseTag = '" />'
	$NewText = $OpenTag + "$Env:USERPROFILE\AppData\Roaming\Notepad++\themes\Dracula.xml" + $CloseTag
	(Get-Content $file) | Foreach-Object {$_ -replace "$OpenTag.*$CloseTag", $NewText} | Set-Content $file
	
	if ($restartNeeded -eq 1) {	
		Write-Output "Starting Notepad++" 
		Start notepad++
	}
}

Function uninstallDraculaNotepad {
	Write-Output "Checking if Notepad++ is running..." 	
	if((get-process "Notepad++" -ea SilentlyContinue) -eq $Null){
		Write-Output "Notepad++ not running." 
	} else { 
		$restartNeeded = 1
		Write-Host "Notepad++ is running and will be killed. Press any key to continue..." -ForegroundColor Yellow -BackgroundColor DarkGreen
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
		killProcess("notepad++");
	}
	
	$file = "$Env:USERPROFILE\AppData\Roaming\Notepad++\config.xml"
	$OpenTag = 'name="stylerTheme" path="'
	$CloseTag = '" />'
	$NewText = $OpenTag + "$Env:USERPROFILE\AppData\Roaming\Notepad++\stylers.xml" + $CloseTag
	(Get-Content $file) | Foreach-Object {$_ -replace "$OpenTag.*$CloseTag", $NewText} | Set-Content $file
	
	if ($restartNeeded -eq 1) {	
		Write-Output "Starting Notepad++" 
		Start notepad++
	}
}	


# Imposes security risk for layer-4 name resolution spoofing attacks, ARP poisoning, KARMA attack and cache poisoning.
Function DisableNetBIOS {
	RegChange "SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" "NetbiosOptions" "2" "Disabling NetBIOS over TCP/IP..." "DWord"	
}

Function EnableNetBIOS {
	RegChange "SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" "NetbiosOptions" "0" "Enabling NetBIOS over TCP/IP..." "DWord"
}

# Link-Local Multicast Name Resolution (LLMNR) protocol, a protocol that allow name resolution without the requirement of a DNS server. LLMNR is a secondary name resolution protocol. 
# With LLMNR, queries are sent using multicast over a local network link on a single subnet from a client computer to another client computer on the same subnet that also has LLMNR enabled.
# Imposes security risk for layer-4 name resolution spoofing attacks, ARP poisoning, KARMA attack and cache poisoning.
Function DisableLLMNR {
	RegChange "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" "0" "Disabling Link-Local Multicast Name Resolution (LLMNR) protocol" "DWord"
}

Function EnableLLMNR {
	RegChange "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" "1" "Enabling Link-Local Multicast Name Resolution (LLMNR) protocol" "DWord"
}	

##########
# Global Functions - End
##########
#--------------------------------------------------------------------------

##########
# Program - Start
##########

if ($beXboxSafe -eq 0) {
	DisableXboxFeatures
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
		Write-Output "Trying to install $safeXboxBloatware1."
		Get-AppxPackage -Name $safeXboxBloatware1| Add-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $safeXboxBloatware1 | Add-AppxProvisionedPackage -Online		
	}
	
	RegChange "System\GameConfigStore" "GameDVR_Enabled" "1" "Changing Registry key to ENABLE Game DVR - GameDVR_Enabled" 
	
	# The Game bar is a Xbox app Game DVR feature that makes it simple to take control of your gaming activities—such as broadcasting, capturing clips, and sharing captures
	# (delete) = Enable
	# 0 = Disable
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -ErrorAction SilentlyContinue
	
	if ($(serviceStatus("Schedule")) -eq "running") {
		Write-Output "Enabling Xbox scheduled tasks..."
		Get-ScheduledTask  XblGameSaveTaskLogon | Enable-ScheduledTask
		Get-ScheduledTask  XblGameSaveTask | Enable-ScheduledTask
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

if ($beCastSafe -eq 1) {
	Write-Output "Trying to install Microsoft.PPIP."
	Get-AppxPackage -Name "*Microsoft.PPIP*" | Add-AppxPackage
	Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*Microsoft.PPIP*" | Add-AppxProvisionedPackage -Online
}

if ($beVpnPppoeSafe -eq 1) {
	RegChange "SYSTEM\CurrentControlSet\services\Dnscache" "Start" "2" "Enabling DNS Cache Service" "DWord"	
}
	
if (GPUVendor -eq "nvidia" -and NvidiaControlPanel -eq 1) {	
	Get-AppxPackage -Name "*NVIDIACorp.NVIDIAControlPanel*" | Add-AppxPackage
	Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*NVIDIACorp.NVIDIAControlPanel*" | Add-AppxProvisionedPackage -Online
	Write-Output "Trying to install Nvidia control panel."
}

if ($draculaThemeNotepad -eq 0) {	
	Write-Output "Checking if Notepad++ is installed..."	
	$fileToCheck = "$Env:USERPROFILE\AppData\Roaming\Notepad++\config.xml"
	if (Test-Path $fileToCheck -PathType leaf)	{
		uninstallDraculaNotepad	
	} else { 		
		Write-Output "Notepad++ is not installed." 
	}
}

if ($draculaThemeNotepad -eq 1) {	
	Write-Output "Checking if Notepad++ is installed..."	
	$fileToCheck = "$Env:USERPROFILE\AppData\Roaming\Notepad++\config.xml"
	if (Test-Path $fileToCheck -PathType leaf)	{
		installDraculaNotepad	
	} else { 		
		Write-Output "Notepad++ is not installed." 
	}
}

# SMB Server is known for opening doors for mass ransomware attacks - WannaCry and NotPetya
if ($disableSMBServer -eq 0) {	
	Write-Output "Enabling SMB Server..."	
	Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
}

if ($disableSMBServer -eq 1) {	
	Write-Output "Disabling SMB Server..."	
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
}

if ($disableSystemRestore -eq 0) {
	Write-Output "Enabling system restore..."
	if ($(serviceStatus("Schedule")) -eq "running") {
		Write-Output "Enabling system restore scheduled task..."
		Enable-ScheduledTask -TaskName "Microsoft\Windows\SystemRestore\SR" -EA SilentlyContinue | Out-Null
	}
	
	Get-Service swprv | Set-Service -StartupType automatic
	Get-Service VSS | Set-Service -StartupType automatic
}

if ($disableSystemRestore -eq 1) {
	Write-Output "Disabling system restore..."
	if ($(serviceStatus("Schedule")) -eq "running") {
		Write-Output "Disabling system restore scheduled task..."
		Disable-ScheduledTask -TaskName "Microsoft\Windows\SystemRestore\SR" -EA SilentlyContinue | Out-Null
	}

	Get-Service swprv | Stop-Service -PassThru | Set-Service -StartupType disabled
	Get-Service VSS | Stop-Service -PassThru | Set-Service -StartupType disabled
}

if ($telemetry -eq 0) {	
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "AllowTelemetry" "0" "Disabling data collection through telemetry"  
	RegChange "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "0" "Disabling data collection through telemetry"  
	RegChange "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "0" "Disabling data collection through telemetry"
	if ($(serviceStatus("Schedule")) -eq "running") {
		Write-Output "Disabling telemetry scheduled tasks..."
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
		Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	}	
}

if ($telemetry -eq 1) {		
	RegChange "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "AllowTelemetry" "1" "Disabling data collection through telemetry"  
	RegChange "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "1" "Disabling data collection through telemetry"  
	RegChange "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "1" "Disabling data collection through telemetry"  
	if ($(serviceStatus("Schedule")) -eq "running") {
		Write-Output "Enabling telemetry scheduled tasks..."
		Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
		Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
		Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
		Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
		Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
		Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	}
}

if ($disableBloatware -eq 0) {	
	foreach ($Bloat in $bloatwareList) {
		Write-Output "Trying to INSTALL $Bloat."
		Get-AppxPackage -Name $Bloat| Add-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Add-AppxProvisionedPackage -Online		
	}	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" "1" "Adding Registry key to ALLOW bloatware apps from returning"	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" "1" "Adding Registry key to ALLOW bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" "1" "Adding Registry key to ALLOW bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" "1" "Adding Registry key to ALLOW bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" "1" "Adding Registry key to ALLOW bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" "1" "Adding Registry key to ALLOW bloatware apps from returning" 
}

if ($disableBloatware -eq 1) {			
	foreach ($Bloat in $bloatwareList) {
		Write-Output "Trying to remove $Bloat."
		Get-AppxPackage -Name $Bloat| Remove-AppxPackage
	}	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" "0" "Adding Registry key to PREVENT bloatware apps from returning"	
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" "0" "Adding Registry key to PREVENT bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" "0" "Adding Registry key to PREVENT bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" "0" "Adding Registry key to PREVENT bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" "0" "Adding Registry key to PREVENT bloatware apps from returning"  
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" "0" "Adding Registry key to PREVENT bloatware apps from returning" 
	regDelete "Software\Microsoft\Windows\CurrentVersion\CloudStore" "Removing CloudStore from registry if it exists, will clear all start menu items." 
	UnpinStart
}	

if ($troubleshootInstalls -eq 1) {
	Write-Output "Troubleshoot Install: Windows Management Instrumentation service enabled."
	Get-Service Winmgmt | Start-Service -PassThru | Set-Service -StartupType automatic
	
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

if ($disablelastaccess -eq 0) {
	Write-Output "Disabling last file access."
	fsutil behavior set disablelastaccess 3
}

if ($disablelastaccess -eq 1) {
	Write-Output "Enabling last file access."
	fsutil behavior set disablelastaccess 2
}

if ($doPerformanceStuff -eq 0) {
	Write-Output "Reverse performance stuff."
	
	RegChange "System\CurrentControlSet\Control\Session Manager\Power" "HibernateEnabled" "1" "Enabling hibernation..." "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" "ShowHibernateOption" "1" "Making visible hibernation..." "DWord"
	
	if ($(serviceStatus("Schedule")) -eq "running") {
		write-Host -ForegroundColor Green -BackgroundColor Black "Defragmentation cause unnecessary wear on SSDs"
		Write-Host "Enabling scheduled defragmentation..."
		Enable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
	}
	
	write-Host "Superfetch is known to cause all kinds of problems: slow boot times, disk wear, bottleneck, RAM consumption" -ForegroundColor Green -BackgroundColor Black 
	Write-Host "Enabling Superfetch service..."
	Get-Service SysMain | Stop-Service -PassThru | Set-Service -StartupType automatic
	
	Write-Host "Enabling SSDPSRV service..."
	Get-Service SSDPSRV | Stop-Service -PassThru | Set-Service -StartupType automatic
	
	Write-Host "Enabling AxInstSV service..."
	Get-Service AxInstSV | Stop-Service -PassThru | Set-Service -StartupType automatic
	
	Write-Host "Enabling MapsBroker (Downloaded Maps Manager) service..."
	Get-Service MapsBroker | Set-Service -StartupType automatic
	
	write-Host "Disabling BITS Background Intelligent Transfer Service, its aggressive bandwidth eating will interfere with you online gameplay, work and navigation. Its aggressive disk usable will reduce your HDD or SSD lifespan" -ForegroundColor Green -BackgroundColor Black 
	Get-Service BITS | Set-Service -StartupType automatic
	
	write-Host "DoSvc (Delivery Optimization) it overrides the windows updates opt-out user option, turn your pc into a p2p peer for Windows updates, mining your network performance and compromises your online gameplay, work and navigation." -ForegroundColor Green -BackgroundColor Black
	Write-Host "Enabling DoSvc (Delivery Optimization)..."
	Get-Service DoSvc | Set-Service -StartupType automatic
	
	RegChange "SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" "3" "Enabling DeliveryOptimization download mode HTTP blended with Internet Peering..." "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode" "3" "Enabling DeliveryOptimization download mode HTTP blended with Internet Peering..." "DWord"
	
	RegChange "System\CurrentControlSet\Services\edgeupdate*" "Start" "2" "Enabling Edge updates..." "DWord"
}

if ($doPerformanceStuff -eq 1) {
	Write-Output "Doing performance stuff."
	
	RegChange "System\CurrentControlSet\Control\Session Manager\Power" "HibernateEnabled" "0" "Disabling hibernation..." "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" "ShowHibernateOption" "0" "Hiding hibernation..." "DWord"
	
	if ($(serviceStatus("Schedule")) -eq "running") {
		write-Host -ForegroundColor Green -BackgroundColor Black "Defragmentation cause unnecessary wear on SSDs"
		Write-Host "Disabling scheduled defragmentation..."
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
	}
	
	write-Host "Superfetch is known to cause all kinds of problems: slow boot times, disk wear, bottleneck, RAM consumption" -ForegroundColor Green -BackgroundColor Black 
	Write-Host "Stopping and disabling Superfetch service..."
	Get-Service SysMain | Stop-Service -PassThru | Set-Service -StartupType disabled	
	
	Write-Host "Stopping and disabling SSDPSRV service..."
	Get-Service SSDPSRV | Stop-Service -PassThru | Set-Service -StartupType disabled
	
	Write-Host "Stopping and disabling AxInstSV service..."
	Get-Service AxInstSV | Stop-Service -PassThru | Set-Service -StartupType disabled
	
	Write-Host "Stopping and disabling MapsBroker (Downloaded Maps Manager) service..."
	Get-Service MapsBroker | Stop-Service -PassThru | Set-Service -StartupType disabled
	
	write-Host "BITS (Background Intelligent Transfer Service), its aggressive bandwidth eating will interfere with you online gameplay, work and navigation. Its aggressive disk usable will reduce your HDD or SSD lifespan" -ForegroundColor Green -BackgroundColor Black
	Write-Host "Disabling BITS Background Intelligent Transfer Service"
	Get-Service BITS | Stop-Service -PassThru | Set-Service -StartupType disabled
	
	write-Host "DoSvc (Delivery Optimization) it overrides the windows updates opt-out user option, turn your pc into a p2p peer for Windows updates, mining your network performance and compromises your online gameplay, work and navigation." -ForegroundColor Green -BackgroundColor Black
	Write-Host "Disabling DoSvc (Delivery Optimization)..."
	Get-Service DoSvc | Stop-Service -PassThru | Set-Service -StartupType disabled
	
	RegChange "SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" "100" "Disabling DeliveryOptimization Peering and HTTP download mode (bypass mode)..." "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode" "100" "Disabling DeliveryOptimization Peering and HTTP download mode (bypass mode)..." "DWord"
	
	RegChange "System\CurrentControlSet\Services\edgeupdate*" "Start" "4" "Disabling Edge updates..." "DWord"
}

if ($doQualityOfLifeStuff -eq 0) {
	Write-Output "Reverse quality of life stuff."
	qualityOfLifeOff
	
}

if ($doQualityOfLifeStuff -eq 1) {
	Write-Output "Doing quality of life stuff."
	qualityOfLife
	
}

if ($doPrivacyStuff -eq 0) {
	Write-Output "Reverse privacy stuff..."
	EnableThumbnail
	EnablePeek
	EnablePrefetcher	
	EnableMemoryDump
	unProtectPrivacy
	
	write-Host "Windows Insider Service contact web servers by its own" -ForegroundColor Green -BackgroundColor Black 
	Write-Host "Enabling wisvc (Windows Insider Service)..."
	Get-Service wisvc | Stop-Service -PassThru | Set-Service -StartupType automatic
	
}

if ($doPrivacyStuff -eq 1) {
	Write-Output "Doing privacy stuff..."
	
	clearCaches
	DisableThumbnail
	DisablePeek
	DisablePrefetcher	
	DisableMemoryDump
	ProtectPrivacy
	
	write-Host "Windows Insider Service contact web servers by its own" -ForegroundColor Green -BackgroundColor Black 
	Write-Host "Stopping and disabling wisvc (Windows Insider Service)..."
	Get-Service wisvc | Stop-Service -PassThru | Set-Service -StartupType disabled
}

EnableDnsCache
if ($doSecurityStuff -eq 0) {
	Write-Output "Reverse security stuff..."
	EnableDnsCache
	EnableLLMNR
	EnableNetBIOS
	
	# Wi-Fi Sense connects you to Open hotspots that are "greenlighted" through crowdsourcing. Open door to Lure10 MITM attack and phishing.
	RegChange "SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" "Value" "1" "Enabling Wi-Fi Sense" "Dword"  
	RegChange "SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" "Value" "1" "Enabling Wi-Fi Sense" "Dword" 
	RegChange "SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" "1" "Enabling Wi-Fi Sense" 
}

if ($doSecurityStuff -eq 1) {
	Write-Output "Doing security stuff..."
	DisableDnsCache
	DisableLLMNR
	DisableNetBIOS	
	
	# Wi-Fi Sense connects you to Open hotspots that are "greenlighted" through crowdsourcing. Open door to Lure10 MITM attack and phishing.
	RegChange "SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" "Value" "0" "Disabling Wi-Fi Sense" "Dword"   
	RegChange "SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" "Value" "0" "Disabling Wi-Fi Sense" "Dword"
	RegChange "SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" "0" "Disabling Wi-Fi Sense"  
}


if ($darkTheme -eq 0) {
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "AppsUseLightTheme" "1" "Disabling dark theme mode" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "SystemUsesLightTheme" "1" "Disabling dark theme for system" "DWord"
}

if ($darkTheme -eq 1) {
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "AppsUseLightTheme" "0" "Enabling dark theme mode" "DWord"
	RegChange "SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "SystemUsesLightTheme" "0" "Enabling dark theme for system" "DWord"
}


if ($firefoxSettings -eq 1) {
	killProcess("notepad++");
	
	$PrefsFiles = Get-Item -Path ($env:SystemDrive+"\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\prefs.js")
	$currentDate = Get-Date -UFormat "%Y-%m-%d-%Hh%M"

	$aboutConfigArr = @('*"geo.enabled"*', '*"general.warnOnAboutConfig"*', '*"dom.push.enabled"*', '*"dom.webnotifications.enabled"*', '*"app.update.auto"*', '*"identity.fxaccounts.enabled"*', '*"privacy.firstparty.isolate"*', '*"privacy.firstparty.isolate.block_post_message"*', '*"privacy.resistFingerprinting"*', '*"browser.cache.offline.enable"*', '*"browser.send_pings"*', '*"browser.sessionstore.max_tabs_undo"*', '*"dom.battery.enabled"*', '*"dom.event.clipboardevents.enabled"*', '*"browser.startup.homepage_override.mstone"*', '*"browser.cache.disk.smart_size"*', '*"browser.cache.disk.capacity"*', '*"dom.event.contextmenu.enabled"*', '*"media.videocontrols.picture-in-picture.video-toggle.enabled"*')

	foreach ($file in $PrefsFiles) {
	$path = Get-ItemProperty -Path $file
	Write-Output "editing $path"
	$out = @()

	#Clean selected values

	foreach ($line in Get-Content $file){
		$matchAboutConfig = 0
		foreach ($aboutConfigArr2 in $aboutConfigArr){
			if ($line -like $aboutConfigArr2) {
				$matchAboutConfig = 1 
			}	
		}	

		if ($matchAboutConfig -eq 0) {				
				$out+= $line  
		}
	}

	$out+= 'user_pref("geo.enabled", false);'
	$out+= 'user_pref("general.warnOnAboutConfig", false);'
	$out+= 'user_pref("dom.push.enabled", false);'
	$out+= 'user_pref("dom.webnotifications.enabled", false);'
	$out+= 'user_pref("app.update.auto", false);'
	$out+= 'user_pref("identity.fxaccounts.enabled", false);'
	$out+= 'user_pref("privacy.firstparty.isolate", true);'
	$out+= 'user_pref("privacy.firstparty.isolate.block_post_message", true);'
	$out+= 'user_pref("privacy.resistFingerprinting", true);'
	$out+= 'user_pref("browser.cache.offline.enable", false);'
	$out+= 'user_pref("browser.send_pings", false);'
	$out+= 'user_pref("browser.sessionstore.max_tabs_undo", 0);'
	$out+= 'user_pref("dom.battery.enabled", false);'
	$out+= 'user_pref("dom.event.clipboardevents.enabled", false);'
	$out+= 'user_pref("browser.startup.homepage_override.mstone", ignore);'
	$out+= 'user_pref("browser.cache.disk.smart_size", false);'
	$out+= 'user_pref("browser.cache.disk.capacity", 1048576);'
	$out+= 'user_pref("dom.event.contextmenu.enabled", false);'
	$out+= 'user_pref("media.videocontrols.picture-in-picture.video-toggle.enabled", false);'
	
	Copy-Item $file $file$currentDate".txt"

	Clear-Content $file
	Add-Content $file $out

	Write-Output "Updated $path"
	}
}



##########
# Program - End
##########
#--------------------------------------------------------------------------

##########
# Fixes - Start
##########


<# FIX NOT BEING ABLE TO LINK OUTLOOK 365 ACCOUNT ON OFFICE OUTLOOK 2019
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" -Name "EnableADAL" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" -Name "DisableADALatopWAMOverride" -Type DWord -Value 1
#>

<# FIX NOT BEING ABLE TO TYPE ON WINDOWS SEARCH AND FREEZED START MENU
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v ctfmon /t REG_SZ /d CTFMON.EXE /f | Out-Null
killProcess("explorer");
killProcess("SearchUI");
RegChange "System\CurrentControlSet\Services\WpnUserService*" "Start" "4" "Fixing WpnUserService freezing start menu..." "DWord"
itemDelete "$env:LocalAppData\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\Settings" "Clearing Cortana settings..."
start explorer.exe	
#>

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
choco install directx
choco install dotnetcore -y

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


# Disable ShadowCopy
vssadmin delete shadows /all /quiet | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Shadowcopy removed"  }else{   write-Host -ForegroundColor green "Windows Shadowcopy already disabled" } 

Get-Service netsvcs | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "BITS service disabled"  }else{   write-Host -ForegroundColor red "BITS service not disabled" } 

# Disable Ip helper due transfering a lot of strange data
Get-Service iphlpsvc | Stop-Service -PassThru | Set-Service -StartupType disabled

# Disable Time Brooker due to huge network usage for spying users
New-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\TimeBrokerSvc' -name Start -PropertyType DWord -Value 4 -Force
if($?){   write-Host -ForegroundColor Green "Windows Time Brooker Service Disabled"  }else{   write-Host -ForegroundColor red "Windows Time Brooker Service not Disabled" } 

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






$disablecortana = Read-Host "Disable Cortana? (y/n)"
switch ($disablecortana) {
	y {
	DisableCortana
	}
}

$remove3d = Read-Host "Remove 3D Objects from explorer 'My Computer' submenu? (y/n)"
switch ($remove3d) {
	y {
	Remove3dObjects
	}
}

$DisableBack = Read-Host "Disable Background Access? (y/n)"
switch ($DisableBack) {
	y {
	DisableBackgroundApps
	}
}



#THINGS TO DO MANUALLY
#CONFIG FIREFOX
# darkreader
# uBlock Origin

## EXTRAS SUBSCRIBE LISTS FOR UBLOCK
## https://filterlists.com/lists/
## Block the EU Cookie Shit List
## EasyList Cookie List
## I Don't Care about Cookies
## ABP Anti-Circumvention Filter List

## NOTES
## DHCP REQUIRED FOR VPN
## TELEPHONY REQUIRED FOR PPOE
## DISABLING WIN FIREWALL CAN PREVENT PRINT NETWORK SHARING

<# UBLOCK FILTERS
www.google.*##div[jscontroller]:if(h4:has-text(People also search for))
||youtube.com/comment_service_ajax*
||youtube.com###comments
 #>

## Credits
## https://github.com/builtbybel/debotnet
## https://github.com/Disassembler0/Win10-Initial-Setup-Script
## https://gist.github.com/alirobe/7f3b34ad89a159e6daa1
## https://github.com/adolfintel/Windows10-Privacy
## https://github.com/Sycnex/Windows10Debloater
## https://github.com/dracula/dracula-theme

Remove-PSDrive HKCR
PAUSE

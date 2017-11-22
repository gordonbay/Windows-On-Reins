# Version 0.3
$ErrorActionPreference = "SilentlyContinue"
Set-ExecutionPolicy unrestricted

$visual = Read-Host "Install Visual C++ Redistributable Packages? (y/n)"

while("y","n" -notcontains $visual)
{
	$visual = Read-Host "y or n?"
}

$netfx = Read-Host "Install NetFramework 3.5? (y/n)"

while("y","n" -notcontains $netfx)
{
	$netfxr = Read-Host "y or n?"
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
while("y","n" -notcontains $disableuac)
{
	$disableuac = Read-Host "y or n?"
}

$ink = Read-Host "Disable Windows INK (y/n)"
while("y","n" -notcontains $ink)
{
	$ink = Read-Host "y or n?"
}

$people = Read-Host "Disable Windows People Bar (y/n)"
while("y","n" -notcontains $people)
{
	$people = Read-Host "y or n?"
}

$hosts = Read-Host "Block software updates by hosts(y/n)"
while("y","n" -notcontains $hosts)
{
	$hosts = Read-Host "y or n?"
}


if ($visual -like "y") { 
#INSTALL VISUAL C++
<#
    .SYNOPSIS
        Download all "english" Visual C++ Runtimes
    .PARAMETER  ParameterA
        $OutputPath = Default Path
    .LINK
        http://www.software-virtualisierung.de
#>
param(
    [String]$outputPath = ".\VCRuntime"
)
Write-Host "Download Microsoft Visual C++ 2005, 2008, 2010, 2012, 2013, 2015"
Write-Host "Andreas Nick, Software-Virtualisierung.de, 2015"
if(! (test-path "$outputPath\VS2005X86SP1")) { New-Item "$outputPath\VS2005" -Type directory -Force}
Write-Verbose "Microsoft Visual C++ 2005 SP1 Redistributable Package (x86)" -Verbose
Invoke-WebRequest   "http://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -OutFile "$outputPath\VS2005\vcredist_x86.exe"
Write-Verbose "Microsoft Visual C++ 2005 SP1 Redistributable Package (x64)" -Verbose
Invoke-WebRequest  "http://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" -OutFile "$outputPath\VS2005\vcredist_x64.exe"
if (! (test-path "$outputPath\VS2008")) { New-Item "$outputPath\VS2008" -Type directory -Force }
Write-Verbose "Microsoft Visual C++ 2008 SP1 Redistributable Package (x86)" -Verbose
Invoke-WebRequest  "http://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe" -OutFile "$outputPath\VS2008\vcredist_x86.exe"
Write-Verbose "Microsoft Visual C++ 2008 SP1 Redistributable Package (x64)" -Verbose
Invoke-WebRequest  "http://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe" -OutFile "$outputPath\VS2008\vcredist_x64.exe"
if (! (test-path "$outputPath\VS2010")) { New-Item "$outputPath\VS2010" -Type directory -Force }
Write-Verbose "Microsoft Visual C++ 2010 SP1 Redistributable Package (x86)" -Verbose
Invoke-WebRequest "http://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe" -OutFile "$outputPath\VS2010\vcredist_x86.exe"
Write-Verbose "Microsoft Visual C++ 2010 SP1 Redistributable Package (x64)" -Verbose
Invoke-WebRequest "http://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe" -OutFile "$outputPath\VS2010\vcredist_x64.exe"
if (! (test-path "$outputPath\VS2012")) { New-Item "$outputPath\VS2012" -Type directory -Force }
Write-Verbose "Microsoft Visual C++ 2012 Update 4 Redistributable Package (x86)" -Verbose
Invoke-WebRequest "http://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe" -OutFile "$outputPath\VS2012\vcredist_x86.exe"
Write-Verbose "Microsoft Visual C++ 2012 Update 4 Redistributable Package (x64)" -Verbose
Invoke-WebRequest "http://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe" -OutFile "$outputPath\VS2012\vcredist_x64.exe"
if (! (test-path "$outputPath\VS2013")) { New-Item "$outputPath\VS2013" -Type directory -Force }
Write-Verbose "Microsoft Visual C++ 2013 Redistributable Package (x86)" -Verbose
Invoke-WebRequest "http://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe" -OutFile "$outputPath\VS2013\vcredist_x86.exe"
Write-Verbose "Microsoft Visual C++ 2013 Redistributable Package (x64)" -Verbose
Invoke-WebRequest "http://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe" -OutFile "$outputPath\VS2013\vcredist_x64.exe"
if (! (test-path "$outputPath\VS2015")) { New-Item "$outputPath\VS2015" -Type directory -Force }
Write-Verbose "Visual C++ Redistributable for Visual Studio 2015 (x86) update 3 RC" -Verbose
Invoke-WebRequest "https://download.microsoft.com/download/0/6/4/064F84EA-D1DB-4EAA-9A5C-CC2F0FF6A638/vc_redist.x86.exe" -OutFile "$outputPath\VS2015\vcredist_x86.exe"
Write-Verbose "Visual C++ Redistributable for Visual Studio 2015 (x64)" -Verbose
Invoke-WebRequest "https://download.microsoft.com/download/0/6/4/064F84EA-D1DB-4EAA-9A5C-CC2F0FF6A638/vc_redist.x64.exe" -OutFile "$outputPath\VS2015\vcredist_x64.exe"
if (! (test-path "$outputPath\VS2017")) { New-Item "$outputPath\VS2017" -Type directory -Force }
Write-Verbose "Visual C++ Redistributable for Visual Studio 2017 (x64)" -Verbose
Invoke-WebRequest "https://download.microsoft.com/download/4/b/c/4bc903be-f3f6-416d-9d19-af2492ca730b/vc_redist.x64.exe" -OutFile "$outputPath\VS2017\vcredist_x64.exe"



<#
    .SYNOPSIS
        Install all "english" Visual C++ Runtimes
 
    .PARAMETER  ParameterA
        $OutputPath = Default Path
 
    .LINK
        http://www.software-virtualisierung.de
 
#>
 
 
param(
    [String]$outputPath = ".\VCRuntime"
)
 
[String]$outputPath = ".\VCRuntime"
 
Write-Host "Install Microsoft Visual C++ 2005, 2008, 2010, 2012, 2013, 2015"
Write-Host "Andreas Nick, Software-Virtualisierung.de, 2015"
 
foreach ($vcFile in Get-ChildItem $outputPath -Recurse -Filter "*.exe")
{
    Write-Host "Install " $vcFile.fullname
    Start-Process  $vcFile.fullname -ArgumentList '/q' -NoNewWindow -Wait
     
     
}

Remove-Item $outputPath -recurse

}

if ($netfx -like "y") { 
#INSTALL .NET FRAMEWORK 3.5
DISM.EXE /Online /Add-Capability /CapabilityName:NetFx3~~~~
DISM.EXE /Online /Add-Capability /CapabilityName:Language.Basic~~~pt-BR~0.0.1.0
}

if ($windowsdefender -like "y") { 
#DISABLE WINDOWS DEFENDER

Set-MpPreference -DisableRealtimeMonitoring $true -EA SilentlyContinue
if($?){   write-Host -ForegroundColor Green "Windows Defender Current Session Disabled"  }else{   write-Host -ForegroundColor Green "Windows Defender Current Session not running" }

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Anti Spyware Disabled"  }else{   write-Host -ForegroundColor red "Windows Anti Spyware not Disabled" }

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Behavior Monitoring Disabled"  }else{   write-Host -ForegroundColor red "Windows Behavior Monitoring not Disabled" }

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows On Access Protection Disabled"  }else{   write-Host -ForegroundColor red "Windows On Access Protection not Disabled" }

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Real Time Protection Disabled"  }else{   write-Host -ForegroundColor red "Windows Real Time Protection not Disabled" }

reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinDefend" /v Start /t REG_DWORD /d 4 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Defender Startup Disabled"  }else{   write-Host -ForegroundColor red "Windows Defender Startup not Disabled" } 

}


if ($windowsfirewall -like "y") { 
#DISABLE WINDOWS FIREWALL

Get-NetFirewallProfile | Set-NetFirewallProfile –Enabled False
if($?){   write-Host -ForegroundColor Green "Windows Firewall Disabled"  }else{   write-Host -ForegroundColor red "Windows Firewall not Disabled" }

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

if ($showhidden -like "y") { 
#SHOW HIDDEN FILES AND EXTENSIONS

$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $key Hidden 1
if($?){   write-Host -ForegroundColor Green "Windows Hidden Files Disabled"  }else{   write-Host -ForegroundColor red "Windows Hidden Files not Disabled" }

Set-ItemProperty $key HideFileExt 0
if($?){   write-Host -ForegroundColor Green "Windows Hidden Extensions Disabled"  }else{   write-Host -ForegroundColor red "Windows Hidden Extensions Options not Disabled" }

}

if ($disableuac -like "y") { 
#Disable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows UAC disabled"  }else{   write-Host -ForegroundColor green "Windows UAC not disabled" } 

#Disable SUGGESTED APPS
New-ItemProperty -Path HKLM:SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name DisableWindowsConsumerFeatures -PropertyType DWord -Value 1 -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows SUGGESTED APPS SPAM disabled"  }else{   write-Host -ForegroundColor green "Windows SUGGESTED APPS SPAM not disabled" } 

#Disable SUGGESTED APPS
New-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -PropertyType DWord -Value 0 -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows SUGGESTED APPS SPAM disabled"  }else{   write-Host -ForegroundColor green "Windows SUGGESTED APPS SPAM not disabled" } 


# Remove all unwanted apps
Get-AppxPackage *3dbuilder* | Remove-AppxPackage
if($?){   write-Host -ForegroundColor Green "3dbuilder removed"  }else{   write-Host -ForegroundColor red "3dbuilder not removed" } 
Get-AppxPackage *windowsalarms* | Remove-AppxPackage
if($?){   write-Host -ForegroundColor Green "alarms removed"  }else{   write-Host -ForegroundColor red "alarms not removed" } 
Get-AppxPackage -allusers *windowscalculator* | Remove-AppxPackage
Get-AppxPackage -allusers *windowscommunicationsapps* | Remove-AppxPackage
Get-AppxPackage -allusers *windowscamera* | Remove-AppxPackage
Get-AppxPackage -allusers *officehub* | Remove-AppxPackage
Get-AppxPackage -allusers *skypeapp* | Remove-AppxPackage
Get-AppxPackage -allusers *getstarted* | Remove-AppxPackage
Get-AppxPackage -allusers *zunemusic* | Remove-AppxPackage
Get-AppxPackage -allusers *windowsmaps* | Remove-AppxPackage
Get-AppxPackage -allusers *solitairecollection* | Remove-AppxPackage
Get-AppxPackage -allusers *bingfinance* | Remove-AppxPackage
Get-AppxPackage -allusers *zunevideo* | Remove-AppxPackage
Get-AppxPackage -allusers *bingnews* | Remove-AppxPackage
Get-AppxPackage -allusers *onenote* | Remove-AppxPackage
Get-AppxPackage -allusers *people* | Remove-AppxPackage
Get-AppxPackage -allusers *windowsphone* | Remove-AppxPackage
Get-AppxPackage -allusers *photos* | Remove-AppxPackage
Get-AppxPackage -allusers *bingsports* | Remove-AppxPackage
Get-AppxPackage -allusers *soundrecorder* | Remove-AppxPackage
Get-AppxPackage -allusers *bingweather* | Remove-AppxPackage
Get-AppxPackage -allusers *xboxapp* | Remove-AppxPackage
Get-AppxPackage -allusers *zunemusic* | Remove-AppxPackage
Get-AppxPackage -allusers *Twitter* | Remove-AppxPackage
Get-AppxPackage -allusers *CandyCrushSodaSaga* | Remove-AppxPackage
Get-AppxPackage -allusers *messaging* | Remove-AppxPackage
Get-AppxPackage -allusers *Microsoft3DViewer* | Remove-AppxPackage
Get-AppxPackage -allusers *XboxGameOverlay* | Remove-AppxPackage
Get-AppxPackage -allusers *XboxSpeechToTextOverlay* | Remove-AppxPackage
Get-AppxPackage -allusers*ParentalControls* | Remove-AppxPackage
Get-AppxPackage -allusers *XboxGameCallableUI* | Remove-AppxPackage
Get-AppxPackage -allusers *Cortana* | Remove-AppxPackage
Get-AppxPackage -allusers *XboxIdentityProvider* | Remove-AppxPackage
Get-appxpackage -allusers *XboxGameOverlay* | Remove-AppxPackage
}

if ($ink -like "y") { 
#Disable INK
New-ItemProperty -Path HKLM:SOFTWARE\Policies\Microsoft -Name WindowsInkWorkspace -PropertyType DWord -Value 0 -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows INK disabled"  }else{   write-Host -ForegroundColor red "Windows INK not disabled" } 
}

if ($people -like "y") { 
#Disable PEOLPLE
New-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Name PeopleBand -PropertyType DWord -Value 0 -Force -EA SilentlyContinue | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows PEOPLE disabled"  }else{   write-Host -ForegroundColor red "Windows PEOPLE not disabled" } 
}

#DISABLE USELESS SERVICES
sc delete diagtrack | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Diagnostics Tracking Service Disabled"  }else{   write-Host -ForegroundColor red "Windows Diagnostics Tracking Service not Disabled" }

sc delete dmwappushservice | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Keylogger Disabled"  }else{   write-Host -ForegroundColor red "Windows Keylogger not Disabled" }

#DISABLE USELESS SERVICES BY REGISTRY
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f | Out-Null
if($?){   write-Host -ForegroundColor Green "Windows Telemetry Disabled"  }else{   write-Host -ForegroundColor red "Windows Telemetry not Disabled" } 


# Patches to avoid
wusa /uninstall /kb:3112343 /quiet /norestart
wusa /uninstall /kb:3083711 /quiet /norestart
wusa /uninstall /kb:3083325 /quiet /norestart
wusa /uninstall /kb:3080149 /quiet /norestart
wusa /uninstall /kb:3075853 /quiet /norestart
wusa /uninstall /kb:3075249 /quiet /norestart
wusa /uninstall /kb:3072318 /quiet /norestart
wusa /uninstall /kb:3068708 /quiet /norestart
wusa /uninstall /kb:3065988 /quiet /norestart
wusa /uninstall /kb:3064683 /quiet /norestart
wusa /uninstall /kb:3058168 /quiet /norestart
wusa /uninstall /kb:3050267 /quiet /norestart
wusa /uninstall /kb:3044374 /quiet /norestart
wusa /uninstall /kb:3035583 /quiet /norestart
wusa /uninstall /kb:3022345 /quiet /norestart
wusa /uninstall /kb:2976978 /quiet /norestart


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

sc config swprv start= disabled
sc config VSS start= disabled


reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v EnableBalloonTips /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer /v DisableNotificationCenter /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer /v DisableNotificationCenter /t REG_DWORD /d 1 /f

# Disable BITS service due still download windows updates even if the user does not want it
Get-Service BITS | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "BITS service disabled"  }else{   write-Host -ForegroundColor red "BITS service not disabled" } 

# Disable Windows Management Instrumentation due transfering a lot of strange data
Get-Service Winmgmt | Stop-Service -PassThru | Set-Service -StartupType disabled
if($?){   write-Host -ForegroundColor Green "Windows Management Instrumentation disabled"  }else{   write-Host -ForegroundColor red "Windows Management Instrumentation not disabled" } 

New-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Winmgmt' -name Start -PropertyType DWord -Value 4 -Force
if($?){   write-Host -ForegroundColor Green "Windows Management Instrumentation disabled by registry"  }else{   write-Host -ForegroundColor red "Windows Management Instrumentation not disabled by registry" } 

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

reg add 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v DisableNotificationCenter /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f

# xbox dvr causing fps issues
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR /v value /t REG_DWORD /d 0 /f

# RAZER THINGS THAT NOBODY USES
Get-Service Razer Chroma SDK Server | Stop-Service -PassThru | Set-Service -StartupType disabled
Get-Service Razer Chroma SDK Service | Stop-Service -PassThru | Set-Service -StartupType disabled
Get-Service Razer Chroma SDK Server | Stop-Service -PassThru | Set-Service -StartupType disabled


# ANOYING PUSH NOTIFICATIONS
Get-Service WpnService | Stop-Service -PassThru | Set-Service -StartupType disabled

# SUPERFETCH IS KNOWN TO CAUSE SLOW BOOT TIME
Get-Service SysMain | Stop-Service -PassThru | Set-Service -StartupType disabled

# WE DONT NEED TELEMETRY AGENT NVIDIA!
Get-Service NvTelemetryContainer | Stop-Service -PassThru | Set-Service -StartupType disabled


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
if ($hosts -like "y") { 
#Disable SOFTWARE UPDATES
If ((Get-Content "$($env:windir)\system32\Drivers\etc\hosts" ) -notcontains "127.0.0.1 conditiontonotapply")   
 {ac -Encoding UTF8  "$($env:windir)\system32\Drivers\etc\hosts" "
127.0.0.1 conditiontonotapply
# Block Corel Servers
#
0.0.0.0  apps.corel.com
0.0.0.0  mc.corel.com

#
# Block Adobe Servers
#
# Main entries go below this comment
0.0.0.0  192.150.18.108
0.0.0.0  192.150.22.40
0.0.0.0  192.150.14.69
0.0.0.0  192.150.8.118
0.0.0.0  192.150.8.100
0.0.0.0  192.150.18.101
0.0.0.0  192.168.112.207
0.0.0.0  194.224.66.48
0.0.0.0  199.7.52.190
0.0.0.0  199.7.52.190:80
0.0.0.0  209.34.83.73:43
0.0.0.0  209.34.83.73:443
0.0.0.0  www.adobeereg.com #75.125.24.83
0.0.0.0  adobeereg.com #207.66.2.10
0.0.0.0  activate.adobe.com  #192.150.22.40
0.0.0.0  practivate.adobe
0.0.0.0  practivate.adobe.com
0.0.0.0  practivate.adobe.*
0.0.0.0  practivate.adobe.com #192.150.18.54
0.0.0.0  practivate.adobe.newoa
0.0.0.0  practivate.adobe.ntp
0.0.0.0  practivate.adobe.ipp
0.0.0.0  activate-sea.adobe.com #192.150.22.40
0.0.0.0  wip.adobe.com
0.0.0.0  wip1.adobe.com
0.0.0.0  wip2.adobe.com
0.0.0.0  wip3.adobe.com #192.150.8.60
0.0.0.0  wip4.adobe.com #192.150.18.200
0.0.0.0  lmlicenses.wip1.adobe.com
0.0.0.0  lmlicenses.wip2.adobe.com
0.0.0.0  lmlicenses.wip3.adobe.com
0.0.0.0  lmlicenses.wip4.adobe.com
0.0.0.0  activate.wip.adobe.com
0.0.0.0  activate.wip1.adobe.com
0.0.0.0  activate.wip2.adobe.com
0.0.0.0  activate.wip3.adobe.com #192.150.22.40
0.0.0.0  activate.wip4.adobe.com #192.150.22.40
0.0.0.0  ereg.wip.adobe.com
0.0.0.0  ereg.wip1.adobe.com
0.0.0.0  ereg.wip2.adobe.com
0.0.0.0  ereg.wip3.adobe.com #192.150.18.63
0.0.0.0  ereg.wip4.adobe.com #192.150.18.103
0.0.0.0  ereg.adobe.com #192.150.18.103
0.0.0.0  3dns.adobe.com
0.0.0.0  3dns-1.adobe.com
0.0.0.0  3dns-2.adobe.com #192.150.22.22
0.0.0.0  3dns-3.adobe.com #192.150.14.21
0.0.0.0  3dns-4.adobe.com #192.150.18.247
0.0.0.0  3dns-5.adobe.com #192.150.22.46
0.0.0.0  adobe-dns.adobe.com #192.150.11.30
0.0.0.0  adobe-dns-1.adobe.com
0.0.0.0  adobe-dns-2.adobe.com #192.150.11.247
0.0.0.0  adobe-dns-3.adobe.com #192.150.22.30
0.0.0.0  adobe-dns-4.adobe.com
0.0.0.0  wwis-dubc1-vip60.adobe.com
0.0.0.0  activate-sjc0.adobe.com #192.150.14.69
0.0.0.0  hl2rcv.adobe.com #192.150.14.174
0.0.0.0  adobe.activate.com
0.0.0.0  lm.licenses.adobe.com
0.0.0.0  na1r.services.adobe.com
0.0.0.0  hlrcv.stage.adobe.com
0.0.0.0  na2m-pr.licenses.adobe.com
0.0.0.0  adobe.tt.omtrdc.net
0.0.0.0  adobe.activate.com #69.175.22.26
# End of main entries present above
# New additional entries go below this comment
0.0.0.0  wwis-dubc1-vip30.adobe.com #192.150.8.30
0.0.0.0  wwis-dubc1-vip31.adobe.com #192.150.8.31
0.0.0.0  wwis-dubc1-vip32.adobe.com #192.150.8.32
0.0.0.0  wwis-dubc1-vip33.adobe.com #192.150.8.33
0.0.0.0  wwis-dubc1-vip34.adobe.com #192.150.8.34
0.0.0.0  wwis-dubc1-vip35.adobe.com #192.150.8.35
0.0.0.0  wwis-dubc1-vip36.adobe.com #192.150.8.36
0.0.0.0  wwis-dubc1-vip37.adobe.com #192.150.8.37
0.0.0.0  wwis-dubc1-vip38.adobe.com #192.150.8.38
0.0.0.0  wwis-dubc1-vip39.adobe.com #192.150.8.39
0.0.0.0  wwis-dubc1-vip40.adobe.com #192.150.8.40
0.0.0.0  wwis-dubc1-vip41.adobe.com #192.150.8.41
0.0.0.0  wwis-dubc1-vip42.adobe.com #192.150.8.42
0.0.0.0  wwis-dubc1-vip43.adobe.com #192.150.8.43
0.0.0.0  wwis-dubc1-vip44.adobe.com #192.150.8.44
0.0.0.0  wwis-dubc1-vip45.adobe.com #192.150.8.45
0.0.0.0  wwis-dubc1-vip46.adobe.com #192.150.8.46
0.0.0.0  wwis-dubc1-vip47.adobe.com #192.150.8.47
0.0.0.0  wwis-dubc1-vip48.adobe.com #192.150.8.48
0.0.0.0  wwis-dubc1-vip49.adobe.com #192.150.8.49
0.0.0.0  wwis-dubc1-vip50.adobe.com #192.150.8.50
0.0.0.0  wwis-dubc1-vip51.adobe.com #192.150.8.51
0.0.0.0  wwis-dubc1-vip52.adobe.com #192.150.8.52
0.0.0.0  wwis-dubc1-vip53.adobe.com #192.150.8.53
0.0.0.0  wwis-dubc1-vip54.adobe.com #192.150.8.54
0.0.0.0  wwis-dubc1-vip55.adobe.com #192.150.8.55
0.0.0.0  wwis-dubc1-vip56.adobe.com #192.150.8.56
0.0.0.0  wwis-dubc1-vip57.adobe.com #192.150.8.57
0.0.0.0  wwis-dubc1-vip58.adobe.com #192.150.8.58
0.0.0.0  wwis-dubc1-vip59.adobe.com #192.150.8.59
0.0.0.0  wwis-dubc1-vip60.adobe.com #192.160.8.60
0.0.0.0  wwis-dubc1-vip61.adobe.com #192.160.8.61
0.0.0.0  wwis-dubc1-vip62.adobe.com #192.160.8.62
0.0.0.0  wwis-dubc1-vip63.adobe.com #192.160.8.63
0.0.0.0  wwis-dubc1-vip64.adobe.com #192.160.8.64
0.0.0.0  wwis-dubc1-vip65.adobe.com #192.160.8.65
0.0.0.0  wwis-dubc1-vip66.adobe.com #192.160.8.66
0.0.0.0  wwis-dubc1-vip67.adobe.com #192.160.8.67
0.0.0.0  wwis-dubc1-vip68.adobe.com #192.160.8.68
0.0.0.0  wwis-dubc1-vip69.adobe.com #192.160.8.69
0.0.0.0  wwis-dubc1-vip70.adobe.com #192.170.8.70
0.0.0.0  wwis-dubc1-vip71.adobe.com #192.170.8.71
0.0.0.0  wwis-dubc1-vip72.adobe.com #192.170.8.72
0.0.0.0  wwis-dubc1-vip73.adobe.com #192.170.8.73
0.0.0.0  wwis-dubc1-vip74.adobe.com #192.170.8.74
0.0.0.0  wwis-dubc1-vip75.adobe.com #192.170.8.75
0.0.0.0  wwis-dubc1-vip76.adobe.com #192.170.8.76
0.0.0.0  wwis-dubc1-vip77.adobe.com #192.170.8.77
0.0.0.0  wwis-dubc1-vip78.adobe.com #192.170.8.78
0.0.0.0  wwis-dubc1-vip79.adobe.com #192.170.8.79
0.0.0.0  wwis-dubc1-vip80.adobe.com #192.180.8.80
0.0.0.0  wwis-dubc1-vip81.adobe.com #192.180.8.81
0.0.0.0  wwis-dubc1-vip82.adobe.com #192.180.8.82
0.0.0.0  wwis-dubc1-vip83.adobe.com #192.180.8.83
0.0.0.0  wwis-dubc1-vip84.adobe.com #192.180.8.84
0.0.0.0  wwis-dubc1-vip85.adobe.com #192.180.8.85
0.0.0.0  wwis-dubc1-vip86.adobe.com #192.180.8.86
0.0.0.0  wwis-dubc1-vip87.adobe.com #192.180.8.87
0.0.0.0  wwis-dubc1-vip88.adobe.com #192.180.8.88
0.0.0.0  wwis-dubc1-vip89.adobe.com #192.180.8.89
0.0.0.0  wwis-dubc1-vip90.adobe.com #192.190.8.90
0.0.0.0  wwis-dubc1-vip91.adobe.com #192.190.8.91
0.0.0.0  wwis-dubc1-vip92.adobe.com #192.190.8.92
0.0.0.0  wwis-dubc1-vip93.adobe.com #192.190.8.93
0.0.0.0  wwis-dubc1-vip94.adobe.com #192.190.8.94
0.0.0.0  wwis-dubc1-vip95.adobe.com #192.190.8.95
0.0.0.0  wwis-dubc1-vip96.adobe.com #192.190.8.96
0.0.0.0  wwis-dubc1-vip97.adobe.com #192.190.8.97
0.0.0.0  wwis-dubc1-vip98.adobe.com #192.190.8.98
0.0.0.0  wwis-dubc1-vip99.adobe.com #192.190.8.99
0.0.0.0  wwis-dubc1-vip100.adobe.com #192.190.8.100
0.0.0.0  wwis-dubc1-vip101.adobe.com #192.190.8.101
0.0.0.0  wwis-dubc1-vip102.adobe.com #192.190.8.102
0.0.0.0  wwis-dubc1-vip103.adobe.com #192.190.8.103
0.0.0.0  wwis-dubc1-vip104.adobe.com #192.190.8.104
0.0.0.0  wwis-dubc1-vip105.adobe.com #192.150.8.105
0.0.0.0  wwis-dubc1-vip106.adobe.com #192.150.8.106
0.0.0.0  wwis-dubc1-vip107.adobe.com #192.150.8.107
0.0.0.0  wwis-dubc1-vip108.adobe.com #192.150.8.108
0.0.0.0  wwis-dubc1-vip109.adobe.com #192.150.8.109
0.0.0.0  wwis-dubc1-vip110.adobe.com #192.150.8.110
0.0.0.0  wwis-dubc1-vip111.adobe.com #192.150.8.111
0.0.0.0  wwis-dubc1-vip112.adobe.com #192.150.8.112
0.0.0.0  wwis-dubc1-vip113.adobe.com #192.150.8.113
0.0.0.0  wwis-dubc1-vip114.adobe.com #192.150.8.114
0.0.0.0  wwis-dubc1-vip115.adobe.com #192.150.8.115
0.0.0.0  wwis-dubc1-vip116.adobe.com #192.150.8.116
0.0.0.0  wwis-dubc1-vip117.adobe.com #192.150.8.117
0.0.0.0  wwis-dubc1-vip118.adobe.com #192.150.8.118
0.0.0.0  wwis-dubc1-vip119.adobe.com #192.150.8.119
0.0.0.0  wwis-dubc1-vip120.adobe.com #192.150.8.120
0.0.0.0  wwis-dubc1-vip121.adobe.com #192.150.8.121
0.0.0.0  wwis-dubc1-vip122.adobe.com #192.150.8.122
0.0.0.0  wwis-dubc1-vip123.adobe.com #192.150.8.123
0.0.0.0  wwis-dubc1-vip124.adobe.com #192.150.8.124
0.0.0.0  wwis-dubc1-vip125.adobe.com #192.150.8.125


# Start of Adobe Updater blockers
127.0.0.1 crl.verisign.net CRL.VERISIGN.NET ood.opsource.net
127.0.0.1 activate.adobe.com
127.0.0.1 activate-sea.adobe.com
127.0.0.1 practivate.adobe
127.0.0.1 practivate.adobe.com
127.0.0.1 practivate.adobe.newoa
127.0.0.1 practivate.adobe.ntp
127.0.0.1 practivate.adobe.ipp
127.0.0.1 adobeereg.com
127.0.0.1 activate.wip1.adobe.com
127.0.0.1 activate.wip2.adobe.com
127.0.0.1 activate.wip3.adobe.com
127.0.0.1 activate.wip4.adobe.com
127.0.0.1 www.adobeereg.com
127.0.0.1 hl2rcv.adobe.com
127.0.0.1 wip.adobe.com
127.0.0.1 wip1.aobe.com
127.0.0.1 wip2.adobe.com
127.0.0.1 wip3.adobe.com
127.0.0.1 wip4.adobe.com
127.0.0.1 www.wip.adobe.com
127.0.0.1 www.wip1.adobe.com
127.0.0.1 www.wip2.adobe.com
127.0.0.1 www.wip3.adobe.com
127.0.0.1 www.wip4.adobe.com
127.0.0.1 3dns.adobe.com
127.0.0.1 3dns-1.adobe.com
127.0.0.1 3dns-2.adobe.com
127.0.0.1 3dns-3.adobe.com
127.0.0.1 3dns-4.adobe.com
127.0.0.1 adobe-dns.adobe.com
127.0.0.1 adobe-dns-1.adobe.com
127.0.0.1 adobe-dns-2.adobe.com
127.0.0.1 adobe-dns-3.adobe.com
127.0.0.1 adobe-dns-4.adobe.com
127.0.0.1 ereg.adobe.com
127.0.0.1 ereg.wip.adobe.com
127.0.0.1 ereg.wip1.adobe.com
127.0.0.1 ereg.wip2.adobe.com
127.0.0.1 ereg.wip3.adobe.com
127.0.0.1 ereg.wip4.adobe.com
127.0.0.1 wwis-dubc1-vip60.adobe.com
127.0.0.1 activate-sjc0.adobe.com
#
# Block Autodesk AutoCAD Servers
#
0.0.0.0 autodesk.fi 
0.0.0.0 autodesk.de
0.0.0.0 autodesk.es
0.0.0.0 autodesk.ca
0.0.0.0 autodesk.dk
0.0.0.0 autodesk.pl
0.0.0.0 ns1.autodesk.com
0.0.0.0 ns2.autodesk.com
0.0.0.0 ns3.autodesk.com
0.0.0.0 a.gtld-servers.net
0.0.0.0 b.gtld-servers.net
0.0.0.0 c.gtld-servers.net
0.0.0.0 d.gtld-servers.net
0.0.0.0 e.gtld-servers.net
0.0.0.0 f.gtld-servers.net
0.0.0.0 g.gtld-servers.net
0.0.0.0 h.gtld-servers.net
0.0.0.0 i.gtld-servers.net
0.0.0.0 j.gtld-servers.net
0.0.0.0 k.gtld-servers.net
0.0.0.0 l.gtld-servers.net
0.0.0.0 ns1.autodesk.com
0.0.0.0 m.gtld-servers.net
0.0.0.0 adobeereg.com
0.0.0.0 126114-app1.autodesk.com
0.0.0.0 94175-app1.autodesk.com
0.0.0.0 94184-app2.autodesk.com
0.0.0.0 96579-lbal1.autodesk.com
0.0.0.0 acamp.autodesk.com
0.0.0.0 adeskdi3.autodesk.com
0.0.0.0 adeskdmzpdc.autodesk.com
0.0.0.0 adeskgate.autodesk.com
0.0.0.0 adesknews2.autodesk.com
0.0.0.0 adeskout.autodesk.com
0.0.0.0 adsknateur.autodesk.com
0.0.0.0 amernetlog.autodesk.com
0.0.0.0 app5.autodesk.com
0.0.0.0 aprimo-relay1.autodesk.com
0.0.0.0 aprimo-relay2.autodesk.com
0.0.0.0 aprimo-relay3.autodesk.com
0.0.0.0 aprimo-relay4.autodesk.com
0.0.0.0 autosketch.autodesk.com
0.0.0.0 blues.autodesk.com
0.0.0.0 cbuanprd.autodesk.com
0.0.0.0 cbuanprhcllb.autodesk.com
0.0.0.0 cbuanqa2lb.autodesk.com
0.0.0.0 ci3dwsdev-svc.autodesk.com
0.0.0.0 ci3dwsprd-svc.autodesk.com
0.0.0.0 ci3dwsstg-svc.autodesk.com
0.0.0.0 community.autodesk.com
0.0.0.0 cut.autodesk.com
0.0.0.0 cvsprd01.autodesk.com
0.0.0.0 discussion.autodesk.com
0.0.0.0 eur.autodesk.com
0.0.0.0 extcidev.autodesk.com
0.0.0.0 extciqa.autodesk.com
0.0.0.0 extupg.autodesk.com
0.0.0.0 ftp-users.autodesk.com
0.0.0.0 ftp2b.autodesk.com
0.0.0.0 gisdmzpdc.autodesk.com
0.0.0.0 hqaribasrf04.autodesk.com
0.0.0.0 hqmgwww01.autodesk.com
0.0.0.0 hqmgwww04.autodesk.com
0.0.0.0 hqmobileweb01.autodesk.com
0.0.0.0 hqprxsrftrn.autodesk.com
0.0.0.0 hqpsweb01.autodesk.com
0.0.0.0 hubdev-svc.autodesk.com
0.0.0.0 hubprd-svc.autodesk.com
0.0.0.0 hubstg-svc.autodesk.com
0.0.0.0 itappprd01-svc.autodesk.com
0.0.0.0 itappprd02-svc.autodesk.com
0.0.0.0 its.autodesk.com
0.0.0.0 jdevextv-new.autodesk.com
0.0.0.0 jp.autodesk.com
0.0.0.0 jstgextv-new.autodesk.com
0.0.0.0 jstgintv-new.autodesk.com
0.0.0.0 lbsvzw.autodesk.com
0.0.0.0 lbsvzw1.autodesk.com
0.0.0.0 lbsvzw2.autodesk.com
0.0.0.0 library.autodesk.com
0.0.0.0 liveupdate.autodesk.com
0.0.0.0 locationservices.autodesk.com
0.0.0.0 lsctsol04.autodesk.com
0.0.0.0 mail-relay.autodesk.com
0.0.0.0 mneprdext-svc.autodesk.com
0.0.0.0 mut.autodesk.com
0.0.0.0 nbugma-dmz.autodesk.com
0.0.0.0 ns1.autodesk.com
0.0.0.0 ns2.autodesk.com
0.0.0.0 ns3.autodesk.com
0.0.0.0 ns4.autodesk.com
0.0.0.0 ns5.autodesk.com
0.0.0.0 nut.autodesk.com
0.0.0.0 otw-new.autodesk.com
0.0.0.0 otwdownloads.autodesk.com
0.0.0.0 partnercenter.autodesk.com
0.0.0.0 partnerproducts.autodesk.com
0.0.0.0 paste.autodesk.com
0.0.0.0 pedidrq.autodesk.com
0.0.0.0 pediqrx.autodesk.com
0.0.0.0 petars1.autodesk.com
0.0.0.0 petcp11ia-2nat.autodesk.com
0.0.0.0 petcr12ihsrp2.autodesk.com
0.0.0.0 phxgciv.autodesk.com
0.0.0.0 phxgciv_dr.autodesk.com
0.0.0.0 planix3d.autodesk.com
0.0.0.0 pointa.autodesk.com
0.0.0.0 register.autodesk.com
0.0.0.0 registerallied-pr.autodesk.com
0.0.0.0 registeronce.autodesk.com
0.0.0.0 salestraining.autodesk.com
0.0.0.0 searchnews.autodesk.com
0.0.0.0 shop.autodesk.com
0.0.0.0 spamster-bulk.autodesk.com
0.0.0.0 sswwwp.autodesk.com
0.0.0.0 trialdownload.autodesk.com
0.0.0.0 usa.autodesk.com
0.0.0.0 uspetcr12ie_198.autodesk.com
0.0.0.0 uspetcr12if.autodesk.com
0.0.0.0 uspetcr12if_198.autodesk.com
0.0.0.0 uspetcrs12ia_ib_vlan500_2_hsrp.autodesk.com
0.0.0.0 uspetcrs12ia_vlan500_2.autodesk.com
0.0.0.0 uspetcrs12ib_vlan500_2.autodesk.com
0.0.0.0 uspetne06ia_ib_untrust_dip7.autodesk.com
0.0.0.0 usrelay.autodesk.com
0.0.0.0 ussclout1.autodesk.com
0.0.0.0 vzwlpsrel.autodesk.com
0.0.0.0 vzwlpstst.autodesk.com
0.0.0.0 web.autodesk.com
0.0.0.0 webservices.autodesk.com
0.0.0.0 wormhole.autodesk.com
0.0.0.0 www.autodesk.com
0.0.0.0 www3.autodesk.com" }
if($?){   write-Host -ForegroundColor Green "Windows HOSTS fixed"  }else{   write-Host -ForegroundColor red "Windows HOSTS not fixed" } 
}
	

PAUSE
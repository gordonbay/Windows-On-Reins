# Windows On Reins - Windows 10 Ameliorated, Bloatware removal, privacy fix and performance optimization
[![made-with-powershell](https://img.shields.io/badge/PowerShell-1f425f?logo=Powershell)](https://microsoft.com/PowerShell)
[![Discord](https://badgen.net/badge/icon/discord?icon=discord&label)](https://discord.gg/SGHFtvx4bN)

## Warning
I do not take responsibility for what may happen to your system. This is at your own risk.


## What it does - Security

- Disable NetBIOS and Link-Local Multicast Name Resolution (LLMNR) protocol. Both imposes security risk for layer-4 name resolution spoofing attacks, ARP poisoning, KARMA attack and cache poisoning
- Disable SMB Server, it's known for opening doors for mass ransomware attacks - WannaCry and NotPetya
- Disable Anonymous enumeration of shares. Allowing anonymous logon users to list all account names and enumerate all shared resources can provide a map of potential points to attack the system (Stigviewer V-220930)
- Disable Wi-Fi Sense, it connects you to open hotspots that are "greenlighted" through crowdsourcing. Openning doors to Lure10 MITM attack and phishing (Stigviewer V-220808)
- Disable Remote Assistance (RA). RA may allow unauthorized parties access to the resources on the computer. (Stigviewer V-220823)
- Disable Autoplay, "allowing autoplay to execute may introduce malicious code to a system" (Stigviewer V-63673)
- Disable WPAD (Web Proxy Auto-Discovery Protocol), it exposes the system to MITM attack

## What it does - Performance

- Disable the Diagnostic Policy Service. To avoid some I/O operations to the file system and reduce system load
- Disable Windows Malicious Software Removal Tool due to hight disk usage
- Disable NTFS encryption and compression due to processing overhead on filesystem operations
- Disable of scheduled defragmentation due to lack of parameters and waste of disk cycles
- Disable Windows Superfetch, due to high RMA usage and is known for causing slow boot times
- Disable Windows Hibernation, there are some evidence that if you use HDD and not a SSD disabling it may lead to lower boot times
- Disable Winmgmt service, Windows Management Instrumentation. This service transfer unusual amount of data, keeps windows updates silent running even if user had it opt-out
- Allow user to disable Cortana
- Disable Software Protection Platform
- Disable SmartScreen Filter, due to huge performance impact, it checks online data about running programs
- Disable BITS - Background Intelligent Transfer Service, UsoSvc - Update Orchestrator Service, DusmSvc - Data Usage, the all showed the same behavior, its aggressive bandwidth eating will interfere with you online gameplay, work and navigation. Its aggressive disk usable will reduce your HDD or SSD lifespan
- Disable DoSvc (Delivery Optimization), it overrides the windows updates opt-out user option, turn your pc into a p2p peer for Windows updates, mining your network performance and compromises your online gameplay, work and navigation
- Disable wlidsvc service, due to conflicts with some games
- Disable Fax service
- Disable Xbox Dvr, its may cause fps problems on some games
- Disable Windows SgrmBroker - System Guard Runtime Monitor Broker, big name and big memory usage on some systems
- Disable Windows SystemRestore, due to performance draw and never works when you need it
- Disable Windows ShadowCopy, due to performance draw
- Disable Windows Fast Boot, due conflicts with Steam and several other programs
- Disable Adobe updates
- Disable Nvidia NGX updates, due to high network usage and lack of settings

## What it does - Privacy

- Disable Diagtrack, Windows Diagnostics Tracking, design by Microsoft to spy on users and to intefere with your programs
- Disable autoplay and autorun
- Disable Windows Location Tracking and Wifi Sensor
- Disable Windows lfsvc service, Geofence service, a cute name for a location tracking service
- Disable NvTelemetryContainer, Nvidia telemetry agent
- Disable Windows Media Player Network Sharing Service

## What it does - Quality of Life

- Disable Windows Ads within file explorer
- Allow users to definitively disable windows updates
- Allow users to definitively disable windows defender
- Installation of VC++ resources
- Allow users to clear all the bloatware that cames with Windows installation
- Disable Windows sound effects
- Disable error reporting
- Enable dark mode
- Install Nvidia control panel, if you own a Nvidia card
- Dracula's dark mode for Notepad++
- Disable error reporting
- Disable Action Center 
- Disable People's Bar
- Show Computer shortcut on desktop
- Remove all pinned bloatware from your start menu
- Disable sticky keys
- Disable Windows from asking your feedback
- Disable SecurityHealthService, due to anoying and non configurable popups
- Disable WpnService, push notification service
- Disable Razer Chroma SDK Server. Its night and you have that game with Razer SDK enabled running and messing up your keys
- Disable Windows Licence check
- Put "This PC" shortcut on desktop
- Disable Game Bar tips
- Disable Vmware Host Server, service uses port 80

## Fingerprinting Prevention

- Disable files last modification date, in most cases;
- Disable Windows unique advertise ID;
- Disable and clear ETL and perfomance logs;
- Clears file thumbnails and allows user to complete disable it;
- Clears minimized windows thumbnails and allows user to complete disable it;
- Disable recent opened files history;
- Disable Cortana web search;
- Disable location tracking;
- Disable recycle bin;

## Gaming

- Disable Windows mouse acceleration (ideal for FPS games);
- Disable VBS (Virtualization-based security), may have a significant performance boost, specially in games;


Usage
============

1) Run Power Shell as admin;
2) Type the following to enable PowerShell script execution:
<code>Set-ExecutionPolicy Unrestricted -Force</code>

3) Confirm the question;

4) Run the script:
<code>%path-to-file%/wor.ps1</code>

or just right click the file wor.ps1 and select "Execute with powershell"

Credits
============

## https://www.stigviewer.com/stig/windows_10
## https://github.com/builtbybel/debotnet
## https://github.com/Disassembler0/Win10-Initial-Setup-Script
## https://gist.github.com/alirobe/7f3b34ad89a159e6daa1
## https://github.com/adolfintel/Windows10-Privacy
## https://github.com/Sycnex/Windows10Debloater
## https://github.com/dracula/dracula-theme

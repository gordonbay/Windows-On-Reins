# Windows On Reins - Windows 10 Ameliorated, Bloatware removal, privacy fix and performance optimization

This project aim is to make windows 10 usable, faster and under control. 

## Warning
I do not take responsibility for what may happen to your system. This is at your own risk.

## What it does - Quality of Life

- Allow users to definitively disable windows updades
- Allow users to definitively disable windows defender
- Installation of those VC++ resources
- Allow users to clear all the bloatware that cames with Windows installation
- Enable dark mode
- Install Nvidia control panel
- Dracula's dark mode for Notepad++

## What it does - Performance details

- Change power plan to high performance
- Disable Windows Malicious Software Removal Tool, its disk usage is out the charts
- Disable of scheduled defragmentation due to lack of parameters, performance and waste of disk cycles
- Disable Windows Superfetch, it lacks parameters, the ram consumption is a unreal and is known for causing slow boot times
- Disable Windows Hibernation, there are some evidence that if you use HDD and not a SSD disabling it may lead to lower boot times
- Disable Winmgmt service, Windows Management Instrumentation. This service transfer unusual amount of very suspicious data, keeps windows updates silent running even if user had it opt-out and its agressive data transfer interfere with navegation and online gaming
- Allow user to disable Cortana
- Disable Software Protection Platform, licence checking
- Disable SmartScreen Filter, it has a massive impact on running a program because its checks online how often people run this same program. By concept its weak, wont offer great security and has huge performance impact. Its non configurable too.
- Disable BITS - Background Intelligent Transfer Service, UsoSvc - Update Orchestrator Service, DusmSvc - Data Usage, the all showed the same behavior, its aggressive bandwidth eating will interfere with you online gameplay, work and navigation. Its aggressive disk usable will reduce your HDD or SSD lifespan.
- Disable DoSvc (Delivery Optimization), it overrides the windows updates opt-out user option, turn your pc into a p2p peer for Windows updates, mining your network performance and compromises your online gameplay, work and navigation.
- Disable wlidsvc service, due to conflicts with some games
- Disable Fax service
- Disable Xbox Dvr, its may cause fps problems on some games
- Disable Windows SgrmBroker - System Guard Runtime Monitor Broker, big name and big memory usage on some systems
- Disable Windows SystemRestore, due to performance draw and never works when you need it
- Disable Windows ShadowCopy, due to performance draw
- Disable Windows Fast Boot, due conflicts with Steam and several other programs


## What it does - Privacy and security details

- Disable Diagtrack, Windows Diagnostics Tracking, design by Microsoft to spy on users and to intefere with your programs
- Disable autoplay and autorun
- Disable Windows Location Tracking and Wifi Sensor
- Disable Windows unique advertise ID
- Disable Windows lfsvc service, Geofence service, a cute name for a location tracking service
- Disable Adobe updates
- Disable NvTelemetryContainer, Nvidia telemetry agent 

## What it does - Security

- Disable NetBIOS and Link-Local Multicast Name Resolution (LLMNR) protocol. Both imposes security risk for layer-4 name resolution spoofing attacks, ARP poisoning, KARMA attack and cache poisoning.
- Disable SMB Server, it's known for opening doors for mass ransomware attacks - WannaCry and NotPetya

## What it does - Annoyances details

- Disable error reporting
- Disable Action Center 
- Disable People's Bar
- Fix not being able to link outlook 365 account on office outlook 2019
- Show Computer shortcut on desktop
- Remove all pinned bloatware from your start menu
- Disable sticky keys
- Disable Windows from asking your feedback
- Disable SecurityHealthService, due to anoying and non configurable popups
- Disable WpnService, push notification service
- Disable Razer Chroma SDK Server, yeah, its night and you have that game with Razer SDK enabled running and messing up you keys light and you cant see the keys


Usage
============

Run Power Shell with adm privileges
Type:

    Set-ExecutionPolicy unrestricted


Confirm the question

Run the script 

    %path-to-file%/wor.ps1
    
Answer the questions with y or n

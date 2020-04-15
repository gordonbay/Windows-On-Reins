# Windows On Reins - Windows 10 Bloatware removal, privacy fix and performance optimization

This project aim is to make windows 10 usable, faster and under control. 

## What it does -General

- Disable windows services that still download updates even if user choose not to
- Disable windows services with unusual data traffic
- Disable windows services with unusual disk usage
- Disable useless and questionable services like "Windows Telemetry"
- Allow users to definitively disable windows updades
- Allow users to definitively disable windows defender
- Installation of those VC++ resources that should came with windows anyway
- Allow users to clear all the bloatware that came with windows installation

## What it does - Performance details

- Change power plan to high performance
- Disable Windows Malicious Software Removal Tool, its disk usage is out the charts
- Disable of scheduled defragmentation due to lack of parameters, performance and waste of disk cycles
- Disable Windows Superfetch, it has several conflicts with programs including Steam, it lacks parameters and the ram consumption is a unreal
- Disable Windows Hibernation, there are some evidence that if you use HDD and not a SSD disabling it may lead to lower boot times
- Disable Winmgmt service, Windows Management Instrumentation. This service transfer unusual amount of very suspicious data, keeps windows updates silent running even if user had it opt-out and its agressive data transfer interfere with navegation and online gaming
- Allow user to disable Cortana
- Disable Software Protection Platform, licence checking


## What it does - Privacy and security details

- Disable Diagtrack, Windows Diagnostics Tracking, design by Microsoft to spy on users and to intefere with your programs
- Disable autoplay and autorun
- Disable Windows Location Tracking/sensor
- Disable Windows unique advertise ID


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


Usage
============

Run Power Shell with adm privileges
Type:

    Set-ExecutionPolicy unrestricted


Confirm the question

Run the script 

    %path-to-file%/wor.ps1
    
Answer the questions with y or n

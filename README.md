# Windows On Reins - Windows 10 Bloatware removal, privacy fix and performance optimization

This project aim is to make windows 10 usable, faster and under control. 

## What it does

- Disable windows services that still download updates even if user choose not to
- Disable windows services with unusual data traffic
- Disable windows services with unusual disk usage
- Disable useless and questionable services like "Windows Telemetry"
- Allow users to definitively disable windows updades
- Allow users to definitively disable windows defender
- Installation of those VC++ resources that should came with windows anyway
- Allow users to clear all the bloatware that came with windows installation

Usage
============

Run Power Shell with adm privileges
Type:

    Set-ExecutionPolicy unrestricted


Confirm the question

Run the script 

    %path-to-file%/wor.ps1
    
Answer the questions with y or n

@echo off

REM To run this script automatically on Windows shutdown:
REM		See:
REM			https://stackoverflow.com/questions/12434863/executing-a-batch-script-on-windows-shutdown
REM			https://superuser.com/questions/773651/run-a-script-just-before-shutdown-or-reboot-on-windows-home-edition
REM		Open Group Policy (gpedit.msc)
REM		Add under:
REM			Local Computer Policy / Computer Configuration / Windows Settings / Scripts (Startup/Shutdown) / Shutdown

cd /d "%~dp0\..\..\.."

rd /s/q cli\bin

rd /s/q daemon\bin
REM don't delete compiled deps binaries under daemon\References\Windows - they don't take much space
rd /s/q daemon\References\Windows\.deps
rd /s/q "daemon\References\Windows\Native Projects\bin"
rd /s/q "daemon\References\Windows\Native Projects\privateLINE Firewall Native\x64"
rd /s/q "daemon\References\Windows\Native Projects\privateLINE Helpers Native\x64"
del daemon\References\Windows\*.dll

rd /s/q ui\dist
rd /s/q ui\node_modules
rd /s/q ui\out
rd /s/q ui\addons\wifi-info-macos\build
rd /s/q ui\References\Windows\bin

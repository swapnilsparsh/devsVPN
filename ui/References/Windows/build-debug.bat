@echo off

REM Build faster by disabling installer compression
SET COMPRESS=off

"%~dp0/build.bat"
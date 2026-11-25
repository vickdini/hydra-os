@echo off
rem Reads the Hydra boot logs off the Hydra USB stick (read only). Right-click > Run as administrator.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0read-hydra-logs.ps1"

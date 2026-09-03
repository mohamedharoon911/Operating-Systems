@echo off
title OSentinel Interactive Menu-Driven System
color 0A
cd /d "%~dp0"
if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe osentinel_menu.py
) else (
    py osentinel_menu.py
)
pause

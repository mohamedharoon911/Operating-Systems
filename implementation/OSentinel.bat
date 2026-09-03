@echo off
title OSentinel Autonomous OS Protection Web App
color 0A
echo ======================================================================
echo           OSentinel - Autonomous OS Process Protection Web App
echo ======================================================================
echo.
echo Launching OSentinel Engine and opening Web Dashboard...
echo Dashboard URL: http://localhost:8000
echo.

cd /d "%~dp0"

:: Launch default web browser after 1.5 seconds
start /b "" powershell -Command "Start-Sleep -Seconds 1.5; Start-Process 'http://localhost:8000'" >nul 2>&1

:: Start FastAPI Python Server
if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe server.py
) else (
    py server.py
)
pause

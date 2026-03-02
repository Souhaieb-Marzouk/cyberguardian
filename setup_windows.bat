@echo off
REM CyberGuardian Quick Setup Script for Windows
REM This script installs all dependencies and prepares the application

echo ============================================================
echo   CyberGuardian Setup Script
echo ============================================================
echo.

REM Check Python installation
echo [1/4] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.9+ from https://www.python.org/downloads/
    pause
    exit /b 1
)
python --version
echo OK: Python found
echo.

REM Create virtual environment
echo [2/4] Creating virtual environment...
if exist "venv" (
    echo Virtual environment already exists
) else (
    python -m venv venv
    echo OK: Virtual environment created
)
echo.

REM Activate virtual environment and install dependencies
echo [3/4] Installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul 2>&1

REM Use the smart installer
python install_deps.py

if errorlevel 1 (
    echo.
    echo WARNING: Some dependencies may have failed to install.
    echo The application may still work with limited functionality.
    echo.
)
echo.

REM Create necessary directories
echo [4/4] Creating application directories...
if not exist "data" mkdir data
if not exist "data\yara_rules" mkdir data\yara_rules
if not exist "logs" mkdir logs
if not exist "quarantine" mkdir quarantine
echo OK: Directories created
echo.

echo ============================================================
echo   Setup Complete!
echo ============================================================
echo.
echo To run CyberGuardian:
echo   1. Activate virtual environment: venv\Scripts\activate
echo   2. Run application: python main.py
echo.
echo Or simply run: run.bat
echo.
echo For full functionality, run as Administrator.
echo.
pause

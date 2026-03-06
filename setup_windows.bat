@echo off
:: CyberGuardian Windows Setup Script
:: This script properly installs all dependencies including pywin32

echo ============================================
echo   CyberGuardian Windows Setup
echo ============================================
echo.

:: Check Python version
python --version 2>NUL
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.9-3.12 from https://www.python.org/
    pause
    exit /b 1
)

echo [1/5] Upgrading pip...
python -m pip install --upgrade pip

echo.
echo [2/5] Installing core dependencies...
pip install PyQt5 psutil requests urllib3 pyyaml keyring cryptography Pillow

echo.
echo [3/5] Installing yara-python...
pip install yara-python

echo.
echo [4/5] Installing Windows-specific dependencies...
pip install pywin32 WMI

echo.
echo [5/5] Running pywin32 post-install script...
:: Run the pywin32 post-install script
python "%LOCALAPPDATA%\Programs\Python\Python3*\Scripts\pywin32_postinstall.py" -install 2>NUL
if errorlevel 1 (
    :: Try alternative location
    for %%i in (python.exe) do set PYTHON_PATH=%%~$PATH:i
    for %%i in ("%PYTHON_PATH%\..\Scripts\pywin32_postinstall.py") do (
        if exist %%i python "%%i" -install
    )
)

echo.
echo Installing PyInstaller...
pip install pyinstaller

echo.
echo ============================================
echo   Setup Complete!
echo ============================================
echo.
echo You can now run CyberGuardian with:
echo   python main.py
echo.
echo Or build the executable with:
echo   python build.py
echo.
pause

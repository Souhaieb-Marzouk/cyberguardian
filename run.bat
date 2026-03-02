@echo off
REM CyberGuardian Launcher
REM Runs the application with optional admin check

echo ============================================================
echo   CyberGuardian - Malware Detection Tool
echo ============================================================
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorlevel% == 0 (
    echo [INFO] Running with Administrator privileges
    echo [INFO] All features are available
) else (
    echo [WARNING] Not running as Administrator
    echo [WARNING] Some features will be limited
    echo.
    echo To enable all features, right-click and select:
    echo "Run as Administrator"
    echo.
)

echo.

REM Activate virtual environment if exists
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
    echo [INFO] Virtual environment activated
) else (
    echo [WARNING] Virtual environment not found
    echo [INFO] Using system Python
)

echo.
echo Starting CyberGuardian...
echo.

REM Run the application
python main.py

if errorlevel 1 (
    echo.
    echo [ERROR] Application exited with an error
    echo.
    echo Common solutions:
    echo   1. Run: pip install -r requirements.txt
    echo   2. Run as Administrator
    echo   3. Check logs in the 'logs' folder
    echo.
)

pause

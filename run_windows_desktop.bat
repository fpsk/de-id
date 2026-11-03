@echo off
setlocal
cd /d "%~dp0"

echo ============================================================================
echo   HIPAA Safe Harbor PDF De-Identification Studio - Windows 11 Desktop GUI
echo ============================================================================

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.11+ from https://www.python.org/downloads/windows/
    pause
    exit /b 1
)

if not exist ".venv_win\Scripts\python.exe" (
    echo [1/2] Creating local virtual environment ^(.venv_win^)...
    python -m venv .venv_win
    echo [2/2] Installing required packages...
    ".venv_win\Scripts\python.exe" -m pip install --upgrade pip
    ".venv_win\Scripts\python.exe" -m pip install -r requirements.txt flask
)

echo Launching Desktop GUI...
".venv_win\Scripts\python.exe" app.py

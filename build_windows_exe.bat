@echo off
setlocal
cd /d "%~dp0"

echo ============================================================================
echo   Build Standalone Windows 11 Executables (.exe) - Zero Python Required
echo ============================================================================

if not exist ".venv_win\Scripts\python.exe" (
    python -m venv .venv_win
)

".venv_win\Scripts\python.exe" -m pip install --upgrade pip
".venv_win\Scripts\python.exe" -m pip install -r requirements.txt flask pyinstaller

echo.
echo [1/2] Building Standalone Web App Executable (dist\HIPAA_DeID_WebApp.exe)...
".venv_win\Scripts\pyinstaller.exe" --noconfirm --onefile ^
    --name "HIPAA_DeID_WebApp" ^
    --add-data "templates;templates" ^
    --hidden-import "pymupdf" ^
    --hidden-import "cryptography" ^
    --hidden-import "PIL" ^
    webapp.py

echo.
echo [2/2] Building Standalone Native Desktop GUI Executable (dist\HIPAA_DeID_Desktop.exe)...
".venv_win\Scripts\pyinstaller.exe" --noconfirm --onefile --windowed ^
    --name "HIPAA_DeID_Desktop" ^
    --hidden-import "pymupdf" ^
    --hidden-import "cryptography" ^
    --hidden-import "PIL" ^
    app.py

echo.
echo ============================================================================
echo   SUCCESS! Standalone Windows 11 executables created in .\dist\ :
echo     1. dist\HIPAA_DeID_WebApp.exe   (Double-click to open Web Studio)
echo     2. dist\HIPAA_DeID_Desktop.exe  (Double-click to open Native Desktop GUI)
echo   You can copy either .exe to any Windows 11 notebook (no Python needed).
echo ============================================================================
pause

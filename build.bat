@echo off
setlocal
python -m pip install -r requirements.txt
if errorlevel 1 exit /b 1
python -m PyInstaller --clean --onefile --noconsole --name Packwiz-Installer installer.py
if errorlevel 1 exit /b 1
python -m PyInstaller --clean --onefile --noconsole --name Packwiz-Installer-Bootstrap bootstrap.py
if errorlevel 1 exit /b 1
echo Build complete. See dist\
pause

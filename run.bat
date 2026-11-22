@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
if not exist ".venv\Scripts\python.exe" (
  echo [js-endpoints-hunter] creating virtual environment...
  where py >nul 2>nul
  if %errorlevel%==0 (
    py -3 -m venv .venv
  ) else (
    python -m venv .venv
  )
  if errorlevel 1 goto :error
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 goto :error
)
".venv\Scripts\python.exe" app.py
if errorlevel 1 goto :error
exit /b 0
:error
echo.
echo [js-endpoints-hunter] failed. See the message above.
pause
exit /b 1

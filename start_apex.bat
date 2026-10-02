@echo off
title APEX-X Launcher
color 0A

echo.
echo  ======================================================
echo.
echo          A P E X - X   L A U N C H E R
echo.
echo     Malware Analysis Platform
echo.
echo  ======================================================
echo.

:: ──────────────────────────────────────────────────────────
:: 1. Validate Backend (Python venv + dependencies)
:: ──────────────────────────────────────────────────────────
echo [1/4] Checking backend environment...

if not exist "%~dp0backend\venv\Scripts\activate.bat" (
    echo.
    echo  [ERROR] Python virtual environment not found!
    echo  Please create it first:
    echo.
    echo    cd backend
    echo    python -m venv venv
    echo    venv\Scripts\activate
    echo    pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

if not exist "%~dp0backend\venv\Scripts\uvicorn.exe" (
    echo.
    echo  [ERROR] uvicorn not installed in venv!
    echo  Please install dependencies:
    echo.
    echo    cd backend
    echo    venv\Scripts\activate
    echo    pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo  [OK] Backend venv found.

:: ──────────────────────────────────────────────────────────
:: 2. Validate Frontend (node_modules)
:: ──────────────────────────────────────────────────────────
echo [2/4] Checking frontend environment...

if not exist "%~dp0frontend\node_modules" (
    echo.
    echo  [INFO] node_modules not found. Installing dependencies...
    echo.
    cd /d "%~dp0frontend"
    call npm install
    if errorlevel 1 (
        echo.
        echo  [ERROR] npm install failed! Please fix the errors above.
        pause
        exit /b 1
    )
    echo  [OK] Frontend dependencies installed.
) else (
    echo  [OK] Frontend node_modules found.
)

:: ──────────────────────────────────────────────────────────
:: 3. Kill any processes occupying ports 8080 and 3000
:: ──────────────────────────────────────────────────────────
echo [3/4] Cleaning up ports 8080 and 3000...

for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr :8080 ^| findstr LISTENING') do (
    taskkill /f /pid %%a 1>nul 2>nul
)
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr :3000 ^| findstr LISTENING') do (
    taskkill /f /pid %%a 1>nul 2>nul
)

timeout /t 2 /nobreak 1>nul 2>nul
echo  [OK] Ports cleared.

:: ──────────────────────────────────────────────────────────
:: 4. Launch Backend and Frontend in separate windows
:: ──────────────────────────────────────────────────────────
echo [4/4] Launching services...

:: Start Backend (FastAPI + Uvicorn)
start "APEX-X Backend" cmd /k "cd /d %~dp0backend && set PYTHONPATH=%~dp0backend && call .\venv\Scripts\activate.bat && uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload"

:: Give backend a moment to start before frontend
timeout /t 3 /nobreak 1>nul 2>nul

:: Start Frontend (Next.js dev server)
start "APEX-X Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

:: ──────────────────────────────────────────────────────────
:: Done
:: ──────────────────────────────────────────────────────────
echo.
echo  ======================================================
echo   APEX-X is starting up!
echo  ======================================================
echo.
echo   Backend API : http://localhost:8080
echo   API Docs    : http://localhost:8080/docs
echo   Frontend    : http://localhost:3000
echo.
echo   Two new terminal windows have been opened.
echo   Check them for live logs.
echo.
echo   Dynamic analysis boots the Android emulator
echo   automatically when an APK is analysed.
echo   (launch_emulator.bat is optional for manual start)
echo.
echo  ======================================================
echo   Press any key to close this launcher window...
echo  ======================================================
pause

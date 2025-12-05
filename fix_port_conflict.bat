@echo off
REM Fix Docker Compose Port 80 Conflict for Windows
REM This script helps resolve the "address already in use" error for port 80

setlocal enabledelayedexpansion

echo.
echo ==========================================
echo Hypersend Docker Port Conflict Fix
echo ==========================================
echo.

echo [INFO] Stopping current Docker containers...
docker compose down
timeout /t 2 /nobreak
echo [OK] Containers stopped
echo.

echo [INFO] Checking port 80 status...
netstat -ano | findstr ":80 " > nul
if %errorlevel% equ 0 (
    echo [WARN] Port 80 is in use by another process
    echo.
    echo [ACTION] Processes using port 80:
    netstat -ano | findstr ":80 "
    echo.
    echo [SOLUTION] Please:
    echo   1. Open Task Manager (Ctrl+Shift+Esc)
    echo   2. Find the process with the PID listed above
    echo   3. Right-click and select "End Task"
    echo   4. Then run this script again
    echo.
    pause
    goto :end
) else (
    echo [OK] Port 80 is free!
    echo.
)

echo [ACTION] Pulling latest Docker images...
docker compose pull
echo.

echo [ACTION] Building and starting containers...
docker compose up -d --build
echo.

echo [INFO] Waiting for containers to stabilize...
timeout /t 5 /nobreak
echo.

echo [ACTION] Checking container status...
docker compose ps
echo.

echo ==========================================
echo Docker Compose Fix Complete!
echo ==========================================
echo.
echo [SUCCESS] Access your app at:
echo   - Frontend: http://localhost
echo   - API: http://localhost/api/v1/docs
echo   - MongoDB: mongodb://admin:changeme@localhost:27017
echo.
echo [TIP] If you see nginx still failing, check:
echo   1. nginx.conf is correct
echo   2. Backend is running: docker compose logs backend
echo   3. Frontend is running: docker compose logs frontend
echo.

:end
pause

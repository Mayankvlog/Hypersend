@echo off
REM Zaply Complete Verification Script for Windows
REM Checks all components for errors and debugging issues

setlocal enabledelayedexpansion

echo ==================================================
echo ZAPLY VERIFICATION ^& DEBUGGING SCRIPT (WINDOWS)
echo ==================================================
echo.

set ERRORS=0
set WARNINGS=0
set PASSED=0

echo [1] CHECKING FILE STRUCTURE
if exist docker-compose.yml (
    echo [PASS] docker-compose.yml exists
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] docker-compose.yml missing
    set /a ERRORS=!ERRORS!+1
)

if exist nginx.conf (
    echo [PASS] nginx.conf exists
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] nginx.conf missing
    set /a ERRORS=!ERRORS!+1
)

if exist .env.example (
    echo [PASS] .env.example exists
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] .env.example missing
    set /a ERRORS=!ERRORS!+1
)

if exist backend\main.py (
    echo [PASS] backend\main.py exists
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] backend\main.py missing
    set /a ERRORS=!ERRORS!+1
)

if exist frontend\app.py (
    echo [PASS] frontend\app.py exists
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] frontend\app.py missing
    set /a ERRORS=!ERRORS!+1
)
echo.

echo [2] CHECKING DOCUMENTATION
if exist README.md (
    echo [PASS] README.md exists
    set /a PASSED=!PASSED!+1
) else (
    echo [WARN] README.md missing
    set /a WARNINGS=!WARNINGS!+1
)

if exist NGINX_SETUP.md (
    echo [PASS] NGINX_SETUP.md exists
    set /a PASSED=!PASSED!+1
) else (
    echo [WARN] NGINX_SETUP.md missing
    set /a WARNINGS=!WARNINGS!+1
)

if exist DEPLOYMENT.md (
    echo [PASS] DEPLOYMENT.md exists
    set /a PASSED=!PASSED!+1
) else (
    echo [WARN] DEPLOYMENT.md missing
    set /a WARNINGS=!WARNINGS!+1
)
echo.

echo [3] CHECKING NGINX CONFIGURATION
findstr "upstream backend_service" nginx.conf >nul
if !errorlevel! equ 0 (
    echo [PASS] nginx.conf has upstream backend_service
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] nginx.conf missing upstream backend_service
    set /a ERRORS=!ERRORS!+1
)

findstr "upstream frontend_service" nginx.conf >nul
if !errorlevel! equ 0 (
    echo [PASS] nginx.conf has upstream frontend_service
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] nginx.conf missing upstream frontend_service
    set /a ERRORS=!ERRORS!+1
)

findstr "listen 80" nginx.conf >nul
if !errorlevel! equ 0 (
    echo [PASS] nginx.conf configured for HTTP (port 80)
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] nginx.conf not configured for port 80
    set /a ERRORS=!ERRORS!+1
)

findstr "client_max_body_size 40G" nginx.conf >nul
if !errorlevel! equ 0 (
    echo [PASS] nginx.conf supports 40GB file uploads
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] nginx.conf file upload size not configured
    set /a ERRORS=!ERRORS!+1
)
echo.

echo [4] CHECKING DOCKER-COMPOSE
findstr "nginx:" docker-compose.yml >nul
if !errorlevel! equ 0 (
    echo [PASS] docker-compose.yml has nginx service
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] docker-compose.yml missing nginx service
    set /a ERRORS=!ERRORS!+1
)

findstr "backend:" docker-compose.yml >nul
if !errorlevel! equ 0 (
    echo [PASS] docker-compose.yml has backend service
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] docker-compose.yml missing backend service
    set /a ERRORS=!ERRORS!+1
)

findstr "frontend:" docker-compose.yml >nul
if !errorlevel! equ 0 (
    echo [PASS] docker-compose.yml has frontend service
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] docker-compose.yml missing frontend service
    set /a ERRORS=!ERRORS!+1
)

findstr "mongodb:" docker-compose.yml >nul
if !errorlevel! equ 0 (
    echo [PASS] docker-compose.yml has mongodb service
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] docker-compose.yml missing mongodb service
    set /a ERRORS=!ERRORS!+1
)
echo.

echo [5] CHECKING ENVIRONMENT VARIABLES
findstr "MONGO_USER" .env.example >nul
if !errorlevel! equ 0 (
    echo [PASS] .env.example has MONGO_USER
    set /a PASSED=!PASSED!+1
) else (
    echo [WARN] .env.example missing MONGO_USER
    set /a WARNINGS=!WARNINGS!+1
)

findstr "SECRET_KEY" .env.example >nul
if !errorlevel! equ 0 (
    echo [PASS] .env.example has SECRET_KEY
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] .env.example missing SECRET_KEY
    set /a ERRORS=!ERRORS!+1
)

findstr "VPS_IP" .env.example >nul
if !errorlevel! equ 0 (
    echo [PASS] .env.example has VPS_IP
    set /a PASSED=!PASSED!+1
) else (
    echo [WARN] .env.example missing VPS_IP
    set /a WARNINGS=!WARNINGS!+1
)
echo.

echo [6] CHECKING FRONTEND CODE
findstr "class ZaplyApp" frontend\app.py >nul
if !errorlevel! equ 0 (
    echo [PASS] Frontend has ZaplyApp class
    set /a PASSED=!PASSED!+1
) else (
    echo [FAIL] Frontend missing ZaplyApp class
    set /a ERRORS=!ERRORS!+1
)

findstr /R "ft.app.*name.*Zaply" frontend\app.py >nul
if !errorlevel! equ 0 (
    echo [PASS] Frontend app name set to 'Zaply'
    set /a PASSED=!PASSED!+1
) else (
    echo [WARN] Frontend app name may not be set properly
    set /a WARNINGS=!WARNINGS!+1
)

findstr "page.bgcolor" frontend\app.py >nul
if !errorlevel! equ 0 (
    echo [PASS] Frontend sets page background color
    set /a PASSED=!PASSED!+1
) else (
    echo [WARN] Frontend may have white screen issue
    set /a WARNINGS=!WARNINGS!+1
)
echo.

echo [7] CHECKING SECURITY
findstr "MONGO_PASSWORD:-changeme" docker-compose.yml >nul
if !errorlevel! equ 0 (
    echo [WARN] MongoDB default password (changeme) - change before production
    set /a WARNINGS=!WARNINGS!+1
) else (
    echo [PASS] MongoDB password configured
    set /a PASSED=!PASSED!+1
)

findstr "DEBUG:-False" docker-compose.yml >nul
if !errorlevel! equ 0 (
    echo [PASS] DEBUG mode disabled in production
    set /a PASSED=!PASSED!+1
) else (
    echo [WARN] DEBUG mode configuration issue
    set /a WARNINGS=!WARNINGS!+1
)
echo.

echo ==================================================
echo VERIFICATION SUMMARY
echo ==================================================
echo Passed: %PASSED%
echo Warnings: %WARNINGS%
echo Errors: %ERRORS%
echo.

if %ERRORS% equ 0 (
    echo [SUCCESS] All checks passed - ready for deployment!
    echo.
    echo Next steps:
    echo 1. Deploy to VPS: docker-compose up -d
    echo 2. Check status: docker-compose ps
    echo 3. Test health: curl http://139.59.82.105/health
    echo 4. View logs: docker logs -f hypersend_nginx
    exit /b 0
) else (
    echo [ERROR] Please fix errors before deployment
    exit /b 1
)

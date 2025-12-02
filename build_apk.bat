@echo off
REM Zaply APK Build Script for Windows
REM Builds optimized APK with size reduction

echo.
echo ╔════════════════════════════════════════════════════════════╗
echo ║     ZAPLY APK BUILD - SIZE OPTIMIZED (Windows)             ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    exit /b 1
)

REM Check if Flet is installed
python -c "import flet" >nul 2>&1
if errorlevel 1 (
    echo ❌ Flet is not installed. Install it with: pip install flet
    exit /b 1
)

echo ✓ Python found
echo ✓ Flet found
echo.

REM Step 1: Clean previous builds
echo [Step 1/5] Cleaning previous builds...
if exist build rmdir /s /q build >nul 2>&1
if exist .flet rmdir /s /q .flet >nul 2>&1
if exist .gradle rmdir /s /q .gradle >nul 2>&1
echo ✓ Cleaned build directories
echo.

REM Step 2: Clean Python cache
echo [Step 2/5] Cleaning Python cache...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d" >nul 2>&1
for /r . %%f in (*.pyc) do @if exist "%%f" del /q "%%f" >nul 2>&1
echo ✓ Cleaned Python cache
echo.

REM Step 3: Choose build type
echo [Step 3/5] Choosing build type...
echo.
echo Build options:
echo   1) Standard (Recommended) - All architectures, optimized - ~100MB
echo   2) Minimal (Smallest) - ARM64 only - ~70MB
echo   3) Split (Fastest) - Separate per architecture - ~50MB each
echo.

if "%1"=="minimal" goto build_minimal
if "%1"=="split" goto build_split

:build_standard
echo Selected: Standard Build (all architectures)
echo.
echo [Step 4/5] Building APK with optimizations...
echo Command: flet build apk --compile-app --cleanup-app --split-per-abi --verbose
echo.
flet build apk --compile-app --cleanup-app --split-per-abi --verbose
goto check_result

:build_minimal
echo Selected: Minimal Build (ARM64 only)
echo.
echo [Step 4/5] Building APK (minimal)...
echo Command: flet build apk --compile-app --cleanup-app --arch arm64-v8a --verbose
echo.
flet build apk --compile-app --cleanup-app --arch arm64-v8a --verbose
goto check_result

:build_split
echo Selected: Split Build (per architecture)
echo.
echo [Step 4/5] Building split APKs...
echo Command: flet build apk --compile-app --cleanup-app --split-per-abi --verbose
echo.
flet build apk --compile-app --cleanup-app --split-per-abi --verbose

:check_result
if errorlevel 1 (
    echo.
    echo ❌ APK build failed!
    echo.
    echo Troubleshooting:
    echo   - Ensure Android SDK is installed
    echo   - Check ANDROID_SDK_ROOT environment variable
    echo   - Run: pip install --upgrade flet
    exit /b 1
)

echo.
echo [Step 5/5] Build completed successfully!
echo.

REM Display APK information
echo ╔════════════════════════════════════════════════════════════╗
echo ║                    APK BUILD COMPLETE                      ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

echo APK Location: build\android\app\build\outputs\apk\release\
echo.
echo APK Files:
echo.

for /r "build\android\app\build\outputs\apk" %%f in (*.apk) do (
    setlocal enabledelayedexpansion
    set "file=%%f"
    set "size=!file!"
    
    REM Display file info
    echo   ✓ %%~nf
    
    REM Get file size using PowerShell
    for /f "tokens=*" %%s in ('powershell -NoProfile -Command "(Get-Item '%%f').length / 1MB"') do (
        echo     Size: %%s MB
    )
    echo.
)

echo ═══════════════════════════════════════════════════════════════
echo.
echo ✅ Your APK is ready to install!
echo.
echo Next steps:
echo   1. Connect Android device via USB
echo   2. Enable USB debugging on device
echo   3. Run: adb install -r build\android\app\build\outputs\apk\release\app-release.apk
echo   4. Or distribute APK to Google Play Store
echo.
echo ═══════════════════════════════════════════════════════════════
echo.

exit /b 0

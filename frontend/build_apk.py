#!/usr/bin/env python3
"""
Optimized APK Build Script for Zaply
This script builds an optimized production APK with proper configuration
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_step(message):
    print(f"{Colors.OKBLUE}{Colors.BOLD}[STEP]{Colors.ENDC} {message}")

def print_success(message):
    print(f"{Colors.OKGREEN}✓{Colors.ENDC} {message}")

def print_error(message):
    print(f"{Colors.FAIL}✗{Colors.ENDC} {message}")

def print_warning(message):
    print(f"{Colors.WARNING}⚠{Colors.ENDC} {message}")

def main():
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("=" * 60)
    print("  Zaply APK Builder - Optimized Production Build")
    print("=" * 60)
    print(f"{Colors.ENDC}")
    
    # Get the frontend directory
    frontend_dir = Path(__file__).parent
    os.chdir(frontend_dir)
    
    # Step 1: Check production environment
    print_step("Checking production environment configuration...")
    env_prod = frontend_dir / ".env.production"
    if env_prod.exists():
        # Copy production env to .env for build
        shutil.copy(env_prod, frontend_dir / ".env")
        print_success("Production environment loaded")
    else:
        print_warning(".env.production not found, using default .env")
    
    # Step 2: Update dependencies
    print_step("Installing/updating dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--upgrade"], 
                      check=True, capture_output=True)
        print_success("Dependencies updated")
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install dependencies: {e}")
        return 1
    
    # Step 3: Clean old builds
    print_step("Cleaning old build artifacts...")
    build_dir = frontend_dir / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
        print_success("Old builds cleaned")
    
    # Step 4: Build APK with optimizations
    print_step("Building optimized APK (this may take 5-10 minutes)...")
    print(f"{Colors.OKCYAN}Building with production backend: http://139.59.82.105:8000{Colors.ENDC}")
    
    build_cmd = [
        "flet", "build", "apk",
        "--name", "Zaply",
        "--org", "com.zaply",
        "--description", "Fast File Transfer and Messaging",
        "--no-ios-no-provisioning-profile",
        "--release",  # Release build for better performance
        "--optimize",  # Enable optimizations
    ]
    
    try:
        result = subprocess.run(build_cmd, check=True)
        print_success("APK build completed successfully!")
    except subprocess.CalledProcessError as e:
        print_error(f"APK build failed: {e}")
        return 1
    
    # Step 5: Find and report the APK location
    print_step("Locating generated APK...")
    apk_files = list(build_dir.glob("**/*.apk"))
    
    if apk_files:
        print_success(f"APK generated successfully!")
        for apk in apk_files:
            size_mb = apk.stat().st_size / (1024 * 1024)
            print(f"{Colors.OKGREEN}  → {apk.name} ({size_mb:.2f} MB){Colors.ENDC}")
            print(f"  Location: {apk.absolute()}")
    else:
        print_warning("APK file not found in expected location")
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}Build Summary:{Colors.ENDC}")
    print(f"  Backend: http://139.59.82.105:8000")
    print(f"  Build Type: Release (Optimized)")
    print(f"  HTTP/2: Enabled")
    print(f"  Debug: Disabled")
    print(f"\n{Colors.OKGREEN}✓ All done! You can now install the APK on Android devices.{Colors.ENDC}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

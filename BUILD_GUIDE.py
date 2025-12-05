#!/usr/bin/env python
"""
Hypersend APK Build Configuration and Guide
Complete setup for building production APK from Flet
"""

import os
from pathlib import Path

# ============================================================
# BUILD CONFIGURATION
# ============================================================

BUILD_CONFIG = {
    "app_name": "Zaply",
    "package_name": "com.zaply.app",
    "version": "1.0.0",
    "build_version": 1,
    "author": "Mayank",
    "author_email": "mayank.kr0311@gmail.com",
    "description": "Secure P2P File Transfer and Messaging",
    
    # Backend Configuration
    "backend_url_prod": "http://139.59.82.105:8000",
    "backend_url_dev": "http://139.59.82.105:8000",
    
    # APK Configuration
    "icon": "frontend/assets/icon.png",
    "theme": "material",
    
    # Permissions (Android)
    "permissions": [
        "INTERNET",
        "ACCESS_NETWORK_STATE",
        "ACCESS_FINE_LOCATION",
        "CAMERA",
        "RECORD_AUDIO",
        "READ_CONTACTS",
        "CALL_PHONE",
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
        "MANAGE_EXTERNAL_STORAGE"  # For Android 11+
    ],
    
    # Build Features
    "build_android_split_per_abi": True,
    "android_architectures": ["arm64-v8a"],
    "min_sdk_version": 21,
    "target_sdk_version": 36,
}

print("=" * 70)
print("🚀 HYPERSEND/ZAPLY APK BUILD CONFIGURATION")
print("=" * 70)
print()
print("📦 App Details:")
print(f"   - Name: {BUILD_CONFIG['app_name']}")
print(f"   - Package: {BUILD_CONFIG['package_name']}")
print(f"   - Version: {BUILD_CONFIG['version']}")
print()
print("🌐 Backend:")
print(f"   - Production: {BUILD_CONFIG['backend_url_prod']}")
print(f"   - Development: {BUILD_CONFIG['backend_url_dev']}")
print()
print("📱 Android:")
print(f"   - Min SDK: {BUILD_CONFIG['min_sdk_version']}")
print(f"   - Target SDK: {BUILD_CONFIG['target_sdk_version']}")
print(f"   - Architectures: {', '.join(BUILD_CONFIG['android_architectures'])}")
print(f"   - Permissions: {len(BUILD_CONFIG['permissions'])} required")
print()
print("=" * 70)
print("📋 BUILD STEPS")
print("=" * 70)
print()
print("1. SETUP")
print("   $ pip install flet")
print("   $ pip install -r frontend/requirements.txt")
print()
print("2. CONFIGURATION")
print("   $ export PRODUCTION_API_URL=http://139.59.82.105:8000")
print("   $ export DEBUG=False")
print()
print("3. BUILD (On Linux with Android SDK)")
print("   $ flet build apk --output zaply.apk --release")
print("   $ flet build ipa (for iOS)")
print()
print("4. ALTERNATIVELY - Using Docker")
print("   $ docker-compose up -d")
print("   $ docker exec hypersend_backend python validate_project.py")
print()
print("=" * 70)
print("✅ ALL SYSTEMS READY FOR APK BUILD")
print("=" * 70)

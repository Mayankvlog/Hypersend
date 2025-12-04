#!/usr/bin/env python3
"""
Zaply Frontend - Comprehensive Test Script
Tests all components of the Zaply frontend application
"""

import sys
import os
from pathlib import Path

# Add frontend to path
frontend_path = (Path(__file__).parent.parent / "frontend").resolve()
sys.path.insert(0, str(frontend_path))
sys.path.insert(0, str(frontend_path.parent))

# Set test environment
os.environ["DEBUG"] = "True"
os.environ["API_BASE_URL"] = "http://localhost:8000"

def test_imports():
    """Test that all modules can be imported"""
    print("\n" + "="*60)
    print("TEST 1: Module Imports")
    print("="*60)
    
    tests = [
        ("flet", "import flet as ft"),
        ("httpx", "import httpx"),
        ("app", "from frontend.app import ZaplyApp, main"),
        ("theme", "from frontend.theme import PRIMARY_COLOR"),
        ("permissions", "from frontend.permissions_manager import request_android_permissions"),
    ]
    
    for name, import_cmd in tests:
        try:
            exec(import_cmd)
            print(f"[OK] {name:20} - passed")
        except Exception as e:
            print(f"[FAIL] {name:20} - {e}")
            assert False, f"Import failed for {name}"
    
    assert True


def test_android_manifest():
    """Test Android manifest configuration"""
    print("\n" + "="*60)
    print("TEST 2: Android Manifest")
    print("="*60)
    
    try:
        # Try main location first
        manifest_path = frontend_path / "build" / "flutter" / "android" / "app" / "src" / "main" / "AndroidManifest.xml"
        if not manifest_path.exists():
            manifest_path = frontend_path / "android" / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            print("[FAIL] AndroidManifest.xml not found")
            assert False, "AndroidManifest.xml not found"
        
        print(f"[OK] Manifest found: {manifest_path}")
        manifest_content = manifest_path.read_text()
        
        required_perms = [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ]
        
        found = sum(1 for perm in required_perms if perm in manifest_content)
        print(f"[OK] Found {found}/{len(required_perms)} required permissions")
        
        if 'package="com.zaply.app"' in manifest_content:
            print("[OK] Package name: com.zaply.app")
        else:
            print("[WARN] Package name not set correctly")
        
        assert found == len(required_perms), f"Only {found}/{len(required_perms)} permissions found"
        
    except Exception as e:
        print(f"[FAIL] {e}")
        import traceback
        traceback.print_exc()
        assert False, str(e)


def test_pubspec():
    """Test pubspec.yaml configuration"""
    print("\n" + "="*60)
    print("TEST 3: Pubspec Configuration")
    print("="*60)
    
    try:
        pubspec_path = frontend_path / "build" / "flutter" / "pubspec.yaml"
        if not pubspec_path.exists():
            pubspec_path = frontend_path / "pubspec.yaml"
        
        if not pubspec_path.exists():
            print("[FAIL] pubspec.yaml not found")
            assert False, "pubspec.yaml not found"
        
        print(f"[OK] Pubspec found: {pubspec_path}")
        pubspec_content = pubspec_path.read_text()
        
        checks = [
            ('name: Zaply', "App name"),
            ('version: 1.0.0+1', "Version"),
            ('flutter:', "Flutter config"),
        ]
        
        all_pass = True
        for pattern, desc in checks:
            if pattern in pubspec_content:
                print(f"[OK] {desc}: found")
            else:
                print(f"[FAIL] {desc}: missing")
                all_pass = False
        
        assert all_pass
        
    except Exception as e:
        print(f"[FAIL] {e}")
        import traceback
        traceback.print_exc()
        assert False, str(e)


def test_permissions_module():
    """Test permissions module"""
    print("\n" + "="*60)
    print("TEST 4: Permissions Manager")
    print("="*60)
    
    try:
        from frontend.permissions_manager import REQUIRED_PERMISSIONS
        
        print("[OK] Permissions manager imported")
        print(f"[OK] {len(REQUIRED_PERMISSIONS)} required permissions configured:")
        
        for perm in REQUIRED_PERMISSIONS:
            short = perm.split(".")[-1]
            print(f"     - {short}")
        
        assert True
    except Exception as e:
        print(f"[FAIL] {e}")
        import traceback
        traceback.print_exc()
        assert False, str(e)


def test_theme():
    """Test theme configuration"""
    print("\n" + "="*60)
    print("TEST 5: Theme Configuration")
    print("="*60)
    
    try:
        from frontend.theme import (
            PRIMARY_COLOR,
            SECONDARY_COLOR,
            BACKGROUND_LIGHT,
            BACKGROUND_DARK,
            TEXT_PRIMARY,
            TEXT_SECONDARY,
        )
        
        print("[OK] Theme imported successfully")
        print(f"[OK] Primary Color:      {PRIMARY_COLOR}")
        print(f"[OK] Secondary Color:    {SECONDARY_COLOR}")
        print(f"[OK] Background Light:   {BACKGROUND_LIGHT}")
        print(f"[OK] Background Dark:    {BACKGROUND_DARK}")
        print(f"[OK] Text Primary:       {TEXT_PRIMARY}")
        print(f"[OK] Text Secondary:     {TEXT_SECONDARY}")
        
        assert True
    except Exception as e:
        print(f"[FAIL] {e}")
        import traceback
        traceback.print_exc()
        assert False, str(e)
#!/usr/bin/env python3
"""
Zaply Frontend - Comprehensive Test Script
Tests all components of the Zaply frontend application
"""

import sys
import os
from pathlib import Path

# Add frontend to path
frontend_path = (Path(__file__).parent / "frontend").resolve()
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
            return False
    
    return True


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
            print(f"[FAIL] AndroidManifest.xml not found")
            return False
        
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
            print(f"[OK] Package name: com.zaply.app")
        else:
            print(f"[WARN] Package name not set correctly")
        
        if found == len(required_perms):
            print("[OK] All permissions present")
            return True
        else:
            print(f"[FAIL] Only {found}/{len(required_perms)} permissions found")
            return False
        
    except Exception as e:
        print(f"[FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


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
            print(f"[FAIL] pubspec.yaml not found")
            return False
        
        print(f"[OK] Pubspec found: {pubspec_path}")
        pubspec_content = pubspec_path.read_text()
        
        checks = [
            ('name: zaply', "App name"),
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
        
        return all_pass
        
    except Exception as e:
        print(f"[FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


def test_permissions_module():
    """Test permissions module"""
    print("\n" + "="*60)
    print("TEST 4: Permissions Manager")
    print("="*60)
    
    try:
        from frontend.permissions_manager import REQUIRED_PERMISSIONS
        
        print(f"[OK] Permissions manager imported")
        print(f"[OK] {len(REQUIRED_PERMISSIONS)} required permissions configured:")
        
        for perm in REQUIRED_PERMISSIONS:
            short = perm.split(".")[-1]
            print(f"     - {short}")
        
        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


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
        
        print(f"[OK] Theme imported successfully")
        print(f"[OK] Primary Color:      {PRIMARY_COLOR}")
        print(f"[OK] Secondary Color:    {SECONDARY_COLOR}")
        print(f"[OK] Background Light:   {BACKGROUND_LIGHT}")
        print(f"[OK] Background Dark:    {BACKGROUND_DARK}")
        print(f"[OK] Text Primary:       {TEXT_PRIMARY}")
        print(f"[OK] Text Secondary:     {TEXT_SECONDARY}")
        
        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all tests"""
    print("\n")
    print("=" * 60)
    print(" " * 15 + "ZAPLY FRONTEND TEST SUITE")
    print("=" * 60)
    
    results = []
    
    # Run all tests
    results.append(("Module Imports", test_imports()))
    results.append(("Android Manifest", test_android_manifest()))
    results.append(("Pubspec Config", test_pubspec()))
    results.append(("Permissions Module", test_permissions_module()))
    results.append(("Theme Config", test_theme()))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{test_name:30} {status}")
    
    print("="*60)
    print(f"Results: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("\n[OK] ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n[FAIL] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)

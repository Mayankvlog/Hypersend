#!/usr/bin/env python3
"""
Final verification script for password authentication fix
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

import requests
import json
from backend.auth.utils import verify_password, hash_password
import hashlib

def test_password_formats():
    """Test all password formats work correctly"""
    print("=" * 60)
    print("PASSWORD FORMATS VERIFICATION")
    print("=" * 60)
    
    # Test 1: Legacy SHA256+salt format
    print("1. Legacy SHA256+salt format:")
    test_password = "Mayank@#03"
    test_salt = "c91742d7343ab1c4c923167777f6bf6e"
    combined = test_password + test_salt
    legacy_hash = hashlib.sha256(combined.encode()).hexdigest()
    
    result = verify_password(test_password, legacy_hash, test_salt, "test_user")
    print(f"   ✅ Legacy format: {result}")
    assert result == True
    
    # Test 2: New PBKDF2 format
    print("2. New PBKDF2 format:")
    new_hash, new_salt = hash_password(test_password)
    result = verify_password(test_password, new_hash, new_salt, "test_user")
    print(f"   ✅ PBKDF2 format: {result}")
    assert result == True
    
    # Test 3: Edge cases
    print("3. Edge cases:")
    result = verify_password("", legacy_hash, test_salt, "test_user")
    print(f"   ✅ Empty password: {not result}")
    assert result == False
    
    print("   ✅ All password formats working!")

def test_database_config():
    """Test database configuration"""
    print(f"\nDATABASE CONFIGURATION")
    print("=" * 60)
    
    from backend.config import settings
    
    print(f"Mock DB disabled: {not settings.USE_MOCK_DB}")
    print(f"MongoDB host: {settings._MONGO_HOST}")
    print(f"Database name: {settings._MONGO_DB}")
    
    assert not settings.USE_MOCK_DB, "Mock database should be disabled"
    print("   ✅ Database configuration correct!")

def test_connectivity():
    """Test service connectivity"""
    print(f"\nSERVICE CONNECTIVITY")
    print("=" * 60)
    
    services = [
        ("Backend", "http://localhost:8000/health"),
        ("API", "http://localhost/api/v1/health"),
        ("Frontend", "http://localhost/health")
    ]
    
    results = {}
    for name, url in services:
        try:
            response = requests.get(url, timeout=5)
            results[name] = response.status_code == 200
            status = "✅" if results[name] else "❌"
            print(f"   {status} {name}: {response.status_code}")
        except Exception as e:
            results[name] = False
            print(f"   ❌ {name}: {type(e).__name__}")
    
    return results

def test_authentication():
    """Test authentication endpoints"""
    print(f"\nAUTHENTICATION ENDPOINTS")
    print("=" * 60)
    
    # Test login
    print("1. Login endpoint:")
    try:
        login_data = {
            "email": "mayank.kr0311@gmail.com",
            "password": "Mayank@#03"
        }
        
        response = requests.post(
            "http://localhost/api/v1/auth/login",
            json=login_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Login successful!")
            return True
        elif response.status_code == 401:
            print("   ⚠️  Login failed - password may not match database")
            return False
        else:
            print(f"   ❌ Unexpected status: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Login error: {type(e).__name__}")
        return False

def main():
    """Run final verification"""
    print("🔍 HYPERSEND FINAL VERIFICATION")
    print("=" * 60)
    
    # Test password formats
    test_password_formats()
    
    # Test database config
    test_database_config()
    
    # Test connectivity
    connectivity_results = test_connectivity()
    
    # Test authentication if services are running
    auth_result = False
    if connectivity_results.get("API", False):
        auth_result = test_authentication()
    
    # Summary
    print(f"\n" + "=" * 60)
    print("FINAL VERIFICATION SUMMARY")
    print("=" * 60)
    
    print("✅ Password formats: WORKING")
    print("✅ Database config: CORRECT")
    print(f"{'✅' if connectivity_results.get('Backend', False) else '❌'} Backend connectivity: {'UP' if connectivity_results.get('Backend', False) else 'DOWN'}")
    print(f"{'✅' if connectivity_results.get('API', False) else '❌'} API connectivity: {'UP' if connectivity_results.get('API', False) else 'DOWN'}")
    print(f"{'✅' if connectivity_results.get('Frontend', False) else '❌'} Frontend connectivity: {'UP' if connectivity_results.get('Frontend', False) else 'DOWN'}")
    print(f"{'✅' if auth_result else '❌'} Authentication: {'WORKING' if auth_result else 'NEEDS TESTING'}")
    
    print(f"\n🎯 STATUS:")
    if all(connectivity_results.values()) and auth_result:
        print("🎉 ALL SYSTEMS OPERATIONAL!")
        print("✅ Legacy password format fixed")
        print("✅ Frontend-backend connected")
        print("✅ Authentication working")
    else:
        print("⚠️  Some services need attention")
        if not connectivity_results.get("Backend", False):
            print("   - Backend service not running")
        if not connectivity_results.get("API", False):
            print("   - API not accessible through nginx")
        if not connectivity_results.get("Frontend", False):
            print("   - Frontend service not running")
        if not auth_result and connectivity_results.get("API", False):
            print("   - Authentication needs database password update")
    
    print(f"\n📋 Deployment Instructions:")
    print("1. On server: cd /hypersend/Hypersend")
    print("2. Test: python test_password_auth_fix.py")
    print("3. Restart: docker compose restart backend frontend nginx")
    print("4. Verify: python final_verification.py")
    print("5. Test login: http://localhost")

if __name__ == "__main__":
    main()

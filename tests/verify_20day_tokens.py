#!/usr/bin/env python3
"""
Final verification that all token expiration is set to 20 days (480 hours)
"""

import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

def verify_all_token_settings():
    """Verify all token expiration settings are 20 days"""
    print("🔍 VERIFYING 20-DAY TOKEN CONFIGURATION")
    print("=" * 60)
    
    try:
        from config import settings
        
        # Check all token settings
        access_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        refresh_days = settings.REFRESH_TOKEN_EXPIRE_DAYS  
        upload_hours = settings.UPLOAD_TOKEN_EXPIRE_HOURS
        
        print("📋 CURRENT SETTINGS:")
        print(f"   ACCESS_TOKEN_EXPIRE_MINUTES: {access_minutes}")
        print(f"   REFRESH_TOKEN_EXPIRE_DAYS: {refresh_days}")
        print(f"   UPLOAD_TOKEN_EXPIRE_HOURS: {upload_hours}")
        
        # Convert all to days for comparison
        access_days = access_minutes / (60 * 24)
        refresh_days_val = refresh_days
        upload_days = upload_hours / 24
        
        print(f"\n📊 CONVERTED TO DAYS:")
        print(f"   Access token: {access_days:.1f} days")
        print(f"   Refresh token: {refresh_days_val:.1f} days")
        print(f"   Upload token: {upload_days:.1f} days")
        
        # Verify all are 20 days
        expected_days = 20
        tolerance = 0.1  # 10% tolerance
        
        access_ok = abs(access_days - expected_days) <= tolerance
        refresh_ok = abs(refresh_days_val - expected_days) <= tolerance
        upload_ok = abs(upload_days - expected_days) <= tolerance
        
        print(f"\n✅ VERIFICATION RESULTS:")
        print(f"   Access token (20 days): {'✅ PASS' if access_ok else '❌ FAIL'}")
        print(f"   Refresh token (20 days): {'✅ PASS' if refresh_ok else '❌ FAIL'}")
        print(f"   Upload token (20 days): {'✅ PASS' if upload_ok else '❌ FAIL'}")
        
        if access_ok and refresh_ok and upload_ok:
            print(f"\n🎉 SUCCESS: All tokens are configured for 20-day expiration!")
            print(f"   ✅ Access tokens: {access_minutes} minutes ({access_days:.1f} days)")
            print(f"   ✅ Refresh tokens: {refresh_days} days")  
            print(f"   ✅ Upload tokens: {upload_hours} hours ({upload_days:.1f} days)")
            return True
        else:
            print(f"\n❌ ERROR: Some tokens are not configured for 20-day expiration!")
            return False
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def check_docker_compose_settings():
    """Check Docker compose file for token settings"""
    print("\n🐳 CHECKING DOCKER COMPOSE SETTINGS")
    print("=" * 60)
    
    try:
        docker_compose_path = os.path.join(os.path.dirname(__file__), '..', 'docker-compose.yml')
        with open(docker_compose_path, 'r') as f:
            content = f.read()
            
        # Look for token settings
        if 'ACCESS_TOKEN_EXPIRE_MINUTES: 28800' in content:
            print("✅ Docker ACCESS_TOKEN_EXPIRE_MINUTES: 28800 (20 days)")
            docker_access_ok = True
        else:
            print("❌ Docker ACCESS_TOKEN_EXPIRE_MINUTES not set to 28800")
            docker_access_ok = False
            
        if 'REFRESH_TOKEN_EXPIRE_DAYS: 20' in content:
            print("✅ Docker REFRESH_TOKEN_EXPIRE_DAYS: 20")
            docker_refresh_ok = True
        else:
            print("❌ Docker REFRESH_TOKEN_EXPIRE_DAYS not set to 20")
            docker_refresh_ok = False
            
        if 'UPLOAD_TOKEN_EXPIRE_HOURS: 480' in content:
            print("✅ Docker UPLOAD_TOKEN_EXPIRE_HOURS: 480 (20 days)")
            docker_upload_ok = True
        else:
            print("❌ Docker UPLOAD_TOKEN_EXPIRE_HOURS not set to 480")
            docker_upload_ok = False
            
        return docker_access_ok and docker_refresh_ok and docker_upload_ok
        
    except Exception as e:
        print(f"❌ ERROR reading docker-compose.yml: {e}")
        return False

if __name__ == "__main__":
    print("🚀 FINAL VERIFICATION: 20-DAY (480-HOUR) TOKEN EXPIRATION")
    print("=" * 70)
    
    config_ok = verify_all_token_settings()
    docker_ok = check_docker_compose_settings()
    
    print("\n" + "=" * 70)
    print("📋 FINAL SUMMARY:")
    print(f"   Config file settings: {'✅ PASS' if config_ok else '❌ FAIL'}")
    print(f"   Docker compose settings: {'✅ PASS' if docker_ok else '❌ FAIL'}")
    
    if config_ok and docker_ok:
        print("\n🎉 ALL 20-DAY TOKEN SETTINGS VERIFIED!")
        print("✅ Users will stay logged in for 20 days")
        print("✅ File uploads support 480-hour sessions")
        print("✅ Refresh tokens last for 20 days")
        print("✅ Perfect for large file uploads and long sessions")
        sys.exit(0)
    else:
        print("\n❌ TOKEN CONFIGURATION ISSUES FOUND!")
        sys.exit(1)

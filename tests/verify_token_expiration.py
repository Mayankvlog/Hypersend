#!/usr/bin/env python3
"""
Test script to verify token expiration is set to 20 days (480 hours)
"""

import sys
import os
from datetime import datetime, timedelta, timezone

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

def test_token_expiration():
    """Test that tokens are created with 20-day expiration"""
    try:
        from auth.utils import create_access_token
        from config import settings
        import jwt
        
        print("🔍 TESTING TOKEN EXPIRATION SETTINGS")
        print("=" * 50)
        
        # Check configuration
        print(f"✅ ACCESS_TOKEN_EXPIRE_MINUTES: {settings.ACCESS_TOKEN_EXPIRE_MINUTES}")
        print(f"✅ REFRESH_TOKEN_EXPIRE_DAYS: {settings.REFRESH_TOKEN_EXPIRE_DAYS}")
        print(f"✅ UPLOAD_TOKEN_EXPIRE_HOURS: {settings.UPLOAD_TOKEN_EXPIRE_HOURS}")
        
        # Calculate expected expiration
        expected_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        expected_hours = expected_minutes / 60
        expected_days = expected_hours / 24
        
        print(f"\n📊 EXPECTED EXPIRATION:")
        print(f"   Minutes: {expected_minutes}")
        print(f"   Hours: {expected_hours}")
        print(f"   Days: {expected_days}")
        
        # Create test token
        test_data = {"sub": "test-user-id"}
        token = create_access_token(test_data)
        
        # Decode token to check expiration
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        exp_timestamp = decoded['exp']
        exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        
        actual_duration = exp_datetime - now
        actual_minutes = actual_duration.total_seconds() / 60
        actual_hours = actual_minutes / 60
        actual_days = actual_hours / 24
        
        print(f"\n🎯 ACTUAL TOKEN EXPIRATION:")
        print(f"   Minutes: {actual_minutes:.0f}")
        print(f"   Hours: {actual_hours:.0f}")
        print(f"   Days: {actual_days:.1f}")
        
        # Verify 20-day expiration
        if 19.5 <= actual_days <= 20.5:  # Allow small variance
            print(f"\n✅ SUCCESS: Token expiration is correctly set to ~20 days!")
            return True
        else:
            print(f"\n❌ ERROR: Token expiration is not 20 days!")
            return False
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def test_upload_token_expiration():
    """Test upload token with 480-hour expiration"""
    try:
        from auth.utils import create_access_token
        from config import settings
        import jwt
        
        print("\n🔍 TESTING UPLOAD TOKEN EXPIRATION")
        print("=" * 50)
        
        # Create token with 480-hour expiration
        test_data = {"sub": "test-user-id"}
        upload_token = create_access_token(test_data, timedelta(hours=480))
        
        # Decode token
        decoded = jwt.decode(upload_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        exp_timestamp = decoded['exp']
        exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        
        actual_duration = exp_datetime - now
        actual_hours = actual_duration.total_seconds() / 3600
        actual_days = actual_hours / 24
        
        print(f"📊 UPLOAD TOKEN EXPIRATION:")
        print(f"   Hours: {actual_hours:.0f}")
        print(f"   Days: {actual_days:.1f}")
        
        if 475 <= actual_hours <= 485:  # Allow small variance
            print(f"✅ SUCCESS: Upload token expiration is correctly set to ~480 hours (20 days)!")
            return True
        else:
            print(f"❌ ERROR: Upload token expiration is not 480 hours!")
            return False
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

if __name__ == "__main__":
    print("🚀 VERIFYING 20-DAY (480-HOUR) TOKEN EXPIRATION")
    print("=" * 60)
    
    success1 = test_token_expiration()
    success2 = test_upload_token_expiration()
    
    print("\n" + "=" * 60)
    if success1 and success2:
        print("🎉 ALL TOKEN EXPIRATION TESTS PASSED!")
        print("✅ Regular tokens: 20 days (28800 minutes)")
        print("✅ Upload tokens: 480 hours (20 days)")
        sys.exit(0)
    else:
        print("❌ TOKEN EXPIRATION TESTS FAILED!")
        sys.exit(1)

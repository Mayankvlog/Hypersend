#!/usr/bin/env python3
"""Test token-based password reset functionality to diagnose reset issues"""

import pytest

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Set mock database
os.environ['USE_MOCK_DB'] = 'True'
os.environ['DEBUG'] = 'True'

from fastapi.testclient import TestClient
try:
    from backend.main import app
    from backend.config import settings
except ImportError:
    app = None
    settings = None
    print("Warning: Could not import main app or settings")

import json
import logging

logger = logging.getLogger(__name__)

def test_email_service_configuration():
    """Test email service configuration"""
    print("\n🔧 Testing Email Service Configuration...")
    
    print(f"EMAIL_SERVICE_ENABLED: {settings.EMAIL_SERVICE_ENABLED if settings else 'N/A'}")
    print(f"SMTP_HOST: {settings.SMTP_HOST if settings else 'N/A'}")
    print(f"SMTP_PORT: {settings.SMTP_PORT if settings else 'N/A'}")
    print(f"SMTP_USERNAME: {settings.SMTP_USERNAME if settings else 'N/A'}")
    print(f"SMTP_PASSWORD: {'SET' if settings.SMTP_PASSWORD else 'EMPTY'}")
    print(f"SMTP_USE_TLS: {settings.SMTP_USE_TLS if settings else 'N/A'}")
    print(f"EMAIL_FROM: {settings.EMAIL_FROM if settings else 'N/A'}")
    
    # Check if email service is properly configured
    if settings and settings.EMAIL_SERVICE_ENABLED:
        print("✅ Email service is ENABLED")
        
        # Check SMTP configuration
        if all([settings.SMTP_HOST, settings.SMTP_USERNAME, settings.SMTP_PASSWORD, settings.EMAIL_FROM]):
            print("✅ SMTP configuration is COMPLETE")
            assert True
        else:
            print("❌ SMTP configuration is INCOMPLETE")
            print("Missing settings:")
            if not settings.SMTP_HOST:
                print("  - SMTP_HOST")
            if not settings.SMTP_USERNAME:
                print("  - SMTP_USERNAME")
            if not settings.SMTP_PASSWORD:
                print("  - SMTP_PASSWORD")
            if not settings.EMAIL_FROM:
                print("  - EMAIL_FROM")
            assert False, "SMTP configuration is incomplete"
    else:
        print("❌ Email service is DISABLED")
        assert False, "Email service is disabled"

def test_forgot_password_endpoint():
    """Test forgot password endpoint functionality"""
    print("\n🧪 Testing Forgot Password Endpoint...")
    
    if not app:
        print("❌ App not available - skipping test")
        pytest.skip("App not available")
    
    client = TestClient(app)
    
    # Test forgot password request
    test_email = "testforgot@example.com"
    forgot_payload = {"email": test_email}
    
    try:
        response = client.post("/api/v1/auth/forgot-password", json=forgot_payload)
        
        print(f"Forgot password status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Response data: {data}")
            
            # Check if token was generated
            if data.get("success") and data.get("token"):
                print("✅ Token generated successfully")
                print(f"Token: {data.get('token')}")
                assert True
            else:
                print("❌ Token not generated or missing in response")
                assert False, "Token not generated or missing in response"
        else:
            print(f"❌ Forgot password failed: {response.status_code}")
            print(f"Response: {response.text}")
            assert False, f"Forgot password failed: {response.status_code}"
            
    except Exception as e:
        print(f"❌ Exception during forgot password test: {e}")
        assert False, f"Exception during forgot password test: {e}"

def test_email_sending_directly():
    """Test email sending function directly"""
    print("\n📧 Testing Email Sending Function Directly...")
    
    if not settings:
        print("❌ Settings not available - skipping email test")
        pytest.skip("Settings not available")
    
    # Import the email sending function
    try:
        from backend.routes.auth import send_password_reset_email
    except ImportError:
        print("❌ Could not import email sending function")
        assert False, "Could not import email sending function"
    
    try:
        # Test email sending with test data
        test_email = "directtest@example.com"
        test_token = "test-token-12345"
        test_name = "Test User"
        
        print(f"Testing email send to: {test_email}")
        print(f"Testing with token: {test_token}")
        
        result = send_password_reset_email(test_email, test_token, test_name)
        
        if result:
            print("✅ Email sending function returned True")
            assert True
        else:
            print("❌ Email sending function returned False")
            assert False, "Email sending function returned False"
            
    except Exception as e:
        print(f"❌ Exception during direct email test: {e}")
        assert False, f"Exception during direct email test: {e}"

def check_smtp_connection():
    """Test SMTP connection if possible"""
    print("\n🔌 Testing SMTP Connection...")
    
    if not settings or not settings.EMAIL_SERVICE_ENABLED:
        print("❌ Email service disabled - skipping SMTP test")
        pytest.skip("Email service disabled")
    
    try:
        import smtplib
        print(f"Attempting to connect to {settings.SMTP_HOST}:{settings.SMTP_PORT}")
        
        server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
        
        if settings.SMTP_USE_TLS:
            server.starttls()
            print("✅ TLS started")
        
        if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            print("✅ SMTP login successful")
            server.quit()
            assert True
        else:
            print("❌ SMTP credentials not configured")
            server.quit()
            assert False, "SMTP credentials not configured"
            
    except Exception as e:
        print(f"❌ SMTP connection failed: {e}")
        assert False, f"SMTP connection failed: {e}"

if __name__ == "__main__":
    print("🔧 Testing Forgot Password Email Functionality")
    print("=" * 60)
    
    # Test 1: Check email service configuration
    config_ok = test_email_service_configuration()
    
    # Test 2: Test forgot password endpoint
    endpoint_ok = test_forgot_password_endpoint()
    
    # Test 3: Test email sending directly
    email_ok = test_email_sending_directly()
    
    # Test 4: Test SMTP connection
    smtp_ok = check_smtp_connection()
    
    print("\n" + "=" * 60)
    print("📊 Test Results:")
    print(f"Email Service Config: {'✅ PASS' if config_ok else '❌ FAIL'}")
    print(f"Forgot Password Endpoint: {'✅ PASS' if endpoint_ok else '❌ FAIL'}")
    print(f"Email Sending Function: {'✅ PASS' if email_ok else '❌ FAIL'}")
    print(f"SMTP Connection: {'✅ PASS' if smtp_ok else '❌ FAIL'}")
    
    # Diagnosis
    if not config_ok:
        print("\n🔍 DIAGNOSIS: Email service is not properly configured")
        print("💡 SOLUTION: Configure SMTP settings in .env file:")
        print("   - SMTP_HOST=smtp.gmail.com")
        print("   - SMTP_PORT=587")
        print("   - SMTP_USERNAME=your-email@gmail.com")
        print("   - SMTP_PASSWORD=your-app-password")
        print("   - SMTP_USE_TLS=True")
        print("   - EMAIL_FROM=noreply@yourdomain.com")
    elif config_ok and not endpoint_ok:
        print("\n🔍 DIAGNOSIS: Email service configured but endpoint failing")
        print("💡 SOLUTION: Check forgot password endpoint logic")
    elif config_ok and not email_ok:
        print("\n🔍 DIAGNOSIS: Email service configured but email sending failing")
        print("💡 SOLUTION: Check SMTP credentials and network connectivity")
    elif config_ok and endpoint_ok and email_ok and not smtp_ok:
        print("\n🔍 DIAGNOSIS: All components working but SMTP connection failing")
        print("💡 SOLUTION: Check firewall, antivirus, or Gmail app password settings")
    else:
        print("\n🎉 All tests passed! Email functionality should be working.")
    
    print("=" * 60)

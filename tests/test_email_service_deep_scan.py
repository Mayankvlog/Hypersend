"""
Deep scan of email service configuration and logic
Tests the complete email sending flow without creating new files
"""

import sys
import os
import asyncio
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

def test_email_service_configuration():
    """Test email service configuration"""
    print("\n" + "="*80)
    print("EMAIL SERVICE CONFIGURATION SCAN")
    print("="*80)
    
    # Check environment variables
    print("\n1. ENVIRONMENT VARIABLES CHECK:")
    print("-" * 80)
    
    env_vars = {
        "SENDER_EMAIL": os.getenv("SENDER_EMAIL"),
        "SENDER_PASSWORD": os.getenv("SENDER_PASSWORD"),
        "SENDER_NAME": os.getenv("SENDER_NAME"),
        "APP_URL": os.getenv("APP_URL"),
        "SMTP_HOST": os.getenv("SMTP_HOST"),
        "SMTP_PORT": os.getenv("SMTP_PORT"),
        "SMTP_USERNAME": os.getenv("SMTP_USERNAME"),
        "SMTP_PASSWORD": os.getenv("SMTP_PASSWORD"),
        "SMTP_USE_TLS": os.getenv("SMTP_USE_TLS"),
        "EMAIL_FROM": os.getenv("EMAIL_FROM"),
        "ENABLE_EMAIL": os.getenv("ENABLE_EMAIL"),
    }
    
    for key, value in env_vars.items():
        if value:
            if "PASSWORD" in key or "SECRET" in key:
                print(f"  {key}: {'*' * len(str(value))}")
            else:
                print(f"  {key}: {value}")
        else:
            print(f"  {key}: NOT SET")
    
    # Check config settings
    print("\n2. CONFIG SETTINGS CHECK:")
    print("-" * 80)
    
    from backend.config import settings
    
    config_attrs = {
        "ENABLE_EMAIL": settings.ENABLE_EMAIL,
        "SMTP_HOST": settings.SMTP_HOST,
        "SMTP_PORT": settings.SMTP_PORT,
        "SMTP_USERNAME": settings.SMTP_USERNAME,
        "EMAIL_FROM": settings.EMAIL_FROM,
        "EMAIL_SERVICE_ENABLED": settings.EMAIL_SERVICE_ENABLED,
        "DEBUG": settings.DEBUG,
    }
    
    for key, value in config_attrs.items():
        if "PASSWORD" in key or "SECRET" in key:
            print(f"  {key}: {'*' * len(str(value)) if value else 'NOT SET'}")
        else:
            print(f"  {key}: {value}")
    
    # Check email service instance
    print("\n3. EMAIL SERVICE INSTANCE CHECK:")
    print("-" * 80)
    
    from backend.utils.email_service import email_service
    
    service_attrs = {
        "smtp_server": email_service.smtp_server,
        "smtp_port": email_service.smtp_port,
        "sender_email": email_service.sender_email,
        "sender_name": email_service.sender_name,
        "app_url": email_service.app_url,
        "enable_email": email_service.enable_email,
    }
    
    for key, value in service_attrs.items():
        if "password" in key.lower():
            print(f"  {key}: {'*' * len(str(value)) if value else 'NOT SET'}")
        else:
            print(f"  {key}: {value}")
    
    # Check sender_password specifically
    print("\n4. SENDER PASSWORD CHECK:")
    print("-" * 80)
    print(f"  sender_password is set: {bool(email_service.sender_password)}")
    print(f"  sender_password length: {len(email_service.sender_password) if email_service.sender_password else 0}")
    print(f"  sender_password value: {'*' * len(email_service.sender_password) if email_service.sender_password else 'EMPTY'}")
    
    # Check SMTP configuration validation
    print("\n5. SMTP CONFIGURATION VALIDATION:")
    print("-" * 80)
    
    if not email_service.sender_password:
        print("  ❌ CRITICAL: sender_password is empty!")
        print("     This is why emails are not being sent.")
        print("     The email service checks for sender_password and returns False if not set.")
    else:
        print(f"  ✅ sender_password is configured")
    
    if not email_service.smtp_server:
        print("  ❌ CRITICAL: smtp_server is not configured!")
    else:
        print(f"  ✅ smtp_server is configured: {email_service.smtp_server}")
    
    if email_service.smtp_port not in [25, 465, 587, 2525]:
        print(f"  ⚠️  WARNING: Unusual SMTP port: {email_service.smtp_port}")
    else:
        print(f"  ✅ smtp_port is valid: {email_service.smtp_port}")
    
    # Check enable_email flag
    print("\n6. EMAIL ENABLE FLAG CHECK:")
    print("-" * 80)
    print(f"  enable_email: {email_service.enable_email}")
    if not email_service.enable_email:
        print("  ⚠️  Email is disabled - emails will not be sent")
    else:
        print("  ✅ Email is enabled")
    
    # Simulate password reset email flow
    print("\n7. PASSWORD RESET EMAIL FLOW SIMULATION:")
    print("-" * 80)
    
    async def simulate_password_reset():
        """Simulate password reset email sending"""
        test_email = "test@example.com"
        test_token = "test_token_12345"
        test_name = "Test User"
        
        print(f"  Simulating password reset email to: {test_email}")
        print(f"  Token: {test_token[:20]}...")
        print(f"  User name: {test_name}")
        
        # Check conditions
        print("\n  Checking conditions:")
        print(f"    1. enable_email: {email_service.enable_email}")
        print(f"    2. sender_password set: {bool(email_service.sender_password)}")
        print(f"    3. sender_email: {email_service.sender_email}")
        
        if not email_service.enable_email:
            print("    ❌ Email is disabled - would return True without sending")
            return
        
        if not email_service.sender_password:
            print("    ❌ sender_password is empty - would return False")
            return
        
        print("    ✅ All conditions met - would attempt to send email")
        
        # Try to send (will fail with invalid credentials, but we can see the attempt)
        try:
            result = await email_service.send_password_reset_email(
                to_email=test_email,
                reset_token=test_token,
                user_name=test_name
            )
            print(f"  Result: {result}")
        except Exception as e:
            print(f"  Error: {type(e).__name__}: {str(e)[:100]}")
    
    asyncio.run(simulate_password_reset())
    
    # Root cause analysis
    print("\n8. ROOT CAUSE ANALYSIS:")
    print("-" * 80)
    
    issues = []
    
    if not email_service.sender_password:
        issues.append("CRITICAL: SENDER_PASSWORD environment variable is not set")
    
    if email_service.sender_password == "your-app-password":
        issues.append("CRITICAL: SENDER_PASSWORD is still a placeholder value")
    
    if not email_service.smtp_server:
        issues.append("CRITICAL: SMTP_HOST is not configured")
    
    if not email_service.sender_email or email_service.sender_email == "noreply@hypersend.io":
        issues.append("WARNING: SENDER_EMAIL is using default value")
    
    if not email_service.enable_email:
        issues.append("WARNING: Email service is disabled (ENABLE_EMAIL=False)")
    
    if issues:
        print("  Issues found:")
        for i, issue in enumerate(issues, 1):
            print(f"    {i}. {issue}")
    else:
        print("  ✅ No configuration issues found")
    
    # Solution
    print("\n9. SOLUTION:")
    print("-" * 80)
    print("  To fix email sending:")
    print("  1. Set SENDER_EMAIL environment variable (or use SMTP_USERNAME)")
    print("  2. Set SENDER_PASSWORD environment variable (or use SMTP_PASSWORD)")
    print("  3. Ensure SMTP_HOST is set to smtp.gmail.com (or your SMTP server)")
    print("  4. Ensure SMTP_PORT is set to 587 (for Gmail with TLS)")
    print("  5. For Gmail: Use an App Password, not your regular password")
    print("  6. Set ENABLE_EMAIL=True in .env")
    print("  7. Restart the backend service")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    test_email_service_configuration()

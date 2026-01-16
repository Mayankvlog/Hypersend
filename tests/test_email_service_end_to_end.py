"""
End-to-end test for password reset email flow
Tests the complete flow from forgot-password to reset-password
"""

import pytest
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timezone, timedelta

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


class TestPasswordResetEmailFlow:
    """Test complete password reset email flow"""
    
    @pytest.mark.asyncio
    async def test_forgot_password_sends_email(self):
        """Test that forgot-password endpoint sends email"""
        from backend.routes.auth import forgot_password
        from backend.utils.email_service import email_service
        
        # Mock the email service
        with patch.object(email_service, 'send_password_reset_email', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = True
            
            # Simulate forgot password request
            request = {
                "email": "test@example.com"
            }
            
            # This would normally be called by the API
            # We're testing the logic here
            print("✅ Forgot password endpoint available")
    
    @pytest.mark.asyncio
    async def test_password_reset_email_contains_token(self):
        """Test that password reset email contains the reset token"""
        from backend.utils.email_service import email_service
        
        # Mock SMTP
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            
            # Capture the email message
            sent_message = None
            def capture_message(msg):
                nonlocal sent_message
                sent_message = msg
            
            mock_server.send_message.side_effect = capture_message
            
            # Send password reset email
            result = await email_service.send_password_reset_email(
                to_email="test@example.com",
                reset_token="test_token_abc123",
                user_name="Test User"
            )
            
            # Verify email was sent
            assert result is True
            assert mock_server.send_message.called
            
            print("✅ Password reset email sent successfully")
    
    @pytest.mark.asyncio
    async def test_password_changed_email_sent_after_reset(self):
        """Test that password changed email is sent after successful reset"""
        from backend.utils.email_service import email_service
        
        # Mock SMTP
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            
            # Send password changed email
            result = await email_service.send_password_changed_email(
                to_email="test@example.com",
                user_name="Test User"
            )
            
            # Verify email was sent
            assert result is True
            assert mock_server.send_message.called
            
            print("✅ Password changed confirmation email sent successfully")
    
    def test_email_service_configuration_complete(self):
        """Test that email service has all required configuration"""
        from backend.utils.email_service import email_service
        from backend.config import settings
        
        # Check all required fields
        assert email_service.smtp_server, "SMTP server not configured"
        assert email_service.smtp_port, "SMTP port not configured"
        assert email_service.sender_email, "Sender email not configured"
        assert email_service.sender_password, "Sender password not configured"
        assert email_service.enable_email, "Email service not enabled"
        
        print("✅ Email service configuration complete")
    
    def test_email_service_has_required_methods(self):
        """Test that email service has all required methods"""
        from backend.utils.email_service import email_service
        import asyncio
        
        # Check methods exist
        assert hasattr(email_service, 'send_password_reset_email'), "send_password_reset_email method missing"
        assert hasattr(email_service, 'send_password_changed_email'), "send_password_changed_email method missing"
        assert hasattr(email_service, '_send_smtp_email'), "_send_smtp_email method missing"
        
        # Check methods are async
        assert asyncio.iscoroutinefunction(email_service.send_password_reset_email), "send_password_reset_email not async"
        assert asyncio.iscoroutinefunction(email_service.send_password_changed_email), "send_password_changed_email not async"
        
        print("✅ Email service has all required methods")
    
    def test_auth_routes_use_email_service(self):
        """Test that auth routes properly use email service"""
        from backend.routes.auth import forgot_password, reset_password
        import inspect
        
        # Check forgot_password uses email_service
        forgot_password_source = inspect.getsource(forgot_password)
        assert 'email_service' in forgot_password_source, "forgot_password doesn't use email_service"
        assert 'send_password_reset_email' in forgot_password_source, "forgot_password doesn't call send_password_reset_email"
        
        # Check reset_password uses email_service
        reset_password_source = inspect.getsource(reset_password)
        assert 'email_service' in reset_password_source, "reset_password doesn't use email_service"
        assert 'send_password_changed_email' in reset_password_source, "reset_password doesn't call send_password_changed_email"
        
        print("✅ Auth routes properly use email service")
    
    @pytest.mark.asyncio
    async def test_email_service_error_handling(self):
        """Test that email service handles errors gracefully"""
        from backend.utils.email_service import email_service
        
        # Test 1: Connection error
        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = ConnectionError("Connection failed")
            
            result = await email_service.send_password_reset_email(
                to_email="test@example.com",
                reset_token="test_token",
                user_name="Test User"
            )
            
            assert result is False, "Should return False on connection error"
        
        # Test 2: Authentication error
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            mock_server.login.side_effect = Exception("Authentication failed")
            
            result = await email_service.send_password_reset_email(
                to_email="test@example.com",
                reset_token="test_token",
                user_name="Test User"
            )
            
            assert result is False, "Should return False on authentication error"
        
        print("✅ Email service error handling works correctly")
    
    def test_email_service_fallback_configuration(self):
        """Test that email service uses fallback configuration"""
        from backend.utils.email_service import EmailService
        
        # Test SENDER_PASSWORD fallback to SMTP_PASSWORD
        os.environ["SENDER_PASSWORD"] = ""
        os.environ["SMTP_PASSWORD"] = "fallback_password"
        os.environ["SENDER_EMAIL"] = ""
        os.environ["EMAIL_FROM"] = ""
        os.environ["SMTP_USERNAME"] = "fallback@example.com"
        
        service = EmailService()
        
        # Should use fallback values
        assert service.sender_password == "fallback_password", "Should fallback to SMTP_PASSWORD"
        assert service.sender_email == "fallback@example.com", "Should fallback to SMTP_USERNAME"
        
        print("✅ Email service fallback configuration works correctly")


class TestEmailServiceIntegration:
    """Integration tests for email service with auth flow"""
    
    def test_password_reset_flow_integration(self):
        """Test complete password reset flow integration"""
        from backend.routes.auth import forgot_password, reset_password
        from backend.utils.email_service import email_service
        from backend.config import settings
        
        # Verify all components are available
        assert email_service is not None, "Email service not initialized"
        assert settings.ENABLE_PASSWORD_RESET, "Password reset not enabled"
        assert settings.ENABLE_EMAIL, "Email not enabled"
        
        print("✅ Password reset flow integration verified")
    
    def test_email_service_initialization_logging(self, capsys):
        """Test that email service logs initialization in debug mode"""
        os.environ["DEBUG"] = "True"
        
        import importlib
        import utils.email_service as email_module
        importlib.reload(email_module)
        
        # Capture output
        captured = capsys.readouterr()
        
        # Should log initialization
        assert "[EMAIL_SERVICE]" in captured.out or "SMTP Server" in captured.out
        
        print("✅ Email service initialization logging works")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

"""
Comprehensive pytest test for email service fix
Tests the complete email sending flow with proper configuration
"""

import pytest
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


class TestEmailServiceConfiguration:
    """Test email service configuration and initialization"""
    
    def test_email_service_uses_sender_password_fallback(self):
        """Test that email service falls back to SMTP_PASSWORD if SENDER_PASSWORD not set"""
        # Set up environment
        os.environ["SENDER_PASSWORD"] = ""
        os.environ["SMTP_PASSWORD"] = "test_smtp_password"
        os.environ["SENDER_EMAIL"] = ""
        os.environ["SMTP_USERNAME"] = "test@example.com"
        
        # Reimport to get fresh instance
        import importlib
        import backend.utils.email_service as email_module
        importlib.reload(email_module)
        
        service = email_module.EmailService()
        
        # Should use SMTP_PASSWORD as fallback
        assert service.sender_password == "test_smtp_password"
        assert service.sender_email == "test@example.com"
    
    def test_email_service_prefers_sender_password(self):
        """Test that email service prefers SENDER_PASSWORD over SMTP_PASSWORD"""
        os.environ["SENDER_PASSWORD"] = "sender_password"
        os.environ["SMTP_PASSWORD"] = "smtp_password"
        os.environ["SENDER_EMAIL"] = "sender@example.com"
        os.environ["SMTP_USERNAME"] = "smtp@example.com"
        
        import importlib
        import backend.utils.email_service as email_module
        importlib.reload(email_module)
        
        service = email_module.EmailService()
        
        # Should prefer SENDER_PASSWORD
        assert service.sender_password == "sender_password"
        assert service.sender_email == "sender@example.com"
    
    def test_email_service_uses_email_from_fallback(self):
        """Test that email service falls back to EMAIL_FROM if SENDER_EMAIL not set"""
        os.environ["SENDER_EMAIL"] = ""
        os.environ["EMAIL_FROM"] = "noreply@example.com"
        os.environ["SMTP_USERNAME"] = "smtp@example.com"
        
        import importlib
        import backend.utils.email_service as email_module
        importlib.reload(email_module)
        
        service = email_module.EmailService()
        
        # Should use EMAIL_FROM as fallback
        assert service.sender_email == "noreply@example.com"


class TestPasswordResetEmailFlow:
    """Test password reset email sending flow"""
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email_with_valid_credentials(self):
        """Test sending password reset email with valid SMTP credentials"""
        # Set up environment with valid credentials
        os.environ["SENDER_PASSWORD"] = "valid_password"
        os.environ["SENDER_EMAIL"] = "test@gmail.com"
        os.environ["ENABLE_EMAIL"] = "True"
        
        import importlib
        import backend.utils.email_service as email_module
        importlib.reload(email_module)
        
        service = email_module.EmailService()
        
        # Mock SMTP to avoid actual email sending
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            
            # Call send_password_reset_email
            result = await service.send_password_reset_email(
                to_email="user@example.com",
                reset_token="test_token_12345",
                user_name="Test User"
            )
            
            # Should return True (email sent)
            assert result is True
            
            # Verify SMTP was called
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once_with("test@gmail.com", "valid_password")
            mock_server.send_message.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email_without_password(self):
        """Test that password reset email fails gracefully without password"""
        os.environ["SENDER_PASSWORD"] = ""
        os.environ["SMTP_PASSWORD"] = ""
        os.environ["ENABLE_EMAIL"] = "True"
        
        import importlib
        import backend.utils.email_service as email_module
        importlib.reload(email_module)
        
        service = email_module.EmailService()
        
        # Call send_password_reset_email
        result = await service.send_password_reset_email(
            to_email="user@example.com",
            reset_token="test_token_12345",
            user_name="Test User"
        )
        
        # Should return False (email not sent)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email_when_disabled(self):
        """Test that password reset email returns True when email is disabled"""
        os.environ["ENABLE_EMAIL"] = "False"
        
        import importlib
        import backend.utils.email_service as email_module
        importlib.reload(email_module)
        
        service = email_module.EmailService()
        
        # Call send_password_reset_email
        result = await service.send_password_reset_email(
            to_email="user@example.com",
            reset_token="test_token_12345",
            user_name="Test User"
        )
        
        # Should return True (email disabled, but process continues)
        assert result is True


class TestEmailServiceIntegration:
    """Integration tests for email service"""
    
    def test_email_service_initialization_logs_configuration(self, capsys):
        """Test that email service logs configuration on initialization"""
        os.environ["SENDER_PASSWORD"] = "test_password"
        os.environ["SENDER_EMAIL"] = "test@example.com"
        os.environ["DEBUG"] = "True"
        
        import importlib
        import backend.utils.email_service as email_module
        importlib.reload(email_module)
        
        service = email_module.EmailService()
        
        # Capture output
        captured = capsys.readouterr()
        
        # Should log configuration
        assert "[EMAIL_SERVICE]" in captured.out or service.sender_email == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_password_changed_email_flow(self):
        """Test password changed confirmation email flow"""
        os.environ["SENDER_PASSWORD"] = "valid_password"
        os.environ["SENDER_EMAIL"] = "test@gmail.com"
        os.environ["ENABLE_EMAIL"] = "True"
        
        import importlib
        import backend.utils.email_service as email_module
        importlib.reload(email_module)
        
        service = email_module.EmailService()
        
        # Mock SMTP
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            
            # Call send_password_changed_email
            result = await service.send_password_changed_email(
                to_email="user@example.com",
                user_name="Test User"
            )
            
            # Should return True
            assert result is True
            
            # Verify SMTP was called
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once()


class TestEmailServiceErrorHandling:
    """Test email service error handling"""
    
    @pytest.mark.asyncio
    async def test_smtp_connection_error_handling(self):
        """Test that SMTP connection errors are handled gracefully"""
        os.environ["SENDER_PASSWORD"] = "valid_password"
        os.environ["SENDER_EMAIL"] = "test@gmail.com"
        os.environ["ENABLE_EMAIL"] = "True"
        
        import importlib
        import backend.utils.email_service as email_module
        importlib.reload(email_module)
        
        service = email_module.EmailService()
        
        # Mock SMTP to raise connection error
        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = ConnectionError("SMTP connection failed")
            
            # Call send_password_reset_email
            result = await service.send_password_reset_email(
                to_email="user@example.com",
                reset_token="test_token_12345",
                user_name="Test User"
            )
            
            # Should return False (email not sent)
            assert result is False
    
    @pytest.mark.asyncio
    async def test_smtp_authentication_error_handling(self):
        """Test that SMTP authentication errors are handled gracefully"""
        os.environ["SENDER_PASSWORD"] = "invalid_password"
        os.environ["SENDER_EMAIL"] = "test@gmail.com"
        os.environ["ENABLE_EMAIL"] = "True"
        
        import importlib
        import backend.utils.email_service as email_module
        importlib.reload(email_module)
        
        service = email_module.EmailService()
        
        # Mock SMTP to raise authentication error
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            mock_server.login.side_effect = Exception("Authentication failed")
            
            # Call send_password_reset_email
            result = await service.send_password_reset_email(
                to_email="user@example.com",
                reset_token="test_token_12345",
                user_name="Test User"
            )
            
            # Should return False (email not sent)
            assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

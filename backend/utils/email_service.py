"""
Email Service for Hypersend
Handles password reset emails and other notifications
"""

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Optional, Dict, Any

try:
    from ..config import settings
except ImportError:
    from config import settings

class EmailService:
    """Service for sending emails"""
    
    def __init__(self):
        # Email Configuration
        # CRITICAL FIX: Support both SENDER_* and SMTP_* environment variables
        # Priority: SENDER_* > SMTP_* > defaults
        self.smtp_server = os.getenv("SMTP_SERVER") or os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        
        # CRITICAL FIX: Try SENDER_EMAIL first, then EMAIL_FROM, then SMTP_USERNAME
        self.sender_email = (
            os.getenv("SENDER_EMAIL") or 
            os.getenv("EMAIL_FROM") or 
            os.getenv("SMTP_USERNAME") or 
            "noreply@hypersend.io"
        )
        
        # CRITICAL FIX: Try SENDER_PASSWORD first, then SMTP_PASSWORD
        self.sender_password = (
            os.getenv("SENDER_PASSWORD") or 
            os.getenv("SMTP_PASSWORD") or 
            ""
        )
        
        self.sender_name = os.getenv("SENDER_NAME", "Hypersend")
        self.app_url = os.getenv("APP_URL", "http://localhost:8000")
        enable_email_env = os.getenv("ENABLE_EMAIL")
        if enable_email_env is None:
            self.enable_email = settings.ENABLE_EMAIL  # Use config setting instead of env directly
        else:
            self.enable_email = enable_email_env.lower() in ("true", "1", "yes")
        
        # Log configuration on initialization (debug mode only)
        if settings.DEBUG:
            print(f"[EMAIL_SERVICE] Initialized with:")
            print(f"  SMTP Server: {self.smtp_server}:{self.smtp_port}")
            print(f"  Sender Email: {self.sender_email}")
            print(f"  Sender Password: {'*' * len(self.sender_password) if self.sender_password else 'NOT SET'}")
            print(f"  Email Enabled: {self.enable_email}")
        
    def _get_email_footer(self) -> str:
        """Get standardized email footer"""
        return f"""
<hr style="border: none; border-top: 1px solid #ddd; margin-top: 30px;">
<p style="font-size: 12px; color: #999; text-align: center;">
    This is an automated message from {self.sender_name}.<br>
    If you did not request this, please ignore this email.<br>
    © {datetime.now(timezone.utc).year} {self.sender_name}. All rights reserved.
</p>
        """
    
    def _send_smtp_email(self, to_email: str, subject: str, html_body: str, text_body: Optional[str] = None) -> bool:
        """Send email via SMTP"""
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.sender_name} <{self.sender_email}>"
            msg["To"] = to_email
            
            # Add text version (fallback)
            if text_body:
                msg.attach(MIMEText(text_body, "plain"))
            else:
                # Create simple text version from HTML
                text_version = html_body.replace("<br>", "\n").replace("<p>", "").replace("</p>", "\n")
                # Remove HTML tags
                import re
                text_version = re.sub("<[^<]+?>", "", text_version)
                msg.attach(MIMEText(text_version, "plain"))
            
            # Add HTML version
            msg.attach(MIMEText(html_body, "html"))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()  # Secure connection
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email to {to_email}: {type(e).__name__}: {str(e)}")
            return False
    
    async def send_password_reset_email(self, to_email: str, reset_token: str, user_name: Optional[str] = None) -> bool:
        """
        Send password reset email with JWT token
        
        Args:
            to_email: Recipient email address
            reset_token: JWT reset token (used in reset link)
            user_name: Optional user name for personalization
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        
        # Check if email is enabled
        if not self.enable_email:
            print(f"📧 Email disabled - would send reset email to {to_email}")
            return True  # Return True so process continues in debug mode
        
        # Check for required SMTP configuration
        if not self.sender_password:
            print(f"⚠️  SENDER_PASSWORD not configured - cannot send email")
            return False
        
        try:
            # Create reset link
            reset_link = f"{self.app_url}/reset-password?token={reset_token}"
            
            # Create HTML email body
            name_greeting = f"Hi {user_name}," if user_name else "Hello,"
            
            html_body = f"""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2>Password Reset Request</h2>
        <p>{name_greeting}</p>
        <p>We received a request to reset your password for your {self.sender_name} account.</p>
        
        <p><strong>⚠️ Security Notice:</strong></p>
        <ul>
            <li>This link expires in 1 hour</li>
            <li>If you didn't request this, ignore this email</li>
            <li>Never share this link with others</li>
        </ul>
        
        <p><a href="{reset_link}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px;">Reset Password</a></p>
        
        <p><strong>Or copy and paste this link:</strong></p>
        <p style="word-break: break-all; color: #666;"><code>{reset_link}</code></p>
        
        <p>If the button doesn't work, copy and paste the entire URL above into your browser.</p>
        
        <p><strong>For security reasons:</strong></p>
        <ul>
            <li>✓ Never share your password with anyone</li>
            <li>✓ Use a unique password for {self.sender_name}</li>
            <li>✓ Enable two-factor authentication if available</li>
        </ul>
        
        {self._get_email_footer()}
    </div>
</body>
</html>
            """
            
            # Create text version
            text_body = f"""
Password Reset Request

{name_greeting}

We received a request to reset your password for your {self.sender_name} account.

⚠️ Security Notice:
- This link expires in 1 hour
- If you didn't request this, ignore this email
- Never share this link with others

Reset your password using this link:
{reset_link}

For security reasons:
✓ Never share your password with anyone
✓ Use a unique password for {self.sender_name}
✓ Enable two-factor authentication if available
            """
            
            # Send email
            subject = f"Password Reset Request - {self.sender_name}"
            success = self._send_smtp_email(to_email, subject, html_body, text_body)
            
            if success:
                print(f"✅ Password reset email sent to {to_email}")
            
            return success
            
        except Exception as e:
            print(f"❌ Error sending password reset email: {type(e).__name__}: {str(e)}")
            return False
    
    async def send_password_changed_email(self, to_email: str, user_name: Optional[str] = None) -> bool:
        """Send password changed confirmation email"""
        
        if not self.enable_email:
            return True
        
        if not self.sender_password:
            return False
        
        try:
            name_greeting = f"Hi {user_name}," if user_name else "Hello,"
            
            html_body = f"""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2>Password Changed Successfully</h2>
        <p>{name_greeting}</p>
        <p>Your {self.sender_name} password has been successfully changed.</p>
        
        <p><strong>✅ What happened:</strong></p>
        <ul>
            <li>Your password has been updated</li>
            <li>All other active sessions have been logged out</li>
            <li>You can now log in with your new password</li>
        </ul>
        
        <p><a href="{self.app_url}/login" style="display: inline-block; padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 4px;">Go to Login</a></p>
        
        <p><strong>If you didn't make this change:</strong></p>
        <p>Your account may be compromised. Please:</p>
        <ol>
            <li>Change your password immediately using "Forgot Password"</li>
            <li>Contact our support team</li>
            <li>Enable two-factor authentication</li>
        </ol>
        
        {self._get_email_footer()}
    </div>
</body>
</html>
            """
            
            text_body = f"""
Password Changed Successfully

{name_greeting}

Your {self.sender_name} password has been successfully changed.

✅ What happened:
- Your password has been updated
- All other active sessions have been logged out
- You can now log in with your new password

If you didn't make this change, please change your password immediately using "Forgot Password" on the login page.
            """
            
            subject = f"Password Changed - {self.sender_name}"
            success = self._send_smtp_email(to_email, subject, html_body, text_body)
            
            if success:
                print(f"✅ Password changed confirmation email sent to {to_email}")
            
            return success
            
        except Exception as e:
            print(f"❌ Error sending password changed email: {type(e).__name__}: {str(e)}")
            return False


# Global email service instance
email_service = EmailService()

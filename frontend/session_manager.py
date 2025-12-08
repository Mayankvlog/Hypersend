"""
Session Manager - Handles persistent login credentials and session storage
Saves and loads authentication tokens from local file storage to avoid frequent logins
"""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Any
import sys

# Platform-specific config directory
if sys.platform == "android":
    # Android: Use app-specific cache directory
    try:
        from kivy.core.window import Window
        config_dir = Path.home() / ".zaply"
    except ImportError:
        config_dir = Path.home() / ".zaply"
else:
    # Desktop/iOS: Use home directory
    config_dir = Path.home() / ".zaply"

# Ensure config directory exists
config_dir.mkdir(parents=True, exist_ok=True)
SESSION_FILE = config_dir / "session.json"


def debug_log(msg: str):
    """Log debug messages"""
    print(f"[SESSION] {msg}")


class SessionManager:
    """Manages user session persistence with encryption-ready design"""
    
    @staticmethod
    def save_session(email: str, access_token: str, refresh_token: str, user_data: Optional[Dict[str, Any]] = None):
        """
        Save session credentials to local file
        
        Args:
            email: User email
            access_token: JWT access token
            refresh_token: JWT refresh token
            user_data: Optional user profile data
        """
        try:
            session_data = {
                "email": email,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user_data": user_data or {}
            }
            
            with open(SESSION_FILE, 'w') as f:
                json.dump(session_data, f)
            
            debug_log(f"✅ Session saved for {email}")
            return True
        except Exception as e:
            debug_log(f"❌ Error saving session: {e}")
            return False
    
    @staticmethod
    def load_session() -> Optional[Dict[str, Any]]:
        """
        Load session credentials from local file
        
        Returns:
            Dictionary with email, access_token, refresh_token, user_data or None
        """
        try:
            if not SESSION_FILE.exists():
                debug_log("⚠️ No saved session found")
                return None
            
            with open(SESSION_FILE, 'r') as f:
                session_data = json.load(f)
            
            # Validate required fields
            required_fields = ['email', 'access_token', 'refresh_token']
            if not all(field in session_data for field in required_fields):
                debug_log("⚠️ Session file corrupted - missing required fields")
                SessionManager.clear_session()
                return None
            
            debug_log(f"✅ Session loaded for {session_data['email']}")
            return session_data
        except json.JSONDecodeError:
            debug_log("❌ Session file corrupted - invalid JSON")
            SessionManager.clear_session()
            return None
        except Exception as e:
            debug_log(f"❌ Error loading session: {e}")
            return None
    
    @staticmethod
    def clear_session():
        """Clear saved session credentials"""
        try:
            if SESSION_FILE.exists():
                SESSION_FILE.unlink()
            debug_log("✅ Session cleared")
            return True
        except Exception as e:
            debug_log(f"❌ Error clearing session: {e}")
            return False
    
    @staticmethod
    def session_exists() -> bool:
        """Check if a valid session file exists"""
        return SESSION_FILE.exists()
    
    @staticmethod
    def update_tokens(access_token: str, refresh_token: str) -> bool:
        """Update tokens for existing session"""
        try:
            session = SessionManager.load_session()
            if not session:
                debug_log("❌ No session to update")
                return False
            
            session['access_token'] = access_token
            session['refresh_token'] = refresh_token
            
            with open(SESSION_FILE, 'w') as f:
                json.dump(session, f)
            
            debug_log("✅ Tokens updated")
            return True
        except Exception as e:
            debug_log(f"❌ Error updating tokens: {e}")
            return False

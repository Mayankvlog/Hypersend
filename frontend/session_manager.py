"""
Session Manager - Handles persistent login credentials and session storage
Saves and loads authentication tokens from local file storage to avoid frequent logins
"""

import os
import json
import hashlib
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

# Ensure config directory exists with proper error handling
try:
    config_dir.mkdir(parents=True, exist_ok=True)
except PermissionError:
    # Fallback to temp directory if home directory not writable
    import tempfile
    config_dir = Path(tempfile.gettempdir()) / "zaply"
    config_dir.mkdir(exist_ok=True)
except Exception as e:
    print(f"[SESSION] Warning: Could not create config directory: {e}")
    config_dir = Path.cwd() / "sessions"
    config_dir.mkdir(exist_ok=True)

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
            # Create a simple hash for basic obfuscation (not true encryption)
            session_key = hashlib.sha256(email.encode()).hexdigest()[:16]
            
            session_data = {
                "email": email,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user_data": user_data or {},
                "session_key": session_key
            }
           
            with open(SESSION_FILE, 'w') as f:
                json.dump(session_data, f)
           
            debug_log(f"[OK] Session saved for {email}")
            return True
        except Exception as e:
            debug_log(f"[ERROR] Error saving session: {e}")
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
                debug_log("[WARN] No saved session found")
                return None
             
            with open(SESSION_FILE, 'r') as f:
                session_data = json.load(f)
             
            # Validate session key
            if 'session_key' not in session_data:
                debug_log("[WARN] Session file corrupted - missing session key")
                SessionManager.clear_session()
                return None
            
            # Validate required fields
            required_fields = ['email', 'access_token', 'refresh_token']
            if not all(field in session_data for field in required_fields):
                debug_log("[WARN] Session file corrupted - missing required fields")
                SessionManager.clear_session()
                return None
             
            debug_log(f"[OK] Session loaded for {session_data.get('email', 'unknown')}")
            return session_data
        except Exception as e:
            debug_log(f"[ERROR] Error loading session: {e}")
            return None
    
    @staticmethod
    def clear_session():
        """Clear saved session"""
        try:
            if SESSION_FILE.exists():
                SESSION_FILE.unlink()
                debug_log("[OK] Session cleared")
            return True
        except Exception as e:
            debug_log(f"[ERROR] Error clearing session: {e}")
            return False
    
    @staticmethod
    def session_exists() -> bool:
        """Check if session file exists"""
        return SESSION_FILE.exists()
    
    @staticmethod
    def update_tokens(access_token: str = None, refresh_token: str = None):
        """Update only tokens in existing session"""
        try:
            if not SESSION_FILE.exists():
                debug_log("[WARN] No session to update")
                return False
            
            with open(SESSION_FILE, 'r') as f:
                session_data = json.load(f)
            
            updated = False
            if access_token:
                session_data['access_token'] = access_token
                updated = True
            if refresh_token:
                session_data['refresh_token'] = refresh_token
                updated = True
            
            if updated:
                with open(SESSION_FILE, 'w') as f:
                    json.dump(session_data, f)
                debug_log("[OK] Tokens updated")
                return True
            else:
                debug_log("[INFO] No token updates provided")
                return True
        except Exception as e:
            debug_log(f"[ERROR] Error updating tokens: {e}")
            return False


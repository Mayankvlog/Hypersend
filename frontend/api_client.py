import httpx
import os
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Backend API URL - configurable via environment variables
# Priority: PRODUCTION_API_URL (for VPS/domain) > API_BASE_URL (for dev/docker)
# IMPORTANT: Do NOT include /api/v1 suffix - endpoints add it automatically
#
# Development examples:
#   API_BASE_URL=http://backend:8000          # Docker service name
#
# Production examples:
#   PRODUCTION_API_URL=http://139.59.82.105:8000
#   PRODUCTION_API_URL=https://api.yourdomain.com
#
PRODUCTION_API_URL = os.getenv("PRODUCTION_API_URL", "").strip()
# Default to your DigitalOcean VPS when API_BASE_URL is not set
DEV_API_URL = os.getenv("API_BASE_URL", "http://139.59.82.105:8000").strip()

# Select final base URL
if PRODUCTION_API_URL:
    API_BASE_URL = PRODUCTION_API_URL
else:
    API_BASE_URL = DEV_API_URL

# Debug mode
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

def debug_log(msg: str):
    """Log debug messages only when DEBUG is enabled"""
    if DEBUG:
        print(msg)


class APIClient:
    def __init__(self):
        self.base_url = API_BASE_URL
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        # Optimized timeout and connection pooling for production VPS
        # HTTP/2 requires 'h2' package: pip install httpx[http2]
        try:
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=15.0, read=45.0, write=30.0),
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=20, keepalive_expiry=30.0),
                http2=True  # Enable HTTP/2 for better performance
            )
        except ImportError:
            # Fallback to HTTP/1.1 if h2 is not installed
            debug_log("[WARN] HTTP/2 not available (h2 package not installed), using HTTP/1.1")
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=15.0, read=45.0, write=30.0),
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=20, keepalive_expiry=30.0)
            )
    
    def set_tokens(self, access_token: str, refresh_token: str):
        """Set authentication tokens"""
        self.access_token = access_token
        self.refresh_token = refresh_token
    
    def clear_tokens(self):
        """Clear authentication tokens"""
        self.access_token = None
        self.refresh_token = None
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with auth token"""
        headers = {"Content-Type": "application/json"}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers
    
    # Auth endpoints
    async def register(self, name: str, email: str, password: str) -> Dict[str, Any]:
        """Register a new user"""
        try:
            debug_log(f"[API] Registering user at {self.base_url}/api/v1/auth/register")
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/register",
                json={"name": name, "email": email, "password": password}
            )

            # Treat non-201 as error and surface backend detail when possible
            if response.status_code != 201:
                try:
                    error_data = response.json()
                    detail = error_data.get("detail", str(error_data))
                except Exception:
                    detail = response.text[:200]
                debug_log(f"[API] Register failed ({response.status_code}): {detail}")
                raise Exception(f"Registration failed ({response.status_code}): {detail}")

            try:
                return response.json()
            except Exception:
                # Some environments return empty body with 201; return minimal payload
                debug_log("[API] Register response had no JSON body, returning empty dict")
                return {}
        except httpx.TimeoutException as e:
            debug_log(f"[API] Register timeout: {e}")
            raise Exception("Request timeout. Please check your internet connection.")
        except httpx.ConnectError as e:
            debug_log(f"[API] Register connection error: {e}")
            raise Exception(f"Cannot connect to server at {self.base_url}. Server might be down.")
        except Exception as e:
            # Bubble up a clean message to the UI
            raise Exception(str(e))
    
    async def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login and receive tokens"""
        try:
            debug_log(f"[API] Attempting login to {self.base_url}/api/v1/auth/login")
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"email": email, "password": password}
            )
            debug_log(f"[API] Login response status: {response.status_code}")
            
            if response.status_code != 200:
                error_detail = "Unknown error"
                try:
                    error_data = response.json()
                    error_detail = error_data.get("detail", str(error_data))
                except Exception:
                    error_detail = response.text[:200]
                debug_log(f"[API] Login failed: {error_detail}")
                raise httpx.HTTPStatusError(
                    f"Login failed: {error_detail}",
                    request=response.request,
                    response=response
                )
            
            data = response.json()
            self.set_tokens(data["access_token"], data["refresh_token"])
            debug_log("[API] Login successful")
            return data
        except httpx.TimeoutException as e:
            debug_log(f"[API] Login timeout: {e}")
            raise Exception("Request timeout. Please check your internet connection.")
        except httpx.ConnectError as e:
            debug_log(f"[API] Connection error: {e}")
            raise Exception(f"Cannot connect to server at {self.base_url}. Server might be down.")
        except httpx.HTTPStatusError as e:
            raise Exception(str(e))
        except Exception as e:
            debug_log(f"[API] Unexpected error during login: {type(e).__name__}: {e}")
            raise Exception(f"Login failed: {str(e)}")
    
    async def logout(self):
        """Logout"""
        if self.refresh_token:
            try:
                await self.client.post(
                    f"{self.base_url}/api/v1/auth/logout",
                    json={"refresh_token": self.refresh_token},
                    headers=self._get_headers()
                )
            except Exception:
                pass
        self.clear_tokens()
    
    # User endpoints
    async def get_current_user(self) -> Dict[str, Any]:
        """Get current user profile"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/users/me",
                headers=self._get_headers(),
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException as e:
            debug_log(f"[API] Get user timeout: {e}")
            raise Exception("Fetching user profile timed out. Please try again.")
        except httpx.HTTPStatusError as e:
            try:
                error_data = e.response.json()
                detail = error_data.get("detail", str(error_data))
            except Exception:
                detail = e.response.text[:200]
            debug_log(f"[API] Get user failed: {detail}")
            raise Exception(f"Failed to fetch user info: {detail}")
        except Exception as e:
            debug_log(f"[API] Get user error: {e}")
            raise Exception(f"Error fetching user profile: {str(e)}")
    
    async def search_users(self, query: str) -> Dict[str, Any]:
        """Search users"""
        response = await self.client.get(
            f"{self.base_url}/api/v1/users/search",
            params={"q": query},
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    # Chat endpoints
    async def create_chat(self, member_ids: list, chat_type: str = "private", name: Optional[str] = None) -> Dict[str, Any]:
        """Create a new chat"""
        response = await self.client.post(
            f"{self.base_url}/api/v1/chats",
            json={"type": chat_type, "name": name, "member_ids": member_ids},
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    async def list_chats(self) -> Dict[str, Any]:
        """List all chats"""
        response = await self.client.get(
            f"{self.base_url}/api/v1/chats",
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()

    async def get_saved_chat(self) -> Dict[str, Any]:
        """Get or create the Saved Messages chat for current user"""
        response = await self.client.get(
            f"{self.base_url}/api/v1/chats/saved",
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    async def get_messages(self, chat_id: str, limit: int = 50) -> Dict[str, Any]:
        """Get messages in a chat"""
        response = await self.client.get(
            f"{self.base_url}/api/v1/chats/{chat_id}/messages",
            params={"limit": limit},
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    async def send_message(self, chat_id: str, text: Optional[str] = None, file_id: Optional[str] = None) -> Dict[str, Any]:
        """Send a message"""
        response = await self.client.post(
            f"{self.base_url}/api/v1/chats/{chat_id}/messages",
            json={"text": text, "file_id": file_id},
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()

    async def save_message(self, message_id: str) -> Dict[str, Any]:
        """Save a message to Saved Messages"""
        response = await self.client.post(
            f"{self.base_url}/api/v1/messages/{message_id}/save",
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()

    async def unsave_message(self, message_id: str) -> Dict[str, Any]:
        """Unsave a message from Saved Messages"""
        response = await self.client.post(
            f"{self.base_url}/api/v1/messages/{message_id}/unsave",
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()

    async def get_saved_messages(self, limit: int = 50) -> Dict[str, Any]:
        """Get all saved messages"""
        response = await self.client.get(
            f"{self.base_url}/api/v1/messages/saved",
            params={"limit": limit},
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    # File endpoints
    async def init_upload(self, filename: str, size: int, mime: str, chat_id: str, checksum: Optional[str] = None) -> Dict[str, Any]:
        """Initialize file upload"""
        response = await self.client.post(
            f"{self.base_url}/api/v1/files/init",
            json={"filename": filename, "size": size, "mime": mime, "chat_id": chat_id, "checksum": checksum},
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    async def upload_chunk(self, upload_id: str, chunk_index: int, chunk_data: bytes, checksum: Optional[str] = None) -> Dict[str, Any]:
        """Upload a single chunk"""
        headers = {"Authorization": f"Bearer {self.access_token}"}
        if checksum:
            headers["X-Chunk-Checksum"] = checksum
        
        response = await self.client.put(
            f"{self.base_url}/api/v1/files/{upload_id}/chunk",
            params={"chunk_index": chunk_index},
            content=chunk_data,
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    
    async def complete_upload(self, upload_id: str) -> Dict[str, Any]:
        """Complete file upload"""
        response = await self.client.post(
            f"{self.base_url}/api/v1/files/{upload_id}/complete",
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    async def cancel_upload(self, upload_id: str):
        """Cancel file upload"""
        await self.client.post(
            f"{self.base_url}/api/v1/files/{upload_id}/cancel",
            headers=self._get_headers()
        )
    
    def get_download_url(self, file_id: str) -> str:
        """Get file download URL"""
        return f"{self.base_url}/api/v1/files/{file_id}/download"
    
    # Password Reset endpoints
    async def forgot_password(self, email: str) -> Dict[str, Any]:
        """Request password reset token"""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/forgot-password",
                json={"email": email}
            )

            if response.status_code != 200:
                try:
                    error_data = response.json()
                    detail = error_data.get("detail", str(error_data))
                except Exception:
                    detail = response.text[:200]
                raise Exception(f"Password reset request failed ({response.status_code}): {detail}")

            try:
                return response.json()
            except Exception:
                # Fallback if response is not JSON for some reason
                return {"message": response.text or "Password reset request processed."}
        except httpx.TimeoutException:
            raise Exception("Request timeout. Please check your internet connection.")
        except httpx.ConnectError:
            raise Exception(f"Cannot connect to server at {self.base_url}. Server might be down.")
        except Exception as e:
            raise Exception(str(e))
    
    async def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """Reset password with token"""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/reset-password",
                json={"token": token, "new_password": new_password}
            )

            if response.status_code != 200:
                try:
                    error_data = response.json()
                    detail = error_data.get("detail", str(error_data))
                except Exception:
                    detail = response.text[:200]
                raise Exception(f"Password reset failed ({response.status_code}): {detail}")

            try:
                return response.json()
            except Exception:
                return {"message": response.text or "Password reset successful."}
        except httpx.TimeoutException:
            raise Exception("Request timeout. Please check your internet connection.")
        except httpx.ConnectError:
            raise Exception(f"Cannot connect to server at {self.base_url}. Server might be down.")
        except Exception as e:
            raise Exception(str(e))
    
    # Permissions endpoints
    async def get_permissions(self) -> Dict[str, bool]:
        """Get current user's permissions"""
        try:
            debug_log(f"[API] Fetching permissions from {self.base_url}/api/v1/users/permissions")
            response = await self.client.get(
                f"{self.base_url}/api/v1/users/permissions",
                headers=self._get_headers()
            )
            
            if response.status_code != 200:
                debug_log(f"[API] Failed to get permissions: {response.status_code}")
                return {}
            
            return response.json()
        except Exception as e:
            debug_log(f"[API] Error fetching permissions: {e}")
            return {}
    
    async def update_permissions(self, permissions: Dict[str, bool]) -> Dict[str, Any]:
        """Update user's permissions"""
        try:
            debug_log(f"[API] Updating permissions to {self.base_url}/api/v1/users/permissions")
            response = await self.client.put(
                f"{self.base_url}/api/v1/users/permissions",
                json=permissions,
                headers=self._get_headers()
            )
            
            if response.status_code not in [200, 201]:
                error_detail = "Unknown error"
                try:
                    error_data = response.json()
                    error_detail = error_data.get("detail", str(error_data))
                except Exception:
                    error_detail = response.text[:200]
                debug_log(f"[API] Update permissions failed: {error_detail}")
                raise Exception(f"Failed to update permissions: {error_detail}")
            
            return response.json()
        except httpx.TimeoutException:
            raise Exception("Request timeout. Please check your internet connection.")
        except httpx.ConnectError:
            raise Exception(f"Cannot connect to server at {self.base_url}. Server might be down.")
        except Exception as e:
            raise Exception(str(e))

"""
API Client for Zaply Backend
Handles HTTP requests to the FastAPI backend with proper error handling and token management.
"""

import httpx
import asyncio
import sys
import os
from typing import Optional, Dict, Any

# Add current directory to sys.path for imports
sys.path.insert(0, os.path.dirname(__file__))

# Import error handler
from error_handler import init_error_handler, handle_error, show_success, show_info

def debug_log(msg: str):
    """Log debug messages only when DEBUG is enabled"""
    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
    if DEBUG:
        print(msg)

class APIClient:
    """HTTP client for Zaply backend API"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self._refreshing = False
        
        # Initialize HTTP client with HTTP/2 support and better performance
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
            debug_log(f"[API] Using access token: {self.access_token[:20]}...")
        else:
            debug_log("[API] No access token available")
        return headers
    
    async def refresh_access_token(self) -> bool:
        """
        Refresh access token using refresh token.
        Returns True if successful, False otherwise.
        """
        if self._refreshing or not self.refresh_token:
            debug_log(f"[API] Cannot refresh - refreshing: {self._refreshing}, has refresh_token: {bool(self.refresh_token)}")
            return False
        
        self._refreshing = True
        try:
            debug_log("[API] Attempting to refresh access token...")
            debug_log(f"[API] Using refresh token: {self.refresh_token[:20]}...")
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/refresh",
                json={"refresh_token": self.refresh_token},
                timeout=30.0
            )
            
            debug_log(f"[API] Refresh response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                new_access_token = data.get("access_token")
                new_refresh_token = data.get("refresh_token", self.refresh_token)
                if new_access_token:
                    self.set_tokens(new_access_token, new_refresh_token)
                    debug_log("[API] ✅ Token refreshed successfully")
                    return True
                else:
                    debug_log("[API] Refresh response missing access_token")
                    self.clear_tokens()
                    return False
            else:
                debug_log(f"[API] Token refresh failed with status {response.status_code}")
                try:
                    error_data = response.json()
                    debug_log(f"[API] Refresh error: {error_data}")
                except:
                    debug_log(f"[API] Refresh error text: {response.text}")
                self.clear_tokens()
                return False
        except Exception as e:
            debug_log(f"[API] Error refreshing token: {e}")
            self.clear_tokens()
            return False
        finally:
            self._refreshing = False
    
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
                debug_log(f"[API] Login failed ({response.status_code}): {error_detail}")
                raise Exception(f"Login failed: {error_detail}")
            
            data = response.json()
            access_token = data.get("access_token")
            refresh_token = data.get("refresh_token")
            
            if access_token and refresh_token:
                self.set_tokens(access_token, refresh_token)
                debug_log("[API] ✅ Login successful, tokens stored")
                return data
            else:
                debug_log("[API] Login response missing tokens")
                raise Exception("Invalid response from server")
                
        except httpx.TimeoutException as e:
            debug_log(f"[API] Login timeout: {e}")
            raise Exception("Request timeout. Please check your internet connection.")
        except httpx.ConnectError as e:
            debug_log(f"[API] Login connection error: {e}")
            raise Exception(f"Cannot connect to server at {self.base_url}. Server might be down.")
        except Exception as e:
            debug_log(f"[API] Login error: {e}")
            raise Exception(str(e))
    
    async def logout(self) -> bool:
        """Logout and clear tokens"""
        try:
            debug_log("[API] Attempting logout")
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/logout",
                headers=self._get_headers()
            )
            
            # Always clear local tokens regardless of server response
            self.clear_tokens()
            debug_log("[API] ✅ Logged out, tokens cleared")
            return True
            
        except Exception as e:
            debug_log(f"[API] Logout error: {e}")
            # Still clear local tokens on error
            self.clear_tokens()
            return False
    
    async def forgot_password(self, email: str) -> Dict[str, Any]:
        """Request password reset"""
        try:
            debug_log(f"[API] Requesting password reset for {email}")
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/forgot-password",
                json={"email": email}
            )
            
            if response.status_code == 200:
                debug_log("[API] ✅ Password reset request sent")
                return {"message": "Password reset email sent"}
            else:
                debug_log(f"[API] Password reset failed: {response.status_code}")
                raise Exception("Failed to send password reset email")
                
        except Exception as e:
            debug_log(f"[API] Password reset error: {e}")
            raise Exception(str(e))
    
    async def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """Reset password with token"""
        try:
            debug_log("[API] Resetting password")
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/reset-password",
                json={"token": token, "new_password": new_password}
            )
            
            if response.status_code == 200:
                debug_log("[API] ✅ Password reset successful")
                return {"message": "Password reset successful"}
            else:
                debug_log(f"[API] Password reset failed: {response.status_code}")
                raise Exception("Failed to reset password")
                
        except Exception as e:
            debug_log(f"[API] Password reset error: {e}")
            raise Exception(str(e))
    
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
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/users/search",
                params={"q": query},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            debug_log(f"[API] Search users error: {e}")
            raise Exception(f"Search failed: {str(e)}")
    
    # Chat endpoints
    async def list_chats(self) -> Dict[str, Any]:
        """List all chats"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/chats",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            debug_log(f"[API] List chats error: {e}")
            raise Exception(f"Failed to load chats: {str(e)}")
    
    async def get_chat(self, chat_id: str) -> Dict[str, Any]:
        """Get chat details"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/chats/{chat_id}",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            debug_log(f"[API] Get chat error: {e}")
            raise Exception(f"Failed to load chat: {str(e)}")
    
    async def create_chat(self, name: str, user_ids: list, chat_type: str = "private") -> Dict[str, Any]:
        """Create a new chat"""
        try:
            # Debug: Log token status before request
            print(f"[API] create_chat - access_token present: {bool(self.access_token)}, refresh_token present: {bool(self.refresh_token)}")
            if self.access_token:
                print(f"[API] create_chat - using access_token: {self.access_token[:30]}...")
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/chats/",
                json={"name": name, "member_ids": user_ids, "type": chat_type},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            print(f"[API] create_chat HTTP error: {e.response.status_code}")
            if e.response.status_code == 401:
                print(f"[API] 401 Unauthorized - refresh_token present: {bool(self.refresh_token)}")
                if self.refresh_token:
                    # Try to refresh token and retry once
                    print("[API] Attempting token refresh...")
                    if await self.refresh_access_token():
                        print("[API] Token refreshed successfully, retrying create_chat...")
                        try:
                            response = await self.client.post(
                                f"{self.base_url}/api/v1/chats/",
                                json={"name": name, "member_ids": user_ids, "type": chat_type},
                                headers=self._get_headers()
                            )
                            response.raise_for_status()
                            return response.json()
                        except Exception as retry_e:
                            print(f"[API] Retry failed: {retry_e}")
                            raise retry_e
                    else:
                        print("[API] Token refresh failed!")
                else:
                    print("[API] No refresh_token available to refresh!")
            
            if e.response.status_code == 403:
                raise Exception("403 Forbidden - Please check backend routes")

            debug_log(f"[API] Create chat error: {e}")
            raise Exception(f"Failed to create chat: {str(e)}")
        except Exception as e:
            debug_log(f"[API] Create chat error: {e}")
            raise Exception(f"Failed to create chat: {str(e)}")
    
    async def get_saved_chat(self) -> Dict[str, Any]:
        """Get or create a Saved Messages chat for current user"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/chats/saved",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 and self.refresh_token:
                # Try to refresh token and retry once
                if await self.refresh_access_token():
                    response = await self.client.get(
                        f"{self.base_url}/api/v1/chats/saved",
                        headers=self._get_headers()
                    )
                    response.raise_for_status()
                    return response.json()
            raise
        except Exception as e:
            debug_log(f"[API] Get saved chat error: {e}")
            raise Exception(f"Failed to load saved messages: {str(e)}")
    
    async def get_messages(self, chat_id: str, limit: int = 50) -> Dict[str, Any]:
        """Get messages in a chat"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/chats/{chat_id}/messages",
                params={"limit": limit},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 and self.refresh_token:
                # Try to refresh token and retry once
                if await self.refresh_access_token():
                    response = await self.client.get(
                        f"{self.base_url}/api/v1/chats/{chat_id}/messages",
                        params={"limit": limit},
                        headers=self._get_headers()
                    )
                    response.raise_for_status()
                    return response.json()
            raise
        except Exception as e:
            debug_log(f"[API] Get messages error: {e}")
            raise Exception(f"Failed to load messages: {str(e)}")
    
    async def send_message(self, chat_id: str, text: Optional[str] = None, file_id: Optional[str] = None) -> Dict[str, Any]:
        """Send a message"""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/chats/{chat_id}/messages",
                json={"text": text, "file_id": file_id},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 and self.refresh_token:
                # Try to refresh token and retry once
                if await self.refresh_access_token():
                    response = await self.client.post(
                        f"{self.base_url}/api/v1/chats/{chat_id}/messages",
                        json={"text": text, "file_id": file_id},
                        headers=self._get_headers()
                    )
                    response.raise_for_status()
                    return response.json()
            raise
        except Exception as e:
            debug_log(f"[API] Send message error: {e}")
            raise Exception(f"Failed to send message: {str(e)}")
    
    async def get_saved_messages(self, limit: int = 50) -> Dict[str, Any]:
        """Get all saved messages"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/chats/messages/saved",
                params={"limit": limit},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 and self.refresh_token:
                # Try to refresh token and retry once
                if await self.refresh_access_token():
                    response = await self.client.get(
                        f"{self.base_url}/api/v1/chats/messages/saved",
                        params={"limit": limit},
                        headers=self._get_headers()
                    )
                    response.raise_for_status()
                    return response.json()
            raise
        except Exception as e:
            debug_log(f"[API] Get saved messages error: {e}")
            raise Exception(f"Failed to load saved messages: {str(e)}")
    
    async def unsave_message(self, message_id: str) -> Dict[str, Any]:
        """Unsave a message from Saved Messages"""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/chats/messages/{message_id}/unsave",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 and self.refresh_token:
                # Try to refresh token and retry once
                if await self.refresh_access_token():
                    response = await self.client.post(
                        f"{self.base_url}/api/v1/chats/messages/{message_id}/unsave",
                        headers=self._get_headers()
                    )
                    response.raise_for_status()
                    return response.json()
            raise
        except Exception as e:
            debug_log(f"[API] Unsave message error: {e}")
            raise Exception(f"Failed to unsave message: {str(e)}")
    
    # File endpoints
    async def init_upload(self, filename: str, size: int, mime: str, chat_id: str, checksum: Optional[str] = None) -> Dict[str, Any]:
        """Initialize a resumable file upload"""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/files/init",
                json={"filename": filename, "size": size, "mime": mime, "chat_id": chat_id, "checksum": checksum},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            debug_log(f"[API] Init upload error: {e}")
            raise Exception(f"Failed to initialize upload: {str(e)}")
    
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
    
    async def upload_large_file(self, file_path: str, chat_id: str, progress_callback=None) -> str:
        """Upload large file in chunks and return file_id"""
        import os
        import mimetypes
        
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        mime_type, _ = mimetypes.guess_type(file_path)
        mime_type = mime_type or "application/octet-stream"
        
        # Init upload
        init_data = await self.init_upload(file_name, file_size, mime_type, chat_id)
        upload_id = init_data.get("upload_id") or init_data.get("id")
        
        chunk_size = 1024 * 1024 # 1MB chunks
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        with open(file_path, "rb") as f:
            for i in range(total_chunks):
                chunk_data = f.read(chunk_size)
                await self.upload_chunk(upload_id, i, chunk_data)
                
                if progress_callback:
                    progress_callback((i + 1) / total_chunks)
                    
        # Complete
        complete_data = await self.complete_upload(upload_id)
        return complete_data.get("file_id") or complete_data.get("id")
    
    async def get_file_info(self, file_id: str) -> Dict[str, Any]:
        """Get file information"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/files/{file_id}",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            debug_log(f"[API] Get file info error: {e}")
            raise Exception(f"Failed to get file info: {str(e)}")
    
    async def download_file(self, file_id: str, output_path: str) -> bool:
        """Download a file"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/files/{file_id}/download",
                headers=self._get_headers()
            )
            response.raise_for_status()
            
            # Save file
            with open(output_path, 'wb') as f:
                async for chunk in response.aiter_bytes():
                    f.write(chunk)
            
            debug_log(f"[API] ✅ File downloaded to {output_path}")
            return True
        except Exception as e:
            debug_log(f"[API] Download file error: {e}")
            raise Exception(f"Failed to download file: {str(e)}")


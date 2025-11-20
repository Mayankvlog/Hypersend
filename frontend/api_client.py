import httpx
import os
from typing import Optional, Dict, Any

# Backend API URL - configurable via environment variable
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")


class APIClient:
    def __init__(self):
        self.base_url = API_BASE_URL
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.client = httpx.AsyncClient(timeout=30.0)
    
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
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/auth/register",
                json={"username": name, "email": email, "password": password}
            )
            response.raise_for_status()
            return response.json()
    
    async def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login and receive tokens"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/auth/login",
                json={"email": email, "password": password}
            )
            response.raise_for_status()
            data = response.json()
            self.set_tokens(data["access_token"], data["refresh_token"])
            return data
    
    async def logout(self):
        """Logout"""
        if self.refresh_token:
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(
                        f"{self.base_url}/auth/logout",
                        json={"refresh_token": self.refresh_token},
                        headers=self._get_headers()
                    )
            except:
                pass
        self.clear_tokens()
    
    # User endpoints
    async def get_current_user(self) -> Dict[str, Any]:
        """Get current user profile"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/users/me",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
    
    async def search_users(self, query: str) -> Dict[str, Any]:
        """Search users"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/users/search",
                params={"q": query},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
    
    # Chat endpoints
    async def create_chat(self, member_ids: list, chat_type: str = "private", name: Optional[str] = None) -> Dict[str, Any]:
        """Create a new chat"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/chats",
                json={"type": chat_type, "name": name, "member_ids": member_ids},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
    
    async def list_chats(self) -> Dict[str, Any]:
        """List all chats"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/chats",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()

    async def get_saved_chat(self) -> Dict[str, Any]:
        """Get or create the Saved Messages chat for current user"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/chats/saved",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
    
    async def get_messages(self, chat_id: str, limit: int = 50) -> Dict[str, Any]:
        """Get messages in a chat"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/chats/{chat_id}/messages",
                params={"limit": limit},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
    
    async def send_message(self, chat_id: str, text: Optional[str] = None, file_id: Optional[str] = None) -> Dict[str, Any]:
        """Send a message"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/chats/{chat_id}/messages",
                json={"chat_id": chat_id, "text": text, "file_id": file_id},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()

    async def save_message(self, message_id: str) -> Dict[str, Any]:
        """Save a message to Saved Messages"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/messages/{message_id}/save",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()

    async def unsave_message(self, message_id: str) -> Dict[str, Any]:
        """Unsave a message from Saved Messages"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/messages/{message_id}/unsave",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()

    async def get_saved_messages(self, limit: int = 50) -> Dict[str, Any]:
        """Get all saved messages"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/messages/saved",
                params={"limit": limit},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
    
    # File endpoints
    async def init_upload(self, filename: str, size: int, mime: str, chat_id: str, checksum: Optional[str] = None) -> Dict[str, Any]:
        """Initialize file upload"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/files/init",
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
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.put(
                f"{self.base_url}/files/{upload_id}/chunk",
                params={"chunk_index": chunk_index},
                content=chunk_data,
                headers=headers
            )
            response.raise_for_status()
            return response.json()
    
    async def complete_upload(self, upload_id: str) -> Dict[str, Any]:
        """Complete file upload"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/files/{upload_id}/complete",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
    
    async def cancel_upload(self, upload_id: str):
        """Cancel file upload"""
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{self.base_url}/files/{upload_id}/cancel",
                headers=self._get_headers()
            )
    
    def get_download_url(self, file_id: str) -> str:
        """Get file download URL"""
        return f"{self.base_url}/files/{file_id}/download"

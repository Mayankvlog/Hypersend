"""
WhatsApp-style P2P File Transfer
- Files stored locally on sender's device
- Server acts as relay/signaling only
- Receiver downloads directly to local storage
- No server file storage (metadata only)
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, status, Depends
from typing import Dict, Optional
import asyncio
import uuid
import json
from datetime import datetime, timedelta, timezone
from db_proxy import files_collection, chats_collection
from auth.utils import get_current_user

def decode_token_safely(token: str) -> Optional[dict]:
    """Safely decode JWT token with proper error handling and validation"""
    try:
        if not token or not isinstance(token, str):
            print(f"[P2P_TRANSFER] Invalid token format: {type(token)}")
            return None
        
        from auth.utils import decode_token
        token_data = decode_token(token)
        
        # Convert to dictionary for consistency
        payload = {
            "sub": token_data.user_id,
            "token_type": token_data.token_type
        }
        
        print(f"[P2P_TRANSFER] Token decoded successfully for user: {token_data.user_id}")
        return payload
    except HTTPException as http_e:
        print(f"[P2P_TRANSFER] HTTPException during token decode: {http_e.detail}")
        return None
    except Exception as e:
        print(f"[P2P_TRANSFER] Unexpected token decode error: {type(e).__name__}: {str(e)}")
        return None

router = APIRouter(prefix="/p2p", tags=["P2P Transfer"])

# OPTIONS handlers for CORS preflight requests
@router.options("/send")
@router.options("/status/{session_id}")
@router.options("/history/{chat_id}")
async def p2p_options():
    """Handle CORS preflight for P2P transfer endpoints"""
    from fastapi.responses import Response
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400"
        }
    )

# Thread-safe session storage
import threading
import time
from typing import Dict
from contextlib import contextmanager

# Active P2P sessions (in-memory, no disk storage)
_active_sessions: Dict[str, dict] = {}
_session_lock = threading.RLock()

@contextmanager
def _session_lock_context():
    """Context manager for session lock with timeout"""
    acquired = _session_lock.acquire(timeout=5.0)
    if not acquired:
        raise RuntimeError("Failed to acquire session lock within timeout")
    try:
        yield
    finally:
        _session_lock.release()

def get_active_session(session_id: str):
    """Thread-safe session access with validation"""
    with _session_lock_context():
        session = _active_sessions.get(session_id)
        if session and hasattr(session, 'session_id'):
            # Validate session hasn't expired
            if session.expires_at < datetime.now(timezone.utc):
                remove_active_session(session_id)
                return None
            return session
        return None

def set_active_session(session_id: str, session) -> None:
    """Thread-safe session storage with validation"""
    with _session_lock_context():
        if not hasattr(session, 'session_id'):
            raise ValueError("Invalid session object type")
        _active_sessions[session_id] = session

def remove_active_session(session_id: str):
    """Thread-safe session removal with cleanup"""
    with _session_lock_context():
        session = _active_sessions.pop(session_id, None)
        if session and hasattr(session, 'sender_ws') and session.sender_ws:
            # Mark websocket for cleanup
            session.cleanup_scheduled = True
        return session

def get_all_active_sessions() -> Dict[str, dict]:
    """Thread-safe session snapshot with cleanup"""
    with _session_lock_context():
        # Clean up expired sessions
        current_time = datetime.now(timezone.utc)
        expired_sessions = [
            sid for sid, sess in _active_sessions.items()
            if sess.expires_at < current_time
        ]
        for sid in expired_sessions:
            remove_active_session(sid)
        return _active_sessions.copy()


class P2PSession:
    """WhatsApp-style transfer session with thread safety"""
    def __init__(self, session_id: str, sender_id: str, receiver_id: str, 
                 filename: str, file_size: int, mime_type: str, chat_id: str):
        self.session_id = session_id
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.filename = filename
        self.file_size = file_size
        self.mime_type = mime_type
        self.chat_id = chat_id
        
        self.sender_ws: Optional[WebSocket] = None
        self.receiver_ws: Optional[WebSocket] = None
        
        self.bytes_transferred = 0
        self.created_at = datetime.now(timezone.utc)
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        self.status = "pending"  # pending, active, completed, failed
        self._lock = threading.RLock()
        self.cleanup_scheduled = False
        
    def is_ready(self):
        """Thread-safe readiness check"""
        with self._lock:
            return self.sender_ws is not None and self.receiver_ws is not None
    
    def get_progress(self):
        """Thread-safe progress calculation"""
        with self._lock:
            if self.file_size == 0:
                return 0
            return round((self.bytes_transferred / self.file_size) * 100, 2)
    
    def set_status(self, status: str):
        """Thread-safe status update"""
        with self._lock:
            old_status = self.status
            self.status = status
            print(f"[P2P_SESSION] Session {self.session_id} status: {old_status} -> {status}")
    
    def add_bytes(self, chunk_size: int):
        """Thread-safe bytes counter"""
        with self._lock:
            self.bytes_transferred += chunk_size
    
    def set_websocket(self, role: str, ws: WebSocket):
        """Thread-safe websocket assignment"""
        with self._lock:
            if role == "sender":
                self.sender_ws = ws
            elif role == "receiver":
                self.receiver_ws = ws
            else:
                raise ValueError(f"Invalid role: {role}")


@router.post("/send")
async def initiate_p2p_transfer(
    receiver_id: str,
    filename: str,
    file_size: int,
    mime_type: str,
    chat_id: str,
    current_user: str = Depends(get_current_user)
):
    """
    Sender initiates transfer (file remains on sender's device)
    Returns session_id for WebSocket connection
    """
    
    # Validate chat exists and user is member
    chat = await chats_collection().find_one({"_id": chat_id})
    if not chat or current_user not in chat.get("members", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this chat"
        )
    
    # Create session
    session_id = str(uuid.uuid4())
    session = P2PSession(
        session_id=session_id,
        sender_id=current_user,
        receiver_id=receiver_id,
        filename=filename,
        file_size=file_size,
        mime_type=mime_type,
        chat_id=chat_id
    )
    
    set_active_session(session_id, session)
    
    # Store metadata only (no file data)
    file_metadata = {
        "session_id": session_id,
        "sender_id": current_user,
        "receiver_id": receiver_id,
        "filename": filename,
        "size": file_size,
        "mime": mime_type,
        "chat_id": chat_id,
        "storage_type": "local",  # WhatsApp-style
        "status": "pending",
        "created_at": datetime.now(timezone.utc),
        "expires_at": session.expires_at,
        # No server path - file is on sender's device
    }
    
    result = await files_collection().insert_one(file_metadata)
    
    return {
        "session_id": session_id,
        "file_id": str(result.inserted_id),
        "sender_ws_url": f"/p2p/sender/{session_id}",
        "receiver_ws_url": f"/p2p/receiver/{session_id}",
        "expires_at": session.expires_at.isoformat()
    }


@router.websocket("/sender/{session_id}")
async def sender_stream(websocket: WebSocket, session_id: str, token: str = None):
    """
    Sender connects and streams file from their local storage
    """
    # Verify token and extract user info
    if not token:
        await websocket.close(code=4001, reason="Authorization token required")
        return
    
    payload = decode_token_safely(token)
    if payload is None:
        await websocket.close(code=4001, reason="Invalid authorization token")
        return
    
    current_user = payload.get("sub")
    
    session = get_active_session(session_id)
    if not session:
        await websocket.close(code=4004, reason="Session not found")
        return
    
    # Verify sender owns this session
    if session.sender_id != current_user:
        await websocket.close(code=4003, reason="Not authorized for this session")
        return
    
    await websocket.accept()
    session.set_websocket("sender", websocket)
    session.set_status("waiting_receiver")
    
    try:
        # Notify sender: connected
        await websocket.send_json({
            "type": "connected",
            "message": "Connected. Waiting for receiver...",
            "session_id": session_id
        })
        
        # Update metadata
        await files_collection().update_one(
            {"session_id": session_id},
            {"$set": {"status": "sender_ready"}}
        )
        
        # Wait for receiver
        while not session.is_ready() and session.status != "failed":
            await asyncio.sleep(0.5)
        
        if session.status == "failed":
            await websocket.send_json({"type": "error", "message": "Transfer cancelled"})
            return
        
        # Both connected - start transfer
        session.set_status("transferring")
        await websocket.send_json({
            "type": "start",
            "message": "Receiver connected. Start sending file chunks."
        })
        
        # Stream file data (sender reads from local storage)
        while session.status == "transferring":
            try:
                # Receive chunk from sender (4 MB chunks)
                message = await websocket.receive()
                
                if "bytes" in message:
                    chunk_data = message["bytes"]
                    
                    # Relay directly to receiver (NO SERVER STORAGE)
                    with session._lock:
                        if session.receiver_ws and session.status == "transferring":
                            try:
                                await session.receiver_ws.send_bytes(chunk_data)
                                session.add_bytes(len(chunk_data))
                                
                                # Send progress to sender
                                await websocket.send_json({
                                    "type": "progress",
                                    "bytes": session.bytes_transferred,
                                    "total": session.file_size,
                                    "percent": session.get_progress()
                                })
                            except Exception as e:
                                print(f"[P2P_TRANSFER] Error sending to receiver: {e}")
                                session.set_status("failed")
                                break
                        else:
                            print(f"[P2P_TRANSFER] Receiver not ready or session not transferring")
                            await asyncio.sleep(0.1)  # Brief wait for receiver
                            continue  # Skip this iteration and try again
                
                elif "text" in message:
                    data = json.loads(message["text"])
                    
                    if data.get("type") == "complete":
                        # Transfer complete
                        session.set_status("completed")
                        await websocket.send_json({
                            "type": "complete",
                            "bytes_transferred": session.bytes_transferred
                        })
                        
                        # Update database
                        await files_collection().update_one(
                            {"session_id": session_id},
                            {"$set": {"status": "completed"}}
                        )
                        break
                        
            except WebSocketDisconnect:
                session.set_status("failed")
                break
            except Exception as e:
                session.set_status("failed")
                await websocket.send_json({"type": "error", "message": str(e)})
                break
    
    finally:
        # Thread-safe cleanup
        removed_session = remove_active_session(session_id)
        if removed_session:
            print(f"[P2P_TRANSFER] Cleaned up session {session_id}")
        await websocket.close()


@router.websocket("/receiver/{session_id}")
async def receiver_stream(websocket: WebSocket, session_id: str, token: str = None):
    """
    Receiver connects and downloads file to their local storage
    """
    # Verify token and extract user info
    if not token:
        await websocket.close(code=4001, reason="Authorization token required")
        return
    
    payload = decode_token_safely(token)
    if payload is None:
        await websocket.close(code=4001, reason="Invalid authorization token")
        return
    
    current_user = payload.get("sub")
    
    session = get_active_session(session_id)
    if not session:
        await websocket.close(code=4004, reason="Session not found")
        return
    
    # Verify receiver is authorized for this session
    if session.receiver_id != current_user:
        await websocket.close(code=4003, reason="Not authorized for this session")
        return
    
    await websocket.accept()
    session.set_websocket("receiver", websocket)
    
    try:
        # Send file metadata
        await websocket.send_json({
            "type": "metadata",
            "filename": session.filename,
            "file_size": session.file_size,
            "mime_type": session.mime_type,
            "message": "Ready to receive. Waiting for sender..."
        })
        
        # Update metadata
        await files_collection().update_one(
            {"session_id": session_id},
            {"$set": {"status": "receiver_ready"}}
        )
        
        # Wait for sender to start
        while not session.is_ready():
            await asyncio.sleep(0.5)
        
        # Receiving mode (data forwarded from sender_stream)
        await websocket.send_json({
            "type": "start",
            "message": "Transfer started. Saving to local storage..."
        })
        
        # Keep connection alive and handle control messages
        while session.status in ["transferring", "receiver_ready"]:
            try:
                # Receiver can send control messages
                message = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=1.0
                )
                
                if message.get("action") == "cancel":
                    session.set_status("failed")
                    await files_collection().update_one(
                        {"session_id": session_id},
                        {"$set": {"status": "cancelled"}}
                    )
                    break
                    
            except asyncio.TimeoutError:
                # Check if transfer completed
                if session.status == "completed":
                    await websocket.send_json({
                        "type": "complete",
                        "message": "File saved to local storage!",
                        "bytes_received": session.bytes_transferred
                    })
                    break
                continue
            except WebSocketDisconnect:
                session.set_status("failed")
                break
        
        # Check completion
        if session.status == "completed":
            await websocket.send_json({
                "type": "complete",
                "message": "File saved to local storage!",
                "bytes_received": session.bytes_transferred
            })
    
    finally:
        await websocket.close()


@router.get("/status/{session_id}")
async def get_session_status(session_id: str):
    """Get transfer status"""
    
    session = get_active_session(session_id)
    if not session:
        # Check database for completed transfers
        metadata = await files_collection().find_one({"session_id": session_id})
        if metadata:
            return {
                "session_id": session_id,
                "status": metadata.get("status", "unknown"),
                "filename": metadata.get("filename"),
                "file_size": metadata.get("size"),
                "created_at": metadata.get("created_at")
            }
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    return {
        "session_id": session_id,
        "status": session.status,
        "filename": session.filename,
        "file_size": session.file_size,
        "bytes_transferred": session.bytes_transferred,
        "progress": session.get_progress(),
        "sender_connected": session.sender_ws is not None,
        "receiver_connected": session.receiver_ws is not None
    }


@router.get("/history/{chat_id}")
async def get_transfer_history(chat_id: str, current_user: str = Depends(get_current_user)):
    """Get file transfer history for a chat (metadata only)"""
    
    files = await files_collection().find({
        "chat_id": chat_id,
        "$or": [
            {"sender_id": current_user},
            {"receiver_id": current_user}
        ]
    }).sort("created_at", -1).limit(50).to_list(50)
    
    return {
        "chat_id": chat_id,
        "files": [
            {
                "session_id": f.get("session_id"),
                "filename": f.get("filename"),
                "size": f.get("size"),
                "mime": f.get("mime"),
                "status": f.get("status"),
                "sender_id": f.get("sender_id"),
                "created_at": f.get("created_at"),
                "storage_type": "local"  # WhatsApp-style
            }
            for f in files
        ]
    }

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
from datetime import datetime, timedelta
from db_proxy import files_collection, chats_collection
from auth.utils import get_current_user

router = APIRouter(prefix="/p2p", tags=["P2P Transfer"])

# Active P2P sessions (in-memory, no disk storage)
active_sessions: Dict[str, dict] = {}


class P2PSession:
    """WhatsApp-style transfer session"""
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
        
    def is_ready(self):
        return self.sender_ws is not None and self.receiver_ws is not None
    
    def get_progress(self):
        if self.file_size == 0:
            return 0
        return round((self.bytes_transferred / self.file_size) * 100, 2)


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
    
    active_sessions[session_id] = session
    
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
    
    try:
        from auth.utils import decode_token
        payload = decode_token(token)
        current_user = payload.get("sub")
    except:
        await websocket.close(code=4001, reason="Invalid authorization token")
        return
    
    if session_id not in active_sessions:
        await websocket.close(code=4004, reason="Session not found")
        return
    
    session = active_sessions[session_id]
    
    # Verify sender owns this session
    if session.sender_id != current_user:
        await websocket.close(code=4003, reason="Not authorized for this session")
        return
    
    await websocket.accept()
    session.sender_ws = websocket
    session.status = "waiting_receiver"
    
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
        session.status = "transferring"
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
                    if session.receiver_ws:
                        await session.receiver_ws.send_bytes(chunk_data)
                        session.bytes_transferred += len(chunk_data)
                        
                        # Send progress
                        await websocket.send_json({
                            "type": "progress",
                            "bytes": session.bytes_transferred,
                            "total": session.file_size,
                            "percent": session.get_progress()
                        })
                    else:
                        raise Exception("Receiver disconnected")
                
                elif "text" in message:
                    data = json.loads(message["text"])
                    
                    if data.get("type") == "complete":
                        # Transfer complete
                        session.status = "completed"
                        await websocket.send_json({
                            "type": "complete",
                            "bytes_transferred": session.bytes_transferred
                        })
                        
                        # Update metadata
                        await files_collection().update_one(
                            {"session_id": session_id},
                            {"$set": {
                                "status": "completed",
                                "completed_at": datetime.now(timezone.utc)
                            }}
                        )
                        break
                        
            except WebSocketDisconnect:
                session.status = "failed"
                break
            except Exception as e:
                session.status = "failed"
                await websocket.send_json({"type": "error", "message": str(e)})
                break
    
    finally:
        # Cleanup
        if session_id in active_sessions:
            del active_sessions[session_id]
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
    
    try:
        from auth.utils import decode_token
        payload = decode_token(token)
        current_user = payload.get("sub")
    except:
        await websocket.close(code=4001, reason="Invalid authorization token")
        return
    
    if session_id not in active_sessions:
        await websocket.close(code=4004, reason="Session not found")
        return
    
    session = active_sessions[session_id]
    
    # Verify receiver is authorized for this session
    if session.receiver_id != current_user:
        await websocket.close(code=4003, reason="Not authorized for this session")
        return
    
    await websocket.accept()
    session.receiver_ws = websocket
    
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
        while session.status == "transferring":
            try:
                # Receiver can send control messages
                message = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=1.0
                )
                
                if message.get("action") == "cancel":
                    session.status = "failed"
                    await files_collection().update_one(
                        {"session_id": session_id},
                        {"$set": {"status": "cancelled"}}
                    )
                    break
                    
            except asyncio.TimeoutError:
                continue
            except WebSocketDisconnect:
                session.status = "failed"
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
    
    if session_id not in active_sessions:
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
    
    session = active_sessions[session_id]
    
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

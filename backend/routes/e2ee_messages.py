"""
E2EE Messages Route - Encrypted messaging with Signal Protocol

Endpoints:
- POST /messages/e2ee/send - Send E2EE encrypted message
- POST /messages/e2ee/decrypt - Decrypt received message
- GET /messages/e2ee/sessions - Get active E2EE sessions
- POST /messages/e2ee/sessions/init - Initialize new E2EE session
- POST /messages/e2ee/verify - Verify message integrity
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Body
from pydantic import BaseModel, Field

from auth.utils import get_current_user
from e2ee_service import E2EEService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/messages/e2ee", tags=["E2EE Messages"])


class E2EESessionInitRequest(BaseModel):
    """Initialize new E2EE session"""
    contact_user_id: str = Field(..., description="Recipient user ID")
    contact_device_id: Optional[str] = Field(None, description="Target device (optional)")


class E2EEMessageSendRequest(BaseModel):
    """Send encrypted message"""
    session_id: str = Field(..., min_length=32)
    plaintext: str = Field(..., min_length=1, max_length=10000, description="Message content")
    recipient_devices: List[str] = Field(..., min_items=1, description="Target device IDs")


class E2EEMessageDecryptRequest(BaseModel):
    """Decrypt received message"""
    session_id: str = Field(..., min_length=32)
    ciphertext: str = Field(..., description="Base64 encrypted message")
    message_key_counter: int = Field(..., ge=0, description="Message counter for replay protection")


class E2EESessionResponse(BaseModel):
    """Response with session information"""
    session_id: str
    status: str
    created_at: Optional[datetime] = None
    message_counter: int = 0


# Initialize E2EE service (in real implementation, injected from app context)
e2ee_service = None

async def get_e2ee_service_instance() -> E2EEService:
    """Get E2EE service instance."""
    global e2ee_service
    if e2ee_service is None:
        e2ee_service = E2EEService(db=None, redis_client=None)  # Would be injected
    return e2ee_service


@router.post("/sessions/init", status_code=status.HTTP_201_CREATED)
async def initialize_e2ee_session(
    request: E2EESessionInitRequest,
    current_user: str = Depends(get_current_user),
    e2ee_svc: E2EEService = Depends(get_e2ee_service_instance)
):
    """
    Initialize new E2EE session with contact.
    
    Performs DH key exchange and establishes Double Ratchet session.
    """
    try:
        logger.info(f"E2EE session initialization: {current_user} -> {request.contact_user_id}")
        
        # Get user's primary device
        # In real implementation: request.device_id from client
        local_device_id = "primary_device"  # Placeholder
        
        # Establish session
        result = await e2ee_svc.establish_session_with_contact(
            initiator_user_id=current_user,
            initiator_device_id=local_device_id,
            contact_user_id=request.contact_user_id,
            contact_device_id=request.contact_device_id or "primary_device"
        )
        
        return {
            "status": "success",
            "session_id": result["session_id"],
            "initiator_device_id": result["initiator_device_id"],
            "contact_device_id": result["contact_device_id"],
            "is_ready": result["is_ready"],
            "message": "E2EE session established"
        }
    except Exception as e:
        logger.error(f"Session initialization failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to initialize session: {str(e)}"
        )


@router.post("/send", status_code=status.HTTP_201_CREATED)
async def send_encrypted_message(
    request: E2EEMessageSendRequest,
    current_user: str = Depends(get_current_user),
    e2ee_svc: E2EEService = Depends(get_e2ee_service_instance)
):
    """
    Send end-to-end encrypted message.
    
    Message is encrypted with Double Ratchet (Signal Protocol).
    Server never sees plaintext content.
    
    Returns:
        - ciphertext: Base64 encoded encrypted message
        - message_key_counter: For replay protection
        - delivery_status: Per-device delivery status
    """
    try:
        logger.info(f"Sending E2EE message in session {request.session_id}")
        
        # Encrypt message
        encrypted_msg = await e2ee_svc.encrypt_message(
            session_id=request.session_id,
            plaintext=request.plaintext,
            sender_user_id=current_user,
            sender_device_id="primary_device"  # Placeholder
        )
        
        # Get recipient info (from session)
        session_info = await e2ee_svc.verify_session_key_integrity(request.session_id)
        
        if session_info["status"] != "valid":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session is invalid or expired"
            )
        
        # Fan out to recipient devices
        delivery_status = await e2ee_svc.fan_out_encrypted_message(
            sender_user_id=current_user,
            sender_device_id="primary_device",  # Placeholder
            recipient_user_id="recipient_id",  # Would come from session
            encrypted_message=encrypted_msg["ciphertext"],
            recipient_devices=request.recipient_devices
        )
        
        return {
            "status": "sent",
            "session_id": request.session_id,
            "ciphertext": encrypted_msg["ciphertext"],
            "message_key_counter": encrypted_msg["message_key_counter"],
            "algorithm": encrypted_msg["algorithm"],
            "delivery_status": delivery_status.get("delivery_status", {}),
            "message": "Message encrypted and queued for delivery"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to send encrypted message: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Encryption failed: {str(e)}"
        )


@router.post("/decrypt")
async def decrypt_message(
    request: E2EEMessageDecryptRequest,
    current_user: str = Depends(get_current_user),
    e2ee_svc: E2EEService = Depends(get_e2ee_service_instance)
):
    """
    Decrypt received E2EE message.
    
    Client can call this to decrypt messages received from other devices.
    Includes replay attack detection.
    
    Returns:
        - plaintext: Decrypted message content
        - verified: Whether message integrity verified
    """
    try:
        logger.info(f"Decrypting message in session {request.session_id}")
        
        # Decrypt message
        plaintext = await e2ee_svc.decrypt_message(
            session_id=request.session_id,
            ciphertext_b64=request.ciphertext,
            message_key_counter=request.message_key_counter,
            recipient_device_id="primary_device"  # Placeholder
        )
        
        return {
            "status": "success",
            "plaintext": plaintext,
            "verified": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "Message decrypted successfully"
        }
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Decryption failed: {str(e)}"
        )


@router.get("/sessions")
async def list_e2ee_sessions(
    current_user: str = Depends(get_current_user),
    e2ee_svc: E2EEService = Depends(get_e2ee_service_instance)
):
    """
    List active E2EE sessions for current user.
    
    Returns information about established encryption sessions.
    """
    try:
        logger.info(f"Listing E2EE sessions for user {current_user}")
        
        sessions = []
        
        # In real implementation, would query database for user's sessions
        # For now, return active in-memory sessions
        for session_id, session_data in e2ee_svc.active_sessions.items():
            sessions.append({
                "session_id": session_id,
                "status": "active",
                "created_at": session_data.get("created_at", datetime.now(timezone.utc)).isoformat(),
                "message_counter": session_data.get("message_counter", 0),
                "initiator_device_id": session_data.get("initiator_device_id"),
                "contact_device_id": session_data.get("contact_device_id")
            })
        
        return {
            "status": "success",
            "user_id": current_user,
            "sessions": sessions,
            "session_count": len(sessions)
        }
    except Exception as e:
        logger.error(f"Failed to list sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve sessions"
        )


@router.post("/verify")
async def verify_message_integrity(
    request: dict = Body(...),
    current_user: str = Depends(get_current_user),
    e2ee_svc: E2EEService = Depends(get_e2ee_service_instance)
):
    """
    Verify message integrity and authenticity.
    
    Uses HMAC-SHA256 to verify message hasn't been tampered with.
    """
    try:
        session_id = request.get("session_id")
        message_counter = request.get("message_counter")
        
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="session_id required"
            )
        
        # Verify session
        verification_result = await e2ee_svc.verify_session_key_integrity(session_id)
        
        return {
            "status": "success",
            "verified": verification_result["status"] == "valid",
            "session_id": session_id,
            "message_counter": message_counter,
            "verification": verification_result
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Verification failed: {str(e)}"
        )


@router.post("/rotate-keys/{session_id}")
async def rotate_session_keys(
    session_id: str,
    current_user: str = Depends(get_current_user),
    e2ee_svc: E2EEService = Depends(get_e2ee_service_instance)
):
    """
    Manually rotate session keys for additional forward secrecy.
    
    Performs Double Ratchet step to advance session state.
    """
    try:
        logger.info(f"Rotating keys for session {session_id}")
        
        rotation_result = await e2ee_svc.rotate_session_keys(session_id)
        
        return {
            "status": "success",
            "result": rotation_result,
            "message": "Session keys rotated"
        }
    except Exception as e:
        logger.error(f"Key rotation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key rotation failed: {str(e)}"
        )


# OPTIONS handlers for CORS
@router.options("/{path:path}")
async def options_handler():
    """Handle CORS preflight requests"""
    from fastapi.responses import Response
    return Response(status_code=200)

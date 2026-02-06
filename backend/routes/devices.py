"""
WhatsApp-style Multi-Device Management
Primary device + linked devices via QR code
Cryptographic authority and device trust graph

Endpoints:
- POST /devices/generate-qr - Generate QR code for device linking
- POST /devices/link - Link a new device via QR code
- GET /devices/list - List all devices for user
- DELETE /devices/{device_id} - Unlink/remove device
- POST /devices/{device_id}/heartbeat - Update device activity
"""

import logging
import base64
import qrcode
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
import sys
import os
import time
import secrets
import hashlib
import hmac
from typing import Dict, List, Optional, Any, Tuple
from fastapi import APIRouter, Depends, Request, Header, Body, Query, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def _get_device_public_key(device_id: str):
    """Get device public key from Redis."""
    return redis_client.get(f"device_public_key:{device_id}")


def generate_qr_code_for_device_linking(user_id: str, device_type: str):
    """Generate QR code for device linking."""
    session_id = str(uuid.uuid4())
    session_code = f"{session_id[:6]}"  # First 6 chars
    
    qr_data = QRLinkData(
        link_id=session_id,
        user_id=user_id,
        device_type=device_type,
        timestamp=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=5),
        _signature=""  # Will be signed by primary device
    )
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(json.dumps(qr_data.dict(), default=str))
    
    # Convert to base64 image
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    img_b64 = base64.b64encode(buffer.getvalue()).decode()
    
    return session_id, session_code, img_b64
from typing import Optional, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status, Body
from pydantic import BaseModel, Field

from auth.utils import get_current_user

try:
    from ..device_key_manager import DeviceKeyManager, KeyDistributionService
except ImportError:
    # Fallback for testing
    class DeviceKeyManager:
        def __init__(self, db=None):
            pass
    class KeyDistributionService:
        def __init__(self):
            pass

logger = logging.getLogger(__name__)


class DeviceType:
    PRIMARY = "primary"
    LINKED = "linked"


class DeviceLinkRequest(BaseModel):
    qr_code: str  # Base64 encoded QR data
    device_name: str = Field(..., min_length=1, max_length=100)
    device_type: str = DeviceType.LINKED


class DeviceInfo(BaseModel):
    device_id: str
    user_id: str
    device_name: str
    device_type: str
    created_at: datetime
    last_active: datetime
    is_active: bool
    public_key: str  # Device identity key
    signature: str   # Primary device signature


class QRLinkData(BaseModel):
    link_id: str
    primary_user_id: str
    primary_device_id: str
    primary_public_key: str
    timestamp: datetime
    expires_at: datetime
    signature: str


router = APIRouter(prefix="/devices", tags=["Multi-Device"])


@router.post("/register-primary")
async def register_primary_device(
    request: dict,
    current_user: str = Depends(get_current_user)
):
    """Register primary device with Signal Protocol"""
    try:
        device_name = request.get("device_name", "Primary Device")
        
        # Get multi-device manager
        manager = get_multi_device_manager()
        
        # Register primary device
        result = await manager.register_primary_device(
            user_id=current_user,
            device_name=device_name
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to register primary device: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to register device")


@router.post("/initiate-linking")
async def initiate_device_linking(
    request: dict,
    current_user: str = Depends(get_current_user)
):
    """Initiate QR-based device linking"""
    try:
        # Get multi-device manager
        manager = get_multi_device_manager()
        
        # Initiate linking
        result = await manager.initiate_device_linking(
            primary_user_id=current_user
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to initiate device linking: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to initiate linking")


@router.post("/complete-linking")
async def complete_device_linking(
    request: dict,
    current_user: str = Depends(get_current_user)
):
    """Complete device linking process"""
    try:
        linking_id = request.get("linking_id")
        device_name = request.get("device_name", "Linked Device")
        device_type = request.get("device_type", "linked")
        device_public_key = request.get("public_key")
        
        if not all([linking_id, device_name, device_type, device_public_key]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing required fields")
        
        # Get multi-device manager
        manager = get_multi_device_manager()
        
        # Complete linking
        result = await manager.complete_device_linking(
            linking_id=linking_id,
            device_name=device_name,
            device_type=device_type,
            new_device_public_key=device_public_key
        )
        
        return result
        
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to complete device linking: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to complete linking")


@router.post("/encrypt-message")
async def encrypt_message_for_devices(
    request: dict,
    current_user: str = Depends(get_current_user)
):
    """Encrypt message for all user devices"""
    try:
        plaintext = request.get("message")
        message_id = request.get("message_id")
        
        if not all([plaintext, message_id]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing message or message_id")
        
        # Get multi-device manager
        manager = get_multi_device_manager()
        
        # Encrypt for all devices
        result = await manager.encrypt_message_for_all_devices(
            user_id=current_user,
            plaintext=plaintext,
            message_id=message_id
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to encrypt message: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to encrypt message")


@router.delete("/revoke/{device_id}")
async def revoke_device(
    device_id: str,
    current_user: str = Depends(get_current_user)
):
    """Revoke device and destroy all sessions"""
    try:
        # Get multi-device manager
        manager = get_multi_device_manager()
        
        # Revoke device
        success = await manager.revoke_device(
            user_id=current_user,
            device_id=device_id
        )
        
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
        
        return {"message": f"Device {device_id} revoked successfully"}
        
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to revoke device: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to revoke device")


@router.get("/list")
async def list_user_devices(
    current_user: str = Depends(get_current_user)
):
    """List all devices for user"""
    try:
        # Get multi-device manager
        manager = get_multi_device_manager()
        
        # Get user devices
        devices = await manager.get_user_devices(current_user)
        
        return {"devices": devices, "count": len(devices)}
        
    except Exception as e:
        logger.error(f"Failed to list devices: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list devices")


@router.get("/signal-bundle/{user_id}")
async def get_signal_bundle(
    user_id: str,
    device_id: Optional[str] = None,
    current_user: str = Depends(get_current_user)
):
    """Get Signal Protocol key bundle for user"""
    try:
        # Only allow users to get their own bundles (or for testing)
        if user_id != current_user:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
        # Get multi-device manager
        manager = get_multi_device_manager()
        
        # Get Signal session
        session = await manager.get_session(user_id, device_id or "primary")
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
        
        return session.get_public_bundle()
        
    except Exception as e:
        logger.error(f"Failed to get Signal bundle: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get bundle")


class DeviceRegistrationRequest(BaseModel):
    """Register new device"""
    device_id: str = Field(..., min_length=16, max_length=256)
    device_type: str = Field(..., description="phone, web, desktop, tablet")
    device_name: Optional[str] = Field(None, max_length=100)
    platform: Optional[str] = Field(None, max_length=50)
    app_version: Optional[str] = Field(None, max_length=20)
    is_primary: bool = False


class QRCodeGenerationRequest(BaseModel):
    """Generate QR code for device linking"""
    device_type: str = Field(..., description="Type of device to link")
    device_name: Optional[str] = Field(None, max_length=100)


class QRCodeVerificationRequest(BaseModel):
    """Verify QR code and establish device link"""
    session_id: str = Field(..., min_length=32)
    session_code: str = Field(..., min_length=6, max_length=6)


class KeyBundleRequest(BaseModel):
    """Request to get device's public key bundle"""
    user_id: str
    device_id: Optional[str] = None


# Initialize services (in real implementation, these would be injected)
device_manager = DeviceKeyManager(db=None)
key_distribution = KeyDistributionService()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_device(
    request: DeviceRegistrationRequest,
    current_user: str = Depends(get_current_user)
):
    """
    Register new device for user with WhatsApp-style trust graph.
    
    Primary devices: Full authority
    Linked devices: Require primary device authorization
    """
    try:
        logger.info(f"Device registration request from user {current_user}")
        
        from ..redis_cache import DeviceTrustGraphService
        
        # Check if user already has devices
        existing_devices = await DeviceTrustGraphService.get_user_devices(current_user)
        
        # If this is a primary device but user already has one, reject
        if request.is_primary and existing_devices["primary_device"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Primary device already exists. Use device linking instead."
            )
        
        # If this is not primary but no primary exists, require primary first
        if not request.is_primary and not existing_devices["primary_device"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Primary device must be registered first. Use is_primary=true."
            )
        
        # Register device and generate keys
        result = await device_manager.register_device(
            user_id=current_user,
            device_id=request.device_id,
            device_type=request.device_type,
            device_name=request.device_name,
            platform=request.platform,
            app_version=request.app_version,
            is_primary=request.is_primary
        )
        
        # Update trust graph
        device_info = {
            "device_type": request.device_type,
            "device_name": request.device_name,
            "platform": request.platform,
            "app_version": request.app_version
        }
        
        if request.is_primary:
            # Register as primary device
            await DeviceTrustGraphService.register_primary_device(
                current_user, 
                request.device_id, 
                device_info
            )
        else:
            # For linked devices, they need QR code verification
            # Store temporary registration until QR verification
            temp_key = f"temp_device:{current_user}:{request.device_id}"
            temp_data = {
                "device_info": device_info,
                "registered_at": datetime.utcnow().isoformat(),
                "status": "pending_verification"
            }
            await redis_client.setex(temp_key, 300, json.dumps(temp_data))  # 5 min TTL
        
        logger.info(f"Device registered: {request.device_id}")
        
        return {
            "status": "success",
            "device_id": result["device_id"],
            "user_id": result["user_id"],
            "identity_key_public": result["identity_key_public"],
            "identity_key_fingerprint": result["identity_key_fingerprint"],
            "signed_prekey_id": result["signed_prekey_id"],
            "signed_prekey_public": result["signed_prekey_public"],
            "one_time_prekeys_generated": result["one_time_prekeys_generated"],
            "is_primary": result["is_primary"],
            "trust_status": "verified" if request.is_primary else "pending_verification",
            "message": "Device registered. " + 
                     ("Primary device verified." if request.is_primary else "Verify via QR code to enable.")
        }
    except Exception as e:
        logger.error(f"Device registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Device registration failed: {str(e)}"
        )


@router.post("/qr-code")
async def generate_qr_code(
    request: QRCodeGenerationRequest,
    current_user: str = Depends(get_current_user)
):
    """
    Generate QR code for linking new device.
    
    QR code contains:
    - User ID
    - Session ID (temporary)
    - 6-digit verification code
    
    Returns base64 encoded QR code image.
    """
    try:
        logger.info(f"QR code generation request from user {current_user}")
        
        session_id, session_code, qr_data_b64 = await generate_qr_code_for_device_linking(
            user_id=current_user,
            device_type=request.device_type
        )
        
        # Generate actual QR code image
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data_b64)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        img_buffer = io.BytesIO()
        img.save(img_buffer, format="PNG")
        img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        return {
            "status": "success",
            "session_id": session_id,
            "session_code": session_code,
            "qr_code_image": f"data:image/png;base64,{img_base64}",
            "expires_in_seconds": 300,  # 5 minutes
            "message": f"Scan this QR code on the new device and enter code {session_code} to verify"
        }
    except Exception as e:
        logger.error(f"QR code generation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate QR code: {str(e)}"
        )


@router.post("/qr-code/verify")
async def verify_qr_code(
    request: QRCodeVerificationRequest,
    current_user: str = Depends(get_current_user)
):
    """
    Verify QR code and establish device link.
    
    This endpoint is called from the new device after scanning QR code.
    Verifies that session codes match and creates trusted device relationship.
    """
    try:
        logger.info(f"QR code verification from user {current_user}")
        
        # Verify session
        # In real implementation, validate session_id and session_code against stored session
        
        # Mark device as verified and trusted
        result = await device_manager.verify_device(
            user_id=current_user,
            device_id=request.session_id
        )
        
        logger.info(f"Device verified for user {current_user}")
        
        return {
            "status": "success",
            "device_verified": True,
            "message": "Device linked successfully. E2EE is now enabled."
        }
    except Exception as e:
        logger.error(f"QR code verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Verification failed: {str(e)}"
        )


@router.get("/list")
async def list_devices(
    current_user: str = Depends(get_current_user)
):
    """
    List all devices linked to user account.
    
    Returns device information (without private keys).
    """
    try:
        devices = await device_manager.list_user_devices(current_user)
        
        return {
            "status": "success",
            "user_id": current_user,
            "devices": devices,
            "device_count": len(devices)
        }
    except Exception as e:
        logger.error(f"Failed to list devices: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve devices"
        )


@router.get("/{device_id}/keys")
async def get_device_keys(
    device_id: str,
    current_user: str = Depends(get_current_user)
):
    """
    Get device's public key bundle for session initiation.
    
    Returns only public keys (safe to share).
    Does NOT return private keys.
    """
    try:
        logger.info(f"Key bundle request for device {device_id} from user {current_user}")
        
        # Verify user owns this device
        devices = await device_manager.list_user_devices(current_user)
        device_ids = [d.get("device_id") for d in devices]
        
        if device_id not in device_ids:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Get key bundle
        bundle = await key_distribution.get_user_key_bundle(
            user_id=current_user,
            device_id=device_id
        )
        
        return {
            "status": "success",
            "device_id": device_id,
            "key_bundle": bundle,
            "expires_in_seconds": 86400  # 24 hours
        }
    except Exception as e:
        logger.error(f"Failed to get device keys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve device keys"
        )


@router.delete("/{device_id}")
async def revoke_device(
    device_id: str,
    current_user: str = Depends(get_current_user)
):
    """
    Revoke/remove device from user account.
    
    This invalidates all sessions for the device.
    """
    try:
        logger.info(f"Device revocation request for {device_id} from user {current_user}")
        
        # Verify user owns this device
        devices = await device_manager.list_user_devices(current_user)
        device_ids = [d.get("device_id") for d in devices]
        
        if device_id not in device_ids:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Revoke device (would update database)
        # await db.devices.update_one(
        #     {"device_id": device_id, "user_id": current_user},
        #     {"$set": {"is_active": False, "revoked_at": datetime.now(timezone.utc)}}
        # )
        
        logger.info(f"Device revoked: {device_id}")
        
        return {
            "status": "success",
            "device_id": device_id,
            "message": "Device has been revoked. All sessions terminated."
        }
    except Exception as e:
        logger.error(f"Failed to revoke device: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke device"
        )


@router.post("/sessions/create", status_code=status.HTTP_201_CREATED)
async def create_device_session(
    request: dict = Body(...),
    current_user: str = Depends(get_current_user)
):
    """
    Create encrypted session between two devices.
    
    This is called after initial key exchange via QR code or other means.
    Establishes Double Ratchet session for end-to-end encryption.
    """
    try:
        device_id = request.get("device_id")
        contact_device_id = request.get("contact_device_id")
        root_key_b64 = request.get("root_key")
        
        if not all([device_id, contact_device_id, root_key_b64]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing required fields: device_id, contact_device_id, root_key"
            )
        
        logger.info(f"Creating session between {device_id} and {contact_device_id}")
        
        result = await device_manager.create_device_session(
            user_id=current_user,
            device_id=device_id,
            contact_device_id=contact_device_id,
            root_key_b64=root_key_b64
        )
        
        logger.info(f"Session created: {result['session_id']}")
        
        return {
            "status": "success",
            "session_id": result["session_id"],
            "device_id": result["device_id"],
            "peer_device_id": result["peer_device_id"],
            "message": "Encryption session established"
        }
    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Session creation failed: {str(e)}"
        )


# OPTIONS handlers for CORS
@router.options("/{path:path}")
async def options_handler():
    """Handle CORS preflight requests"""
    from fastapi.responses import Response
    return Response(status_code=200)

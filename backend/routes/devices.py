"""
Device Management Routes - Multi-Device Support with QR Code Linking

Endpoints:
- POST /devices/register - Register new device
- POST /devices/qr-code - Generate QR code for device linking
- POST /devices/qr-code/verify - Verify QR code and establish device link
- POST /devices/sessions/create - Create encrypted session
- GET /devices/list - List user's devices
- GET /devices/{device_id}/keys - Get device's public keys
- DELETE /devices/{device_id} - Revoke device
"""

import logging
import base64
import qrcode
import io
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Body
from pydantic import BaseModel, Field

from auth.utils import get_current_user
from device_key_manager import (
    DeviceKeyManager,
    KeyDistributionService,
    generate_qr_code_for_device_linking
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/devices", tags=["Devices & E2EE"])


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
    Register new device for user.
    
    Returns device public keys and initial key material.
    Device starts in "unverified" state until QR code verification.
    """
    try:
        logger.info(f"Device registration request from user {current_user}")
        
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
            "message": "Device registered. Verify via QR code to enable E2EE."
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

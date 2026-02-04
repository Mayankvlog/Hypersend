"""
Debug endpoints for development and troubleshooting
These endpoints are only available in DEBUG mode
"""

from fastapi import APIRouter, HTTPException, status, Depends

try:
    from ..config import settings
    from ..models import ProfileUpdate, PasswordChangeRequest
except ImportError:
    from config import settings
    from models import ProfileUpdate, PasswordChangeRequest

from auth.utils import get_current_user
from pydantic import BaseModel
from typing import Dict, Any
import json

router = APIRouter(prefix="/debug", tags=["Debug"])


def check_debug_mode():
    """Verify that DEBUG mode is enabled"""
    if not settings.DEBUG:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Debug endpoints are only available in DEBUG mode"
        )


@router.get("/profile-schema")
async def get_profile_update_schema(
    current_user: str = Depends(get_current_user)
):
    """
    Get the JSON schema for ProfileUpdate model
    Useful for debugging validation errors
    Only available in DEBUG mode
    """
    check_debug_mode()
    
    schema = ProfileUpdate.model_json_schema()
    
    return {
        "model": "ProfileUpdate",
        "description": "Profile update request model",
        "schema": schema,
        "example": {
            "name": "John Doe",
            "username": "johndoe",
            "email": "john@zaply.in.net",
            "bio": "Software developer",
            "avatar": "JD",
            "avatar_url": "https://zaply.in.net/api/v1/files/avatar.jpg"
        },
        "notes": [
            "All fields are optional - at least one must be provided",
            "name: 2-100 characters",
            "username: 3-50 characters",
            "email: 5-255 characters (valid email format)",
            "avatar: 2-10 characters (e.g., 'JD', 'AM')",
            "bio: max 500 characters",
            "avatar_url: max 500 characters"
        ]
    }


@router.get("/password-change-schema")
async def get_password_change_schema(
    current_user: str = Depends(get_current_user)
):
    """
    Get the JSON schema for PasswordChangeRequest model
    Useful for debugging validation errors
    Only available in DEBUG mode
    """
    check_debug_mode()
    
    schema = PasswordChangeRequest.model_json_schema()
    
    return {
        "model": "PasswordChangeRequest",
        "description": "Password change request model",
        "schema": schema,
        "example": {
            "old_password": "CurrentPassword123",
            "new_password": "NewPassword456"
        },
        "requirements": [
            "old_password: 6-128 characters (must be valid for current user)",
            "new_password: 6-128 characters (must be different from old password)"
        ]
    }


@router.get("/email-change-schema")
async def get_email_change_schema(
    current_user: str = Depends(get_current_user)
):
    """
    Get the JSON schema for EmailChangeRequest model - DISABLED
    Useful for debugging validation errors
    Only available in DEBUG mode
    """
    check_debug_mode()
    
    return {
        "model": "EmailChangeRequest",
        "description": "Email change request model - DISABLED",
        "schema": {},
        "example": {
            "message": "Email change functionality has been disabled"
        }
    }


@router.get("/validation-examples")
async def get_validation_examples(
    current_user: str = Depends(get_current_user)
):
    """
    Get examples of common validation errors and how to fix them
    Only available in DEBUG mode
    """
    check_debug_mode()
    
    return {
        "profile_update_errors": [
            {
                "error": "name must be at least 2 characters",
                "received": {"name": "J"},
                "fix": "Provide at least 2 characters for name"
            },
            {
                "error": "username must be at least 3 characters",
                "received": {"username": "ab"},
                "fix": "Provide at least 3 characters for username"
            },
            {
                "error": "email must be at least 5 characters",
                "received": {"email": "a@b"},
                "fix": "Provide a valid email like user@localhost.com"
            },
            {
                "error": "email does not match pattern",
                "received": {"email": "invalid"},
                "fix": "Email must be in format: user@domain.extension"
            },
            {
                "error": "At least one field must be provided",
                "received": {},
                "fix": "Include at least one field to update"
            }
        ],
        "password_change_errors": [
            {
                "error": "old_password must be at least 6 characters",
                "received": {"old_password": "short"},
                "fix": "Provide current password (at least 6 characters)"
            },
            {
                "error": "new_password must be at least 6 characters",
                "received": {"new_password": "short"},
                "fix": "New password must be at least 6 characters"
            }
        ],
        "email_change_errors": [
            {
                "error": "email does not match pattern",
                "received": {"email": "invalid"},
                "fix": "Email must be in format: user@domain.extension"
            },
            {
                "error": "password must be at least 6 characters",
                "received": {"password": "short"},
                "fix": "Provide current password (at least 6 characters)"
            }
        ]
    }


@router.post("/test-validation")
async def test_validation(
    current_user: str = Depends(get_current_user),
    data: Dict[str, Any] = None
):
    """
    Test validation of ProfileUpdate data
    Send any data and see validation errors
    Useful for debugging API requests
    Only available in DEBUG mode
    """
    check_debug_mode()
    
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide 'data' in request body"
        )
    
    try:
        # Try to validate as ProfileUpdate
        validated = ProfileUpdate(**data)
        return {
            "status": "success",
            "message": "Validation passed!",
            "validated_data": validated.model_dump()
        }
    except Exception as e:
        return {
            "status": "error",
            "message": "Validation failed",
            "error_type": type(e).__name__,
            "error_details": str(e),
            "raw_error": str(e)
        }


@router.post("/diagnose-password")
async def diagnose_password_for_user(
    email: str,
    current_user: str = Depends(get_current_user)
):
    """
    Diagnose password format for a specific user (ADMIN ONLY)
    Helps troubleshoot password verification issues
    Only available in DEBUG mode
    """
    check_debug_mode()
    
    # Import database function
    from database import users_collection
    
    # Find user by email
    user = await users_collection().find_one({"email": email.lower().strip()})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email {email} not found"
        )
    
    # Get password info
    password_hash = user.get("password_hash")
    password_salt = user.get("password_salt")
    
    # Import diagnosis function
    from auth.utils import diagnose_password_format, hash_password
    
    diagnosis = diagnose_password_format(password_hash, password_salt)
    
    # Generate what a correct hash should be for a test password
    test_password = "TestPassword123!"
    test_hash, test_salt = hash_password(test_password)
    
    return {
        "email": email,
        "user_id": str(user.get("_id")),
        "diagnosis": diagnosis,
        "password_info": {
            "hash_exists": bool(password_hash),
            "salt_exists": bool(password_salt),
            "password_migrated": user.get("password_migrated", False)
        },
        "test_hash_example": {
            "password": test_password,
            "hash": test_hash,
            "salt": test_salt,
            "format_created": "separate_hash_and_salt"
        },
        "recommendations": [
            "If hash format is 'SHA256_hex' with no salt, password needs migration",
            "If hash format is 'combined_format', password will be auto-migrated on next login",
            "If salt is missing but hash exists, password migration is needed",
            "Contact admin to reset password if format is unrecognized"
        ]
    }


@router.get("/endpoints-info")
async def get_endpoints_info(
    current_user: str = Depends(get_current_user)
):
    """
    Get information about all profile-related endpoints
    Only available in DEBUG mode
    """
    check_debug_mode()
    
    return {
        "endpoints": [
            {
                "method": "GET",
                "path": "/users/me",
                "description": "Get current user profile",
                "auth": "Required",
                "response": "User object with all profile data"
            },
            {
                "method": "PUT",
                "path": "/users/profile",
                "description": "Update user profile",
                "auth": "Required",
                "body": "ProfileUpdate model (all fields optional)",
                "response": "Updated User object"
            },
            {
                "method": "POST",
                "path": "/users/change-password",
                "description": "Change user password",
                "auth": "Required",
                "body": {
                    "old_password": "string (6-128 chars)",
                    "new_password": "string (6-128 chars)"
                },
                "response": "Success message"
            },
            {
                "method": "POST",
                "path": "/users/change-email",
                "description": "Change user email",
                "auth": "Required",
                "body": {
                    "email": "string (valid email format)",
                    "password": "string (current password)"
                },
                "response": "Success message with new email"
            },
            {
                "method": "POST",
                "path": "/users/avatar",
                "description": "Upload user avatar image",
                "auth": "Required",
                "body": "multipart/form-data with 'file' field",
                "response": "Avatar object with avatar_url"
            }
        ],
        "debug_endpoints": [
            {
                "method": "GET",
                "path": "/debug/profile-schema",
                "description": "Get ProfileUpdate JSON schema"
            },
            {
                "method": "GET",
                "path": "/debug/password-change-schema",
                "description": "Get PasswordChangeRequest JSON schema"
            },
            {
                "method": "GET",
                "path": "/debug/email-change-schema",
                "description": "Get EmailChangeRequest JSON schema"
            },
            {
                "method": "GET",
                "path": "/debug/validation-examples",
                "description": "Get common validation errors and fixes"
            },
            {
                "method": "POST",
                "path": "/debug/test-validation",
                "description": "Test any data against ProfileUpdate validation"
            },
            {
                "method": "POST",
                "path": "/debug/diagnose-password",
                "description": "Diagnose password format issues for a user",
                "params": {"email": "user email address"}
            }
        ]
    }

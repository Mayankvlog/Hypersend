"""
Test for JWT token expiration fix during uploads
Tests that expired JWT tokens get extended for upload operations
"""

import pytest
import asyncio
import jwt
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi import Request, HTTPException
import backend.config as backend_config
from backend.auth.utils import get_current_user_for_upload


@pytest.mark.asyncio
async def test_jwt_token_extension_for_upload():
    """Test that expired JWT tokens get extended for upload operations"""

    # Create an expired JWT token
    user_id = "test_user_123"
    now = datetime.now(timezone.utc)
    expired_payload = {
        "sub": user_id,
        "exp": int((now - timedelta(hours=1)).timestamp()),  # Expired 1 hour ago
        "iat": int((now - timedelta(hours=2)).timestamp()),  # Issued 2 hours ago
        "token_type": "access",
    }

    expired_token = jwt.encode(
        expired_payload,
        backend_config.settings.SECRET_KEY,
        algorithm=backend_config.settings.ALGORITHM,
    )

    # Create mock request for upload operation
    mock_request = MagicMock()
    mock_request.headers = {"authorization": f"Bearer {expired_token}"}
    mock_request.url = MagicMock()
    mock_request.url.path = "/api/v1/files/init"  # Upload operation

    print(f"✓ Created expired JWT token for user: {user_id}")
    print(f"✓ Token expired at: {expired_payload['exp']}")

    # Test the token extension
    result_user_id = await get_current_user_for_upload(mock_request)

    # Verify the user ID is returned (token was extended)
    assert result_user_id == user_id, f"Expected {user_id}, got {result_user_id}"

    print(f"✓ Expired token successfully extended for upload operation")
    print(f"✓ User ID returned: {result_user_id}")


@pytest.mark.asyncio
async def test_jwt_token_no_extension_for_non_upload():
    """Test that expired tokens are NOT extended for non-upload operations"""
    
    # Create an expired JWT token
    user_id = "test_user_123"
    now = datetime.now(timezone.utc)
    expired_payload = {
        "sub": user_id,
        "exp": int((now - timedelta(hours=1)).timestamp()),  # Expired 1 hour ago
        "iat": int((now - timedelta(hours=2)).timestamp()),  # Issued 2 hours ago
        "token_type": "access",
    }

    expired_token = jwt.encode(
        expired_payload,
        backend_config.settings.SECRET_KEY,
        algorithm=backend_config.settings.ALGORITHM,
    )

    # Create mock request for NON-upload operation
    mock_request = MagicMock()
    mock_request.headers = {"authorization": f"Bearer {expired_token}"}
    mock_request.url = MagicMock()
    mock_request.url.path = "/api/v1/messages"  # NOT an upload operation

    print(f"✓ Created expired JWT token for user: {user_id}")
    print(f"✓ Token expired at: {expired_payload['exp']}")

    # Test that expired token is NOT extended for non-upload operations
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user_for_upload(mock_request)

    # Verify it's a normal token expiration error
    assert "Token has expired" in str(exc_info.value.detail) or "Invalid token" in str(exc_info.value.detail)

    print(f"✓ Expired token correctly rejected for non-upload operation")
    print(f"✓ Error: {exc_info.value.detail}")


@pytest.mark.asyncio
async def test_valid_jwt_token_no_extension_needed():
    """Test that valid JWT tokens work normally without extension"""
    
    # Create a valid JWT token
    user_id = "test_user_123"
    now = datetime.now(timezone.utc)
    valid_payload = {
        "sub": user_id,
        "exp": int((now + timedelta(minutes=30)).timestamp()),  # Valid for 30 minutes
        "iat": int((now - timedelta(minutes=10)).timestamp()),  # Issued 10 minutes ago
        "token_type": "access",
    }

    valid_token = jwt.encode(
        valid_payload,
        backend_config.settings.SECRET_KEY,
        algorithm=backend_config.settings.ALGORITHM,
    )

    # Create mock request for upload operation
    mock_request = MagicMock()
    mock_request.headers = {"authorization": f"Bearer {valid_token}"}
    mock_request.url = MagicMock()
    mock_request.url.path = "/api/v1/files/init"  # Upload operation

    print(f"✓ Created valid JWT token for user: {user_id}")
    print(f"✓ Token expires at: {valid_payload['exp']}")

    # Test the valid token
    result_user_id = await get_current_user_for_upload(mock_request)

    # Verify the user ID is returned
    assert result_user_id == user_id, f"Expected {user_id}, got {result_user_id}"

    print(f"✓ Valid token worked normally without extension")
    print(f"✓ User ID returned: {result_user_id}")


@pytest.mark.asyncio
async def test_upload_token_scope():
    """Test that upload tokens with upload_scope work correctly"""

    # Create an upload token with upload_scope
    user_id = "test_user_123"
    now = datetime.now(timezone.utc)
    upload_payload = {
        "sub": user_id,
        "exp": int((now + timedelta(hours=24)).timestamp()),  # 24 hour expiration
        "iat": int(now.timestamp()),
        "token_type": "access",
        "upload_scope": True,
        "upload_id": "upload_test_123",
    }

    upload_token = jwt.encode(
        upload_payload,
        backend_config.settings.SECRET_KEY,
        algorithm=backend_config.settings.ALGORITHM,
    )

    # Create mock request
    mock_request = MagicMock()
    mock_request.headers = {"authorization": f"Bearer {upload_token}"}
    mock_request.url = MagicMock()
    mock_request.url.path = "/api/v1/files/chunk"  # Upload operation

    print(f"✓ Created upload token with upload_scope for user: {user_id}")

    # Mock the validate_upload_token function
    with patch('backend.auth.utils.validate_upload_token', return_value=user_id):
        result_user_id = await get_current_user_for_upload(mock_request)

        # Verify the user ID is returned (the function should work)
        assert result_user_id == user_id, f"Expected {user_id}, got {result_user_id}"

        # Note: Due to the new 480-hour logic, validate_upload_token might not be called
        print(f"✓ Upload token with upload_scope worked correctly")
        print(f"✓ User ID returned: {result_user_id}")


@pytest.mark.asyncio
async def test_600mb_upload_scenario():
    """Test the specific 600MB upload scenario"""

    # Simulate a 600MB upload that takes longer than 15 minutes
    user_id = "test_user_600mb"
    now = datetime.now(timezone.utc)

    # Create a token that will expire during the upload
    initial_payload = {
        "sub": user_id,
        "exp": int((now + timedelta(minutes=10)).timestamp()),  # Expires in 10 minutes
        "iat": int(now.timestamp()),
        "token_type": "access",
    }

    initial_token = jwt.encode(
        initial_payload,
        backend_config.settings.SECRET_KEY,
        algorithm=backend_config.settings.ALGORITHM,
    )

    print(f"✓ 600MB Upload Scenario:")
    print(f"  - User: {user_id}")
    print(f"  - Initial token expires in: 10 minutes")
    print(f"  - Upload duration estimate: 20-30 minutes for 600MB")
    print(f"  - Token will expire during upload")

    # Test initial upload (token still valid)
    mock_request_init = MagicMock()
    mock_request_init.headers = {"authorization": f"Bearer {initial_token}"}
    mock_request_init.url = MagicMock()
    mock_request_init.url.path = "/api/v1/files/init"

    result_user_id = await get_current_user_for_upload(mock_request_init)
    assert result_user_id == user_id

    print(f"✓ Initial upload request successful")


    # Simulate token expiration during chunk upload
    expired_payload = {
        "sub": user_id,
        "exp": int((now - timedelta(minutes=5)).timestamp()),  # Expired 5 minutes ago
        "iat": int((now - timedelta(minutes=25)).timestamp()),  # Issued 25 minutes ago
        "token_type": "access",
    }

    expired_token = jwt.encode(
        expired_payload,
        backend_config.settings.SECRET_KEY,
        algorithm=backend_config.settings.ALGORITHM,
    )
        

    mock_request_chunk = MagicMock()
    mock_request_chunk.headers = {"authorization": f"Bearer {expired_token}"}
    mock_request_chunk.url = MagicMock()
    mock_request_chunk.url.path = "/api/v1/files/upload_123/chunk"
        

    # Test chunk upload with expired token (should be extended)
    result_user_id = await get_current_user_for_upload(mock_request_chunk)
    assert result_user_id == user_id
    print(f"✓ Chunk upload successful with expired token (extended)")

    print(f"✓ 600MB upload scenario tested")


if __name__ == "__main__":
    import asyncio
    
    print("\n" + "="*60)
    print("JWT Token Extension Fix Validation")
    print("="*60)
    
    loop = asyncio.get_event_loop()
    
    test_functions = [
        test_jwt_token_extension_for_upload,
        test_jwt_token_no_extension_for_non_upload,
        test_valid_jwt_token_no_extension_needed,
        test_upload_token_scope,
        test_600mb_upload_scenario,
    ]
    
    for test_func in test_functions:
        try:
            loop.run_until_complete(test_func())
        except AssertionError as e:
            print(f"✗ {test_func.__name__} FAILED: {e}")
        except Exception as e:
            print(f"✗ {test_func.__name__} ERROR: {e}")
    
    print("\n" + "="*60)
    print("JWT Token Extension Tests Completed")
    print("="*60)

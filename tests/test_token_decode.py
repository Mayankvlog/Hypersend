#!/usr/bin/env python3
import pytest
from backend.auth.utils import create_access_token
from backend.config import settings
import jwt

def test_create_and_decode_access_token():
    """Test that access tokens can be created and decoded successfully"""
    payload = {
        'sub': 'test_user_123',
        'email': 'test@example.com',
        'token_type': 'access'
    }
    token = create_access_token(payload)
    
    # Verify token is a string
    assert isinstance(token, str), "Token should be a string"
    
    # Decode and verify contents
    decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    assert decoded.get("sub") == payload['sub'], "Subject should match payload"
    assert decoded.get("email") == payload['email'], "Email should match payload"
    assert decoded.get("token_type") == payload['token_type'], "Token type should match payload"
    
    print('✓ Token created and decoded successfully')
    print(f'✓ User: {decoded.get("sub")}')
    print(f'✓ Email: {decoded.get("email")}')
    print(f'✓ Token Type: {decoded.get("token_type")}')

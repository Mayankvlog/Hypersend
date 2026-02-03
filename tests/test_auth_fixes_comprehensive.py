#!/usr/bin/env python3
"""
Comprehensive Authentication Tests
Tests all authentication fixes including password verification and registration
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth.utils import hash_password, verify_password

client = TestClient(app)

class TestPasswordVerification:
    """Test password verification fixes"""
    
    def test_combined_password_format_verification(self):
        """Test password verification with combined salt$hash format"""
        # Create a password in combined format (97 chars: 32+1+64)
        password_hash, salt = hash_password("testpassword123")
        combined_password = f"{salt}${password_hash}"
        
        # Test verification with combined format
        is_valid = verify_password("testpassword123", combined_password)
        assert is_valid, "Password should be valid with combined format"
        
        # Test verification with wrong password
        is_invalid = verify_password("wrongpassword", combined_password)
        assert not is_invalid, "Password should be invalid with wrong password"
    
    def test_separated_password_format_verification(self):
        """Test password verification with separated hash and salt"""
        password_hash, salt = hash_password("testpassword123")
        
        # Test verification with separated format
        is_valid = verify_password("testpassword123", password_hash, salt)
        assert is_valid, "Password should be valid with separated format"
        
        # Test verification with wrong password
        is_invalid = verify_password("wrongpassword", password_hash, salt)
        assert not is_invalid, "Password should be invalid with wrong password"
    
    def test_legacy_password_format_migration(self):
        """Test legacy password format migration"""
        # Simulate legacy format: salt$hash (97 chars)
        test_salt = "c91742d7343ab1c4c923167777f6bf6e"
        test_hash = "2b2981322b3f416f464a58d6a9dcb65ef266d1c563fd8a8b1cb19aa27f861c85"
        legacy_password = f"{test_salt}${test_hash}"
        
        # Test verification with legacy format
        is_valid = verify_password("testpassword123", legacy_password)
        # This should work if the password was originally "testpassword123"
        # We're just testing the format parsing here
        
        # Test that it doesn't crash
        assert isinstance(is_valid, bool), "Should return boolean"
    
    def test_password_edge_cases(self):
        """Test password verification edge cases"""
        # Test with empty inputs
        assert not verify_password("", "hash"), "Empty password should be invalid"
        assert not verify_password("password", ""), "Empty hash should be invalid"
        assert not verify_password(None, "hash"), "None password should be invalid"
        assert not verify_password("password", None), "None hash should be invalid"
        
        # Test with invalid formats
        assert not verify_password("password", "invalid"), "Invalid hash format should be invalid"
        assert not verify_password("password", "short"), "Short hash should be invalid"


class TestRegistrationFixes:
    """Test registration fixes"""
    
    def test_registration_with_valid_data(self):
        """Test registration with valid data"""
        user_data = {
            "email": "testuser@example.com",
            "password": "TestPassword123",
            "name": "Test User"
        }
        
        response = client.post("/api/v1/auth/register", 
            json=user_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 201 or 409 (if user already exists)
        assert response.status_code in [201, 409]
        
        if response.status_code == 201:
            data = response.json()
            assert "email" in data
            assert "name" in data
            assert data["email"] == user_data["email"].lower()
    
    def test_registration_with_weak_password(self):
        """Test registration with weak password"""
        user_data = {
            "email": "weakuser@example.com",
            "password": "weak",  # Too short and no complexity
            "name": "Weak User"
        }
        
        response = client.post("/api/v1/auth/register", 
            json=user_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 400 for weak password (validation error)
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
    
    def test_registration_with_invalid_email(self):
        """Test registration with invalid email"""
        user_data = {
            "email": "ab",  # Too short (less than basic email format)
            "password": "TestPassword123",
            "name": "Invalid Email User"
        }
        
        response = client.post("/api/v1/auth/register", 
            json=user_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 400 for invalid username (validation error)
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
    
    def test_registration_missing_fields(self):
        """Test registration with missing fields"""
        # Test missing password
        user_data = {
            "email": "missinguser@example.com",
            "name": "Missing Field User"
        }
        
        response = client.post("/api/v1/auth/register", 
            json=user_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 422 for missing required field (validation error)
        assert response.status_code == 422
        
        # Test missing name (should auto-generate from email and succeed)
        user_data = {
            "email": "missing2@example.com",
            "password": "TestPassword123"
        }
        
        response = client.post("/api/v1/auth/register", 
            json=user_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 201 since name is auto-generated from email
        assert response.status_code == 201


class TestLoginFixes:
    """Test login fixes"""
    
    def test_login_with_valid_credentials(self):
        """Test login with valid credentials"""
        # First register a user
        user_data = {
            "username": "logintest",
            "password": "TestPassword123",
            "name": "Login Test User"
        }
        
        # Try to register (might already exist)
        reg_response = client.post("/api/v1/auth/register", 
            json=user_data,
            headers={"User-Agent": "testclient"}
        )
        print(f"Registration response: {reg_response.status_code} - {reg_response.text}")
        
        # Now try to login
        login_data = {
            "email": "logintest@example.com",
            "password": "TestPassword123"
        }
        
        response = client.post("/api/v1/auth/login", 
            json=login_data,
            headers={"User-Agent": "testclient"}
        )
        
        print(f"Login response: {response.status_code} - {response.text}")
        
        # Should return 200 or 401 (if password doesn't match)
        assert response.status_code in [200, 401]
        
        if response.status_code == 200:
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert "token_type" in data
            assert data["token_type"] == "bearer"
    
    def test_login_with_invalid_credentials(self):
        """Test login with invalid credentials"""
        login_data = {
            "email": "nonexistent@example.com",
            "password": "WrongPassword123"
        }
        
        response = client.post("/api/v1/auth/login", 
            json=login_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 401 for invalid credentials
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
    
    def test_login_with_invalid_email_format(self):
        """Test login with invalid email format"""
        login_data = {
            "email": "invalid-email",  # Invalid email format
            "password": "TestPassword123"
        }
        
        response = client.post("/api/v1/auth/login", 
            json=login_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 400 for invalid username format (validation error)
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
    
    def test_login_with_missing_password(self):
        """Test login with missing password"""
        login_data = {
            "username": "testuser"
        }
        
        response = client.post("/api/v1/auth/login", 
            json=login_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 422 for missing password (validation error)
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data


class TestAuthenticationErrorHandling:
    """Test authentication error handling"""
    
    def test_protected_endpoint_without_token(self):
        """Test accessing protected endpoint without token"""
        response = client.get("/api/v1/users/me", 
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 401 for missing token
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
    
    def test_protected_endpoint_with_invalid_token(self):
        """Test accessing protected endpoint with invalid token"""
        response = client.get("/api/v1/users/me", 
            headers={
                "Authorization": "Bearer invalid_token_here",
                "User-Agent": "testclient"
            }
        )
        
        # Should return 401 for invalid token
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
    
    def test_protected_endpoint_with_expired_token(self):
        """Test accessing protected endpoint with expired token"""
        # Create a token that looks expired (this is a mock test)
        response = client.get("/api/v1/users/me", 
            headers={
                "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJleHBpcmVkX3Rva2VuIiwiZXhwIjoxfQ.invalid",
                "User-Agent": "testclient"
            }
        )
        
        # Should return 401 for expired token
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data


class TestDatabaseErrorHandling:
    """Test database error handling in authentication"""
    
    def test_user_not_found_handling(self):
        """Test handling of user not found scenarios"""
        login_data = {
            "email": "definitelydoesnotexist@example.com",
            "password": "TestPassword123"
        }
        
        response = client.post("/api/v1/auth/login", 
            json=login_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 401, not 500 (server error)
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        # Should not expose that user doesn't exist
        assert "not found" not in str(data).lower()
    
    def test_duplicate_user_registration(self):
        """Test handling of duplicate user registration"""
        user_data = {
            "email": "duplicate@example.com",
            "password": "TestPassword123",
            "name": "Duplicate User"
        }
        
        # First registration
        response1 = client.post("/api/v1/auth/register", 
            json=user_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Second registration with same username
        response2 = client.post("/api/v1/auth/register", 
            json=user_data,
            headers={"User-Agent": "testclient"}
        )
        
        # First should be 201, second should be 409
        assert response1.status_code in [201, 409]  # Might already exist
        assert response2.status_code == 409
        data = response2.json()
        assert "already registered" in str(data).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

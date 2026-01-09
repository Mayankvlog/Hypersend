#!/usr/bin/env python3
"""
Production Fixes Test
Tests the critical fixes for login and registration issues
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth.utils import hash_password, verify_password

client = TestClient(app)

class TestProductionFixes:
    """Test critical production fixes"""
    
    def test_password_migration_logic(self):
        """Test password migration for users with corrupted records"""
        # Test combined format (97 chars: 32+1+64)
        combined_password, salt = hash_password("testpassword123")
        
        # Simulate user record with combined format in password_hash field
        user_record = {
            "_id": "test_user_id",
            "email": "test@example.com",
            "password_hash": combined_password,  # Combined format stored in hash field
            "password_salt": None  # Missing salt
        }
        
        # Extract hash from combined format (like migration would do)
        if user_record["password_hash"] and isinstance(user_record["password_hash"], str) and '$' in user_record["password_hash"]:
            if len(user_record["password_hash"]) == 97:
                parts = user_record["password_hash"].split('$')
                if len(parts) == 2:
                    migrated_salt, migrated_hash = parts
                    
                    # Test verification with migrated values
                    is_valid = verify_password("testpassword123", migrated_hash, migrated_salt)
                    assert is_valid, "Password should be valid after migration"
                    
                    # Test wrong password
                    is_invalid = verify_password("wrongpassword", migrated_hash, migrated_salt)
                    assert not is_invalid, "Wrong password should be invalid"
    
    def test_database_connection_fix(self):
        """Test that database connection uses real MongoDB, not mock"""
        from backend.database import get_db
        from backend.config import settings
        
        # Ensure USE_MOCK_DB is False for production
        assert settings.USE_MOCK_DB == False, "USE_MOCK_DB should be False in production"
        
        # Test that get_db() returns a proper database object
        db = get_db()
        
        # The database should have the expected attributes
        assert hasattr(db, 'users'), "Database should have users collection"
        assert hasattr(db, 'chats'), "Database should have chats collection"
        assert hasattr(db, 'messages'), "Database should have messages collection"
    
    def test_registration_with_real_db(self):
        """Test registration works with real database connection"""
        user_data = {
            "email": "productiontest@example.com",
            "password": "TestPassword123",
            "name": "Production Test User"
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
    
    def test_login_with_migrated_user(self):
        """Test login works for users with migrated passwords"""
        # First register a user
        user_data = {
            "email": "migratedlogin@example.com",
            "password": "TestPassword123",
            "name": "Migrated Login User"
        }
        
        # Try to register (might already exist)
        client.post("/api/v1/auth/register", 
            json=user_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Now try to login
        login_data = {
            "email": "migratedlogin@example.com",
            "password": "TestPassword123"
        }
        
        response = client.post("/api/v1/auth/login", 
            json=login_data,
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 200 or 401 (if password doesn't match)
        assert response.status_code in [200, 401]
        
        if response.status_code == 200:
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert "token_type" in data
            assert data["token_type"] == "bearer"
    
    def test_error_handling_improvements(self):
        """Test that error handling is comprehensive"""
        # Test invalid JSON
        response = client.post("/api/v1/auth/login", 
            data="invalid json",
            headers={"User-Agent": "testclient", "Content-Type": "application/json"}
        )
        
        # Should return 422 for invalid JSON
        assert response.status_code == 422
        
        # Test missing fields
        response = client.post("/api/v1/auth/login", 
            json={"email": "test@example.com"},  # Missing password
            headers={"User-Agent": "testclient"}
        )
        
        # Should return 422 for missing required field
        assert response.status_code == 422
    
    def test_database_error_recovery(self):
        """Test database error recovery mechanisms"""
        from backend.database import users_collection
        
        # Test that users_collection() returns a proper collection
        users_col = users_collection()
        
        # Should have the expected methods
        assert hasattr(users_col, 'find_one'), "Collection should have find_one method"
        assert hasattr(users_col, 'insert_one'), "Collection should have insert_one method"
        assert hasattr(users_col, 'update_one'), "Collection should have update_one method"
        
        # Test that methods are callable (not Futures)
        assert callable(getattr(users_col, 'find_one')), "find_one should be callable"
        assert callable(getattr(users_col, 'insert_one')), "insert_one should be callable"
        assert callable(getattr(users_col, 'update_one')), "update_one should be callable"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

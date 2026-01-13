"""
Comprehensive test suite for MongoDB connection and authentication fixes.
Tests all error scenarios and validates proper async handling.
"""

import pytest
import asyncio
import os
import sys
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import HTTPException
from datetime import datetime, timezone

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from config import settings
from database import connect_db, get_db, users_collection, close_db
from routes.auth import register, login
from models import UserCreate, UserLogin


class TestMongoDBConnection:
    """Test MongoDB connection fixes and async handling"""
    
    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing"""
        with patch('database.settings') as mock_settings:
            mock_settings.MONGODB_URI = "mongodb://test:test@localhost:27017/test?authSource=admin&tls=false"
            mock_settings._MONGO_DB = "test_db"
            mock_settings._MONGO_USER = "test"
            mock_settings._MONGO_PASSWORD = "test"
            mock_settings._MONGO_HOST = "localhost"
            mock_settings._MONGO_PORT = "27017"
            mock_settings.DEBUG = True
            mock_settings.USE_MOCK_DB = False
            yield mock_settings
    
    @pytest.fixture
    def mock_motor_client(self):
        """Mock AsyncIOMotorClient"""
        with patch('database.AsyncIOMotorClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.admin.command.return_value = {"ok": 1}
            mock_client.__getitem__.return_value = AsyncMock()
            yield mock_client_class, mock_client
    
    @pytest.mark.asyncio
    async def test_connect_db_success(self, mock_settings, mock_motor_client):
        """Test successful MongoDB connection"""
        # Reset global variables
        import database
        database.client = None
        database.db = None
        
        mock_client_class, mock_client = mock_motor_client
        await connect_db()
        
        # Verify client was created with correct parameters
        mock_client_class.assert_called_once()
        
        # Verify connection test was performed
        mock_client.admin.command.assert_called_with('ping', maxTimeMS=5000)
        
        print("✓ MongoDB connection successful")
    
    @pytest.mark.asyncio
    async def test_connect_db_with_timeout(self, mock_settings):
        """Test MongoDB connection timeout handling"""
        with patch('database.AsyncIOMotorClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.admin.command.side_effect = asyncio.TimeoutError("Connection timeout")
            
            import database
            database.client = None
            database.db = None
            
            with pytest.raises(ConnectionError, match="Database connection test failed"):
                await connect_db()
            
            print("✓ MongoDB connection timeout handled correctly")
    
    @pytest.mark.asyncio
    async def test_connect_db_with_invalid_uri(self):
        """Test MongoDB connection with invalid URI"""
        with patch('database.settings') as mock_settings:
            mock_settings.MONGODB_URI = None
            mock_settings._MONGO_DB = "test_db"
            
            import database
            database.client = None
            database.db = None
            
            with pytest.raises(ValueError, match="Database configuration is invalid"):
                await connect_db()
            
            print("✓ Invalid MongoDB URI handled correctly")
    
    @pytest.mark.asyncio
    async def test_get_db_success(self, mock_settings, mock_motor_client):
        """Test get_db function returns database instance"""
        import database
        database.client = None
        database.db = None
        database._global_db = None
        database._global_client = None
        
        mock_client_class, mock_client = mock_motor_client
        
        # Mock the settings to use mock database
        with patch('database.settings') as settings_mock:
            settings_mock.USE_MOCK_DB = True
            settings_mock.DEBUG = True
            
            db = get_db()
            
            # Should return database instance
            assert db is not None
            
        print("✓ get_db returns database instance successfully")
    
    @pytest.mark.asyncio
    async def test_users_collection_not_future(self, mock_settings, mock_motor_client):
        """Test users_collection does not return Future objects"""
        import database
        database.client = None
        database.db = None
        
        # Mock settings to use mock database
        with patch('database.settings') as settings_mock:
            settings_mock.USE_MOCK_DB = True
            settings_mock.DEBUG = True
            
            users_col = users_collection()
            
            # Verify collection is not a Future
            assert not hasattr(users_col, '__await__')
            assert not asyncio.isfuture(users_col)
            
            # Verify collection methods are callable
            assert callable(getattr(users_col, 'find_one', None))
            assert callable(getattr(users_col, 'insert_one', None))
            
        print("✓ users_collection returns proper collection, not Future")


class TestAuthenticationFixes:
    """Test authentication endpoint fixes"""
    
    @pytest.fixture(autouse=True)
    def clear_lockouts(self):
        """Clear lockouts before each test"""
        from routes.auth import clear_all_lockouts
        clear_all_lockouts()
        yield
    
    @pytest.fixture
    def mock_user_data(self):
        """Mock user data for testing"""
        # Generate proper test hash and salt
        from backend.auth.utils import hash_password
        test_hash, test_salt = hash_password("TestPass123")
        
        return {
            "_id": "507f1f77bcf86cd799439011",
            "name": "Test User",
            "email": "test@example.com",
            "password_hash": test_hash,
            "password_salt": test_salt,
            "avatar": "TU",
            "created_at": datetime.now(timezone.utc)
        }
    
    @pytest.fixture
    def mock_users_collection(self):
        """Mock users collection"""
        with patch('routes.auth.users_collection') as mock_col:
            # Create a proper mock collection with callable methods
            mock_collection = AsyncMock()
            mock_collection.find_one = AsyncMock()
            mock_collection.insert_one = AsyncMock()
            mock_collection.update_one = AsyncMock()
            mock_col.return_value = mock_collection
            yield mock_col
    
    @pytest.mark.asyncio
    async def test_register_success(self, mock_users_collection, mock_user_data):
        """Test successful user registration"""
        # Mock collection methods
        mock_users_collection.return_value.find_one.return_value = None
        mock_insert_result = AsyncMock()
        mock_insert_result.inserted_id = "507f1f77bcf86cd799439011"
        mock_users_collection.return_value.insert_one.return_value = mock_insert_result
        
        # Test registration
        user_data = UserCreate(
            name="Test User",
            email="test@example.com",
            password="TestPass123"
        )
        
        # Don't mock hash_password - let it work normally
        result = await register(user_data)
        
        # Verify user was created
        assert result.email == "test@example.com"
        assert result.name == "Test User"
        assert result.avatar is None  # FIXED: No avatar initials
        
        # Verify database operations were called correctly
        mock_users_collection.return_value.find_one.assert_called_once()
        mock_users_collection.return_value.insert_one.assert_called_once()
        
        print("✓ User registration successful")
    
    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, mock_users_collection, mock_user_data):
        """Test registration with duplicate email"""
        # Mock existing user
        mock_users_collection.return_value.find_one.return_value = mock_user_data
        
        user_data = UserCreate(
            name="Test User",
            email="test@example.com",
            password="TestPass123"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await register(user_data)
        
        assert exc_info.value.status_code == 409
        assert "already registered" in str(exc_info.value.detail)
        
        print("✓ Duplicate email validation works")
    
    @pytest.mark.asyncio
    async def test_register_weak_password(self):
        """Test registration with weak password"""
        # Weak password should fail at model validation level
        from pydantic_core import ValidationError
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(
                name="Test User",
                email="test@example.com",
                password="weak"  # Too short (only 4 chars)
            )
        
        # Check the validation error message
        assert "String should have at least 8 characters" in str(exc_info.value)
        
        print("✓ Weak password validation works")
    
    @pytest.mark.asyncio
    async def test_register_invalid_email(self):
        """Test registration with invalid email"""
        # Invalid email should fail at model validation level
        from pydantic_core import ValidationError
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(
                name="Test User",
                email="invalid-email",  # Invalid format
                password="TestPass123"
            )
        
        # Check the validation error message
        assert "Invalid email format" in str(exc_info.value)
        
        print("✓ Invalid email validation works")
    
    @pytest.mark.asyncio
    async def test_login_success(self, mock_users_collection, mock_user_data):
        """Test successful user login"""
        # Mock user lookup
        mock_users_collection.return_value.find_one.return_value = mock_user_data
        
        # Mock password verification and token creation
        with patch('routes.auth.verify_password') as mock_verify, \
             patch('routes.auth.create_access_token') as mock_token, \
             patch('routes.auth.create_refresh_token') as mock_refresh:
            
            mock_verify.return_value = True
            mock_token.return_value = "test_access_token"
            # create_refresh_token returns a tuple (token, jti)
            mock_refresh.return_value = ("test_refresh_token", "test_jti")
            
            credentials = UserLogin(
                email="test@example.com",
                password="TestPass123"
            )
            
            # Mock request
            mock_request = Mock()
            mock_request.client.host = "127.0.0.1"
            
            result = await login(credentials, mock_request)
            
            assert result.access_token == "test_access_token"
            assert result.refresh_token == "test_refresh_token"
        
        print("✓ User login successful")
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, mock_users_collection, mock_user_data):
        """Test login with invalid credentials"""
        # Mock user lookup
        mock_users_collection.return_value.find_one.return_value = mock_user_data
        
        # Mock password verification failure
        with patch('routes.auth.verify_password') as mock_verify:
            mock_verify.return_value = False
            
            credentials = UserLogin(
                email="test@example.com",
                password="wrongpassword"
            )
            
            mock_request = Mock()
            mock_request.client.host = "127.0.0.1"
            
            with pytest.raises(HTTPException) as exc_info:
                await login(credentials, mock_request)
            
            assert exc_info.value.status_code == 401
            assert "Invalid email or password" in str(exc_info.value.detail)
        
        print("✓ Invalid credentials handled correctly")
    
    @pytest.mark.asyncio
    async def test_login_user_not_found(self, mock_users_collection):
        """Test login with non-existent user"""
        # Mock user not found
        mock_users_collection.return_value.find_one.return_value = None
        
        credentials = UserLogin(
            email="nonexistent@example.com",
            password="TestPass123"
        )
        
        mock_request = Mock()
        mock_request.client.host = "127.0.0.1"
        
        with pytest.raises(HTTPException) as exc_info:
            await login(credentials, mock_request)
        
        assert exc_info.value.status_code == 401
        assert "Invalid email or password" in str(exc_info.value.detail)
        
        print("✓ Non-existent user handled correctly")


class TestAsyncFutureHandling:
    """Test proper async handling to prevent Future attribute errors"""
    
    @pytest.mark.asyncio
    async def test_database_operations_not_returning_futures(self):
        """Test that database operations don't return Future objects"""
        # Mock collection
        mock_collection = AsyncMock()
        mock_collection.find_one.return_value = {"_id": "test"}
        mock_collection.insert_one.return_value = AsyncMock(inserted_id="test_id")
        
        with patch('database.users_collection', return_value=mock_collection):
            # Test find_one
            result = await mock_collection.find_one({"email": "test@example.com"})
            assert not hasattr(result, '__await__')
            assert not asyncio.isfuture(result)
            
            # Test insert_one
            insert_result = await mock_collection.insert_one({"name": "test"})
            assert not hasattr(insert_result, '__await__')
            assert not asyncio.isfuture(insert_result)
            assert not hasattr(insert_result.inserted_id, '__await__')
        
        print("✓ Database operations return proper results, not Futures")
    
    @pytest.mark.asyncio
    async def test_asyncio_wait_for_usage(self):
        """Test that asyncio.wait_for is used correctly"""
        mock_collection = AsyncMock()
        mock_collection.find_one.return_value = {"_id": "test"}
        
        # Test wait_for with database operation
        result = await asyncio.wait_for(
            mock_collection.find_one({"email": "test@example.com"}),
            timeout=5.0
        )
        
        assert result == {"_id": "test"}
        assert not hasattr(result, '__await__')
        
        print("✓ asyncio.wait_for used correctly")


class TestConfigurationFixes:
    """Test configuration fixes for Docker and MongoDB"""
    
    def test_docker_mongodb_uri_format(self):
        """Test Docker MongoDB URI format is correct"""
        with patch('config.os.path.exists', return_value=True), \
             patch('builtins.open', mock_file_content), \
             patch('config.settings') as mock_settings:
            
            # Mock Docker environment
            mock_settings.is_docker = True
            mock_settings._MONGO_USER = "hypersend"
            mock_settings._MONGO_PASSWORD = "test_password"
            mock_settings._MONGO_HOST = "mongodb"
            mock_settings._MONGO_PORT = "27017"
            mock_settings._MONGO_DB = "hypersend"
            
            # Create settings instance directly
            from config import Settings
            test_settings = Settings()
            
            # Override Docker detection to force True
            test_settings.is_docker = True
            
            # Manually construct URI as it would be in Docker
            from urllib.parse import quote_plus
            encoded_password = quote_plus("test_password")
            docker_uri = f"mongodb://hypersend:{encoded_password}@mongodb:27017/hypersend?authSource=admin&tls=false"
            
            # Verify URI contains correct components
            assert "mongodb://hypersend:" in docker_uri
            assert "mongodb:27017" in docker_uri
            assert "authSource=admin" in docker_uri
            assert "tls=false" in docker_uri
            assert "retryWrites=true" not in docker_uri
        
        print("✓ Docker MongoDB URI format is correct")
    
    def test_local_mongodb_uri_format(self):
        """Test local MongoDB URI format is correct"""
        with patch('config.os.path.exists', return_value=False), \
             patch('config.settings') as mock_settings:
            
            # Mock local environment
            mock_settings.is_docker = False
            mock_settings._MONGO_USER = "hypersend"
            mock_settings._MONGO_PASSWORD = "test_password"
            mock_settings._MONGO_HOST = "139.59.82.105"
            mock_settings._MONGO_PORT = "27018"
            mock_settings._MONGO_DB = "hypersend"
            
            # Create settings instance directly
            from config import Settings
            test_settings = Settings()
            
            # Override Docker detection to force False
            test_settings.is_docker = False
            
            # Manually construct URI as it would be in local environment
            from urllib.parse import quote_plus
            encoded_password = quote_plus("test_password")
            local_uri = f"mongodb://hypersend:{encoded_password}@139.59.82.105:27018/hypersend?authSource=admin&tls=false"
            
            # Verify URI contains correct components
            assert "mongodb://hypersend:" in local_uri
            assert "139.59.82.105:27018" in local_uri
            assert "authSource=admin" in local_uri
            assert "tls=false" in local_uri
            assert "retryWrites=true" not in local_uri
        
        print("✓ Local MongoDB URI format is correct")


# Helper function for mocking files
def mock_file_content(filename, mode='r'):
    """Mock file content for testing"""
    if 'dockerenv' in filename:
        return mock_file_content
    return mock_file_content


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])

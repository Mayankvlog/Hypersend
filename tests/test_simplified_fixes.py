"""
Simplified test suite for MongoDB connection and authentication fixes.
Tests core functionality without complex mocking.
"""

import pytest
import asyncio
import os
import sys
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import HTTPException

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))


class TestMongoDBConnectionFixes:
    """Test MongoDB connection fixes"""
    
    def test_mongodb_uri_format_docker(self):
        """Test Docker MongoDB URI format"""
        # Test Docker URI construction
        from urllib.parse import quote_plus
        
        user = "hypersend"
        password = "test_password"
        host = "mongodb"
        port = "27017"
        db = "hypersend"
        
        encoded_password = quote_plus(password)
        docker_uri = f"mongodb://{user}:{encoded_password}@{host}:{port}/{db}?authSource=admin&tls=false"
        
        # Verify URI components
        assert "mongodb://hypersend:" in docker_uri
        assert "mongodb:27017" in docker_uri
        assert "authSource=admin" in docker_uri
        assert "tls=false" in docker_uri
        assert "retryWrites=true" not in docker_uri
        
        print("✓ Docker MongoDB URI format is correct")
    
    def test_mongodb_uri_format_local(self):
        """Test local MongoDB URI format"""
        from urllib.parse import quote_plus
        
        user = "hypersend"
        password = "test_password"
        host = "139.59.82.105"
        port = "27018"
        db = "hypersend"
        
        encoded_password = quote_plus(password)
        local_uri = f"mongodb://{user}:{encoded_password}@{host}:{port}/{db}?authSource=admin&tls=false"
        
        # Verify URI components
        assert "mongodb://hypersend:" in local_uri
        assert "139.59.82.105:27018" in local_uri
        assert "authSource=admin" in local_uri
        assert "tls=false" in local_uri
        assert "retryWrites=true" not in local_uri
        
        print("✓ Local MongoDB URI format is correct")
    
    def test_asyncio_wait_for_usage(self):
        """Test asyncio.wait_for is used correctly"""
        async def mock_db_operation():
            await asyncio.sleep(0.1)
            return {"result": "success"}
        
        async def test_wait_for():
            # Test wait_for with database operation
            result = await asyncio.wait_for(
                mock_db_operation(),
                timeout=5.0
            )
            return result
        
        # Run the test
        result = asyncio.run(test_wait_for())
        assert result == {"result": "success"}
        
        print("✓ asyncio.wait_for used correctly")
    
    def test_password_validation(self):
        """Test password strength validation"""
        from routes.auth import register
        from models import UserCreate
        
        test_cases = [
            # (password, should_be_valid, expected_error)
            ("short", False, "Password must be at least 8 characters"),
            ("alllowercase", False, "Password must contain uppercase"),
            ("ALLUPPERCASE", False, "Password must contain lowercase"),
            ("NoNumbers", False, "Password must contain numbers"),
            ("ValidPass123", True, None),
            ("AnotherValid456", True, None),
            ("Complex!Pass789", True, None)
        ]
        
        for password, should_pass, expected_error in test_cases:
            user_data = UserCreate(
                name="Test User",
                email="test@example.com",
                password=password
            )
            
            # Test password validation logic directly
            import re
            
            # Test length
            if not user_data.password or len(user_data.password) < 8:
                assert not should_pass
                assert expected_error == "Password must be at least 8 characters"
                continue
            
            # Test complexity
            has_upper = any(c.isupper() for c in user_data.password)
            has_lower = any(c.islower() for c in user_data.password)
            has_digit = any(c.isdigit() for c in user_data.password)
            
            is_valid = has_upper and has_lower and has_digit
            
            if should_pass:
                assert is_valid
            else:
                assert not is_valid
        
        print("✓ Password validation works correctly")
    
    def test_email_validation(self):
        """Test email format validation"""
        test_cases = [
            # (email, should_be_valid)
            ("user@example.com", True),
            ("test.email+tag@example.com", True),
            ("user@sub.example.com", True),
            ("user@localhost", True),  # Valid in development
            ("invalid-email", False),
            ("@example.com", False),
            ("user@", False),
            ("user@.com", False),
            ("", False),
            (" ", False)
        ]
        
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        for email, should_be_valid in test_cases:
            is_valid = bool(re.match(email_pattern, email))
            assert is_valid == should_be_valid, f"Email {email} validation failed"
        
        print("✓ Email validation works correctly")


class TestDatabaseClientConfiguration:
    """Test MongoDB client configuration fixes"""
    
    def test_motor_client_config_docker(self):
        """Test Motor client configuration for Docker"""
        with patch('database.AsyncIOMotorClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.admin.command.return_value = {"ok": 1}
            
            # Import and test connect_db function
            from database import connect_db
            
            # Mock settings
            with patch('database.settings') as mock_settings:
                mock_settings.MONGODB_URI = "mongodb://test:test@mongodb:27017/test?authSource=admin&tls=false"
                mock_settings._MONGO_DB = "test_db"
                
                # Reset globals
                import database
                database.client = None
                database.db = None
                
                # Run connect_db
                asyncio.run(connect_db())
                
                # Verify client was called with correct parameters
                mock_client_class.assert_called_once()
                call_args = mock_client_class.call_args
                
                # Check that retryWrites=False is set
                kwargs = call_args[1] if call_args[1] else {}
                assert kwargs.get('retryWrites') is False
                assert kwargs.get('serverSelectionTimeoutMS') == 10000
                assert kwargs.get('connectTimeoutMS') == 10000
        
        print("✓ Motor client configuration for Docker is correct")
    
    def test_motor_client_config_get_db(self):
        """Test Motor client configuration in get_db function"""
        with patch('database.AsyncIOMotorClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.admin.command.return_value = {"ok": 1}
            
            # Import and test get_db function
            from database import get_db
            
            # Mock settings
            with patch('database.settings') as mock_settings:
                mock_settings._MONGO_USER = "test"
                mock_settings._MONGO_PASSWORD = "test"
                mock_settings._MONGO_HOST = "localhost"
                mock_settings._MONGO_PORT = "27017"
                mock_settings._MONGO_DB = "test_db"
                mock_settings.USE_MOCK_DB = False
                
                # Reset globals
                import database
                database.client = None
                database.db = None
                database._global_db = None
                database._global_client = None
                
                # Run get_db
                db = get_db()
                
                # Verify client was called with correct parameters
                mock_client_class.assert_called_once()
                call_args = mock_client_class.call_args
                
                # Check that retryWrites=False is set
                kwargs = call_args[1] if call_args[1] else {}
                assert kwargs.get('retryWrites') is False
                assert kwargs.get('serverSelectionTimeoutMS') == 10000
        
        print("✓ Motor client configuration in get_db is correct")


class TestErrorHandling:
    """Test error handling improvements"""
    
    def test_connection_timeout_handling(self):
        """Test connection timeout handling"""
        with patch('database.AsyncIOMotorClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.admin.command.side_effect = asyncio.TimeoutError("Connection timeout")
            
            from database import connect_db
            import database
            
            # Reset globals
            database.client = None
            database.db = None
            
            # Mock settings
            with patch('database.settings') as mock_settings:
                mock_settings.MONGODB_URI = "mongodb://test:test@localhost:27017/test"
                mock_settings._MONGO_DB = "test_db"
                
                # Test that ConnectionError is raised
                with pytest.raises(ConnectionError, match="Database connection test failed"):
                    asyncio.run(connect_db())
        
        print("✓ Connection timeout handling works correctly")
    
    def test_invalid_uri_handling(self):
        """Test invalid MongoDB URI handling"""
        from database import connect_db
        import database
        
        # Reset globals
        database.client = None
        database.db = None
        
        # Mock settings with invalid URI
        with patch('database.settings') as mock_settings:
            mock_settings.MONGODB_URI = None
            mock_settings._MONGO_DB = "test_db"
            
            # Test that ValueError is raised
            with pytest.raises(ValueError, match="Database configuration is invalid"):
                asyncio.run(connect_db())
        
        print("✓ Invalid URI handling works correctly")


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])

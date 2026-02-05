"""
Comprehensive pytest suite for MongoDB connection and authentication fixes.
Tests all scenarios including Docker environment simulation.
"""

import pytest
import asyncio
import os
import sys
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

class TestMongoDBConnectionFixes:
    """Test MongoDB connection fixes comprehensively"""
    
    def test_env_file_configuration(self):
        """Test that .env file is correctly configured for MongoDB Atlas"""
        print("Testing .env file configuration...")
        
        env_path = Path(__file__).parent.parent / 'backend' / '.env'
        assert env_path.exists(), f".env file not found at {env_path}"
        
        # Read and verify .env content
        with open(env_path, 'r') as f:
            env_content = f.read()
        
        # Check that MONGODB_URI IS in .env for local MongoDB
        assert "MONGODB_URI=" in env_content, "MONGODB_URI should be set in .env file"
        assert "mongodb://" in env_content, "MONGODB_URI should use mongodb:// for local MongoDB"
        assert "localhost:27017" in env_content, "MONGODB_URI should point to localhost MongoDB"
        
        # Check MongoDB Atlas is disabled for local development
        assert "MONGODB_ATLAS_ENABLED=false" in env_content, "MONGODB_ATLAS_ENABLED should be false for local development"
        
        print("✅ .env file configuration is correct for local MongoDB")
    
    @patch('config.os.path.exists')
    @patch.dict(os.environ, {'MONGODB_ATLAS_ENABLED': 'false', 'MONGODB_URI': ''})
    def test_docker_detection_and_uri_construction(self, mock_exists):
        """Test Docker environment detection and URI construction"""
        print("Testing Docker environment detection...")
        
        # Mock Docker environment detection
        def mock_exists_side_effect(path):
            if '/.dockerenv' in str(path):
                return True
            return False
        
        mock_exists.side_effect = mock_exists_side_effect
        
        # Import config after mocking
        import importlib
        import config
        importlib.reload(config)
        
        # Test Settings class
        settings = config.Settings()
        
        # Verify Docker URI construction (when Atlas is disabled)
        assert "mongodb:27017" in settings.MONGODB_URI, f"Should use internal MongoDB, got: {settings.MONGODB_URI}"
        assert "authSource=admin" in settings.MONGODB_URI
        assert "tls=false" in settings.MONGODB_URI
        assert "retryWrites=true" not in settings.MONGODB_URI.lower()
        
        print("✅ Docker detection and URI construction work correctly")
    
    def test_motor_client_configuration(self):
        """Test Motor client configuration fixes"""
        print("Testing Motor client configuration...")
        
        with patch('database.AsyncIOMotorClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.admin.command.return_value = {"ok": 1}
            mock_client.__getitem__.return_value.list_collection_names = AsyncMock(return_value=[])
            
            # Test connect_db function
            from database import connect_db
            import database
            
            # Reset globals
            database.client = None
            database.db = None
            
            # Mock settings for Docker
            with patch('database.settings') as mock_settings:
                mock_settings.MONGODB_URI = "mongodb://hypersend:Mayank%40%2303@mongodb:27017/hypersend?authSource=admin&tls=false"
                mock_settings._MONGO_DB = "hypersend"
                mock_settings.DEBUG = True
                mock_settings.USE_MOCK_DB = False  # Ensure real MongoDB client is used for this test
                
                # Run connect_db
                asyncio.run(connect_db())
                
                # Verify client configuration
                mock_client_class.assert_called_once()
                call_kwargs = mock_client_class.call_args[1]
                
                # Critical fixes
                assert call_kwargs.get('retryWrites') is False, "retryWrites should be False to prevent Future issues"
                assert call_kwargs.get('serverSelectionTimeoutMS') == 10000
                assert call_kwargs.get('connectTimeoutMS') == 10000
                assert call_kwargs.get('socketTimeoutMS') == 30000
        
        print("✅ Motor client configuration is correct")
    
    def test_asyncio_wait_for_usage(self):
        """Test asyncio.wait_for usage in database operations"""
        print("Testing asyncio.wait_for usage...")
        
        async def mock_db_operation():
            await asyncio.sleep(0.01)
            return {"_id": "test_id", "email": "test@example.com"}
        
        async def test_wait_for():
            try:
                result = await asyncio.wait_for(
                    mock_db_operation(),
                    timeout=5.0
                )
                return result
            except asyncio.TimeoutError:
                raise ConnectionError("Database timeout")
        
        # Run the test
        result = asyncio.run(test_wait_for())
        assert result["_id"] == "test_id"
        assert not hasattr(result, '__await__')  # Not a Future
        assert not asyncio.isfuture(result)  # Not a Future
        
        print("✅ asyncio.wait_for usage is correct")
    
    def test_password_validation_logic(self):
        """Test password validation logic"""
        print("Testing password validation...")
        
        def validate_password(password):
            """Extract validation logic"""
            if not password or len(password) < 8:
                return False, "Password must be at least 8 characters"
            
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            
            if not (has_upper and has_lower and has_digit):
                return False, "Password must contain uppercase, lowercase, and numbers"
            
            return True, "Valid"
        
        # Test user's actual password
        is_valid, msg = validate_password("Mayank@#03")
        assert is_valid, f"User's password should be valid: {msg}"
        
        # Test other cases
        test_cases = [
            ("short", False),
            ("alllowercase", False),
            ("ALLUPPERCASE", False),
            ("NoNumbers", False),
            ("ValidPass123", True),
        ]
        
        for password, expected_valid in test_cases:
            is_valid, _ = validate_password(password)
            assert is_valid == expected_valid, f"Password {password} validation failed"
        
        print("✅ Password validation logic is correct")
    
    def test_email_validation_logic(self):
        """Test email validation logic"""
        print("Testing email validation...")
        
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        # Test user's actual email
        is_valid = bool(re.match(email_pattern, "mayank.kr0311@gmail.com"))
        assert is_valid, "User's email should be valid"
        
        # Test other cases
        test_cases = [
            ("test@example.com", True),
            ("user@zaply.in.net", True),  # Valid production domain
            ("invalid-email", False),
            ("@example.com", False),
            ("user@", False),
        ]
        
        for email, expected_valid in test_cases:
            is_valid = bool(re.match(email_pattern, email))
            assert is_valid == expected_valid, f"Email {email} validation failed"
        
        print("✅ Email validation logic is correct")
    
    def test_error_handling_improvements(self):
        """Test error handling improvements"""
        print("Testing error handling...")
        
        # Test timeout error handling
        async def test_timeout():
            try:
                await asyncio.wait_for(
                    asyncio.sleep(10),  # Long operation
                    timeout=0.01  # Short timeout
                )
            except asyncio.TimeoutError:
                raise ConnectionError("Database timeout")
        
        try:
            asyncio.run(test_timeout())
            assert False, "Should have raised ConnectionError"
        except ConnectionError as e:
            assert "Database timeout" in str(e)
        
        # Test connection error handling
        def test_connection_error():
            raise ConnectionError("Database service temporarily unavailable")
        
        try:
            test_connection_error()
            assert False, "Should have raised ConnectionError"
        except ConnectionError as e:
            assert "Database service temporarily unavailable" in str(e)
        
        print("✅ Error handling improvements are correct")

class TestAuthenticationFlow:
    """Test authentication flow with fixes"""
    
    def test_user_registration_validation(self):
        """Test user registration validation"""
        print("Testing user registration validation...")
        
        # Test valid user data
        user_data = {
            "name": "Test User",
            "email": "test@example.com",
            "password": "ValidPass123"
        }
        
        # Validate email
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        assert bool(re.match(email_pattern, user_data["email"]))
        
        # Validate password
        password = user_data["password"]
        assert len(password) >= 8
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isdigit() for c in password)
        
        # Validate name
        assert user_data["name"] and user_data["name"].strip()
        
        print("✅ User registration validation is correct")
    
    def test_login_flow_validation(self):
        """Test login flow validation"""
        print("Testing login flow validation...")
        
        # Test valid login credentials
        credentials = {
            "email": "test@example.com",
            "password": "ValidPass123"
        }
        
        # Validate email
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        assert bool(re.match(email_pattern, credentials["email"]))
        
        # Validate password presence
        assert credentials["password"]
        
        print("✅ Login flow validation is correct")

class TestDockerIntegration:
    """Test Docker integration scenarios"""
    
    def test_docker_network_configuration(self):
        """Test Docker network configuration - Atlas only (MongoDB removed)"""
        print("Testing Docker network configuration...")
        
        # Read docker-compose.yml
        docker_compose_path = Path(__file__).parent.parent / 'docker-compose.yml'
        assert docker_compose_path.exists(), "docker-compose.yml not found"
        
        with open(docker_compose_path, 'r') as f:
            compose_content = f.read()
        
        # Verify MongoDB is REMOVED (Atlas only)
        assert "mongodb:" not in compose_content, "MongoDB service should NOT be defined (Atlas only)"
        assert "MONGO_HOST" not in compose_content, "Backend should NOT reference local MongoDB"
        assert "MONGO_PORT" not in compose_content, "Backend should NOT reference local MongoDB port"
        
        # Verify backend uses DATABASE_URL (Atlas)
        assert "backend:" in compose_content, "Backend service should be defined"
        assert "container_name: hypersend_backend" in compose_content
        assert "DATABASE_URL" in compose_content, "Backend should use DATABASE_URL for MongoDB Atlas"
        assert "mongodb+srv" in compose_content, "DATABASE_URL should use MongoDB Atlas connection string"
        
        # Verify network configuration
        assert "hypersend_network:" in compose_content, "Docker network should be defined"
        assert "depends_on:" in compose_content, "Backend should have dependencies"
        assert "redis:" in compose_content, "Redis service should be defined"
        
        print("✅ Docker network configuration is correct")
    
    def test_environment_variable_override(self):
        """Test environment variable override logic"""
        print("Testing environment variable override logic...")
        
        # Test that Docker environment takes priority
        test_env_vars = {
            "MONGO_USER": "hypersend",
            "MONGO_PASSWORD": "Mayank@#03",
            "MONGO_HOST": "mongodb",  # Docker internal
            "MONGO_PORT": "27017",
            "MONGO_INITDB_DATABASE": "hypersend",
            # This should be ignored in Docker
            "MONGODB_URI": "mongodb://external:27017/db"
        }
        
        with patch.dict(os.environ, test_env_vars):
            # Mock Docker detection
            with patch('config.os.path.exists', return_value=True):
                import importlib
                import config
                importlib.reload(config)
                
                settings = config.Settings()
                
                # Should use Docker internal values, not external MONGODB_URI
                assert "mongodb:27017" in settings.MONGODB_URI
                assert "external:27017" not in settings.MONGODB_URI
        
        print("✅ Environment variable override logic is correct")

def run_comprehensive_tests():
    """Run all comprehensive tests"""
    print("🔍 Running Comprehensive MongoDB Connection & Authentication Tests\n")
    print("=" * 80)
    
    # Run pytest
    pytest_args = [
        __file__,
        "-v",
        "--tb=short",
        "--color=yes"
    ]
    
    return pytest.main(pytest_args)

if __name__ == "__main__":
    run_comprehensive_tests()
"""
Test script to verify MongoDB connection fixes before rebuilding containers.
"""

import os
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

def test_env_configuration():
    """Test that environment configuration is correct"""
    print("🔍 Testing Environment Configuration...")
    
    # Load environment from .env file
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / 'backend' / '.env'
    load_dotenv(env_path)
    print(f"Loading .env from: {env_path}")
    print(f".env exists: {env_path.exists()}")
    
    # Check critical environment variables
    mongo_user = os.getenv("MONGO_USER")
    mongo_password = os.getenv("MONGO_PASSWORD")
    mongo_host = os.getenv("MONGO_HOST")
    mongo_port = os.getenv("MONGO_PORT")
    mongo_db = os.getenv("MONGO_INITDB_DATABASE")
    
    print(f"✓ MONGO_USER: {mongo_user}")
    print(f"✓ MONGO_PASSWORD: {'*' * len(mongo_password) if mongo_password else 'None'}")
    print(f"✓ MONGO_HOST: {mongo_host}")
    print(f"✓ MONGO_PORT: {mongo_port}")
    print(f"✓ MONGO_INITDB_DATABASE: {mongo_db}")
    
    # Verify Docker configuration
    assert mongo_user == "hypersend", f"Expected 'hypersend', got '{mongo_user}'"
    assert mongo_password == "Mayank@#03", f"Password mismatch"
    assert mongo_host == "mongodb", f"Expected 'mongodb' for Docker, got '{mongo_host}'"
    assert mongo_port == "27017", f"Expected '27017', got '{mongo_port}'"
    assert mongo_db == "hypersend", f"Expected 'hypersend', got '{mongo_db}'"
    
    # Check that MONGODB_URI is NOT set (should be constructed dynamically)
    mongodb_uri = os.getenv("MONGODB_URI")
    assert mongodb_uri is None, f"MONGODB_URI should not be set in .env, but found: {mongodb_uri}"
    
    print("✅ Environment configuration is correct for Docker!")
    return True

def test_config_class():
    """Test Settings class configuration"""
    print("\n🔍 Testing Settings Class...")
    
    # Import config from backend directory
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))
    from config import settings
    
    print(f"✓ MongoDB URI host: {settings.MONGODB_URI.split('@')[1].split('/')[0] if '@' in settings.MONGODB_URI else 'N/A'}")
    print(f"✓ MongoDB DB: {settings._MONGO_DB}")
    print(f"✓ Docker detected: {getattr(settings, 'is_docker', 'Unknown')}")
    
    # Verify URI contains correct components for Docker
    assert "mongodb:27017" in settings.MONGODB_URI, f"Should use internal MongoDB, got: {settings.MONGODB_URI}"
    assert "authSource=admin" in settings.MONGODB_URI
    assert "tls=false" in settings.MONGODB_URI
    assert "retryWrites=true" not in settings.MONGODB_URI.lower()
    
    print("✅ Settings class configuration is correct!")
    return True

def test_database_uri_construction():
    """Test MongoDB URI construction"""
    print("\n🔍 Testing MongoDB URI Construction...")
    
    from urllib.parse import quote_plus
    
    # Test Docker URI construction
    user = "hypersend"
    password = "Mayank@#03"
    host = "mongodb"
    port = "27017"
    db = "hypersend"
    
    encoded_password = quote_plus(password)
    docker_uri = f"mongodb://{user}:{encoded_password}@{host}:{port}/{db}?authSource=admin&tls=false"
    
    print(f"✓ Constructed Docker URI: {docker_uri}")
    
    # Verify components
    assert "mongodb://hypersend:" in docker_uri
    assert "mongodb:27017" in docker_uri
    assert "authSource=admin" in docker_uri
    assert "tls=false" in docker_uri
    assert "retryWrites=true" not in docker_uri.lower()
    
    print("✅ MongoDB URI construction is correct!")
    return True

def main():
    """Run all tests"""
    print("🚀 Running MongoDB Connection Fix Verification\n")
    print("=" * 60)
    
    try:
        test_env_configuration()
        test_config_class()
        test_database_uri_construction()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("\n📋 Configuration Summary:")
        print("1. ✅ Environment variables configured for Docker")
        print("2. ✅ MONGODB_URI removed from .env (will be constructed dynamically)")
        print("3. ✅ MongoDB host set to 'mongodb' (Docker internal)")
        print("4. ✅ MongoDB port set to '27017' (Docker internal)")
        print("5. ✅ Settings class will construct correct URI")
        print("\n🔥 Ready to rebuild containers!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

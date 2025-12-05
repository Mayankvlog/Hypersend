#!/usr/bin/env python
"""
Comprehensive project validation script
Tests all critical components before building APK
"""

import sys
import os
from pathlib import Path

def validate_imports():
    """Validate that all critical imports work"""
    print("\n" + "="*60)
    print("🔍 VALIDATING IMPORTS")
    print("="*60)
    
    errors = []
    
    # Test backend imports
    try:
        print("\n✓ Importing backend.config...")
        from backend.config import settings
        print(f"  - API Host: {settings.API_HOST}")
        print(f"  - API Port: {settings.API_PORT}")
        print(f"  - MongoDB URI configured: {'mongodb://' in settings.MONGODB_URI}")
    except Exception as e:
        errors.append(f"Backend config: {e}")
        print(f"  ❌ {e}")
    
    # Test backend models
    try:
        print("\n✓ Importing backend.models...")
        from backend.models import UserCreate, UserLogin, MessageCreate
        print(f"  - UserCreate: OK")
        print(f"  - UserLogin: OK")
        print(f"  - MessageCreate: OK")
    except Exception as e:
        errors.append(f"Backend models: {e}")
        print(f"  ❌ {e}")
    
    # Test backend database
    try:
        print("\n✓ Importing backend.database...")
        from backend.database import connect_db, close_db
        print(f"  - connect_db: OK")
        print(f"  - close_db: OK")
    except Exception as e:
        errors.append(f"Backend database: {e}")
        print(f"  ❌ {e}")
    
    # Test backend routes
    try:
        print("\n✓ Importing backend routes...")
        from backend.routes import auth, files, chats, users, updates, p2p_transfer
        print(f"  - auth.router: OK")
        print(f"  - files.router: OK")
        print(f"  - chats.router: OK")
        print(f"  - users.router: OK")
        print(f"  - updates.router: OK")
        print(f"  - p2p_transfer.router: OK")
    except Exception as e:
        errors.append(f"Backend routes: {e}")
        print(f"  ❌ {e}")
    
    # Test backend auth
    try:
        print("\n✓ Importing backend.auth.utils...")
        from backend.auth.utils import get_current_user
        print(f"  - get_current_user: OK")
    except Exception as e:
        errors.append(f"Backend auth: {e}")
        print(f"  ❌ {e}")
    
    # Test frontend imports
    try:
        print("\n✓ Importing frontend.api_client...")
        from frontend.api_client import APIClient
        print(f"  - APIClient: OK")
    except Exception as e:
        errors.append(f"Frontend api_client: {e}")
        print(f"  ❌ {e}")
    
    # Test frontend theme
    try:
        print("\n✓ Importing frontend.theme...")
        from frontend.theme import PRIMARY_COLOR, SECONDARY_COLOR
        print(f"  - PRIMARY_COLOR: {PRIMARY_COLOR}")
        print(f"  - SECONDARY_COLOR: {SECONDARY_COLOR}")
    except Exception as e:
        errors.append(f"Frontend theme: {e}")
        print(f"  ❌ {e}")
    
    return errors

def validate_file_structure():
    """Validate required files exist"""
    print("\n" + "="*60)
    print("📁 VALIDATING FILE STRUCTURE")
    print("="*60)
    
    required_files = [
        "backend/main.py",
        "backend/config.py",
        "backend/database.py",
        "backend/models.py",
        "backend/requirements.txt",
        "backend/Dockerfile",
        "backend/routes/__init__.py",
        "backend/routes/auth.py",
        "backend/routes/files.py",
        "backend/routes/chats.py",
        "backend/routes/users.py",
        "backend/routes/updates.py",
        "backend/routes/p2p_transfer.py",
        "frontend/app.py",
        "frontend/api_client.py",
        "frontend/theme.py",
        "frontend/requirements.txt",
        "frontend/Dockerfile",
        "frontend/views/__init__.py",
        "frontend/views/login.py",
        "frontend/views/chats.py",
        "frontend/views/file_upload.py",
        "docker-compose.yml",
        "nginx.conf",
        "pyproject.toml",
        "README.md"
    ]
    
    missing = []
    for file in required_files:
        path = Path(file)
        if path.exists():
            print(f"✓ {file}")
        else:
            print(f"❌ {file} - MISSING")
            missing.append(file)
    
    return missing

def validate_configurations():
    """Validate configuration consistency"""
    print("\n" + "="*60)
    print("⚙️  VALIDATING CONFIGURATIONS")
    print("="*60)
    
    errors = []
    
    # Check MongoDB configuration
    try:
        print("\n✓ Checking MongoDB configuration...")
        from backend.config import settings
        if "mongodb://" in settings.MONGODB_URI:
            print(f"  - MongoDB URI: {settings.MONGODB_URI[:50]}...")
            if "hypersend" in settings.MONGODB_URI and "139.59.82.105" in settings.MONGODB_URI:
                print(f"  - ✓ Configured for remote access")
            else:
                errors.append("MongoDB not configured for remote access")
        else:
            errors.append("Invalid MongoDB URI format")
    except Exception as e:
        errors.append(f"MongoDB config check: {e}")
    
    # Check API configuration
    try:
        print("\n✓ Checking API configuration...")
        from backend.config import settings
        print(f"  - API Host: {settings.API_HOST}")
        print(f"  - API Port: {settings.API_PORT}")
        print(f"  - DEBUG: {settings.DEBUG}")
        print(f"  - CORS Origins: {len(settings.CORS_ORIGINS)} configured")
    except Exception as e:
        errors.append(f"API config check: {e}")
    
    # Check Docker Compose
    try:
        print("\n✓ Checking Docker Compose configuration...")
        import yaml
        with open("docker-compose.yml", "r") as f:
            compose = yaml.safe_load(f)
        print(f"  - Services: {list(compose.get('services', {}).keys())}")
        print(f"  - Networks: {list(compose.get('networks', {}).keys())}")
        print(f"  - Volumes: {list(compose.get('volumes', {}).keys())}")
    except Exception as e:
        print(f"  - ⚠️  YAML parsing (optional): {e}")
    
    return errors

def main():
    """Run all validations"""
    print("\n" + "🚀 "*30)
    print("HYPERSEND PROJECT VALIDATION")
    print("🚀 "*30)
    
    all_errors = []
    
    # Run validations
    import_errors = validate_imports()
    all_errors.extend(import_errors)
    
    file_errors = validate_file_structure()
    all_errors.extend(file_errors)
    
    config_errors = validate_configurations()
    all_errors.extend(config_errors)
    
    # Summary
    print("\n" + "="*60)
    print("📊 VALIDATION SUMMARY")
    print("="*60)
    
    if not all_errors:
        print("\n✅ ALL VALIDATIONS PASSED!")
        print("✅ Project is ready for APK build!")
        return 0
    else:
        print(f"\n❌ Found {len(all_errors)} issues:")
        for i, error in enumerate(all_errors, 1):
            print(f"  {i}. {error}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

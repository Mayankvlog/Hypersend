#!/usr/bin/env python3
"""
Comprehensive fix for all import issues in the hypersend project
Fixes:
1. Redis cache import issues
2. Backend route import issues  
3. Test file import issues
4. Database import issues
5. Auth package import issues
"""

import os
import sys
import glob
from pathlib import Path

def fix_redis_imports():
    """Fix redis cache import issues"""
    print("🔧 Fixing redis cache imports...")
    
    redis_cache_file = "backend/redis_cache.py"
    with open(redis_cache_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Fix the redis import
    fixed_content = content.replace(
        "import redis.asyncio as redis",
        """try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("Redis not available, using mock cache")"""
    )
    
    with open(redis_cache_file, 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    
    print("✅ Redis cache imports fixed")

def fix_backend_imports():
    """Fix all backend import issues"""
    print("🔧 Fixing backend route imports...")
    
    # Files that need relative imports
    route_files = [
        "backend/routes/auth.py",
        "backend/routes/chats.py", 
        "backend/routes/files.py",
        "backend/routes/groups.py",
        "backend/routes/messages.py",
        "backend/routes/users.py",
        "backend/routes/debug.py",
        "backend/routes/p2p_transfer.py",
        "backend/routes/channels.py",
        "backend/routes/updates.py"
    ]
    
    # Fix import patterns in route files
    for file_path in route_files:
        if not os.path.exists(file_path):
            continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Fix imports to use relative paths properly
        fixed_content = content
        
        # Fix main imports
        if "from models import" in content:
            fixed_content = fixed_content.replace("from models import", "from ..models import")
        
        if "from db_proxy import" in content:
            fixed_content = fixed_content.replace("from db_proxy import", "from ..db_proxy import")
        
        if "from validators import" in content:
            fixed_content = fixed_content.replace("from validators import", "from ..validators import")
        
        if "from rate_limiter import" in content:
            fixed_content = fixed_content.replace("from rate_limiter import", "from ..rate_limiter import")
        
        if "from redis_cache import" in content:
            fixed_content = fixed_content.replace("from redis_cache import", "from ..redis_cache import")
        
        if "from utils.email_service import" in content:
            fixed_content = fixed_content.replace("from utils.email_service import", "from ..utils.email_service import")
        
        if "from config import" in content:
            fixed_content = fixed_content.replace("from config import", "from ..config import")
        
        # Fix auth utils imports with proper package structure
        if "from auth.utils import" in content:
            # Replace with backend.auth.utils
            fixed_content = fixed_content.replace("from auth.utils import", "from backend.auth.utils import")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
    
    print("✅ Backend route imports fixed")

def fix_database_imports():
    """Fix database imports"""
    print("🔧 Fixing database imports...")
    
    database_files = [
        "backend/database.py",
        "backend/mock_database.py"
    ]
    
    for file_path in database_files:
        if not os.path.exists(file_path):
            continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Fix relative imports
        fixed_content = content.replace("from config import", "from .config import")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
    
    print("✅ Database imports fixed")

def fix_test_imports():
    """Fix all test file imports"""
    print("🔧 Fixing test file imports...")
    
    # Find all test files
    test_files = glob.glob("tests/test_*.py")
    
    for file_path in test_files:
        if not os.path.exists(file_path):
            continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        fixed_content = content
        
        # Fix path issues in test files
        if "backend_path = os.path.join(os.path.dirname(__file__), 'backend')" in content:
            fixed_content = fixed_content.replace(
                "backend_path = os.path.join(os.path.dirname(__file__), 'backend')",
                "backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')"
            )
        
        # Fix import paths in test files
        fixed_content = fixed_content.replace("from models import", "from backend.models import")
        fixed_content = fixed_content.replace("from db_proxy import", "from backend.db_proxy import")
        fixed_content = fixed_content.replace("from routes.auth import", "from backend.routes.auth import")
        fixed_content = fixed_content.replace("from routes.groups import", "from backend.routes.groups import")
        fixed_content = fixed_content.replace("from utils.email_service import", "from backend.utils.email_service import")
        fixed_content = fixed_content.replace("from config import", "from backend.config import")
        fixed_content = fixed_content.replace("from main import", "from backend.main import")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
    
    print("✅ Test file imports fixed")

def fix_auth_package():
    """Fix auth package structure"""
    print("🔧 Fixing auth package structure...")
    
    # Create auth package init if it doesn't exist
    auth_init = "backend/auth/__init__.py"
    
    auth_init_content = '''"""
Authentication utilities package
"""

# Import functions from utils to avoid circular imports
try:
    from .utils import (
        hash_password, verify_password, create_access_token, 
        create_refresh_token, decode_token, get_current_user,
        get_current_user_for_upload, get_current_user_optional, get_current_user_or_query
    )
except ImportError:
    # Fallback for circular import issues
    from .auth_utils import (
        hash_password, verify_password, create_access_token, 
        create_refresh_token, decode_token, get_current_user,
        get_current_user_for_upload, get_current_user_optional, get_current_user_or_query
    )

# Expose all functions to support both import patterns
__all__ = [
    'hash_password', 'verify_password', 'create_access_token', 
    'create_refresh_token', 'decode_token', 'get_current_user',
    'get_current_user_for_upload', 'get_current_user_optional', 'get_current_user_or_query'
]
'''
    
    # Write updated auth init
    with open(auth_init, 'w', encoding='utf-8') as f:
        f.write(auth_init_content)
    
    print("✅ Auth package structure fixed")

def main():
    """Run all fixes"""
    print("Starting comprehensive import fixes...")
    print()
    
    # Fix each type of import issue
    fix_redis_imports()
    fix_backend_imports()
    fix_database_imports()
    fix_test_imports()
    fix_auth_package()
    
    print("\n✅ All import fixes completed!")
    print("\n📋 Summary of fixes:")
    print("   • Redis cache imports: Fixed async import pattern")
    print("   • Backend route imports: Fixed relative import paths")
    print("   • Database imports: Fixed relative import paths")
    print("   • Test file imports: Fixed path and import issues")
    print("   • Auth package: Fixed circular import structure")
    print("\n🔍 Next steps:")
    print("   1. Run 'python -c \"from backend.main import app; print(\\'Success\\')\"' to verify backend imports")
    print("   2. Run 'pytest tests/test_file_download.py -v' to verify test imports work")
    print("   3. Run 'flutter analyze' from frontend directory")

if __name__ == "__main__":
    main()
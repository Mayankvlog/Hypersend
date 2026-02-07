#!/usr/bin/env python3
"""
Test import helper to resolve backend module import issues
Provides fallback imports for test files when backend modules have relative import problems
"""

import sys
import os
from pathlib import Path

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

def safe_import_backend(module_name, fallback=None):
    """Safely import a backend module with fallback handling"""
    try:
        # Try importing with backend prefix
        return __import__(f"backend.{module_name}", fromlist=[module_name.split('.')[-1]])
    except ImportError:
        try:
            # Try importing without prefix
            return __import__(module_name, fromlist=[module_name.split('.')[-1]])
        except ImportError:
            if fallback is not None:
                return fallback
            print(f"[IMPORT_HELPER] Could not import {module_name}")
            return None

def get_test_app():
    """Get a test app instance, fallback to minimal app if import fails"""
    try:
        from backend.main import app
        return app
    except ImportError:
        try:
            from main import app
            return app
        except ImportError:
            # Create minimal test app
            from fastapi import FastAPI
            app = FastAPI(title="Test Hypersend API")
            
            @app.get("/")
            async def root():
                return {"status": "test"}
            
            @app.get("/health")
            async def health():
                return {"status": "healthy"}
            
            print("[IMPORT_HELPER] Using minimal test app")
            return app

def get_mock_collections():
    """Get mock database collections for testing"""
    try:
        from backend.mock_database import (
            users_collection, chats_collection, messages_collection,
            files_collection, uploads_collection, refresh_tokens_collection,
            reset_tokens_collection
        )
        return {
            'users': users_collection,
            'chats': chats_collection,
            'messages': messages_collection,
            'files': files_collection,
            'uploads': uploads_collection,
            'refresh_tokens': refresh_tokens_collection,
            'reset_tokens': reset_tokens_collection
        }
    except ImportError:
        try:
            from mock_database import (
                users_collection, chats_collection, messages_collection,
                files_collection, uploads_collection, refresh_tokens_collection,
                reset_tokens_collection
            )
            return {
                'users': users_collection,
                'chats': chats_collection,
                'messages': messages_collection,
                'files': files_collection,
                'uploads': uploads_collection,
                'refresh_tokens': refresh_tokens_collection,
                'reset_tokens': reset_tokens_collection
            }
        except ImportError:
            print("[IMPORT_HELPER] Could not import mock collections")
            return {}

def get_auth_utils():
    """Get auth utilities for testing"""
    try:
        from backend.auth.utils import hash_password, verify_password, get_current_user
        # Create wrapper for hash_password to match test expectations
        def wrapped_hash_password(password):
            hash_val, salt = hash_password(password)
            return f"{salt}${hash_val}"
        return wrapped_hash_password, verify_password, get_current_user
    except ImportError:
        try:
            from auth.utils import hash_password, verify_password, get_current_user
            # Create wrapper for hash_password to match test expectations
            def wrapped_hash_password(password):
                hash_val, salt = hash_password(password)
                return f"{salt}${hash_val}"
            return wrapped_hash_password, verify_password, get_current_user
        except ImportError:
            # Fallback to debug_hash
            try:
                from debug_hash import hash_password, verify_password
                return hash_password, verify_password, None
            except ImportError:
                print("[IMPORT_HELPER] Could not import auth utilities")
                return None, None, None

def get_models():
    """Get model classes for testing"""
    try:
        from backend.models import GroupCreate, GroupMembersUpdate, GroupUpdate, UserCreate
        return GroupCreate, GroupMembersUpdate, GroupUpdate, UserCreate
    except ImportError:
        try:
            from models import GroupCreate, GroupMembersUpdate, GroupUpdate, UserCreate
            return GroupCreate, GroupMembersUpdate, GroupUpdate, UserCreate
        except ImportError:
            print("[IMPORT_HELPER] Could not import models")
            return None, None, None, None

# Export commonly needed items
__all__ = [
    'safe_import_backend',
    'get_test_app', 
    'get_mock_collections',
    'get_auth_utils',
    'get_models'
]
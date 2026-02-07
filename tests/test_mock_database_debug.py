#!/usr/bin/env python3
"""
Debug test for mock database query matching
"""

import sys
import os
import asyncio
from datetime import datetime

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Import test utilities
from test_utils import clear_collection, setup_test_document, clear_all_test_collections

from backend.mock_database import users_collection

def test_mock_database_query():
    """Test mock database query matching"""
    print("🧪 Testing Mock Database Query Matching")
    
    # Clear database
    clear_collection(users_collection())
    
    # Create test user
    test_user = {
        "_id": "507f1f77bcf86cd799439011",
        "email": "test@example.com",
        "name": "Test User",
        "password_hash": "abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234567890",
        "password_salt": "abcdef1234567890abcdef1234567890",
        "created_at": datetime.now(),
        "quota_used": 0,
        "quota_limit": 16106127360
    }
    
    # Store user with different keys to test
    setup_test_document(users_collection(), test_user)
    
    # Create a different user document for second insert
    test_user_2 = test_user.copy()
    test_user_2["_id"] = "507f1f77bcf86cd799439012"  # Different ID
    test_user_2["email"] = "test2@example.com"  # Different email
    test_user_2["name"] = "Test User 2"
    setup_test_document(users_collection(), test_user_2)
    
    print(f"📥 Stored users: {list(users_collection().data.keys())}")
    
    # Test different query methods
    async def test_queries():
        print("\n📥 Testing queries:")
        
        # Test 1: Query by email field
        query1 = {"email": "test@example.com"}
        result1 = await users_collection().find_one(query1)
        print(f"📥 Query 1 - {{'email': 'test@example.com'}}: {result1 is not None}")
        
        # Test 2: Query by _id field
        query2 = {"_id": "507f1f77bcf86cd799439011"}
        result2 = await users_collection().find_one(query2)
        print(f"📥 Query 2 - {{'_id': '507f1f77bcf86cd799439011'}}: {result2 is not None}")
        
        # Test 3: Query by key (shouldn't work)
        query3 = {"_id": "test@example.com"}
        result3 = await users_collection().find_one(query3)
        print(f"📥 Query 3 - {{'_id': 'test@example.com'}}: {result3 is not None}")
        
        # Show actual document structure
        if result1:
            print(f"📥 Found document: {result1}")
        else:
            print("📥 No document found with email field")
            # Show all documents for debugging
            for key, doc in users_collection().data.items():
                print(f"📥 Document {key}: {doc}")
    
    asyncio.run(test_queries())

if __name__ == "__main__":
    test_mock_database_query()

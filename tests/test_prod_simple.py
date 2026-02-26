#!/usr/bin/env python3
"""
Simple Production Fixes Test
"""

import pytest
import asyncio
from backend.database import get_database, users_collection
from backend.auth.utils import hash_password, verify_password
import unittest.mock


class TestProductionFixes:
    """Test critical production fixes"""

    def test_async_database_operations(self):
        """Test that async database operations don't return Future objects"""
        # Skip this test when using mock database
        from backend.config import settings

        # Check if USE_MOCK_DB attribute exists, otherwise assume mock mode
        use_mock_db = getattr(settings, 'USE_MOCK_DB', True)
        if use_mock_db:
            pytest.skip("Test requires real MongoDB connection")

        # Initialize database for testing with real MongoDB Atlas
        from backend.database import initialize_database

        asyncio.run(initialize_database())

        # Test 1: Database connection returns proper database, not Future
        db = get_database()
        assert db is not None, "Database should be initialized"
        assert not hasattr(db, "__await__"), "Database should not be a coroutine"
        assert (
            str(type(db)) == "<class 'motor.motor_asyncio.AsyncIOMotorDatabase'>"
        ), "Should be Motor database"

        # Test 2: Collection operations work correctly
        users_col = users_collection()
        assert users_col is not None, "Users collection should be available"
        assert not hasattr(
            users_col, "__await__"
        ), "Users collection should not be a coroutine"
        assert callable(
            getattr(users_col, "find_one", None)
        ), "find_one should be callable"

        print("✅ Async database operations test passed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

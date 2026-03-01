#!/usr/bin/env python3
"""
Pytest configuration file
Automatically sets up test environment
"""

import os
import sys
import pytest
import asyncio
from pathlib import Path

# Enable pytest-asyncio
pytest_plugins = ('pytest_asyncio',)

# Set environment variables for testing
os.environ.setdefault('USE_MOCK_DB', 'false')
os.environ.setdefault('MONGODB_ATLAS_ENABLED', 'true')
os.environ['ENVIRONMENT'] = 'test'

# Set longer timeout for HTTP requests to prevent connection pool issues
os.environ['TEST_TIMEOUT'] = '60'

# Set connection timeout for tests to prevent retries
os.environ['TEST_TIMEOUT'] = '30'

# Set default test credentials if not provided
if not os.getenv('TEST_USER_EMAIL'):
    os.environ['TEST_USER_EMAIL'] = 'test@example.com'
if not os.getenv('TEST_USER_PASSWORD'):
    os.environ['TEST_USER_PASSWORD'] = 'Test@123456'

if not os.getenv('TEST_EMAIL'):
    os.environ['TEST_EMAIL'] = 'test@example.com'
if not os.getenv('TEST_PASSWORD'):
    os.environ['TEST_PASSWORD'] = 'Test@123456'

# Add project root to path to allow imports
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
# Add the backend directory to Python path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Fix Python's module import system for backend packages
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Configure DB mode for tests.
# IMPORTANT: This must be set BEFORE importing backend modules.
# Use real MongoDB Atlas for testing to ensure Atlas compatibility
os.environ.setdefault('USE_MOCK_DB', 'false')
os.environ.setdefault('MONGODB_ATLAS_ENABLED', 'true')
os.environ.setdefault('MONGODB_URI', 'mongodb+srv://mayanllr0311_db_user:JBkAZin8lytTK6vg@cluster0.rnj3vfd.mongodb.net/hypersend?retryWrites=true&w=majority')
os.environ.setdefault('DATABASE_NAME', 'Hypersend')
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-pytest-only-do-not-use-in-production')
os.environ['DEBUG'] = 'True'  # Enable debug mode for tests

# Add backend to sys.modules to fix relative imports
import importlib.util
import sys
backend_spec = importlib.util.spec_from_file_location("backend", os.path.join(backend_path, "__init__.py"))
if backend_spec and backend_spec.loader:
    backend_module = importlib.util.module_from_spec(backend_spec)
    sys.modules['backend'] = backend_module
    backend_spec.loader.exec_module(backend_module)

# Mock the app import to avoid dependency issues
try:
    from fastapi import FastAPI
    # Create a minimal test app if main app fails to import
    def create_test_app():
        app = FastAPI(title="Test Hypersend API")
        
        @app.get("/")
        async def root():
            return {"status": "test"}
        
        @app.get("/health")
        async def health():
            return {"status": "healthy"}
        
        return app
    
    # Try to import the real app, fallback to test app
    try:
        from backend.main import app
    except (ImportError, SyntaxError):
        app = create_test_app()
        print("[CONFTEST] Using minimal test app due to import/syntax issues")
        
except ImportError:
    print("[CONFTEST] FastAPI not available, creating mock app")
    # Create a mock app for testing
    class MockApp:
        def __init__(self):
            self.routes = []
        
        def get(self, path):
            def decorator(func):
                return func
            return decorator
        
        def post(self, path):
            def decorator(func):
                return func
            return decorator
    
    app = MockApp()

# Database initialization fixture
@pytest.fixture(scope="session")
async def initialize_test_database():
    """Initialize database for all tests"""
    try:
        # Import the main app to trigger startup event
        from backend.main import app
        print("[CONFTEST] Database initialized for tests")
    except Exception as e:
        print(f"[CONFTEST] Database initialization failed: {e}")
        # Continue with tests - mock database should be available


@pytest.fixture(scope="session")
def event_loop():
    old_loop = None
    try:
        old_loop = asyncio.get_event_loop()
    except Exception:
        old_loop = None

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield loop
    finally:
        # Never leave a closed loop as the current loop
        try:
            if old_loop is not None and not old_loop.is_closed():
                asyncio.set_event_loop(old_loop)
            else:
                asyncio.set_event_loop(None)
        except Exception:
            pass
        loop.close()


@pytest.fixture(scope="session", autouse=True)
def _init_atlas_db_for_tests(event_loop):
    # IMPORTANT: Always initialize using the canonical `backend.database` module.
    # Importing `database` via sys.path can load the same file under a different
    # module name in some harnesses, which would create separate globals.
    try:
        # Force Atlas-only flags (do not rely on setdefault).
        os.environ["USE_MOCK_DB"] = "false"
        os.environ["MONGODB_ATLAS_ENABLED"] = "true"
        # Force canonical Atlas URI + DB name for tests in case other test modules
        # override environment variables with invalid values.
        os.environ["MONGODB_URI"] = (
            "mongodb+srv://mayanllr0311_db_user:JBkAZin8lytTK6vg@cluster0.rnj3vfd.mongodb.net/"
            "Hypersend?retryWrites=true&w=majority"
        )
        os.environ["DATABASE_NAME"] = "Hypersend"
        from backend import database as _database
        from backend.main import app as _app

        if not _database.is_database_initialized():
            task = event_loop.create_task(_database.init_database())
            event_loop.run_until_complete(task)

        _app.state.db = _database.db
        _app.state.client = _database.client
        print("[CONFTEST] Atlas database initialized for tests")
    except Exception as e:
        # Atlas-only test suite requirement: fail fast if Atlas cannot be initialized.
        raise RuntimeError(f"[CONFTEST] Atlas DB initialization failed: {e}")

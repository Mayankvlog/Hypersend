#!/usr/bin/env python3
"""
Pytest configuration file
Automatically sets up test environment
"""

import os
import sys
import pytest
from pathlib import Path

# Set USE_MOCK_DB for all tests
os.environ['USE_MOCK_DB'] = 'True'

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

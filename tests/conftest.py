#!/usr/bin/env python3
"""
Pytest configuration file
Automatically sets up test environment
"""

import os
import sys

# Set USE_MOCK_DB for all tests
os.environ['USE_MOCK_DB'] = 'True'

# Set longer timeout for HTTP requests to prevent connection pool issues
os.environ['TEST_TIMEOUT'] = '60'

# Set connection timeout for tests to prevent retries
os.environ['TEST_TIMEOUT'] = '30'

# Add the backend directory to Python path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

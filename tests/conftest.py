#!/usr/bin/env python3
"""
Pytest configuration file
Automatically sets up test environment
"""

import os
import sys

# Set USE_MOCK_DB for all tests
os.environ['USE_MOCK_DB'] = 'True'

# Add the backend directory to Python path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

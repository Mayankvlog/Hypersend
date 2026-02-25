#!/usr/bin/env python3

import sys
import os
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

print("Testing imports...")

try:
    print("1. Testing basic imports...")
    from fastapi import FastAPI
    print("✅ FastAPI imported")
    
    print("2. Testing config import...")
    from config import settings
    print("✅ Config imported")
    
    print("3. Testing models import...")
    from models import UserCreate
    print("✅ Models imported")
    
    print("4. Testing auth routes import...")
    from routes import auth
    print("✅ Auth routes imported")
    
    print("5. Testing crypto imports...")
    from crypto.signal_protocol import SignalProtocol
    print("✅ Signal protocol imported")
    
    print("6. Testing main app creation...")
    from main import app
    print("✅ Main app imported")
    
    print("✅ All imports successful!")
    
except Exception as e:
    print(f"❌ Import failed: {e}")
    import traceback
    print(f"Traceback: {traceback.format_exc()}")

#!/usr/bin/env python3
"""
Test script to verify saved messages functionality
"""

import asyncio
import sys
import os

# Add frontend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'frontend'))

from api_client import APIClient

async def test_saved_messages():
    """Test saved messages functionality"""
    
    # Initialize API client
    api_client = APIClient("http://139.59.82.105:8000")
    
    # Test login (you'll need to provide actual credentials)
    try:
        print("Testing login...")
        # Note: Replace with actual credentials for testing
        # result = await api_client.login("mobimix33@gmail.com", "your_password")
        # print(f"Login result: {result}")
        
        print("Testing get_saved_chat...")
        saved_chat = await api_client.get_saved_chat()
        print(f"Saved chat: {saved_chat}")
        
        print("Testing get_saved_messages...")
        saved_messages = await api_client.get_saved_messages()
        print(f"Saved messages: {saved_messages}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_saved_messages())
#!/usr/bin/env python
"""Test script to verify app functionality"""
import asyncio
from frontend.api_client import APIClient, API_BASE_URL, DEBUG
from frontend.app import API_URL, debug_log

async def test_api():
    """Test API connectivity"""
    print("=" * 50)
    print("Zaply App Test")
    print("=" * 50)
    
    print(f"\n✓ API_BASE_URL (from api_client): {API_BASE_URL}")
    print(f"✓ API_URL (from app): {API_URL}")
    print(f"✓ DEBUG mode: {DEBUG}")
    
    # Test API client initialization
    client = APIClient()
    print(f"\n✓ API Client initialized")
    print(f"  Base URL: {client.base_url}")
    
    # Test health endpoint
    try:
        print(f"\n⏳ Testing VPS connection...")
        response = await client.client.get("http://139.59.82.105:8000/health")
        print(f"✓ Health check successful!")
        print(f"  Status: {response.status_code}")
        print(f"  Response: {response.text}")
    except Exception as e:
        print(f"✗ Health check failed: {e}")
        return False
    
    # Test root endpoint
    try:
        print(f"\n⏳ Testing root endpoint...")
        response = await client.client.get("http://139.59.82.105:8000/")
        print(f"✓ Root endpoint successful!")
        print(f"  Status: {response.status_code}")
        print(f"  Response: {response.text}")
    except Exception as e:
        print(f"✗ Root endpoint failed: {e}")
        return False
    
    print("\n" + "=" * 50)
    print("✓ All tests passed!")
    print("=" * 50)
    return True

if __name__ == "__main__":
    result = asyncio.run(test_api())
    exit(0 if result else 1)

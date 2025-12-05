#!/usr/bin/env python
"""Test script to verify app functionality with support for local and VPS testing"""
import asyncio
import os
import pytest
from frontend.api_client import APIClient, API_BASE_URL, DEBUG
from frontend.app import API_URL, debug_log

@pytest.fixture
def vps_url() -> str:
    """Fixture to supply VPS URL for tests.

    If TEST_VPS_URL is not set, skip the VPS test instead of failing.
    """
    url = os.getenv("TEST_VPS_URL", "").strip()
    if not url:
        pytest.skip("TEST_VPS_URL is not set; skipping VPS connectivity test")
    return url

@pytest.mark.asyncio
async def test_local_api():
    """Test local API connectivity (development)"""
    print("\n" + "==" * 30)
    print("LOCAL API TEST (Development)")
    print("==" * 30)
    
    print(f"\nTesting: {API_BASE_URL}")
    
    client = APIClient()
    
    # Test health endpoint
    try:
        print(f"\nTesting /health endpoint...")
        response = await client.client.get(f"{API_BASE_URL}/health")
        print(f"✓ Health check successful!")
        print(f"  Status: {response.status_code}")
        print(f"  Response: {response.json()}")
    except Exception as e:
        print(f"âœ— Health check failed: {type(e).__name__}: {e}")
        print(f"\nâš ï¸  Make sure backend is running:")
        print(f"   python -m uvicorn backend.main:app --reload")
        pytest.fail(f"Health check failed: {type(e).__name__}: {e}")
    
    # Test root endpoint
    try:
        print(f"\n⏳ Testing / (root) endpoint...")
        response = await client.client.get(f"{API_BASE_URL}/")
        print(f"✓ Root endpoint successful!")
        print(f"  Status: {response.status_code}")
        print(f"  Response: {response.json()}")
    except Exception as e:
        print(f"âœ— Root endpoint failed: {e}")
        pytest.fail(f"Root endpoint failed: {e}")
    
    print("\n" + "==" * 30)
    print("âœ“ All local tests passed!")
    print("==" * 30)
@pytest.mark.asyncio
async def test_vps_api(vps_url: str):
    """Test VPS API connectivity (production)"""
    print("\n" + "==" * 30)
    print("VPS API TEST (Production)")
    print("==" * 30)
    
    print(f"\nTesting: {vps_url}")
    
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Test health endpoint
            print(f"\n⏳ Testing {vps_url}/health endpoint...")
            response = await client.get(f"{vps_url}/health")
            print(f"✓ Health check successful!")
            print(f"  Status: {response.status_code}")
            print(f"  Response: {response.text[:100]}")
            
            # Test root endpoint
            print(f"\n⏳ Testing {vps_url}/ (root) endpoint...")
            response = await client.get(f"{vps_url}/")
            print(f"✓ Root endpoint successful!")
            print(f"  Status: {response.status_code}")
            print(f"  Response: {response.text[:100]}")
    except Exception as e:
        print(f"âœ— VPS connection failed: {type(e).__name__}: {e}")
        print(f"\nâš ï¸  Check that:")
        print(f"   1. VPS is running and reachable")
        print(f"   2. Backend service is listening on port 8000")
        print(f"   3. Network/firewall allows connections")
        pytest.fail(f"VPS connection failed: {type(e).__name__}: {e}")
    
    print("\n" + "==" * 30)
    print("✓ VPS tests passed!")
    print("==" * 30)
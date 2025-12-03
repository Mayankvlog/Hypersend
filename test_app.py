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
        print(f"\n⏳ Testing /health endpoint...")
        response = await client.client.get(f"{API_BASE_URL}/health")
        print(f"✓ Health check successful!")
        print(f"  Status: {response.status_code}")
        print(f"  Response: {response.json()}")
    except Exception as e:
        print(f"✗ Health check failed: {type(e).__name__}: {e}")
        print(f"\n⚠️  Make sure backend is running:")
        print(f"   python -m uvicorn backend.main:app --reload")
        return False
    
    # Test root endpoint
    try:
        print(f"\n⏳ Testing / (root) endpoint...")
        response = await client.client.get(f"{API_BASE_URL}/")
        print(f"✓ Root endpoint successful!")
        print(f"  Status: {response.status_code}")
        print(f"  Response: {response.json()}")
    except Exception as e:
        print(f"✗ Root endpoint failed: {e}")
        return False
    
    print("\n" + "==" * 30)
    print("✓ All local tests passed!")
    print("==" * 30)
    return True

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
        print(f"✗ VPS connection failed: {type(e).__name__}: {e}")
        print(f"\n⚠️  Check that:")
        print(f"   1. VPS is running and reachable")
        print(f"   2. Backend service is listening on port 8000")
        print(f"   3. Network/firewall allows connections")
        return False
    
    print("\n" + "==" * 30)
    print("✓ VPS tests passed!")
    print("==" * 30)
    return True

async def main():
    """Main test runner"""
    print("\n" + "#" * 60)
    print("# HYPERSEND APP TEST SUITE")
    print("#" * 60)
    
    print(f"\n📋 Configuration:")
    print(f"  API_BASE_URL (from api_client): {API_BASE_URL}")
    print(f"  API_URL (from app): {API_URL}")
    print(f"  DEBUG mode: {DEBUG}")
    
    # Test local API first
    local_result = await test_local_api()
    
    if not local_result:
        print(f"\n⚠️  Local API test failed!")
    
    # Optionally test VPS if environment variable is set
    vps_url = os.getenv("TEST_VPS_URL", "").strip()
    if vps_url:
        print(f"\n✓ TEST_VPS_URL environment variable found: {vps_url}")
        vps_result = await test_vps_api(vps_url)
        if not vps_result:
            print(f"\n⚠️  VPS test failed!")
            return 1
    else:
        print(f"\n💡 To test VPS connectivity, set TEST_VPS_URL environment variable:")
        print(f"   set TEST_VPS_URL=http://your-vps-ip:8000")
        print(f"   python test_app.py")
    
    if local_result:
        print("\n\n" + "#" * 60)
        print("# ✓ PRIMARY TESTS PASSED")
        print("#" * 60)
        return 0
    else:
        print("\n\n" + "#" * 60)
        print("# ✗ TESTS FAILED")
        print("#" * 60)
        return 1

if __name__ == "__main__":
    result = asyncio.run(main())
    exit(result)

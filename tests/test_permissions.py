#!/usr/bin/env python3
"""
Test script for permissions system endpoints
Tests both GET and PUT endpoints for permissions management
"""

import asyncio
import httpx
import json
from typing import Dict, Any

# Configuration (point tests to your DigitalOcean VPS backend)
API_BASE_URL = "http://139.59.82.105:8000/api/v1"
TEST_TOKEN = "test_token_here"  # Replace with actual token from login

class PermissionsTestSuite:
    def __init__(self, base_url: str = API_BASE_URL, token: str = TEST_TOKEN):
        self.base_url = base_url
        self.token = token
        self.headers = {"Authorization": f"Bearer {self.token}"}
        self.client = None
    
    async def __aenter__(self):
        self.client = httpx.AsyncClient(timeout=10.0)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()
    
    async def test_get_permissions(self) -> Dict[str, Any]:
        """Test GET /users/permissions endpoint"""
        print("\n[TEST] Testing GET /users/permissions")
        print(f"[TEST] Endpoint: {self.base_url}/users/permissions")
        print(f"[TEST] Headers: {self.headers}")
        
        try:
            response = await self.client.get(
                f"{self.base_url}/users/permissions",
                headers=self.headers
            )
            
            print(f"[TEST] Status Code: {response.status_code}")
            print(f"[TEST] Response Body: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                print("[TEST] ✅ GET /permissions PASSED")
                print(f"[TEST] Permissions returned: {json.dumps(data, indent=2)}")
                return data
            else:
                print("[TEST] ❌ GET /permissions FAILED")
                print(f"[TEST] Error: {response.text}")
                return None
        
        except httpx.ConnectError as e:
            print(f"[TEST] ❌ Connection Error: {str(e)}")
            print(f"[TEST] Is backend running on {self.base_url}?")
            return None
        except Exception as e:
            print(f"[TEST] ❌ Error: {str(e)}")
            return None
    
    async def test_put_permissions(self, permissions: Dict[str, bool]) -> bool:
        """Test PUT /users/permissions endpoint"""
        print("\n[TEST] Testing PUT /users/permissions")
        print(f"[TEST] Endpoint: {self.base_url}/users/permissions")
        print(f"[TEST] Payload: {json.dumps(permissions, indent=2)}")
        
        try:
            response = await self.client.put(
                f"{self.base_url}/users/permissions",
                headers=self.headers,
                json=permissions
            )
            
            print(f"[TEST] Status Code: {response.status_code}")
            print(f"[TEST] Response Body: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                print("[TEST] ✅ PUT /permissions PASSED")
                print(f"[TEST] Response: {json.dumps(data, indent=2)}")
                return True
            else:
                print("[TEST] ❌ PUT /permissions FAILED")
                print(f"[TEST] Error: {response.text}")
                return False
        
        except httpx.ConnectError as e:
            print(f"[TEST] ❌ Connection Error: {str(e)}")
            print(f"[TEST] Is backend running on {self.base_url}?")
            return False
        except Exception as e:
            print(f"[TEST] ❌ Error: {str(e)}")
            return False
    
    async def run_full_test(self):
        """Run complete permissions test suite"""
        print("="*70)
        print("PERMISSIONS SYSTEM TEST SUITE")
        print("="*70)
        
        # Test 1: Get initial permissions
        initial_perms = await self.test_get_permissions()
        if initial_perms is None:
            print("\n[TEST] ⚠️  Cannot proceed with tests - backend not responding")
            return False
        
        # Test 2: Update all permissions to enabled
        print("\n[TEST] Updating all permissions to enabled...")
        test_permissions = {
            "location": True,
            "camera": True,
            "microphone": True,
            "contacts": True,
            "phone": True,
            "storage": True
        }
        update_success = await self.test_put_permissions(test_permissions)
        if not update_success:
            print("[TEST] ⚠️  Update test failed")
            return False
        
        # Test 3: Get updated permissions
        print("\n[TEST] Fetching updated permissions...")
        updated_perms = await self.test_get_permissions()
        
        # Test 4: Verify values match
        if updated_perms and updated_perms == test_permissions:
            print("\n[TEST] ✅ Permissions persist correctly!")
        else:
            print("\n[TEST] ⚠️  Permissions mismatch after update")
        
        # Test 5: Update selective permissions
        print("\n[TEST] Testing selective permission updates...")
        selective_perms = {
            "location": False,
            "camera": True,
            "microphone": False,
            "contacts": True,
            "phone": False,
            "storage": True
        }
        await self.test_put_permissions(selective_perms)
        
        print("\n" + "="*70)
        print("TEST SUITE COMPLETE")
        print("="*70)
        return True


async def main():
    """Main entry point"""
    print("\n🔐 PERMISSIONS SYSTEM TESTING\n")
    print("Prerequisites:")
    print("1. Backend must be running on http://139.59.82.105:8000")
    print("2. MongoDB must be running")
    print("3. You must have a valid JWT token from login")
    print("\nUsage:")
    print("  python test_permissions.py")
    print("\nNote: Replace TEST_TOKEN with actual token from login")
    
    # Check if token is set
    if TEST_TOKEN == "test_token_here":
        print("\n⚠️  WARNING: Using placeholder token!")
        print("To test with real data:")
        print("  1. Start the app")
        print("  2. Login to get a valid token")
        print("  3. Replace TEST_TOKEN in this file with your token")
        print("  4. Run: python test_permissions.py")
    
    # Run tests
    async with PermissionsTestSuite() as tester:
        await tester.run_full_test()


if __name__ == "__main__":
    asyncio.run(main())

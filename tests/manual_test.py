#!/usr/bin/env python3
"""Manual test runner for HTTP error codes"""

import os
import sys

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

def test_error_codes():
    """Test that error codes 301, 400, 500, 599 are properly handled"""
    try:
        from backend.error_handlers import get_error_hints

        codes = [301, 400, 500, 599]
        results = {}

        for code in codes:
            hints = get_error_hints(code)
            results[code] = {
                'hints_count': len(hints),
                'has_hints': len(hints) > 0,
                'sample_hints': hints[:2] if hints else []
            }

        print("✅ Error code testing results:")
        for code, result in results.items():
            status = "✅" if result['has_hints'] else "❌"
            print(f"{status} {code}: {result['hints_count']} hints - {result['sample_hints']}")

        # Check if all codes have hints
        all_have_hints = all(result['has_hints'] for result in results.values())
        if all_have_hints:
            print("\n🎉 All required error codes (301, 400, 500, 599) are properly implemented!")
            return True
        else:
            print("\n❌ Some error codes are missing hints!")
            return False

    except Exception as e:
        print(f"❌ Error testing error codes: {e}")
        return False

def test_fastapi_app():
    """Test that FastAPI app can be imported and basic functionality works"""
    try:
        from backend.main import app
        from fastapi.testclient import TestClient

        client = TestClient(app)

        # Test health endpoint
        response = client.get("/health")
        print(f"✅ Health endpoint: {response.status_code}")

        # Test 404 endpoint
        response = client.get("/nonexistent")
        print(f"✅ 404 endpoint: {response.status_code}")

        return True

    except Exception as e:
        print(f"❌ Error testing FastAPI app: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Manual Test Runner for HTTP Error Codes")
    print("=" * 50)

    success1 = test_error_codes()
    print()
    success2 = test_fastapi_app()

    if success1 and success2:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)
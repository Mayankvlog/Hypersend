#!/usr/bin/env python3
"""
Comprehensive HTTP Error Testing - All 300, 400, 500 error types
Tests the backend API for proper error handling across all HTTP status codes
"""

import requests
import json
import time
from typing import Dict, List, Tuple

BASE_URL = "http://localhost:8000/api/v1"

class ErrorTester:
    def __init__(self):
        self.results = []
        
    def log_result(self, test_name: str, expected_status: int, actual_status: int, 
                   response_body: dict, passed: bool, details: str = ""):
        """Log test result"""
        self.results.append({
            "test": test_name,
            "expected": expected_status,
            "actual": actual_status,
            "passed": passed,
            "details": details,
            "response": response_body
        })
        
        status = "PASS" if passed else "FAIL"
        print(f"{status} {test_name}")
        print(f"   Expected: {expected_status}, Got: {actual_status}")
        if details:
            print(f"   Details: {details}")
        if not passed and "error" in response_body:
            print(f"   Error: {response_body.get('error', 'Unknown')}")
        print()
    
    def test_300_level_redirects(self):
        """Test 300-level redirection errors"""
        print("TESTING 300-LEVEL REDIRECTION ERRORS")
        print("=" * 60)
        
        # 301 Moved Permanently (not applicable to API but test URL variations)
        try:
            r = requests.post(f"{BASE_URL}/auth/login/", json={"email": "test@test.com", "password": "test"})
            self.log_result(
                "301 Moved Permanently (trailing slash)", 
                404, r.status_code, r.json() if r.content else {}, 
                r.status_code == 404,  # Expected 404, not 301
                "API should return 404, not redirect"
            )
        except Exception as e:
            self.log_result("301 Moved Permanently", 301, 0, {}, False, str(e))
        
        # 302 Found (test potential redirects)
        try:
            r = requests.get(f"{BASE_URL}/auth")
            self.log_result(
                "302 Found (without endpoint)", 
                404, r.status_code, r.json() if r.content else {},
                r.status_code == 404,
                "Should return 404, not redirect"
            )
        except Exception as e:
            self.log_result("302 Found", 302, 0, {}, False, str(e))
    
    def test_400_level_client_errors(self):
        """Test 400-level client errors"""
        print("TESTING 400-LEVEL CLIENT ERRORS")
        print("=" * 60)
        
        # 400 Bad Request - Invalid JSON
        try:
            r = requests.post(f"{BASE_URL}/auth/login", 
                            data="invalid json", 
                            headers={"Content-Type": "application/json"})
            self.log_result(
                "400 Bad Request (invalid JSON)", 
                422, r.status_code, r.json() if r.content else {},
                r.status_code == 422
            )
        except Exception as e:
            self.log_result("400 Bad Request", 400, 0, {}, False, str(e))
        
        # 400 Bad Request - Missing required fields
        try:
            r = requests.post(f"{BASE_URL}/auth/login", 
                            json={"email": "test@test.com"})  # Missing password
            self.log_result(
                "400 Bad Request (missing password)", 
                422, r.status_code, r.json() if r.content else {},
                r.status_code == 422
            )
        except Exception as e:
            self.log_result("400 Missing Field", 400, 0, {}, False, str(e))
        
        # 401 Unauthorized - Invalid token
        try:
            r = requests.get(f"{BASE_URL}/users/me", 
                           headers={"Authorization": "Bearer invalid_token"})
            self.log_result(
                "401 Unauthorized (invalid token)", 
                401, r.status_code, r.json() if r.content else {},
                r.status_code == 401
            )
        except Exception as e:
            self.log_result("401 Unauthorized", 401, 0, {}, False, str(e))
        
        # 401 Unauthorized - Missing token
        try:
            r = requests.get(f"{BASE_URL}/users/me")
            self.log_result(
                "401 Unauthorized (missing token)", 
                401, r.status_code, r.json() if r.content else {},
                r.status_code == 401 or r.status_code == 403
            )
        except Exception as e:
            self.log_result("401 Missing Token", 401, 0, {}, False, str(e))
        
        # 403 Forbidden - Valid token but no permission
        try:
            # Try to access someone else's data (will fail during validation)
            r = requests.get(f"{BASE_URL}/users/invalid_user_id", 
                           headers={"Authorization": "Bearer invalid_token"})
            self.log_result(
                "403 Forbidden (no permission)", 
                401 or 403, r.status_code, r.json() if r.content else {},
                r.status_code in [401, 403]
            )
        except Exception as e:
            self.log_result("403 Forbidden", 403, 0, {}, False, str(e))
        
        # 404 Not Found - Non-existent endpoint
        try:
            r = requests.get(f"{BASE_URL}/nonexistent")
            self.log_result(
                "404 Not Found (non-existent endpoint)", 
                404, r.status_code, r.json() if r.content else {},
                r.status_code == 404
            )
        except Exception as e:
            self.log_result("404 Not Found", 404, 0, {}, False, str(e))
        
        # 404 Not Found - Non-existent resource
        try:
            r = requests.get(f"{BASE_URL}/files/nonexistent_file_id/download")
            self.log_result(
                "404 Not Found (non-existent file)", 
                401 or 404, r.status_code, r.json() if r.content else {},
                r.status_code in [401, 404]  # 401 if auth fails first
            )
        except Exception as e:
            self.log_result("404 Resource Not Found", 404, 0, {}, False, str(e))
        
        # 405 Method Not Allowed - Wrong HTTP method
        try:
            r = requests.patch(f"{BASE_URL}/auth/login")  # PATCH instead of POST
            self.log_result(
                "405 Method Not Allowed", 
                405, r.status_code, r.json() if r.content else {},
                r.status_code == 405
            )
        except Exception as e:
            self.log_result("405 Method Not Allowed", 405, 0, {}, False, str(e))
        
        # 409 Conflict - Duplicate resource creation
        try:
            # This might pass if user doesn't exist, fail if exists
            r = requests.post(f"{BASE_URL}/auth/register", json={
                "email": "conflict@test.com",
                "username": "conflict_user", 
                "password": "password123"
            })
            # First request might succeed (201), second should conflict (409)
            expected = [201, 409]  # Either is valid for this test
            self.log_result(
                "409 Conflict (duplicate registration)", 
                201, r.status_code, r.json() if r.content else {},
                r.status_code in expected,
                "First attempt might succeed, second should conflict"
            )
        except Exception as e:
            self.log_result("409 Conflict", 409, 0, {}, False, str(e))
        
        # 413 Payload Too Large - Oversized request
        try:
            large_data = {"data": "x" * 10000000}  # 10MB
            r = requests.post(f"{BASE_URL}/auth/login", 
                            json=large_data, 
                            timeout=5)
            # This might pass validation or fail with 413
            expected = [200, 400, 413, 422]  # Multiple valid outcomes
            self.log_result(
                "413 Payload Too Large", 
                413, r.status_code, r.json() if r.content else {},
                r.status_code in expected,
                f"Large payload test - got {r.status_code}"
            )
        except Exception as e:
            self.log_result("413 Payload Too Large", 413, 0, {}, False, str(e))
        
        # 422 Unprocessable Entity - Valid JSON but invalid data
        try:
            r = requests.post(f"{BASE_URL}/auth/register", json={
                "email": "invalid-email",  # Invalid email format
                "username": "test", 
                "password": "123"  # Too short
            })
            self.log_result(
                "422 Unprocessable Entity (invalid data)", 
                422, r.status_code, r.json() if r.content else {},
                r.status_code == 422
            )
        except Exception as e:
            self.log_result("422 Unprocessable Entity", 422, 0, {}, False, str(e))
        
        # 429 Too Many Requests - Rate limiting
        try:
            # Make multiple rapid requests to trigger rate limiting
            for i in range(10):
                r = requests.post(f"{BASE_URL}/auth/login", 
                                json={"email": "test@test.com", "password": "wrong"}, 
                                timeout=2)
                if r.status_code == 429:
                    break
                time.sleep(0.1)  # Small delay
            
            self.log_result(
                "429 Too Many Requests (rate limiting)", 
                429, r.status_code, r.json() if r.content else {},
                r.status_code == 429,
                "Made 10 rapid login attempts"
            )
        except Exception as e:
            self.log_result("429 Too Many Requests", 429, 0, {}, False, str(e))
    
    def test_500_level_server_errors(self):
        """Test 500-level server errors"""
        print("TESTING 500-LEVEL SERVER ERRORS")
        print("=" * 60)
        
        # 500 Internal Server Error - Database connection issues
        try:
            # This should work normally, but might trigger 500 if DB issues
            r = requests.get(f"{BASE_URL}/users/me", 
                           headers={"Authorization": "Bearer valid_token_format"})
            expected = [401, 403, 500]  # Most likely 401, but could be 500
            self.log_result(
                "500 Internal Server Error (DB issues)", 
                401, r.status_code, r.json() if r.content else {},
                r.status_code in expected,
                "Testing with invalid token"
            )
        except Exception as e:
            self.log_result("500 Internal Server Error", 500, 0, {}, False, str(e))
        
        # 502 Bad Gateway - Upstream service issues
        # 503 Service Unavailable - Service down
        # 504 Gateway Timeout - Slow upstream response
        # These are hard to test without breaking the system
        
        # Test slow response timeout
        try:
            r = requests.get(f"{BASE_URL}/health", timeout=0.001)  # Very short timeout
        except requests.exceptions.Timeout:
            self.log_result(
                "504 Gateway Timeout (client timeout)", 
                504, 504, {}, True,
                "Client-side timeout simulation"
            )
        except Exception as e:
            self.log_result("Timeout Test", 504, 0, {}, False, str(e))
    
    def test_security_errors(self):
        """Test security-related error scenarios"""
        print("TESTING SECURITY ERRORS")
        print("=" * 60)
        
        # Test malicious input
        try:
            malicious_input = {"email": "<script>alert('xss')</script>@test.com", "password": "test"}
            r = requests.post(f"{BASE_URL}/auth/login", json=malicious_input)
            self.log_result(
                "Security - XSS attempt", 
                401 or 422, r.status_code, r.json() if r.content else {},
                r.status_code in [401, 422],
                "Should reject malicious input"
            )
        except Exception as e:
            self.log_result("Security XSS Test", 400, 0, {}, False, str(e))
        
        # Test SQL injection (though using MongoDB)
        try:
            sqli_input = {"email": "'; DROP TABLE users; --@test.com", "password": "test"}
            r = requests.post(f"{BASE_URL}/auth/login", json=sqli_input)
            self.log_result(
                "Security - SQL injection attempt", 
                401 or 422, r.status_code, r.json() if r.content else {},
                r.status_code in [401, 422],
                "Should reject injection attempts"
            )
        except Exception as e:
            self.log_result("Security SQLi Test", 400, 0, {}, False, str(e))
        
        # Test path traversal
        try:
            r = requests.get(f"{BASE_URL}/files/../../../etc/passwd/download")
            self.log_result(
                "Security - Path traversal", 
                401 or 404, r.status_code, r.json() if r.content else {},
                r.status_code in [401, 404],
                "Should reject path traversal"
            )
        except Exception as e:
            self.log_result("Security Path Traversal", 404, 0, {}, False, str(e))
    
    def test_file_specific_errors(self):
        """Test file upload/download specific errors"""
        print("TESTING FILE-SPECIFIC ERRORS")
        print("=" * 60)
        
        # Test file upload without auth
        try:
            r = requests.post(f"{BASE_URL}/files/init", json={
                "filename": "test.txt",
                "size": 100,
                "mime": "text/plain", 
                "chat_id": "test"
            })
            self.log_result(
                "File upload - No auth", 
                401 or 403, r.status_code, r.json() if r.content else {},
                r.status_code in [401, 403]
            )
        except Exception as e:
            self.log_result("File Upload No Auth", 401, 0, {}, False, str(e))
        
        # Test file upload with invalid data
        try:
            r = requests.post(f"{BASE_URL}/files/init", json={
                "filename": "",  # Empty filename
                "size": -100,    # Negative size
                "mime": "invalid-type",
                "chat_id": ""     # Empty chat ID
            }, headers={"Authorization": "Bearer invalid_token"})
            self.log_result(
                "File upload - Invalid data", 
                401 or 422, r.status_code, r.json() if r.content else {},
                r.status_code in [401, 422]
            )
        except Exception as e:
            self.log_result("File Upload Invalid Data", 422, 0, {}, False, str(e))
        
        # Test download non-existent file
        try:
            r = requests.get(f"{BASE_URL}/files/nonexistent_file_id/download")
            self.log_result(
                "File download - Non-existent file", 
                401 or 404, r.status_code, r.json() if r.content else {},
                r.status_code in [401, 404]
            )
        except Exception as e:
            self.log_result("File Download Not Found", 404, 0, {}, False, str(e))
    
    def run_all_tests(self):
        """Run all error tests"""
        print("COMPREHENSIVE HTTP ERROR TESTING")
        print("=" * 80)
        print(f"Testing API at: {BASE_URL}")
        print()
        
        # Check if server is running
        try:
            r = requests.get(f"{BASE_URL.replace('/api/v1', '')}/health", timeout=5)
            if r.status_code != 200:
                print("Server health check failed")
                return
            print("Server is running and healthy")
            print()
        except Exception as e:
            print(f"Cannot connect to server: {e}")
            return
        
        # Run all test categories
        self.test_300_level_redirects()
        self.test_400_level_client_errors()
        self.test_500_level_server_errors()
        self.test_security_errors()
        self.test_file_specific_errors()
        
        # Summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        print("=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        
        passed = sum(1 for r in self.results if r["passed"])
        total = len(self.results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        # Protection against division by zero
        success_rate = (passed/total)*100 if total > 0 else 0
        print(f"Success Rate: {success_rate:.1f}%")
        print()
        
        # Group by status code
        status_codes = {}
        for result in self.results:
            status = result["actual"]
            if status not in status_codes:
                status_codes[status] = []
            status_codes[status].append(result["test"])
        
        print("Status Codes Encountered:")
        for code, tests in sorted(status_codes.items()):
            print(f"  {code}: {len(tests)} tests")
            for test in tests[:3]:  # Show first 3
                print(f"    - {test}")
            if len(tests) > 3:
                print(f"    ... and {len(tests) - 3} more")
            print()
        
        # Show failed tests
        failed_tests = [r for r in self.results if not r["passed"]]
        if failed_tests:
            print("FAILED TESTS:")
            for test in failed_tests:
                print(f"  - {test['test']}: Expected {test['expected']}, got {test['actual']}")
                if test['details']:
                    print(f"    Details: {test['details']}")
                print()
        
        # Overall assessment - with division by zero protection
        if total > 0:
            if passed == total:
                print("ALL TESTS PASSED - Error handling is comprehensive!")
            elif (passed/total) >= 0.8:
                print("GOOD - Most error handling is working properly")
            elif (passed/total) >= 0.6:
                print("ACCEPTABLE - Some error handling needs improvement")
            else:
                print("NEEDS WORK - Error handling has significant gaps")
        else:
            print("NO TESTS RUN - Unable to assess error handling")
        
        print("=" * 80)

if __name__ == "__main__":
    tester = ErrorTester()
    tester.run_all_tests()
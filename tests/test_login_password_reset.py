#!/usr/bin/env python3
"""
Comprehensive test for Login and Password Reset functionality
Tests authentication flow and password recovery
"""
import requests
import json
import sys
from datetime import datetime
from typing import Dict, Any

API_URL = "http://localhost:8000/api/v1"
TEST_USER_EMAIL = "mobimix33@gmail.com"
TEST_USER_PASSWORD = "Mayank@#03"

class TestRunner:
    def __init__(self):
        self.results = {}
        self.test_count = 0
        self.passed_count = 0
    
    def log_test(self, name: str, passed: bool, details: str = ""):
        """Log test result"""
        self.test_count += 1
        self.results[name] = passed
        
        status = "[PASS] PASS" if passed else "[FAIL] FAIL"
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] {status} - {name}")
        if details:
            print(f"         └─ {details}")
        
        if passed:
            self.passed_count += 1
    
    def test_server_health(self) -> bool:
        """Test if server is running"""
        print("\n[TEST] Checking server health...")
        try:
            response = requests.get(f"{API_URL}/health", timeout=5)
            passed = response.status_code == 200
            self.log_test("Server Health", passed, f"Status: {response.status_code}")
            return passed
        except Exception as e:
            self.log_test("Server Health", False, f"Error: {e}")
            return False
    
    def test_login_success(self) -> bool:
        """Test successful login"""
        print("\n[TEST] Testing successful login...")
        try:
            payload = {
                "email": TEST_USER_EMAIL,
                "password": TEST_USER_PASSWORD
            }
            response = requests.post(
                f"{API_URL}/auth/login",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                has_token = "access_token" in data and "refresh_token" in data
                self.log_test(
                    "Login Success",
                    has_token,
                    f"Status: {response.status_code}, Has tokens: {has_token}"
                )
                return has_token
            else:
                error_msg = response.json().get("detail", "Unknown error")
                self.log_test("Login Success", False, f"Status: {response.status_code}, Error: {error_msg}")
                return False
        except Exception as e:
            self.log_test("Login Success", False, f"Exception: {e}")
            return False
    
    def test_login_wrong_password(self) -> bool:
        """Test login with wrong password"""
        print("\n[TEST] Testing login with wrong password...")
        try:
            payload = {
                "email": TEST_USER_EMAIL,
                "password": "WrongPassword123"
            }
            response = requests.post(
                f"{API_URL}/auth/login",
                json=payload,
                timeout=10
            )
            
            passed = response.status_code == 401
            error_msg = response.json().get("detail", "Unknown")
            self.log_test(
                "Login Wrong Password",
                passed,
                f"Status: {response.status_code}, Message: {error_msg}"
            )
            return passed
        except Exception as e:
            self.log_test("Login Wrong Password", False, f"Exception: {e}")
            return False
    
    def test_login_nonexistent_user(self) -> bool:
        """Test login with non-existent email"""
        print("\n[TEST] Testing login with non-existent user...")
        try:
            payload = {
                "email": "nonexistent@example.com",
                "password": "Password123"
            }
            response = requests.post(
                f"{API_URL}/auth/login",
                json=payload,
                timeout=10
            )
            
            passed = response.status_code == 401
            error_msg = response.json().get("detail", "Unknown")
            self.log_test(
                "Login Nonexistent User",
                passed,
                f"Status: {response.status_code}, Message: {error_msg}"
            )
            return passed
        except Exception as e:
            self.log_test("Login Nonexistent User", False, f"Exception: {e}")
            return False
    
    def test_forgot_password(self) -> bool:
        """Test forgot password endpoint"""
        print("\n[TEST] Testing forgot password request...")
        try:
            payload = {"email": TEST_USER_EMAIL}
            response = requests.post(
                f"{API_URL}/auth/forgot-password",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                success = data.get("success", False)
                email_sent = data.get("email_sent", False)
                self.log_test(
                    "Forgot Password Request",
                    success,
                    f"Status: {response.status_code}, Email sent: {email_sent}"
                )
                return success
            else:
                error_msg = response.json().get("detail", "Unknown error")
                self.log_test(
                    "Forgot Password Request",
                    False,
                    f"Status: {response.status_code}, Error: {error_msg}"
                )
                return False
        except Exception as e:
            self.log_test("Forgot Password Request", False, f"Exception: {e}")
            return False
    
    def test_forgot_password_invalid_email(self) -> bool:
        """Test forgot password with invalid email"""
        print("\n[TEST] Testing forgot password with invalid email...")
        try:
            payload = {"email": "notanemail"}
            response = requests.post(
                f"{API_URL}/auth/forgot-password",
                json=payload,
                timeout=10
            )
            
            passed = response.status_code in [400, 422]
            self.log_test(
                "Forgot Password Invalid Email",
                passed,
                f"Status: {response.status_code}"
            )
            return passed
        except Exception as e:
            self.log_test("Forgot Password Invalid Email", False, f"Exception: {e}")
            return False
    
    def test_forgot_password_nonexistent(self) -> bool:
        """Test forgot password with non-existent email (should return generic message)"""
        print("\n[TEST] Testing forgot password with non-existent email...")
        try:
            payload = {"email": "nonexistent@example.com"}
            response = requests.post(
                f"{API_URL}/auth/forgot-password",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                # Should return generic message (security: prevent user enumeration)
                has_generic_msg = "If an account exists" in data.get("message", "")
                self.log_test(
                    "Forgot Password Nonexistent User",
                    has_generic_msg,
                    f"Status: {response.status_code}, Generic message: {has_generic_msg}"
                )
                return has_generic_msg
            else:
                self.log_test("Forgot Password Nonexistent User", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Forgot Password Nonexistent User", False, f"Exception: {e}")
            return False
    
    def run_all_tests(self):
        """Run all tests"""
        print("=" * 70)
        print("LOGIN & PASSWORD RESET COMPREHENSIVE TEST SUITE")
        print("=" * 70)
        
        # Check server first
        if not self.test_server_health():
            print("\n[FAIL] Server is not running. Cannot continue tests.")
            sys.exit(1)
        
        # Run all tests
        self.test_login_success()
        self.test_login_wrong_password()
        self.test_login_nonexistent_user()
        self.test_forgot_password()
        self.test_forgot_password_invalid_email()
        self.test_forgot_password_nonexistent()
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        for test_name, passed in self.results.items():
            status = "[PASS]" if passed else "[FAIL]"
            print(f"{status} {test_name}")
        
        print(f"\nTotal Tests: {self.test_count}")
        print(f"Passed: {self.passed_count}")
        print(f"Failed: {self.test_count - self.passed_count}")
        print(f"Success Rate: {(self.passed_count / self.test_count * 100):.1f}%")
        
        if self.passed_count == self.test_count:
            print("\n[PASS] All tests passed!")
            return 0
        else:
            print(f"\n⚠️  {self.test_count - self.passed_count} test(s) failed")
            return 1

if __name__ == "__main__":
    runner = TestRunner()
    exit_code = runner.run_all_tests()
    sys.exit(exit_code)

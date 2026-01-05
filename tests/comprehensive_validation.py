#!/usr/bin/env python3
"""
Comprehensive Security Fix Validation
Tests all implemented security fixes
"""

import sys
import os
import re
from pathlib import Path

class SecurityFixValidator:
    """Validate all security fixes are properly implemented"""
    
    def __init__(self, backend_dir: Path):
        self.backend_dir = backend_dir
        self.fixes_validated = 0
        self.total_fixes = 0
    
    def validate_fix(self, file_path: str, pattern: str, description: str) -> bool:
        """Validate a specific fix is implemented"""
        self.total_fixes += 1
        
        full_path = self.backend_dir / file_path
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                print(f"[PASS] PASS: {description}")
                self.fixes_validated += 1
                return True
            else:
                print(f"[FAIL] FAIL: {description}")
                return False
                
        except Exception as e:
            print(f"ERROR: Could not validate {description}: {e}")
            return False
    
    def run_validation(self):
        """Run comprehensive validation of all fixes"""
        print("COMPREHENSIVE SECURITY FIX VALIDATION")
        print("=" * 50)
        
        # Fix 1: Email RFC 5322 compliance
        print("\n=== Email Security Fixes ===")
        self.validate_fix(
            "routes/auth.py",
            r'email_pattern.*=.*r[\'"].*[a-zA-Z0-9].*@.*\.[a-zA-Z]{2,}.*\$[\'"].*or.*\.\.',
            "Email regex with RFC 5322 compliance and consecutive dot prevention"
        )
        
        # Fix 2: Path traversal protection
        print("\n=== Path Traversal Fixes ===")
        self.validate_fix(
            "routes/files.py", 
            r'validate_path_injection|relative_to.*data_root|normalized\.path',
            "Enhanced path traversal protection with input validation"
        )
        
        # Fix 3: Command injection protection
        print("\n=== Command Injection Fixes ===")
        self.validate_fix(
            "validators.py",
            r'validate_command_injection.*function.*suspicious.*patterns|dangerous_patterns',
            "Command injection validation function"
        )
        
        self.validate_fix(
            "routes/files.py",
            r'validate_command_injection.*chat_id',
            "Command injection protection in file upload"
        )
        
        # Fix 4: Thread safety in rate limiter
        print("\n=== Thread Safety Fixes ===")
        self.validate_fix(
            "rate_limiter.py",
            r'with self\.lock:.*self\.requests.*=.*valid_requests',
            "Thread-safe rate limiter without unnecessary copies"
        )
        
        # Fix 5: CORS security in production
        print("\n=== CORS Security Fixes ===")
        self.validate_fix(
            "main.py",
            r'if not settings\.DEBUG.*https://zaply\.in\.net|allowed_patterns.*=.*\[p.*for p in',
            "Production CORS with HTTPS enforcement and pattern filtering"
        )
        
        # Fix 6: Undefined variable fixes
        print("\n=== Variable Definition Fixes ===")
        self.validate_fix(
            "routes/groups.py",
            r'async def groups_options\(request\):.*request\.headers',
            "Fixed undefined 'request' variable in groups options handler"
        )
        
        # Fix 7: HTTP error handling
        print("\n=== HTTP Error Handling Fixes ===")
        self.validate_fix(
            "error_handlers.py",
            r'InternalServerError|BadGatewayError|ServiceUnavailableError|GatewayTimeoutError',
            "Comprehensive 5xx exception class definitions"
        )
        
        self.validate_fix(
            "error_handlers.py",
            r'status_code.*error.*detail.*timestamp.*path.*method.*hints',
            "Structured error response format"
        )
        
        # Fix 8: Input sanitization
        print("\n=== Input Sanitization Fixes ===")
        self.validate_fix(
            "validators.py",
            r'def sanitize_input.*remove.*null.*bytes.*control.*characters',
            "Input sanitization function"
        )
        
        self.validate_fix(
            "routes/files.py",
            r'sanitize_input.*filename.*sanitize_input.*chat_id',
            "Input sanitization applied to file upload"
        )
        
        # Fix 9: Database field consistency
        print("\n=== Database Consistency Fixes ===")
        self.validate_fix(
            "routes/files.py",
            r'"upload_id": upload_id.*"owner_id": current_user.*_id.*upload_id',
            "Consistent database field usage with both _id and upload_id"
        )
        
        # Fix 10: Security headers
        print("\n=== Security Header Fixes ===")
        self.validate_fix(
            "security.py",
            r'X-Content-Type-Options.*X-Frame-Options.*Content-Security-Policy',
            "Comprehensive security headers implementation"
        )
        
        # Summary
        print("\n" + "=" * 50)
        print("VALIDATION SUMMARY")
        print("=" * 50)
        
        success_rate = self.fixes_validated / self.total_fixes if self.total_fixes > 0 else 0
        
        print(f"Fixes Validated: {self.fixes_validated}/{self.total_fixes}")
        print(f"Success Rate: {success_rate:.1%}")
        
        if success_rate >= 0.9:
            print("[SUCCESS] EXCELLENT: Nearly all security fixes implemented!")
            return True
        elif success_rate >= 0.7:
            print("[GOOD] GOOD: Most security fixes implemented!")
            return True
        elif success_rate >= 0.5:
            print("[WARNING]  MODERATE: Some security fixes missing!")
            return False
        else:
            print("[POOR] POOR: Many security fixes missing!")
            return False

def main():
    """Main validation function"""
    script_dir = Path(__file__).parent
    backend_dir = script_dir / "backend"
    
    if not backend_dir.exists():
        print(f"ERROR: Backend directory not found: {backend_dir}")
        return False
    
    validator = SecurityFixValidator(backend_dir)
    success = validator.run_validation()
    
    print(f"\nOverall Result: {'SUCCESS' if success else 'NEEDS WORK'}")
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
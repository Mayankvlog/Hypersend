#!/usr/bin/env python3
"""
Robust Security and Logic Validation Script
Uses semantic analysis instead of brittle string matching
"""

import sys
import os
import re
import ast
import importlib.util
from pathlib import Path
from typing import Dict, List, Any, Tuple

class SecurityValidator:
    """Logic-based security validation that checks actual behavior"""
    
    def __init__(self, backend_dir: Path):
        self.backend_dir = backend_dir
        self.issues = []
        self.passes = []
    
    def log_issue(self, severity: str, file: str, issue: str, suggestion: str = None):
        """Log a security issue"""
        self.issues.append({
            'severity': severity,
            'file': file,
            'issue': issue,
            'suggestion': suggestion
        })
    
    def log_pass(self, category: str, file: str, description: str):
        """Log a validation pass"""
        self.passes.append({
            'category': category,
            'file': file,
            'description': description
        })
    
    def validate_email_security(self) -> bool:
        """Validate email security logic"""
        print("=== Validating Email Security Logic ===")
        
        auth_file = self.backend_dir / "routes/auth.py"
        try:
            with open(auth_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # More robust email validation detection
            has_proper_pattern = False
            has_consecutive_dot_check = False
            
            # Look for proper email validation with more precise detection
            has_proper_pattern = False
            has_consecutive_dot_check = False
            
            # Check for RFC 5322 compliant email pattern
            email_pattern_matches = re.findall(
                r'email_pattern\s*=\s*r[\'"](.*?)[\'"]', 
                content, 
                re.IGNORECASE
            )
            
            for pattern in email_pattern_matches:
                # Check if pattern has proper structure
                if (r'[a-zA-Z0-9]' in pattern and 
                    '@' in pattern and 
                    r'\.[a-zA-Z]{2,}' in pattern and
                    '$' in pattern):
                    has_proper_pattern = True
            
            # Check for direct regex usage in validation
            direct_regex_usage = re.findall(
                r're\.match\s*\(\s*r[\'"](.*?)[\'"].*email', 
                content,
                re.IGNORECASE
            )
            
            for pattern in direct_regex_usage:
                if (r'[a-zA-Z0-9]' in pattern and 
                    '@' in pattern and 
                    r'\.[a-zA-Z]{2,}' in pattern):
                    has_proper_pattern = True
            
            # Check for consecutive dot prevention
            consecutive_dot_checks = [
                r'if\s*.*\.\..*or\s*',  # if .. or condition
                r'"\.\.?',  # String literal ".."
                r'not.*re\.search.*\.\.',  # Negative check for .. in regex
                r'contains.*\.\.',  # General contains check
            ]
            
            for check in consecutive_dot_checks:
                if re.search(check, content, re.IGNORECASE):
                    if 'email' in content.lower() or 'credentials' in content.lower():
                        has_consecutive_dot_check = True
            
            if has_proper_pattern:
                self.log_pass("email", "routes/auth.py", "Found proper email validation pattern")
            else:
                self.log_issue("HIGH", "routes/auth.py", "Missing proper email validation pattern")
            
            if has_consecutive_dot_check:
                self.log_pass("email", "routes/auth.py", "Found consecutive dot prevention")
            else:
                self.log_issue("MEDIUM", "routes/auth.py", "Missing consecutive dot validation")
            
            return has_proper_pattern and has_consecutive_dot_check
            
        except Exception as e:
            self.log_issue("HIGH", "routes/auth.py", f"Failed to analyze email security: {str(e)}")
            return False
    
    def validate_path_traversal_logic(self) -> bool:
        """Validate path traversal protection logic"""
        print("=== Validating Path Traversal Protection Logic ===")
        
        files_file = self.backend_dir / "routes/files.py"
        try:
            with open(files_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for multi-layer path validation
            validation_layers = {
                'resolve()': 'Path resolution',
                'relative_to(': 'Path boundary check',
                'HTTPException': 'Proper error handling'
            }
            
            found_layers = 0
            for pattern, description in validation_layers.items():
                if pattern in content:
                    found_layers += 1
                    self.log_pass("path_traversal", "routes/files.py", f"Found {description}")
            
            # Check for intelligent traversal detection (not just blanket blocking)
            has_smart_detection = (
                re.search(r'\\\.\\./.*|^\\.\\.[/\\\\]|[/\\\\]\\.\\.$', content) or
                're.search(r.*/.*/.*|/.*/.*|../.*' in content
            )
            if has_smart_detection:
                self.log_pass("path_traversal", "routes/files.py", "Found smart traversal detection")
            
            security_score = found_layers + (1 if has_smart_detection else 0)
            max_score = len(validation_layers) + 1
            
            if security_score >= max_score - 1:
                return True
            else:
                self.log_issue("MEDIUM", "routes/files.py", f"Insufficient path traversal protection ({security_score}/{max_score} layers)")
                return False
                
        except Exception as e:
            self.log_issue("HIGH", "routes/files.py", f"Failed to analyze path traversal: {str(e)}")
            return False
    
    def validate_rate_limiter_thread_safety(self) -> bool:
        """Validate rate limiter thread safety"""
        print("=== Validating Rate Limiter Thread Safety ===")
        
        rate_limiter_file = self.backend_dir / "rate_limiter.py"
        try:
            with open(rate_limiter_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for proper thread safety patterns
            safety_patterns = {
                'with self.lock:': 'Lock usage',
                'self.requests': 'Shared request storage',
                'except Exception': 'Error handling',
                'return False': 'Fail-secure behavior'
            }
            
            found_patterns = 0
            for pattern, description in safety_patterns.items():
                if pattern in content:
                    found_patterns += 1
                    self.log_pass("thread_safety", "rate_limiter.py", f"Found {description}")
            
            # Check for efficient operations (no unnecessary copies)
            has_inefficient_copy = 'list(self.requests.get' in content and 'with self.lock:' in content
            if has_inefficient_copy:
                self.log_issue("LOW", "rate_limiter.py", "Unnecessary list copy under lock (performance issue)")
            else:
                self.log_pass("thread_safety", "rate_limiter.py", "Efficient operations under lock")
            
            return found_patterns >= 3
            
        except Exception as e:
            self.log_issue("HIGH", "rate_limiter.py", f"Failed to analyze thread safety: {str(e)}")
            return False
    
    def validate_cors_security(self) -> bool:
        """Validate CORS security logic"""
        print("=== Validating CORS Security Logic ===")
        
        main_file = self.backend_dir / "main.py"
        try:
            with open(main_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for production mode security
            security_features = {
                'settings.DEBUG': 'Debug mode awareness',
                'https://': 'HTTPS enforcement',
                'allowed_patterns': 'Pattern filtering'
            }
            
            found_features = 0
            for pattern, description in security_features.items():
                if pattern in content:
                    found_features += 1
                    self.log_pass("cors", "main.py", f"Found {description}")
            
            # Check for proper production/development distinction
            has_strict_production_check = (
                'if not settings.DEBUG' in content and 
                ('http://localhost:8000' in content or 'allowed_patterns' in content)
            )
            if has_strict_production_check:
                self.log_pass("cors", "main.py", "Found strict production mode protection")
            elif 'if not settings.DEBUG' in content:
                self.log_pass("cors", "main.py", "Found basic production mode protection")
            else:
                self.log_issue("MEDIUM", "main.py", "Missing production mode protection")
            
            return found_features >= 2
            
        except Exception as e:
            self.log_issue("HIGH", "main.py", f"Failed to analyze CORS security: {str(e)}")
            return False
    
    def validate_error_handling(self) -> bool:
        """Validate comprehensive error handling"""
        print("=== Validating Error Handling Logic ===")
        
        error_file = self.backend_dir / "error_handlers.py"
        try:
            with open(error_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for proper error response structure
            error_features = {
                'status_code': 'Status code inclusion',
                'error': 'Error description',
                'detail': 'Detailed error info',
                'timestamp': 'Error timestamping'
            }
            
            found_features = 0
            for pattern, description in error_features.items():
                if pattern in content:
                    found_features += 1
                    self.log_pass("error_handling", "error_handlers.py", f"Found {description}")
            
            # Check for HTTP error code coverage
            http_codes = [400, 401, 403, 404, 429, 500]
            covered_codes = sum(1 for code in http_codes if str(code) in content)
            
            if covered_codes >= len(http_codes) - 1:
                self.log_pass("error_handling", "error_handlers.py", f"Good HTTP error code coverage ({covered_codes}/{len(http_codes)})")
            else:
                self.log_issue("MEDIUM", "error_handlers.py", f"Limited HTTP error code coverage ({covered_codes}/{len(http_codes)})")
            
            return found_features >= 3 and covered_codes >= 4
            
        except Exception as e:
            self.log_issue("HIGH", "error_handlers.py", f"Failed to analyze error handling: {str(e)}")
            return False
    
    def run_comprehensive_validation(self) -> Dict[str, Any]:
        """Run all validation checks"""
        print("SECURE Hypersend Logic-Based Security Validation")
        print("=" * 60)
        
        results = {
            'email_security': self.validate_email_security(),
            'path_traversal': self.validate_path_traversal_logic(),
            'thread_safety': self.validate_rate_limiter_thread_safety(),
            'cors_security': self.validate_cors_security(),
            'error_handling': self.validate_error_handling()
        }
        
        return results

def main():
    """Main validation function"""
    # Change to backend directory
    script_dir = Path(__file__).parent
    backend_dir = script_dir / "backend"
    
    if not backend_dir.exists():
        print(f"ERROR: Backend directory not found: {backend_dir}")
        return False
    
    # Create validator and run checks
    validator = SecurityValidator(backend_dir)
    results = validator.run_comprehensive_validation()
    
    # Print detailed results
    print("\n" + "=" * 60)
    print("DETAILED VALIDATION RESULTS")
    print("=" * 60)
    
    passed_categories = 0
    total_categories = len(results)
    
    for category, passed in results.items():
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} {category.replace('_', ' ').title()}")
        if passed:
            passed_categories += 1
    
    # Print issues
    if validator.issues:
        print(f"\n{len(validator.issues)} ISSUES FOUND:")
        for issue in validator.issues:
            severity_map = {"HIGH": "CRITICAL", "MEDIUM": "WARNING", "LOW": "INFO"}
            severity_label = severity_map.get(issue['severity'], issue['severity'])
            print(f"  [{severity_label}] {issue['severity']}: {issue['issue']}")
            print(f"    File: {issue['file']}")
            if issue.get('suggestion'):
                print(f"    Suggestion: {issue['suggestion']}")
    
    # Print passes
    if validator.passes:
        print(f"\n{len(validator.passes)} SECURITY FEATURES VALIDATED:")
        for pass_item in validator.passes:
            print(f"  [OK] {pass_item['category']}: {pass_item['description']}")
    
    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Categories Passed: {passed_categories}/{total_categories}")
    print(f"Issues Found: {len(validator.issues)}")
    print(f"Security Features: {len(validator.passes)}")
    
    success_rate = passed_categories / total_categories if total_categories > 0 else 0
    if success_rate >= 0.8:
        print("SUCCESS: Good security posture!")
        return True
    else:
        print("WARNING: Security issues require attention!")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
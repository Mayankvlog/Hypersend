#!/usr/bin/env python3
"""
Zaply VPS Connectivity Fix Validation
Checks that all code changes have been applied correctly
"""

import os
import sys
from pathlib import Path
from typing import List, Tuple

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text.center(70)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}\n")

def print_check(passed: bool, text: str):
    status = f"{Colors.GREEN}[PASS] PASS{Colors.RESET}" if passed else f"{Colors.RED}[FAIL] FAIL{Colors.RESET}"
    print(f"  {status} {text}")
    return passed

def check_file_content(file_path: str, expected_strings: List[str], description: str) -> bool:
    """Check if file contains expected strings"""
    try:
        if not os.path.exists(file_path):
            print_check(False, f"{description}: File not found ({file_path})")
            return False
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        all_found = True
        for expected in expected_strings:
            if expected not in content:
                all_found = False
                print_check(False, f"{description}: Missing '{expected[:50]}...'")
            else:
                print_check(True, f"{description}: Found '{expected[:50]}...'")
        
        return all_found
    except Exception as e:
        print_check(False, f"{description}: Error reading file - {str(e)}")
        return False

def validate_fixes():
    """Validate all VPS connectivity fixes"""
    print_header("Zaply VPS Connectivity Fix Validation")
    
    results = []
    
    # Check 1: Frontend API URL
    print(f"{Colors.BOLD}{Colors.BLUE}→ Frontend API Configuration{Colors.RESET}")
    print(f"{Colors.BLUE}{'-'*60}{Colors.RESET}")
    
    checks_1 = check_file_content(
        'frontend/lib/core/constants/api_constants.dart',
        [
            "defaultValue: 'http://localhost:8000/api/v1'",
            "if (uri == null) return 'http://localhost:8000';"
        ],
        "Frontend API URL corrected"
    )
    results.append(checks_1)
    print()
    
    # Check 2: Backend Configuration
    print(f"{Colors.BOLD}{Colors.BLUE}→ Backend API Configuration{Colors.RESET}")
    print(f"{Colors.BLUE}{'-'*60}{Colors.RESET}")
    
    checks_2a = check_file_content(
        'backend/config.py',
        [
            'API_PORT: int = int(os.getenv("API_PORT", "8000"))',
            'API_BASE_URL: str = os.getenv("API_BASE_URL", "http://localhost:8000/api/v1")'
        ],
        "Backend API port and URL"
    )
    results.append(checks_2a)
    print()
    
    # Check 3: Enhanced Error Messages
    print(f"{Colors.BOLD}{Colors.BLUE}→ Frontend Error Handling{Colors.RESET}")
    print(f"{Colors.BLUE}{'-'*60}{Colors.RESET}")
    
    checks_3 = check_file_content(
        'frontend/lib/data/services/api_service.dart',
        [
            "if (error.message?.contains('HandshakeException') == true)",
            "API endpoint (${ApiConstants.baseUrl}) is reachable"
        ],
        "Enhanced error messages"
    )
    results.append(checks_3)
    print()
    
    # Check 4: Health Endpoint
    print(f"{Colors.BOLD}{Colors.BLUE}→ Backend Health Endpoint{Colors.RESET}")
    print(f"{Colors.BLUE}{'-'*60}{Colors.RESET}")
    
    checks_4 = check_file_content(
        'backend/main.py',
        [
            '"api_base_url": settings.API_BASE_URL',
            '"api_port": settings.API_PORT',
            '"debug": settings.DEBUG'
        ],
        "Enhanced health endpoint"
    )
    results.append(checks_4)
    print()
    
    # Check 5: Test Script
    print(f"{Colors.BOLD}{Colors.BLUE}→ Diagnostic Tools{Colors.RESET}")
    print(f"{Colors.BLUE}{'-'*60}{Colors.RESET}")
    
    test_script_exists = os.path.exists('test_vps_connectivity.py')
    print_check(test_script_exists, "VPS connectivity test script exists")
    results.append(test_script_exists)
    
    deploy_script_exists = os.path.exists('deploy_vps_fix.sh')
    print_check(deploy_script_exists, "VPS deployment script exists")
    results.append(deploy_script_exists)
    
    doc_exists = os.path.exists('VPS_CONNECTIVITY_FIX.md')
    print_check(doc_exists, "VPS connectivity fix documentation exists")
    results.append(doc_exists)
    print()
    
    # Summary
    print_header("VALIDATION SUMMARY")
    
    total = len(results)
    passed = sum(results)
    
    print(f"Results: {passed}/{total} checks passed")
    print()
    
    if all(results):
        print(f"{Colors.GREEN}{Colors.BOLD}[PASS] All fixes validated successfully!{Colors.RESET}")
        print()
        print("Next Steps:")
        print("  1. Rebuild frontend with:")
        print("     flutter build web --release --dart-define=API_BASE_URL=http://localhost:8000/api/v1")
        print()
        print("  2. Deploy to VPS:")
        print("     chmod +x deploy_vps_fix.sh")
        print("     ./deploy_vps_fix.sh")
        print()
        print("  3. Verify connectivity:")
        print("     python test_vps_connectivity.py")
        print()
        return 0
    else:
        print(f"{Colors.RED}{Colors.BOLD}[FAIL] Some fixes are missing!{Colors.RESET}")
        print()
        print("Please review the failed checks above and apply the fixes from:")
        print("  VPS_CONNECTIVITY_FIX.md")
        print()
        return 1

def main():
    # Check we're in the right directory
    if not os.path.exists('backend/config.py'):
        print(f"{Colors.RED}Error: Please run this script from the hypersend project root{Colors.RESET}")
        print(f"{Colors.YELLOW}Current directory: {os.getcwd()}{Colors.RESET}")
        return 1
    
    return validate_fixes()

if __name__ == "__main__":
    sys.exit(main())

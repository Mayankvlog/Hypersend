#!/usr/bin/env python3
"""
Test VPS Connectivity and API Endpoint Configuration
Diagnoses connection issues with zaply.in.net backend server
"""

import requests
import json
import sys
from urllib.parse import urljoin
from datetime import datetime
from typing import Dict, Tuple, Optional

# Test configuration
PROD_DOMAIN = "zaply.in.net"
VPS_IP = "139.59.82.105"
API_BASE_URL = f"https://{PROD_DOMAIN}/api/v1"
HEALTH_ENDPOINT = f"https://{PROD_DOMAIN}/health"

# Test patterns for common connection issues
TEST_URLS = [
    # HTTPS endpoints (production)
    (f"https://{PROD_DOMAIN}/health", "HTTPS Health Check (Domain)"),
    (f"https://{PROD_DOMAIN}/api/v1/auth/login", "HTTPS API Login Endpoint"),
    (f"https://{VPS_IP}/health", "HTTPS Health Check (IP)"),
    
    # HTTP endpoints (development)
    (f"http://{PROD_DOMAIN}/health", "HTTP Health Check (Domain)"),
    (f"http://{PROD_DOMAIN}:8000/health", "HTTP Port 8000 (Domain)"),
    (f"http://{VPS_IP}:8000/health", "HTTP Port 8000 (IP)"),
    
    # Direct backend port
    (f"http://localhost:8000/health", "Local Backend Port 8000"),
]

class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text.center(70)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}\n")

def print_section(text: str):
    """Print formatted section"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}→ {text}{Colors.RESET}")
    print(f"{Colors.BLUE}{'-'*60}{Colors.RESET}")

def print_success(text: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")

def print_error(text: str):
    """Print error message"""
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")

def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")

def print_info(text: str):
    """Print info message"""
    print(f"{Colors.WHITE}ℹ {text}{Colors.RESET}")

def test_endpoint(url: str, description: str, timeout: int = 5) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """Test a single endpoint"""
    try:
        print(f"  Testing: {Colors.CYAN}{description}{Colors.RESET}")
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,  # Skip SSL verification for self-signed certs
            headers={"User-Agent": "Zaply-Connectivity-Test/1.0"}
        )
        
        if response.status_code == 200:
            try:
                data = response.json()
                print_success(f"{description} - Status: {response.status_code}")
                return True, data, None
            except json.JSONDecodeError:
                print_success(f"{description} - Status: {response.status_code} (non-JSON response)")
                return True, {"text": response.text[:100]}, None
        else:
            print_error(f"{description} - Status: {response.status_code}")
            return False, None, f"HTTP {response.status_code}"
            
    except requests.exceptions.Timeout:
        print_error(f"{description} - Connection timeout")
        return False, None, "Timeout (30s)"
    except requests.exceptions.ConnectionError as e:
        print_error(f"{description} - Connection refused")
        return False, None, "Connection refused"
    except requests.exceptions.SSLError as e:
        print_warning(f"{description} - SSL Certificate error")
        return False, None, f"SSL Error: {str(e)[:50]}"
    except Exception as e:
        print_error(f"{description} - {type(e).__name__}")
        return False, None, str(e)[:100]

def check_dns_resolution() -> bool:
    """Check if domain resolves to IP"""
    try:
        import socket
        print_section("DNS Resolution Check")
        
        try:
            ip = socket.gethostbyname(PROD_DOMAIN)
            print_info(f"Domain: {PROD_DOMAIN}")
            print_success(f"Resolves to: {ip}")
            if ip == VPS_IP:
                print_success(f"IP matches expected VPS IP: {VPS_IP}")
                return True
            else:
                print_warning(f"IP {ip} doesn't match expected {VPS_IP}")
                return True  # Still OK, might be different setup
        except socket.gaierror:
            print_error(f"Cannot resolve {PROD_DOMAIN}")
            print_warning("Check DNS settings or domain registration")
            return False
            
    except Exception as e:
        print_error(f"DNS check failed: {str(e)}")
        return False

def test_endpoints_batch() -> Dict[str, Tuple[bool, Optional[Dict], Optional[str]]]:
    """Test all endpoints"""
    print_section("API Endpoint Connectivity Tests")
    
    results = {}
    for url, description in TEST_URLS:
        success, data, error = test_endpoint(url, description)
        results[description] = (success, data, error)
        print()
    
    return results

def check_cors_configuration() -> bool:
    """Check CORS headers"""
    print_section("CORS Configuration Check")
    
    try:
        response = requests.options(
            f"{API_BASE_URL}/auth/login",
            timeout=5,
            verify=False,
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            }
        )
        
        cors_headers = {
            "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
            "Access-Control-Allow-Methods": response.headers.get("Access-Control-Allow-Methods"),
            "Access-Control-Allow-Headers": response.headers.get("Access-Control-Allow-Headers"),
        }
        
        print_info("CORS Headers from server:")
        for header, value in cors_headers.items():
            if value:
                print_success(f"  {header}: {value}")
            else:
                print_warning(f"  {header}: Not set")
        
        if cors_headers["Access-Control-Allow-Origin"]:
            return True
        else:
            print_error("CORS is not properly configured")
            return False
            
    except Exception as e:
        print_warning(f"Could not test CORS: {str(e)}")
        return False

def test_api_functionality() -> bool:
    """Test basic API functionality"""
    print_section("API Functionality Test")
    
    try:
        # Test login endpoint (should return 422 or 400 for invalid input)
        print_info("Testing login endpoint with invalid credentials...")
        response = requests.post(
            f"{API_BASE_URL}/auth/login",
            json={"email": "test@example.com", "password": "test"},
            timeout=5,
            verify=False
        )
        
        if response.status_code in [400, 422, 401, 404]:
            print_success(f"Login endpoint accessible (Status: {response.status_code})")
            print_info(f"Response: {response.text[:200]}")
            return True
        elif response.status_code == 200:
            print_warning("Login endpoint returned 200 (unexpected)")
            return True
        else:
            print_error(f"Login endpoint error (Status: {response.status_code})")
            return False
            
    except Exception as e:
        print_error(f"API test failed: {str(e)}")
        return False

def generate_report(results: Dict) -> None:
    """Generate test report"""
    print_header("CONNECTIVITY TEST REPORT")
    
    successful = sum(1 for success, _, _ in results.values() if success)
    total = len(results)
    success_rate = (successful / total * 100) if total > 0 else 0
    
    print_info(f"Test Results: {successful}/{total} endpoints reachable ({success_rate:.1f}%)")
    print()
    
    # Successful connections
    successful_endpoints = [desc for desc, (success, _, _) in results.items() if success]
    if successful_endpoints:
        print_success(f"Successful Connections ({len(successful_endpoints)}):")
        for endpoint in successful_endpoints:
            print(f"  • {endpoint}")
    
    print()
    
    # Failed connections
    failed_endpoints = [(desc, error) for desc, (success, _, error) in results.items() if not success]
    if failed_endpoints:
        print_error(f"Failed Connections ({len(failed_endpoints)}):")
        for endpoint, error in failed_endpoints:
            print(f"  • {endpoint}")
            if error:
                print(f"    Error: {error}")
    
    print()

def print_recommendations() -> None:
    """Print recommendations based on test results"""
    print_section("Recommendations")
    
    print(f"""
{Colors.BOLD}Configuration Checklist:{Colors.RESET}

1. {Colors.YELLOW}Frontend API URL Configuration:{Colors.RESET}
   • Check: frontend/lib/core/constants/api_constants.dart
   • Default should be: https://zaply.in.net/api/v1
   • Build with: --dart-define=API_BASE_URL=https://zaply.in.net/api/v1

2. {Colors.YELLOW}Backend API Configuration:{Colors.RESET}
   • Check: backend/config.py
   • API_BASE_URL must be: https://zaply.in.net/api/v1
   • API_PORT should be: 8000 (behind Nginx proxy)

3. {Colors.YELLOW}Nginx Configuration:{Colors.RESET}
   • Nginx proxies /api/ to backend:8000
   • Ensure HTTPS certificates are valid
   • Check: /etc/letsencrypt/live/zaply.in.net/

4. {Colors.YELLOW}VPS Backend Service:{Colors.RESET}
   • Ensure FastAPI is running on port 8000
   • Verify MongoDB is accessible
   • Check logs: docker logs hypersend_backend

5. {Colors.YELLOW}Network/Firewall:{Colors.RESET}
   • Port 443 (HTTPS) must be open
   • Port 80 (HTTP) must redirect to HTTPS
   • Port 8000 internal communication only (behind Nginx)

{Colors.BOLD}Next Steps:{Colors.RESET}
   1. Rebuild frontend with correct API_BASE_URL
   2. Verify backend is running: curl https://zaply.in.net/health
   3. Check Docker containers: docker-compose ps
   4. View backend logs: docker-compose logs -f backend
""")

def main():
    """Main test execution"""
    print_header("ZAPLY VPS CONNECTIVITY DIAGNOSTICS")
    
    print_info(f"Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info(f"Production Domain: {PROD_DOMAIN}")
    print_info(f"VPS IP: {VPS_IP}")
    print_info(f"API Base URL: {API_BASE_URL}")
    
    # Run tests
    dns_ok = check_dns_resolution()
    results = test_endpoints_batch()
    cors_ok = check_cors_configuration()
    api_ok = test_api_functionality()
    
    # Generate report
    generate_report(results)
    
    # Print recommendations
    print_recommendations()
    
    # Final summary
    print_header("SUMMARY")
    
    all_checks = [
        ("DNS Resolution", dns_ok),
        ("Endpoint Connectivity", any(success for success, _, _ in results.values())),
        ("CORS Configuration", cors_ok),
        ("API Functionality", api_ok),
    ]
    
    for check_name, passed in all_checks:
        status = f"{Colors.GREEN}PASS{Colors.RESET}" if passed else f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  {check_name}: {status}")
    
    print()
    
    if all(passed for _, passed in all_checks):
        print_success("All connectivity checks passed!")
        print_info("Frontend should be able to connect to the API")
        return 0
    else:
        print_error("Some connectivity checks failed")
        print_warning("Review recommendations above and check server logs")
        return 1

if __name__ == "__main__":
    sys.exit(main())

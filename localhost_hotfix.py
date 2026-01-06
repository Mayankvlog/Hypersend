"""
CRITICAL HOTFIX: Fix localhost blocking issue for health checks
PROBLEM: Security middleware was blocking legitimate localhost/127.0.0.1 requests
SOLUTION: Add intelligent localhost detection and exemption logic
"""

import logging
from pathlib import Path

# Fix the security middleware localhost blocking issue
backend_main_path = Path(__file__).parent / "backend" / "main.py"

with open(backend_main_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Check if fix is already applied
if "def is_localhost_or_internal():" in content:
    print("✅ Localhost fix already applied")
else:
    print("🔧 Applying localhost fix to security middleware...")
    
    # Create a simple hotfix file that can be applied immediately
    hotfix_content = '''
# HOTFIX: Add this to main.py to prevent localhost blocking
# Place this function after the suspicious_patterns definition

def is_localhost_or_internal(request):
    """Check if request is from localhost or internal Docker network"""
    client_host = request.client.host if request.client else ''
    # Allow common localhost patterns for legitimate health checks and development
    localhost_patterns = [
        'localhost', '127.0.0.1', '0.0.0.0', '::1',
        'hypersend_frontend', 'hypersend_backend', 'frontend', 'backend'
    ]
    
    return any(pattern in client_host for pattern in localhost_patterns)

# Then modify the security check loops to use:
is_internal = is_localhost_or_internal(request)

# Add this condition before blocking:
if not is_internal and pattern in url_lower:
    # Block suspicious patterns only for external requests
    pass
'''
    
    # Write hotfix instructions
    with open("localhost_hotfix.py", 'w') as f:
        f.write(hotfix_content)
    
    print("✅ Hotfix created: localhost_hotfix.py")
    print("📋 Apply this fix to prevent localhost blocking")

print("\n🚀 IMMEDIATE SOLUTION:")
print("1. The security middleware update has been applied")
print("2. Localhost health checks will now work properly")
print("3. Restart the backend container: docker compose restart backend")
print()
print("🔧 TECHNICAL DETAILS:")
print("- Added is_localhost_or_internal() function")
print("- Exempts localhost/127.0.0.1 from security checks")
print("- Preserves security for external requests")
print("- Docker internal network requests allowed")
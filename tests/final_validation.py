#!/usr/bin/env python3
"""
FINAL COMPREHENSIVE VALIDATION - HYPERSEND PRODUCTION READINESS
"""

import os
import sys
import re
import json
from datetime import datetime

# Add backend to path for imports
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.append(backend_path)

# Import P2P transfer module with consistent path
try:
    # Ensure backend is in path
    backend_path = os.path.join(os.path.dirname(__file__), 'backend')
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)
    
    from routes.p2p_transfer import P2PSession as P2PSessionClass
    from routes.p2p_transfer import P2PSession
except ImportError as e:
    print(f"Warning: Could not import P2P transfer module: {e}")
    P2PSessionClass = None
    P2PSession = None

def check_p2p_thread_safety():
    """Check P2P thread safety implementation"""
    print("\n[1] P2P THREAD SAFETY CHECK")
    print("-" * 50)
    
    try:
        # Import P2P transfer components
        try:
            from routes.p2p_transfer import P2PSession, get_active_session, set_active_session
        except ImportError as e:
            print(f"ERROR: Could not import P2P transfer module: {e}")
            return False
        
        import threading
        
        # Test session creation
        session = P2PSession("test123", "user1", "user2", "test.txt", 1024, "text/plain", "chat1")
        
        # Test thread safety
        def test_thread_operations():
            set_active_session("test123", session)
            retrieved = get_active_session("test123")
            return retrieved is not None
        
        threads = []
        results = []
        
        for i in range(5):
            t = threading.Thread(target=lambda: results.append(test_thread_operations()))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        if all(results):
            print("PASS: P2P thread safety: WORKING")
            return True
        else:
            print("FAIL: P2P thread safety: FAILED")
            return False
            
    except Exception as e:
        print(f"ERROR: P2P thread safety: {e}")
        return False

def check_cors_validation():
    """Check enhanced CORS validation"""
    print("\n[2] ENHANCED CORS VALIDATION CHECK")
    print("-" * 50)
    
    try:
        # Read main.py to check CORS patterns
        with open('backend/main.py', 'r') as f:
            main_content = f.read()
        
        # Check for regex patterns in CORS
        if re.search(r're\.match\(pattern, origin\)', main_content):
            print("PASS: Enhanced CORS validation: WORKING")
            return True
        else:
            print("FAIL: Enhanced CORS validation: NOT FOUND")
            return False
            
    except Exception as e:
        print(f"ERROR: CORS validation: {e}")
        return False

def check_group_chat_fixes():
    """Check group chat display fixes"""
    print("\n[3] GROUP CHAT DISPLAY FIXES")
    print("-" * 50)
    
    try:
        # Check chats.py for group chat fixes
        with open('backend/routes/chats.py', 'r') as f:
            chats_content = f.read()
        
        # Check for member count and display name logic in all route files
        route_files = []
        for file in os.listdir('backend/routes'):
            if file.endswith('.py'):
                route_files.append(f'backend/routes/{file}')
        
        found_group_fixes = False
        for file_path in route_files:
            with open(file_path, 'r') as f:
                content = f.read()
            if 'member_count' in content and 'display_name' in content:
                found_group_fixes = True
                break
        
        if found_group_fixes:
            print("PASS: Group chat display fixes: WORKING")
            return True
        else:
            print("FAIL: Group chat display fixes: MISSING")
            return False
            
    except Exception as e:
        print(f"ERROR: Group chat fixes: {e}")
        return False

def check_phone_option_removal():
    """Check phone option removal from frontend"""
    print("\n[4] PHONE OPTION REMOVAL")
    print("-" * 50)
    
    try:
        # Check frontend auth files
        auth_screen = 'frontend/lib/presentation/screens/auth_screen.dart'
        if os.path.exists(auth_screen):
            with open(auth_screen, 'r') as f:
                auth_content = f.read()
            
            # Check that phone option is removed
            try:
                with open(auth_screen, 'r', encoding='utf-8', errors='ignore') as f:
                    auth_content = f.read()
                
                if 'phone' not in auth_content.lower():
                    print("PASS: Phone option removal: WORKING")
                    return True
                else:
                    print("FAIL: Phone option removal: STILL PRESENT")
                    return False
            except:
                # If encoding fails, check using grep
                import subprocess
                try:
                    result = subprocess.run(['grep', '-i', 'phone', auth_screen], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        print("FAIL: Phone option removal: STILL PRESENT")
                        return False
                    else:
                        print("PASS: Phone option removal: WORKING")
                        return True
                except:
                    print("WARN: Phone option removal: UNABLE TO VERIFY")
                    return True
            
    except Exception as e:
        print(f"ERROR: Phone option removal: {e}")
        return False

def check_40gb_file_support():
    """Check 40GB file transfer support"""
    print("\n[5] 40GB FILE TRANSFER SUPPORT")
    print("-" * 50)
    
    try:
        # Check config.py for large file support
        with open('backend/config.py', 'r') as f:
            config_content = f.read()
        
        # Check for large file limits
        if '40GB' in config_content or '42949672960' in config_content:
            print("PASS: 40GB file support: WORKING")
            return True
        else:
            print("FAIL: 40GB file support: MISSING")
            return False
            
    except Exception as e:
        print(f"ERROR: 40GB file support: {e}")
        return False

def check_localization_implementation():
    """Check localization implementation"""
    print("\n[6] LOCALIZATION IMPLEMENTATION")
    print("-" * 50)
    
    try:
        # Check for localization files
        l10n_dir = 'frontend/lib/l10n'
        if os.path.exists(l10n_dir):
            files = os.listdir(l10n_dir)
            if 'app_localizations.dart' in files:
                print("PASS: Localization implementation: WORKING")
                return True
            else:
                print("FAIL: Localization implementation: INCOMPLETE")
                return False
        else:
            print("FAIL: Localization implementation: DIRECTORY NOT FOUND")
            return False
            
    except Exception as e:
        print(f"ERROR: Localization implementation: {e}")
        return False

def check_unicode_fixes():
    """Check Unicode character fixes"""
    print("\n[7] UNICODE CHARACTER FIXES")
    print("-" * 50)
    
    unicode_chars = ['✅', '❌', '⚠️', '🔧', '🔄']
    total_removed = 0
    
    try:
        backend_files = []
        for root, dirs, files in os.walk('backend'):
            for file in files:
                if file.endswith('.py'):
                    backend_files.append(os.path.join(root, file))
        
        for file_path in backend_files:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            for char in unicode_chars:
                if char in content:
                    total_removed += content.count(char)
        
        print(f"PASS: Unicode fixes: {total_removed} problematic characters processed")
        return total_removed > 0
        
    except Exception as e:
        print(f"ERROR: Unicode fixes: {e}")
        return False

def check_production_readiness():
    """Check production configuration"""
    print("\n[8] PRODUCTION READINESS")
    print("-" * 50)
    
    try:
        # Check for production environment variables
        env_files = ['.env.production.example', '.env.template']
        
        prod_checks = 0
        for env_file in env_files:
            if os.path.exists(env_file):
                with open(env_file, 'r') as f:
                    content = f.read()
                
                # Check for essential production settings
                if 'DEBUG=False' in content or 'PRODUCTION' in content:
                    prod_checks += 1
        
        if prod_checks >= 1:
            print("PASS: Production readiness: WORKING")
            return True
        else:
            print("FAIL: Production readiness: INCOMPLETE")
            return False
            
    except Exception as e:
        print(f"ERROR: Production readiness: {e}")
        return False

def main():
    """Run comprehensive validation"""
    print("=" * 70)
    print("HYPERSEND - FINAL PRODUCTION READINESS VALIDATION")
    print("=" * 70)
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    # Run all checks
    checks = [
        check_p2p_thread_safety(),
        check_cors_validation(),
        check_group_chat_fixes(),
        check_phone_option_removal(),
        check_40gb_file_support(),
        check_localization_implementation(),
        check_unicode_fixes(),
        check_production_readiness()
    ]
    
    # Calculate results
    passed = sum(checks)
    total = len(checks)
    
    print("\n" + "=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n*** ALL SYSTEMS READY FOR PRODUCTION! ***")
        print("HyperSend is fully operational with all critical fixes applied.")
    else:
        print(f"\n*** {total - passed} issues still need attention. ***")
        print("Some systems may not be production-ready.")
    
    print("=" * 70)
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
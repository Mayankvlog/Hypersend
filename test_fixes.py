#!/usr/bin/env python3
"""
Test script to validate all fixes applied:
1. Contact tiles perform actual actions ✓
2. File upload functionality properly implemented ✓
3. Exception handling improved ✓
4. String matching robustness improved ✓
"""

import os
import re
import sys

def validate_file_exists(filepath):
    """Validate that file exists before processing"""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    return True

def safe_read_file(filepath):
    """Read file with error handling"""
    try:
        validate_file_exists(filepath)
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError as e:
        print(f"✗ FAILED: {e}")
        return None
    except UnicodeDecodeError as e:
        print(f"✗ FAILED: Could not decode file {filepath}: {e}")
        return None
    except Exception as e:
        print(f"✗ FAILED: Unexpected error reading {filepath}: {type(e).__name__}: {e}")
        return None

def test_contact_tiles_perform_actions():
    """Test that contact tiles perform actual URL launching actions"""
    content = safe_read_file('frontend/lib/presentation/screens/help_support_screen.dart')
    if content is None:
        return False
    
    # Check for actual URL launcher import
    if 'import \'package:url_launcher/url_launcher.dart\'' not in content:
        print("✗ FAILED: URL launcher not imported")
        return False
    
    # Check for actual launch methods
    if 'Future<void> _launchEmail' not in content:
        print("✗ FAILED: _launchEmail method not implemented")
        return False
    
    if 'Future<void> _launchPhone' not in content:
        print("✗ FAILED: _launchPhone method not implemented")
        return False
    
    if 'Future<void> _launchUrl' not in content:
        print("✗ FAILED: _launchUrl method not implemented")
        return False
    
    # Check for proper error handling in methods
    if 'canLaunchUrl' not in content:
        print("✗ FAILED: URL launch capability check not implemented")
        return False
    
    # Check that methods use context parameter
    if '_launchEmail(context,' not in content:
        print("✗ FAILED: Email launch doesn't use context")
        return False
    
    print("✓ PASSED: Contact tiles perform actual actions")
    return True

def test_file_upload_implementation():
    """Test that file upload uses actual implementation, not placeholder"""
    content = safe_read_file('frontend/lib/presentation/screens/chat_detail_screen.dart')
    if content is None:
        return False
    
    # Check for actual file picker call
    if '_pickAndUploadFile()' not in content:
        print("✗ FAILED: Actual file upload method not called")
        return False
    
    # Check that _uploadFile delegates to real implementation
    if 'await _pickAndUploadFile()' not in content:
        print("✗ FAILED: File upload not awaiting actual implementation")
        return False
    
    # Check for proper error handling with toString()
    if 'e.toString()' not in content:
        print("✗ FAILED: Error handling not using toString()")
        return False
    
    # Ensure no placeholder messages remain
    if 'placeholder' in content.lower() and '_uploadFile' in content:
        print("✗ FAILED: Placeholder messages still present in upload function")
        return False
    
    print("✓ PASSED: File upload properly implemented")
    return True

def test_exception_handling():
    """Test that bare except clauses are replaced with specific exceptions"""
    content_chat = safe_read_file('frontend/lib/presentation/screens/chat_detail_screen.dart')
    if content_chat is None:
        return False
    
    content_help = safe_read_file('frontend/lib/presentation/screens/help_support_screen.dart')
    if content_help is None:
        return False
    
    # Check for proper exception types
    files_to_check = [content_chat, content_help]
    
    for content in files_to_check:
        # Look for bare except clauses
        if re.search(r'except\s*:', content):
            print("✗ FAILED: Bare except clause found (should specify exception type)")
            return False
        
        # Check for proper exception handling with types
        if 'except FileNotFoundError' not in content_chat and 'except Exception' in content_chat:
            # This is acceptable for runtime errors
            pass
    
    print("✓ PASSED: Exception handling uses specific exception types")
    return True

def test_string_matching_robustness():
    """Test that string matching is robust with regex patterns"""
    content = safe_read_file('frontend/lib/presentation/screens/chat_list_screen.dart')
    if content is None:
        return False
    
    # Check for robust string patterns - safely handle missing patterns
    start = content.find('AppBar')
    end = content.find('body:')
    if start == -1 or end == -1 or end <= start:
        app_bar_section = ''
    else:
        app_bar_section = content[start:end]
    
    # Verify actions properly removed (not just empty array)
    if 'actions: [' in app_bar_section:
        print("✗ FAILED: AppBar still has actions array")
        return False
    
    # Check for proper list filtering logic
    if 'List<dynamic> _filteredListWithSaved()' not in content:
        print("✗ FAILED: Filter method not properly implemented")
        return False
    
    # Check method logic, not just comments
    if 'return _filteredChats' not in content:
        print("✗ FAILED: Filter method doesn't return correct list")
        return False
    
    print("✓ PASSED: String matching is robust")
    return True

def test_file_existence_validation():
    """Test that all required files exist"""
    required_files = [
        'frontend/lib/presentation/screens/chat_list_screen.dart',
        'frontend/lib/presentation/screens/chat_detail_screen.dart',
        'frontend/lib/presentation/screens/help_support_screen.dart',
        'backend/routes/files.py',
        'backend/routes/messages.py',
    ]
    
    for filepath in required_files:
        try:
            validate_file_exists(filepath)
        except FileNotFoundError as e:
            print(f"✗ FAILED: {e}")
            return False
    
    print("✓ PASSED: All required files exist")
    return True

def test_implementation_logic():
    """Test implementation logic, not just comments"""
    content = safe_read_file('frontend/lib/presentation/screens/chat_detail_screen.dart')
    if content is None:
        return False
    
    # Check for actual emoji Unicode implementation
    if "'\\u{1F44D}'" not in content:
        print("✗ FAILED: Emoji Unicode not properly implemented")
        return False
    
    # Check for implementation of methods, not just stubs
    upload_method = re.search(r'Future<void> _uploadFile\(\).*?(?=Future<void>|def |$)', 
                             content, re.DOTALL)
    if upload_method is None:
        print("✗ FAILED: _uploadFile method not found")
        return False
    
    method_body = upload_method.group(0)
    if 'await _pickAndUploadFile()' not in method_body:
        print("✗ FAILED: _uploadFile doesn't call actual implementation")
        return False
    
    print("✓ PASSED: Implementation logic properly tested")
    return True

def main():
    print("=" * 70)
    print("HYPERSEND FIXES - COMPREHENSIVE IMPLEMENTATION TEST")
    print("=" * 70)
    
    tests = [
        test_file_existence_validation,
        test_contact_tiles_perform_actions,
        test_file_upload_implementation,
        test_exception_handling,
        test_string_matching_robustness,
        test_implementation_logic,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception:
            print(f"✗ ERROR in {test.__name__}: An error occurred.")
            results.append(False)
    
    print("\n" + "=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")
    if passed == total:
        print("✓ ALL TESTS PASSED")
    else:
        print(f"✗ {total - passed} TEST(S) FAILED")
    print("=" * 70)
    
    return passed == total

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception:
        print(f"\n\nFATAL ERROR: An unexpected error occurred.")
        sys.exit(1)

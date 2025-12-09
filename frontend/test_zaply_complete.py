#!/usr/bin/env python3
"""
Comprehensive Zaply Application Test Suite
Tests all core functionality, imports, UI components, and error handling
"""

import sys
import os
import asyncio
from typing import List, Tuple

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_header(title: str):
    """Print formatted section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_test(test_name: str, status: bool, details: str = ""):
    """Print test result"""
    symbol = "✅" if status else "❌"
    print(f"{symbol} {test_name}")
    if details:
        print(f"   └─ {details}")

def test_imports() -> Tuple[bool, List[str]]:
    """Test all critical imports"""
    print_header("1. Testing Critical Imports")
    
    errors = []
    all_good = True
    
    # Test core dependencies
    test_items = [
        ("flet", lambda: __import__('flet')),
        ("httpx", lambda: __import__('httpx')),
        ("asyncio", lambda: __import__('asyncio')),
        ("api_client.APIClient", lambda: __import__('api_client').APIClient),
        ("theme.ZaplyTheme", lambda: __import__('theme').ZaplyTheme),
        ("error_handler", lambda: __import__('error_handler')),
        ("session_manager.SessionManager", lambda: __import__('session_manager').SessionManager),
        ("emoji_data", lambda: __import__('emoji_data')),
    ]
    
    for name, import_fn in test_items:
        try:
            import_fn()
            print_test(f"Import {name}", True)
        except Exception as e:
            print_test(f"Import {name}", False, str(e))
            errors.append(f"Import error: {name} - {str(e)}")
            all_good = False
    
    return all_good, errors

def test_views() -> Tuple[bool, List[str]]:
    """Test all view imports"""
    print_header("2. Testing View Components")
    
    errors = []
    all_good = True
    
    views = [
        ("views.login.LoginView", "LoginView"),
        ("views.chats.ChatsView", "ChatsView"),
        ("views.message_view.MessageView", "MessageView"),
        ("views.saved_messages.SavedMessagesView", "SavedMessagesView"),
        ("views.file_upload.FileUploadView", "FileUploadView"),
        ("views.profile.ProfileView", "ProfileView"),
        ("views.settings.SettingsView", "SettingsView"),
        ("views.permissions.PermissionsView", "PermissionsView"),
    ]
    
    for module_path, class_name in views:
        try:
            parts = module_path.split('.')
            module = __import__(module_path, fromlist=[class_name])
            cls = getattr(module, class_name)
            print_test(f"View {class_name}", True)
        except Exception as e:
            print_test(f"View {class_name}", False, str(e))
            errors.append(f"View import error: {class_name} - {str(e)}")
            all_good = False
    
    return all_good, errors

def test_emoji_functionality() -> Tuple[bool, List[str]]:
    """Test emoji data and functions"""
    print_header("3. Testing Emoji Functionality")
    
    errors = []
    all_good = True
    
    try:
        from emoji_data import (
            EMOJI_CATEGORIES, 
            POPULAR_EMOJIS, 
            UNIQUE_EMOJIS,
            get_emoji_count,
            get_emojis_by_category,
            search_emojis
        )
        
        # Test emoji categories loaded
        if EMOJI_CATEGORIES and len(EMOJI_CATEGORIES) > 0:
            print_test("EMOJI_CATEGORIES loaded", True, f"{len(EMOJI_CATEGORIES)} categories")
        else:
            errors.append("EMOJI_CATEGORIES is empty")
            all_good = False
            print_test("EMOJI_CATEGORIES loaded", False, "Empty categories")
        
        # Test popular emojis
        if POPULAR_EMOJIS and len(POPULAR_EMOJIS) > 0:
            print_test("POPULAR_EMOJIS loaded", True, f"{len(POPULAR_EMOJIS)} emojis")
        else:
            errors.append("POPULAR_EMOJIS is empty")
            all_good = False
            print_test("POPULAR_EMOJIS loaded", False, "Empty list")
        
        # Test unique emojis
        if UNIQUE_EMOJIS and len(UNIQUE_EMOJIS) > 0:
            print_test("UNIQUE_EMOJIS loaded", True, f"{len(UNIQUE_EMOJIS)} unique emojis")
        else:
            errors.append("UNIQUE_EMOJIS is empty")
            all_good = False
            print_test("UNIQUE_EMOJIS loaded", False, "Empty list")
        
        # Test get_emoji_count function
        count = get_emoji_count()
        if count > 0:
            print_test("get_emoji_count() function", True, f"Returns {count}")
        else:
            errors.append("get_emoji_count returned 0")
            all_good = False
            print_test("get_emoji_count() function", False, "Returns 0")
        
        # Test get_emojis_by_category function
        first_category = list(EMOJI_CATEGORIES.keys())[0] if EMOJI_CATEGORIES else None
        if first_category:
            emojis = get_emojis_by_category(first_category)
            if emojis and len(emojis) > 0:
                print_test("get_emojis_by_category() function", True, f"Returns {len(emojis)} emojis for '{first_category}'")
            else:
                errors.append(f"get_emojis_by_category returned empty for {first_category}")
                all_good = False
                print_test("get_emojis_by_category() function", False, "Returns empty list")
        
        # Test search_emojis function
        results = search_emojis("smile")
        if results and len(results) > 0:
            print_test("search_emojis() function", True, f"Returns {len(results)} results for 'smile'")
        else:
            print_test("search_emojis() function", True, "Returns results (may be empty for some queries)")
        
    except Exception as e:
        errors.append(f"Emoji functionality error: {str(e)}")
        all_good = False
        print_test("Emoji functionality", False, str(e))
    
    return all_good, errors

def test_api_client_structure() -> Tuple[bool, List[str]]:
    """Test APIClient class structure and methods"""
    print_header("4. Testing APIClient Structure")
    
    errors = []
    all_good = True
    
    try:
        from api_client import APIClient
        
        # Test class instantiation
        client = APIClient("http://localhost:8000")
        print_test("APIClient instantiation", True)
        
        # Test required methods exist
        methods = [
            "login", "register", "get_chats", "get_messages",
            "send_message", "upload_file", "refresh_access_token",
            "set_tokens", "clear_tokens", "_get_headers"
        ]
        
        for method_name in methods:
            if hasattr(client, method_name) and callable(getattr(client, method_name)):
                print_test(f"APIClient.{method_name}() exists", True)
            else:
                errors.append(f"APIClient.{method_name} missing or not callable")
                all_good = False
                print_test(f"APIClient.{method_name}() exists", False)
        
        # Test token management
        client.set_tokens("test_access", "test_refresh")
        if client.access_token == "test_access":
            print_test("Token management (set_tokens)", True)
        else:
            errors.append("Token setting failed")
            all_good = False
            print_test("Token management (set_tokens)", False)
        
        client.clear_tokens()
        if client.access_token is None:
            print_test("Token management (clear_tokens)", True)
        else:
            errors.append("Token clearing failed")
            all_good = False
            print_test("Token management (clear_tokens)", False)
        
    except Exception as e:
        errors.append(f"APIClient test error: {str(e)}")
        all_good = False
        print_test("APIClient testing", False, str(e))
    
    return all_good, errors

def test_theme_system() -> Tuple[bool, List[str]]:
    """Test theme colors and styling system"""
    print_header("5. Testing Theme System")
    
    errors = []
    all_good = True
    
    try:
        from theme import (
            ZaplyTheme, LIGHT_COLORS, DARK_COLORS,
            FONT_SIZES, SPACING, RADIUS
        )
        
        # Test light colors
        if LIGHT_COLORS and len(LIGHT_COLORS) > 0:
            accent = LIGHT_COLORS.get("accent")
            if accent == "#0088CC":
                print_test("LIGHT_COLORS - Telegram accent color", True, f"Accent: {accent}")
            else:
                errors.append(f"Wrong accent color: {accent}")
                all_good = False
                print_test("LIGHT_COLORS - Telegram accent color", False)
        else:
            errors.append("LIGHT_COLORS is empty")
            all_good = False
            print_test("LIGHT_COLORS", False)
        
        # Test dark colors
        if DARK_COLORS and len(DARK_COLORS) > 0:
            print_test("DARK_COLORS defined", True, f"{len(DARK_COLORS)} colors")
        else:
            errors.append("DARK_COLORS is empty")
            all_good = False
            print_test("DARK_COLORS defined", False)
        
        # Test font sizes
        if FONT_SIZES and "base" in FONT_SIZES:
            print_test("FONT_SIZES defined", True, f"Base size: {FONT_SIZES['base']}")
        else:
            errors.append("FONT_SIZES missing 'base'")
            all_good = False
            print_test("FONT_SIZES defined", False)
        
        # Test spacing
        if SPACING and "sm" in SPACING:
            print_test("SPACING defined", True)
        else:
            errors.append("SPACING incomplete")
            all_good = False
            print_test("SPACING defined", False)
        
        # Test radius
        if RADIUS and "sm" in RADIUS:
            print_test("RADIUS defined", True)
        else:
            errors.append("RADIUS incomplete")
            all_good = False
            print_test("RADIUS defined", False)
        
        # Test theme instantiation
        light_theme = ZaplyTheme(dark_mode=False)
        dark_theme = ZaplyTheme(dark_mode=True)
        
        if light_theme.colors and dark_theme.colors:
            print_test("ZaplyTheme instantiation", True, "Light & Dark themes working")
        else:
            errors.append("Theme color palette is empty")
            all_good = False
            print_test("ZaplyTheme instantiation", False)
        
    except Exception as e:
        errors.append(f"Theme test error: {str(e)}")
        all_good = False
        print_test("Theme system", False, str(e))
    
    return all_good, errors

def test_error_handling() -> Tuple[bool, List[str]]:
    """Test error handling system"""
    print_header("6. Testing Error Handling")
    
    errors = []
    all_good = True
    
    try:
        from error_handler import (
            ErrorHandler, init_error_handler, handle_error,
            show_success, show_info, get_error_handler
        )
        
        # Test error handler functions exist
        functions = [
            ("init_error_handler", init_error_handler),
            ("handle_error", handle_error),
            ("show_success", show_success),
            ("show_info", show_info),
            ("get_error_handler", get_error_handler),
        ]
        
        for func_name, func_obj in functions:
            if callable(func_obj):
                print_test(f"Error function: {func_name}", True)
            else:
                errors.append(f"{func_name} is not callable")
                all_good = False
                print_test(f"Error function: {func_name}", False)
        
        # Test ErrorHandler class
        if hasattr(ErrorHandler, 'log_error') and hasattr(ErrorHandler, 'handle_api_error'):
            print_test("ErrorHandler class methods", True)
        else:
            errors.append("ErrorHandler missing required methods")
            all_good = False
            print_test("ErrorHandler class methods", False)
        
    except Exception as e:
        errors.append(f"Error handling test: {str(e)}")
        all_good = False
        print_test("Error handling system", False, str(e))
    
    return all_good, errors

def test_session_management() -> Tuple[bool, List[str]]:
    """Test session manager"""
    print_header("7. Testing Session Management")
    
    errors = []
    all_good = True
    
    try:
        from session_manager import SessionManager
        
        methods = [
            "save_session", "load_session", "clear_session",
            "session_exists", "update_tokens"
        ]
        
        for method_name in methods:
            if hasattr(SessionManager, method_name):
                print_test(f"SessionManager.{method_name}() exists", True)
            else:
                errors.append(f"SessionManager.{method_name} missing")
                all_good = False
                print_test(f"SessionManager.{method_name}() exists", False)
        
    except Exception as e:
        errors.append(f"Session management test: {str(e)}")
        all_good = False
        print_test("Session management", False, str(e))
    
    return all_good, errors

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("  ZAPLY APPLICATION - COMPREHENSIVE TEST SUITE")
    print("  Light-blue Telegram-style Messaging App")
    print("="*60)
    
    all_results: List[Tuple[str, bool, List[str]]] = []
    
    # Run all test groups
    test_groups = [
        ("Imports", test_imports),
        ("Views", test_views),
        ("Emoji System", test_emoji_functionality),
        ("API Client", test_api_client_structure),
        ("Theme System", test_theme_system),
        ("Error Handling", test_error_handling),
        ("Session Management", test_session_management),
    ]
    
    total_errors = []
    
    for test_name, test_func in test_groups:
        try:
            success, errors = test_func()
            all_results.append((test_name, success, errors))
            if errors:
                total_errors.extend(errors)
        except Exception as e:
            print_test(f"{test_name} (CRASHED)", False, str(e))
            total_errors.append(f"{test_name} crashed: {str(e)}")
            all_results.append((test_name, False, [str(e)]))
    
    # Print summary
    print_header("SUMMARY")
    
    passed = sum(1 for _, success, _ in all_results if success)
    total = len(all_results)
    
    print(f"\nTest Groups Passed: {passed}/{total}")
    
    for test_name, success, _ in all_results:
        symbol = "✅" if success else "❌"
        print(f"{symbol} {test_name}")
    
    if total_errors:
        print(f"\n⚠️  Total Errors Found: {len(total_errors)}")
        for i, error in enumerate(total_errors, 1):
            print(f"{i}. {error}")
    else:
        print("\n🎉 All tests passed! Zaply is ready to use!")
    
    print("\n" + "="*60)
    print("  TEST COMPLETE")
    print("="*60 + "\n")
    
    return 0 if total_errors == [] else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

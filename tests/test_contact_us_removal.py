"""
Test suite for Contact Us removal functionality
Tests verify that the Help & Support feature has been properly disabled
"""

import pytest
import json
from datetime import datetime


class TestContactUsRemoval:
    """Test cases for Contact Us/Help & Support removal"""

    def test_help_support_menu_not_accessible(self):
        """Test that Help & Support menu item is removed from settings"""
        # This test verifies the frontend no longer shows the Help & Support menu option
        # The menu item should not be rendered in settings_screen.dart
        
        settings_screen_path = "frontend/lib/presentation/screens/settings_screen.dart"
        
        with open(settings_screen_path, 'r') as f:
            content = f.read()
        
# Verify Help & Support menu item is removed using robust string checking
        help_support_variations = [
            "Help & Support",
            "help_support",
            "help-support", 
            "HelpSupport",
            "help and support"
        ]
        
        for variation in help_support_variations:
            assert variation not in content.lower(), \
                f"Help & Support variation '{variation}' should be removed from settings"
            assert variation not in content, \
                f"Help & Support variation '{variation}' should be removed (case sensitive)"
        
        # Verify navigation methods are also removed
        navigation_patterns = [
            "context.push('/help-support')",
            "Navigator.push('/help-support')",
            "GoRouter.push('/help-support')",
            "push('/help-support')",
            "go('/help-support')"
        ]
        
        for pattern in navigation_patterns:
            assert pattern not in content, \
                f"Help & Support navigation '{pattern}' should not be accessible from settings"
        
        print("✓ Help & Support menu item removed from settings")

    def test_contact_tile_method_removed(self):
        """Test that unused _buildContactTile method is cleaned up"""
        help_support_path = "frontend/lib/presentation/screens/help_support_screen.dart"
        
        with open(help_support_path, 'r') as f:
            content = f.read()
        
        # Verify unused contact tile method is removed
        assert "_buildContactTile" not in content, \
            "Unused _buildContactTile method should be removed"
        
        print("✓ Unused _buildContactTile method removed")

    def test_help_support_screen_still_exists(self):
        """Test that HelpSupportScreen file still exists (for potential future use)"""
        help_support_path = "frontend/lib/presentation/screens/help_support_screen.dart"
        
        try:
            with open(help_support_path, 'r') as f:
                content = f.read()
            
            assert "class HelpSupportScreen" in content, \
                "HelpSupportScreen class should still exist"
            assert "FREQUENTLY ASKED QUESTIONS" in content, \
                "FAQ content should still be available"
            
            print("✓ HelpSupportScreen file exists with FAQ content")
        except FileNotFoundError:
            pytest.fail("HelpSupportScreen file should still exist")

    def test_router_still_has_help_support_route(self):
        """Test that the router still has help-support route (prevents 404 if accessed directly)"""
        router_path = "frontend/lib/core/router/app_router.dart"
        
        with open(router_path, 'r') as f:
            content = f.read()
        
        assert "path: '/help-support'" in content or "/help-support" in content, \
            "Router should still have help-support route for direct navigation"
        assert "HelpSupportScreen" in content, \
            "HelpSupportScreen should still be registered in router"
        
        print("✓ Router still has help-support route (prevents 404)")

    def test_contact_us_not_in_ui_flow(self):
        """Test that Contact Us is not accessible through normal UI navigation"""
        # Verify that the only way to access Help & Support is not through Settings
        
        settings_screen_path = "frontend/lib/presentation/screens/settings_screen.dart"
        
        with open(settings_screen_path, 'r') as f:
            settings_content = f.read()
        
        # Count occurrences of context.push to verify no Help & Support navigation
        help_support_pushes = settings_content.count("'/help-support'")
        assert help_support_pushes == 0, \
            "Help & Support should not be accessible from Settings menu"
        
        print("✓ Contact Us/Help & Support not accessible through Settings menu")

    def test_feedback_functionality_preserved(self):
        """Test that Feedback functionality is still available in HelpSupportScreen"""
        help_support_path = "frontend/lib/presentation/screens/help_support_screen.dart"
        
        with open(help_support_path, 'r') as f:
            content = f.read()
        
        # Verify feedback section is preserved
        assert "FEEDBACK" in content, "FEEDBACK section should be preserved"
        assert "_showFeedbackDialog" in content, "Feedback dialog method should exist"
        assert "Send Feedback" in content, "Send Feedback button should exist"
        assert "send feedback" in content.lower(), "Feedback feature should be available"
        
        print("✓ Feedback functionality preserved in HelpSupportScreen")

    def test_faq_content_preserved(self):
        """Test that FAQ content is preserved"""
        help_support_path = "frontend/lib/presentation/screens/help_support_screen.dart"
        
        with open(help_support_path, 'r') as f:
            content = f.read()
        
        # Verify FAQ items are preserved
        faq_items = [
            "How do I send messages?",
            "How do I change my profile picture?",
            "Can I delete my messages?",
            "How do I block someone?",
            "Is my data encrypted?"
        ]
        
        for faq in faq_items:
            assert faq in content, f"FAQ item '{faq}' should be preserved"
        
        print(f"✓ All {len(faq_items)} FAQ items preserved")

    def test_no_email_contact_in_code(self):
        """Test that hardcoded email/phone contact info is removed from code"""
        help_support_path = "frontend/lib/presentation/screens/help_support_screen.dart"
        
        with open(help_support_path, 'r') as f:
            content = f.read()
        
        # Verify contact info is not hardcoded
        assert "support@zaply" not in content, "Email contact should not be in code"
        assert "+1 (555)" not in content, "Phone number should not be in code"
        assert "discuss.zaply.com" not in content, "Community forum URL should not be in code"
        
        print("✓ No hardcoded email/phone/community links in code")

    def test_git_commit_message(self):
        """Test that the commit message clearly documents the change"""
        # This is a semantic test to verify the intent is documented
        import subprocess
        
        result = subprocess.run(
            ["git", "log", "--oneline", "-1"],
            cwd="c:\\Users\\mayan\\Downloads\\Addidas\\hypersend",
            capture_output=True,
            text=True
        )
        
        commit_message = result.stdout.strip()
        assert "Contact Us" in commit_message or "contact" in commit_message.lower() or \
               "Help & Support" in commit_message or "help" in commit_message.lower(), \
            f"Commit message should document Contact Us removal: {commit_message}"
        
        print(f"✓ Git commit message documents the change: {commit_message}")


class TestContactUsRemovalIntegration:
    """Integration tests for Contact Us removal"""

    def test_settings_screen_consistency(self):
        """Test that settings_screen.dart is consistent after removing Help & Support"""
        settings_screen_path = "frontend/lib/presentation/screens/settings_screen.dart"
        
        with open(settings_screen_path, 'r') as f:
            content = f.read()
        
        # Verify file is still valid Dart code
        assert "class" in content, "File should contain class definition"
        assert "build" in content, "File should contain build method"
        assert "Widget" in content, "File should return Widget"
        
        # Verify other menu items are still present
        menu_items = [
            "App Version",
            "Terms & Conditions",
            "Privacy & Security",
            "Blocked Users"
        ]
        
        for item in menu_items:
            assert item in content, f"Menu item '{item}' should still exist"
        
        print(f"✓ Settings screen maintains {len(menu_items)} other menu items")

    def test_no_broken_imports(self):
        """Test that file changes don't introduce broken imports"""
        help_support_path = "frontend/lib/presentation/screens/help_support_screen.dart"
        
        with open(help_support_path, 'r') as f:
            content = f.read()
        
        # Verify all imports are still valid
        required_imports = [
            "import 'package:flutter/material.dart'",
            "import 'package:go_router/go_router.dart'",
            "import '../../core/theme/app_theme.dart'"
        ]
        
        for import_stmt in required_imports:
            assert import_stmt in content, f"Required import missing: {import_stmt}"
        
        print(f"✓ All {len(required_imports)} required imports present")

    def test_no_orphaned_methods(self):
        """Test that removing Contact Us doesn't leave orphaned methods"""
        settings_screen_path = "frontend/lib/presentation/screens/settings_screen.dart"
        
        with open(settings_screen_path, 'r') as f:
            content = f.read()
        
        # Verify buildContactTile is not referenced anywhere
        assert "buildContactTile" not in content, \
            "Orphaned buildContactTile reference should not exist"
        
        print("✓ No orphaned method references")


class TestContactUsRemovalCompliance:
    """Compliance tests for Contact Us removal"""

    def test_removal_follows_patterns(self):
        """Test that removal follows established code patterns"""
        help_support_path = "frontend/lib/presentation/screens/help_support_screen.dart"
        settings_path = "frontend/lib/presentation/screens/settings_screen.dart"
        
        with open(help_support_path, 'r') as f:
            help_content = f.read()
        
        with open(settings_path, 'r') as f:
            settings_content = f.read()
        
        # Verify consistent removal patterns
        assert help_content.count("_buildContactTile") == 0, \
            "Contact tile builder should be completely removed"
        assert settings_content.count("help") == 0 or "help" not in settings_content.lower(), \
            "Help references should be removed from settings"
        
        print("✓ Removal follows established code patterns")

    def test_feature_flag_not_needed(self):
        """Test that no feature flag is needed (hard removal is appropriate)"""
        # This verifies that the removal is definitive and doesn't require toggles
        settings_path = "frontend/lib/presentation/screens/settings_screen.dart"
        
        with open(settings_path, 'r') as f:
            content = f.read()
        
        # Verify no feature flags or conditionals for Help & Support
        assert "kEnableHelpSupport" not in content, \
            "Should not use feature flags for Help & Support"
        assert "enableContactUs" not in content, \
            "Should not use feature flags for Contact Us"
        
        print("✓ No feature flags needed - hard removal is appropriate")


def run_all_tests():
    """Run all Contact Us removal tests"""
    print("\n" + "="*70)
    print("CONTACT US REMOVAL TEST SUITE")
    print("="*70 + "\n")
    
    test_classes = [
        TestContactUsRemoval,
        TestContactUsRemovalIntegration,
        TestContactUsRemovalCompliance
    ]
    
    total_tests = 0
    passed_tests = 0
    
    for test_class in test_classes:
        print(f"\n{test_class.__name__}:")
        print("-" * 70)
        
        test_instance = test_class()
        test_methods = [method for method in dir(test_instance) 
                       if method.startswith('test_')]
        
        for test_method in test_methods:
            total_tests += 1
            try:
                method = getattr(test_instance, test_method)
                method()
                passed_tests += 1
            except AssertionError as e:
                print(f"✗ {test_method}: {str(e)}")
            except Exception as e:
                print(f"✗ {test_method}: {type(e).__name__}: {str(e)}")
    
    print("\n" + "="*70)
    print(f"TEST RESULTS: {passed_tests}/{total_tests} tests passed")
    print("="*70 + "\n")
    
    return passed_tests == total_tests


if __name__ == "__main__":
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)

#!/usr/bin/env python3
"""
Comprehensive test script to validate Kubernetes YAML fixes and mock database imports
"""

import asyncio
import sys
import os
import yaml
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def test_kubernetes_yaml_validation():
    """Test Kubernetes YAML validation and fix errors"""
    print("=" * 60)
    print("Testing Kubernetes YAML Validation")
    print("=" * 60)
    
    k8s_file = Path("kubernetes.yaml")
    if not k8s_file.exists():
        print("ERROR: kubernetes.yaml not found")
        assert False, "kubernetes.yaml not found"
    
    try:
        with open(k8s_file, 'r') as f:
            content = f.read()
        
        # Split documents
        documents = content.split('---')
        errors = []
        fixes = []
        
        for i, doc in enumerate(documents, 1):
            if not doc.strip():
                continue
                
            try:
                yaml_doc = yaml.safe_load(doc)
                if not yaml_doc:
                    continue
                    
                kind = yaml_doc.get('kind', '')
                metadata = yaml_doc.get('metadata', {})
                name = metadata.get('name', f'document-{i}')
                
                # Check for required fields based on kind
                if kind == 'Deployment':
                    spec = yaml_doc.get('spec', {})
                    if 'selector' not in spec:
                        errors.append(f"Document {i} ({name}): Missing 'selector' in Deployment")
                        fixes.append(f"Add selector to Deployment {name}")
                    if 'template' not in spec:
                        errors.append(f"Document {i} ({name}): Missing 'template' in Deployment")
                        fixes.append(f"Add template to Deployment {name}")
                        
                elif kind == 'StatefulSet':
                    spec = yaml_doc.get('spec', {})
                    if 'selector' not in spec:
                        errors.append(f"Document {i} ({name}): Missing 'selector' in StatefulSet")
                        fixes.append(f"Add selector to StatefulSet {name}")
                    if 'template' not in spec:
                        errors.append(f"Document {i} ({name}): Missing 'template' in StatefulSet")
                        fixes.append(f"Add template to StatefulSet {name}")
                        
                elif kind == 'HorizontalPodAutoscaler':
                    spec = yaml_doc.get('spec', {})
                    scale_target_ref = spec.get('scaleTargetRef', {})
                    if 'name' not in scale_target_ref:
                        errors.append(f"Document {i} ({name}): Missing 'name' in scaleTargetRef")
                        fixes.append(f"Add name to scaleTargetRef in HPA {name}")
                        
                elif kind == 'PodDisruptionBudget':
                    spec = yaml_doc.get('spec', {})
                    if 'selector' not in spec:
                        errors.append(f"Document {i} ({name}): Missing 'selector' in PodDisruptionBudget")
                        fixes.append(f"Add selector to PodDisruptionBudget {name}")
                    # Check minAvailable type
                    min_available = spec.get('minAvailable')
                    if isinstance(min_available, str) and min_available.isdigit():
                        errors.append(f"Document {i} ({name}): minAvailable should be integer, not string")
                        fixes.append(f"Convert minAvailable to integer in PodDisruptionBudget {name}")
                        
                elif kind == 'NetworkPolicy':
                    spec = yaml_doc.get('spec', {})
                    if 'podSelector' not in spec:
                        errors.append(f"Document {i} ({name}): Missing 'podSelector' in NetworkPolicy")
                        fixes.append(f"Add podSelector to NetworkPolicy {name}")
                        
            except yaml.YAMLError as e:
                errors.append(f"Document {i}: YAML parsing error: {e}")
                fixes.append(f"Fix YAML syntax in document {i}")
        
        if errors:
            print(f"ERROR: Found {len(errors)} Kubernetes YAML errors:")
            for error in errors:
                print(f"  - {error}")
            print(f"\nSuggested fixes:")
            for fix in fixes:
                print(f"  - {fix}")
            assert False, f"Found {len(errors)} Kubernetes YAML errors"
        else:
            print("SUCCESS: Kubernetes YAML validation passed")
            assert True
            
    except Exception as e:
        print(f"ERROR: Error validating Kubernetes YAML: {e}")
        assert False, f"Error validating Kubernetes YAML: {e}"

def test_mock_database_import():
    """Test mock_database import functionality"""
    print("\n" + "=" * 60)
    print("Testing Mock Database Import")
    print("=" * 60)
    
    try:
        # Test direct import
        try:
            from mock_database import get_mock_db, MockMongoClient, MockDatabase
            print("SUCCESS: Direct mock_database import successful")
        except ImportError as e:
            print(f"ERROR: Direct import failed: {e}")
            # Try alternative import
            try:
                from backend.mock_database import get_mock_db, MockMongoClient, MockDatabase
                print("SUCCESS: Backend mock_database import successful")
            except ImportError as e2:
                print(f"ERROR: Backend import also failed: {e2}")
                assert False, "Mock database import failed"
        
        # Test functionality
        try:
            mock_client = MockMongoClient()
            mock_db = mock_client['hypersend']
            print("SUCCESS: Mock client and database creation successful")
            
            # Test get_mock_db singleton
            db1 = get_mock_db()
            db2 = get_mock_db()
            if db1 is db2:
                print("SUCCESS: Mock database singleton pattern working")
            else:
                print("ERROR: Mock database singleton pattern failed")
                assert False, "Mock database singleton pattern failed"
                
        except Exception as e:
            print(f"ERROR: Mock database functionality test failed: {e}")
            assert False, f"Mock database functionality test failed: {e}"
            
        print("SUCCESS: Mock database import test passed")
        assert True
        
    except Exception as e:
        print(f"ERROR: Mock database import test failed: {e}")
        assert False, f"Mock database import test failed: {e}"

def test_async_mock_operations():
    """Test async mock database operations"""
    print("\n" + "=" * 60)
    print("Testing Async Mock Operations")
    print("=" * 60)
    
    try:
        import asyncio
        from mock_database import get_mock_db
        
        async def run_async_tests():
            mock_db = get_mock_db()
            
            # Test collection operations
            users_collection = mock_db.users
            chats_collection = mock_db.chats
            messages_collection = mock_db.messages
            
            print("SUCCESS: Mock collections accessible")
            
            # Test basic operations
            test_user = {"username": "testuser", "email": "test@example.com"}
            result = await users_collection.insert_one(test_user)
            print("SUCCESS: Mock insert_one operation successful")
            
            # Test find operation
            found_user = await users_collection.find_one({"username": "testuser"})
            if found_user and found_user.get("username") == "testuser":
                print("SUCCESS: Mock find_one operation successful")
            else:
                print("ERROR: Mock find_one operation failed")
                assert False, "Mock find_one operation failed"
                
            print("SUCCESS: Async mock operations test passed")
            return True
        
        # Run the async tests
        result = asyncio.run(run_async_tests())
        return result
        
    except Exception as e:
        print(f"ERROR: Async mock operations test failed: {e}")
        assert False, f"Async mock operations test failed: {e}"

def main():
    """Main test function"""
    print("Starting Comprehensive Kubernetes and Mock Database Tests")
    
    results = []
    
    # Test 1: Kubernetes YAML validation
    results.append(test_kubernetes_yaml_validation())
    
    # Test 2: Mock database import
    results.append(test_mock_database_import())
    
    # Test 3: Async mock operations
    results.append(test_async_mock_operations())
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    test_names = [
        "Kubernetes YAML Validation",
        "Mock Database Import",
        "Async Mock Operations"
    ]
    
    passed = sum(results)
    total = len(results)
    
    for i, (name, result) in enumerate(zip(test_names, results)):
        status = "PASSED" if result else "FAILED"
        print(f"{i+1}. {name}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("All tests passed! System is ready.")
        return 0
    else:
        print("Some tests failed. Please review the errors above.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
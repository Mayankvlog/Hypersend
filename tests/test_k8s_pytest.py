#!/usr/bin/env python3
"""
Pytest test suite for Kubernetes YAML validation and mock database functionality
"""

import pytest
import asyncio
import sys
import os
import yaml
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

class TestKubernetesValidation:
    """Test Kubernetes YAML validation"""
    
    def test_kubernetes_yaml_exists(self):
        """Test that kubernetes.yaml file exists"""
        k8s_file = Path("kubernetes.yaml")
        assert k8s_file.exists(), "kubernetes.yaml file not found"
    
    def test_kubernetes_yaml_syntax(self):
        """Test that kubernetes.yaml has valid YAML syntax"""
        k8s_file = Path("kubernetes.yaml")
        with open(k8s_file, 'r') as f:
            content = f.read()
        
        documents = content.split('---')
        for i, doc in enumerate(documents, 1):
            if not doc.strip():
                continue
            try:
                yaml.safe_load(doc)
            except yaml.YAMLError as e:
                pytest.fail(f"Document {i} has invalid YAML syntax: {e}")
    
    def test_kubernetes_deployments_have_required_fields(self):
        """Test that all Deployments have required selector and template fields"""
        k8s_file = Path("kubernetes.yaml")
        with open(k8s_file, 'r') as f:
            content = f.read()
        
        documents = content.split('---')
        for i, doc in enumerate(documents, 1):
            if not doc.strip():
                continue
                
            try:
                yaml_doc = yaml.safe_load(doc)
                if not yaml_doc:
                    continue
                    
                if yaml_doc.get('kind') == 'Deployment':
                    spec = yaml_doc.get('spec', {})
                    assert 'selector' in spec, f"Deployment {i} missing selector"
                    assert 'template' in spec, f"Deployment {i} missing template"
                    
            except yaml.YAMLError:
                continue  # Skip if invalid YAML (caught by previous test)
    
    def test_kubernetes_statefulsets_have_required_fields(self):
        """Test that all StatefulSets have required selector and template fields"""
        k8s_file = Path("kubernetes.yaml")
        with open(k8s_file, 'r') as f:
            content = f.read()
        
        documents = content.split('---')
        for i, doc in enumerate(documents, 1):
            if not doc.strip():
                continue
                
            try:
                yaml_doc = yaml.safe_load(doc)
                if not yaml_doc:
                    continue
                    
                if yaml_doc.get('kind') == 'StatefulSet':
                    spec = yaml_doc.get('spec', {})
                    assert 'selector' in spec, f"StatefulSet {i} missing selector"
                    assert 'template' in spec, f"StatefulSet {i} missing template"
                    
            except yaml.YAMLError:
                continue
    
    def test_kubernetes_pod_disruption_budgets_have_correct_types(self):
        """Test that PodDisruptionBudgets have correct field types"""
        k8s_file = Path("kubernetes.yaml")
        with open(k8s_file, 'r') as f:
            content = f.read()
        
        documents = content.split('---')
        for i, doc in enumerate(documents, 1):
            if not doc.strip():
                continue
                
            try:
                yaml_doc = yaml.safe_load(doc)
                if not yaml_doc:
                    continue
                    
                if yaml_doc.get('kind') == 'PodDisruptionBudget':
                    spec = yaml_doc.get('spec', {})
                    assert 'selector' in spec, f"PodDisruptionBudget {i} missing selector"
                    
                    min_available = spec.get('minAvailable')
                    if min_available is not None:
                        # Allow integers, percentage strings, and integer strings
                        if isinstance(min_available, str):
                            if not (min_available.isdigit() or min_available.endswith('%')):
                                pytest.fail(f"PodDisruptionBudget {i} minAvailable should be integer or percentage, not: {min_available}")
                    
            except yaml.YAMLError:
                continue
    
    def test_kubernetes_network_policies_have_pod_selector(self):
        """Test that NetworkPolicies have podSelector field"""
        k8s_file = Path("kubernetes.yaml")
        with open(k8s_file, 'r') as f:
            content = f.read()
        
        documents = content.split('---')
        for i, doc in enumerate(documents, 1):
            if not doc.strip():
                continue
                
            try:
                yaml_doc = yaml.safe_load(doc)
                if not yaml_doc:
                    continue
                    
                if yaml_doc.get('kind') == 'NetworkPolicy':
                    spec = yaml_doc.get('spec', {})
                    assert 'podSelector' in spec, f"NetworkPolicy {i} missing podSelector"
                    
            except yaml.YAMLError:
                continue


class TestMockDatabase:
    """Test mock database functionality"""
    
    def test_mock_database_import(self):
        """Test that mock_database can be imported"""
        try:
            from mock_database import get_mock_db, MockMongoClient, MockDatabase
        except ImportError as e:
            pytest.fail(f"Failed to import mock_database: {e}")
    
    def test_mock_mongo_client_creation(self):
        """Test MockMongoClient can be created"""
        from mock_database import MockMongoClient
        
        client = MockMongoClient()
        assert client is not None
        assert hasattr(client, 'databases')
    
    def test_mock_database_creation(self):
        """Test MockDatabase can be created"""
        from mock_database import MockDatabase
        
        db = MockDatabase()
        assert db is not None
        assert db.name == "test"
        assert hasattr(db, 'collections')
    
    def test_mock_database_singleton(self):
        """Test that get_mock_db returns singleton instance"""
        from mock_database import get_mock_db
        
        db1 = get_mock_db()
        db2 = get_mock_db()
        assert db1 is db2, "get_mock_db should return same instance (singleton)"
    
    def test_mock_collection_access(self):
        """Test that mock collections can be accessed"""
        from mock_database import get_mock_db
        
        db = get_mock_db()
        users_collection = db.users
        chats_collection = db.chats
        messages_collection = db.messages
        
        assert users_collection is not None
        assert chats_collection is not None
        assert messages_collection is not None


class TestAsyncMockOperations:
    """Test async mock database operations"""
    
    @pytest.mark.asyncio
    async def test_mock_insert_one(self):
        """Test async insert_one operation"""
        from mock_database import get_mock_db
        
        mock_db = get_mock_db()
        users_collection = mock_db.users
        
        test_user = {"username": "pytest_user", "email": "pytest@example.com"}
        result = await users_collection.insert_one(test_user)
        
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_mock_find_one(self):
        """Test async find_one operation"""
        from mock_database import get_mock_db
        
        mock_db = get_mock_db()
        users_collection = mock_db.users
        
        # First insert a test document
        test_user = {"username": "pytest_find", "email": "find@example.com"}
        await users_collection.insert_one(test_user)
        
        # Then find it
        found_user = await users_collection.find_one({"username": "pytest_find"})
        
        assert found_user is not None
        assert found_user.get("username") == "pytest_find"
        assert found_user.get("email") == "find@example.com"
    
    @pytest.mark.asyncio
    async def test_mock_find_nonexistent(self):
        """Test find_one with non-existent document"""
        from mock_database import get_mock_db
        
        mock_db = get_mock_db()
        users_collection = mock_db.users
        
        found_user = await users_collection.find_one({"username": "nonexistent_user"})
        assert found_user is None


class TestIntegration:
    """Integration tests"""
    
    def test_kubernetes_and_mock_database_integration(self):
        """Test that Kubernetes YAML validation and mock database both work"""
        # This is a simple integration test to ensure both systems work together
        from mock_database import get_mock_db
        
        # Verify mock database works
        db = get_mock_db()
        assert db is not None
        
        # Verify kubernetes.yaml exists and is parseable
        k8s_file = Path("kubernetes.yaml")
        assert k8s_file.exists()
        
        with open(k8s_file, 'r') as f:
            content = f.read()
        
        # Should not crash when parsing
        documents = content.split('---')
        for doc in documents:
            if doc.strip():
                yaml.safe_load(doc)  # Should not raise exception


if __name__ == "__main__":
    # Allow running directly
    pytest.main([__file__, "-v"])
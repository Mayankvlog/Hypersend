#!/usr/bin/env python3
"""
Test script to validate Kubernetes YAML fixes
"""

import yaml
import pytest

def test_kubernetes_yaml_syntax():
    """Test that Kubernetes YAML has valid syntax"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        try:
            documents = list(yaml.safe_load_all(f))
            assert len(documents) > 0, "YAML should contain at least one document"
        except yaml.YAMLError as e:
            pytest.fail(f"Invalid YAML syntax: {e}")

def test_no_duplicate_separators():
    """Test that there are no duplicate document separators"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        content = f.read()
        assert '---\n---' not in content, "Found duplicate document separators"

def test_configmap_references():
    """Test that ConfigMap references are correct"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        content = f.read()
        # Check that nginx-configmap is referenced correctly
        assert 'name: nginx-configmap' in content, "nginx-configmap should be referenced"
        # Check that incorrect ConfigMap reference doesn't exist in configMap sections
        import re
        # Find all configMap sections and ensure none reference nginx-config incorrectly
        configmap_sections = re.findall(r'configMap:\s*\n\s*name:\s*(\S+)', content)
        incorrect_refs = [ref for ref in configmap_sections if ref == 'nginx-config']
        assert not incorrect_refs, f"Incorrect configMap references found: {incorrect_refs}"

def test_secret_key_references():
    """Test that secret key references match actual keys"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        documents = list(yaml.safe_load_all(f))
        
    # Find the hypersend-secrets secret
    secret_doc = None
    for doc in documents:
        if doc and doc.get('kind') == 'Secret' and doc.get('metadata', {}).get('name') == 'hypersend-secrets':
            secret_doc = doc
            break
    
    assert secret_doc is not None, "hypersend-secrets secret should exist"
    secret_keys = set(secret_doc.get('data', {}).keys())
    
    # Check that referenced keys exist in the secret
    expected_keys = {'MONGODB_URI', 'SECRET_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'}
    missing_keys = expected_keys - secret_keys
    assert not missing_keys, f"Missing secret keys: {missing_keys}"

def test_no_fan_out_worker_pdb():
    """Test that fan-out-worker-pdb has been removed"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        content = f.read()
        assert 'fan-out-worker-pdb' not in content, "fan-out-worker-pdb should be removed"

def test_no_duplicate_hpa():
    """Test that duplicate e2ee-service HPA has been removed"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        content = f.read()
        # Should have only one e2ee-service HPA
        hpa_count = content.count('name: e2ee-service-hpa')
        assert hpa_count == 1, f"Should have exactly one e2ee-service HPA, found {hpa_count}"
        assert 'e2ee-service-hpa-duplicate' not in content, "Duplicate HPA should be removed"

def test_deployments_have_required_fields():
    """Test that all Deployments have selector and template"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        documents = list(yaml.safe_load_all(f))
    
    for doc in documents:
        if doc and doc.get('kind') == 'Deployment':
            spec = doc.get('spec', {})
            assert 'selector' in spec, f"Deployment {doc.get('metadata', {}).get('name')} missing selector"
            assert 'template' in spec, f"Deployment {doc.get('metadata', {}).get('name')} missing template"

def test_networkpolicies_have_podselector():
    """Test that all NetworkPolicies have podSelector"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        documents = list(yaml.safe_load_all(f))
    
    for doc in documents:
        if doc and doc.get('kind') == 'NetworkPolicy':
            spec = doc.get('spec', {})
            assert 'podSelector' in spec, f"NetworkPolicy {doc.get('metadata', {}).get('name')} missing podSelector"

def test_limitranges_have_limits():
    """Test that all LimitRanges have limits"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        documents = list(yaml.safe_load_all(f))
    
    for doc in documents:
        if doc and doc.get('kind') == 'LimitRange':
            spec = doc.get('spec', {})
            assert 'limits' in spec, f"LimitRange {doc.get('metadata', {}).get('name')} missing limits"
            assert len(spec['limits']) > 0, f"LimitRange {doc.get('metadata', {}).get('name')} should have at least one limit"

def test_all_deployments_complete():
    """Test that all Deployments found are actually complete"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        documents = list(yaml.safe_load_all(f))
    
    deployments = [doc for doc in documents if doc and doc.get('kind') == 'Deployment']
    
    for deployment in deployments:
        name = deployment.get('metadata', {}).get('name', 'unknown')
        spec = deployment.get('spec', {})
        
        # Check required fields
        assert 'selector' in spec, f"Deployment {name} missing selector"
        assert 'matchLabels' in spec['selector'], f"Deployment {name} missing selector.matchLabels"
        assert 'template' in spec, f"Deployment {name} missing template"
        assert 'spec' in spec['template'], f"Deployment {name} missing template.spec"
        assert 'containers' in spec['template']['spec'], f"Deployment {name} missing template.spec.containers"
        assert len(spec['template']['spec']['containers']) > 0, f"Deployment {name} has no containers"

def test_all_networkpolicies_complete():
    """Test that all NetworkPolicies found are actually complete"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        documents = list(yaml.safe_load_all(f))
    
    networkpolicies = [doc for doc in documents if doc and doc.get('kind') == 'NetworkPolicy']
    
    for policy in networkpolicies:
        name = policy.get('metadata', {}).get('name', 'unknown')
        spec = policy.get('spec', {})
        
        # Check required fields
        assert 'podSelector' in spec, f"NetworkPolicy {name} missing podSelector"
        assert 'policyTypes' in spec, f"NetworkPolicy {name} missing policyTypes"
        assert len(spec['policyTypes']) > 0, f"NetworkPolicy {name} has no policyTypes"

def test_all_limitranges_complete():
    """Test that all LimitRanges found are actually complete"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        documents = list(yaml.safe_load_all(f))
    
    limitranges = [doc for doc in documents if doc and doc.get('kind') == 'LimitRange']
    
    for limitrange in limitranges:
        name = limitrange.get('metadata', {}).get('name', 'unknown')
        spec = limitrange.get('spec', {})
        
        # Check required fields
        assert 'limits' in spec, f"LimitRange {name} missing limits"
        assert len(spec['limits']) > 0, f"LimitRange {name} has no limits"
        
        for limit in spec['limits']:
            assert 'type' in limit, f"LimitRange {name} limit missing type"
            assert 'default' in limit or 'max' in limit, f"LimitRange {name} limit missing default/max"

def test_no_invalid_service_types():
    """Test that all Service type fields are strings"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        documents = list(yaml.safe_load_all(f))
    
    services = [doc for doc in documents if doc and doc.get('kind') == 'Service']
    
    for service in services:
        name = service.get('metadata', {}).get('name', 'unknown')
        spec = service.get('spec', {})
        
        if 'type' in spec:
            assert isinstance(spec['type'], str), f"Service {name} type should be string, got {type(spec['type'])}"

def test_document_structure():
    """Test that all Kubernetes resources are properly structured"""
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    kubernetes_path = os.path.join(current_dir, '..', 'kubernetes.yaml')
    with open(kubernetes_path, 'r') as f:
        documents = list(yaml.safe_load_all(f))
    
    for i, doc in enumerate(documents):
        if doc is None:  # Skip empty documents
            continue
            
        # Every document should have apiVersion, kind, and metadata
        assert 'apiVersion' in doc, f"Document {i} missing apiVersion"
        assert 'kind' in doc, f"Document {i} missing kind"
        assert 'metadata' in doc, f"Document {i} missing metadata"
        assert 'name' in doc['metadata'], f"Document {i} missing metadata.name"

if __name__ == '__main__':
    # Run tests directly if script is executed
    pytest.main([__file__, '-v'])
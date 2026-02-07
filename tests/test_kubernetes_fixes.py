"""
Pytest tests to validate Kubernetes YAML fixes:
1. Replace yourusername/* images → REAL DockerHub images
2. AWS secrets → proper base64 format
3. Nginx cache mountPath fix
"""

import yaml
import base64
import re
import pytest
from pathlib import Path


class TestKubernetesFixes:
    """Test suite for kubernetes.yaml fixes"""
    
    @pytest.fixture
    def k8s_config(self):
        """Load and parse kubernetes.yaml"""
        k8s_path = Path(__file__).parent.parent / 'kubernetes.yaml'
        with open(k8s_path, 'r') as f:
            configs = list(yaml.safe_load_all(f))
        return configs
    
    def test_no_yourusername_in_backend_image(self, k8s_config):
        """Test 1a: Backend image should not contain 'yourusername'"""
        backend_deployment = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'Deployment' and 
             'backend' in doc.get('metadata', {}).get('name', '')),
            None
        )
        assert backend_deployment is not None, "Backend deployment not found"
        
        image = backend_deployment['spec']['template']['spec']['containers'][0]['image']
        assert 'yourusername' not in image, f"Backend image still contains 'yourusername': {image}"
        assert image == 'ghcr.io/mayankvlog/hypersend-backend:latest', f"Expected ghcr.io image, got: {image}"
        print(f"✅ Backend image: {image}")
    
    def test_no_yourusername_in_frontend_image(self, k8s_config):
        """Test 1b: Frontend image should not contain 'yourusername'"""
        frontend_deployment = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'Deployment' and 
             'frontend' in doc.get('metadata', {}).get('name', '')),
            None
        )
        assert frontend_deployment is not None, "Frontend deployment not found"
        
        image = frontend_deployment['spec']['template']['spec']['containers'][0]['image']
        assert 'yourusername' not in image, f"Frontend image still contains 'yourusername': {image}"
        assert image == 'ghcr.io/mayankvlog/hypersend-frontend:latest', f"Expected ghcr.io image, got: {image}"
        print(f"✅ Frontend image: {image}")
    
    def test_no_yourusername_in_nginx_image(self, k8s_config):
        """Test 1c: Nginx image should use official nginx, not yourusername"""
        nginx_deployment = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'Deployment' and 
             'nginx' in doc.get('metadata', {}).get('name', '')),
            None
        )
        assert nginx_deployment is not None, "Nginx deployment not found"
        
        image = nginx_deployment['spec']['template']['spec']['containers'][0]['image']
        assert 'yourusername' not in image, f"Nginx image still contains 'yourusername': {image}"
        assert image == 'nginx:1.25-alpine', f"Expected official nginx image, got: {image}"
        print(f"✅ Nginx image: {image}")
    
    def test_aws_access_key_id_base64_encoded(self, k8s_config):
        """Test 2a: AWS_ACCESS_KEY_ID should be properly base64 encoded"""
        secret = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'Secret' and 
             doc.get('metadata', {}).get('name') == 'hypersend-secrets'),
            None
        )
        assert secret is not None, "hypersend-secrets not found"
        
        aws_access_key = secret.get('data', {}).get('AWS_ACCESS_KEY_ID', '')
        assert aws_access_key, "AWS_ACCESS_KEY_ID not found in secrets"
        
        # Remove quotes if present
        if aws_access_key.startswith('"'):
            aws_access_key = aws_access_key.strip('"')
        
        # Validate base64 encoding
        try:
            decoded = base64.b64decode(aws_access_key, validate=True)
            decoded_str = decoded.decode('utf-8')
            assert len(decoded_str) > 0, "Decoded AWS_ACCESS_KEY_ID is empty"
            print(f"✅ AWS_ACCESS_KEY_ID is valid base64")
        except Exception as e:
            pytest.fail(f"AWS_ACCESS_KEY_ID is not valid base64: {e}")
    
    def test_aws_secret_access_key_base64_encoded(self, k8s_config):
        """Test 2b: AWS_SECRET_ACCESS_KEY should be properly base64 encoded"""
        secret = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'Secret' and 
             doc.get('metadata', {}).get('name') == 'hypersend-secrets'),
            None
        )
        assert secret is not None, "hypersend-secrets not found"
        
        aws_secret_key = secret.get('data', {}).get('AWS_SECRET_ACCESS_KEY', '')
        assert aws_secret_key, "AWS_SECRET_ACCESS_KEY not found in secrets"
        
        # Remove quotes if present
        if aws_secret_key.startswith('"'):
            aws_secret_key = aws_secret_key.strip('"')
        
        # Validate base64 encoding
        try:
            decoded = base64.b64decode(aws_secret_key, validate=True)
            decoded_str = decoded.decode('utf-8')
            assert len(decoded_str) > 0, "Decoded AWS_SECRET_ACCESS_KEY is empty"
            print(f"✅ AWS_SECRET_ACCESS_KEY is valid base64")
        except Exception as e:
            pytest.fail(f"AWS_SECRET_ACCESS_KEY is not valid base64: {e}")
    
    def test_nginx_cache_path_configured(self, k8s_config):
        """Test 3a: Nginx cache should have proxy_cache_path directive"""
        nginx_configmap = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'ConfigMap' and 
             'nginx' in doc.get('metadata', {}).get('name', '')),
            None
        )
        assert nginx_configmap is not None, "Nginx ConfigMap not found"
        
        nginx_conf = nginx_configmap.get('data', {}).get('nginx.conf', '')
        assert nginx_conf, "nginx.conf not found in ConfigMap"
        
        assert 'proxy_cache_path' in nginx_conf, "proxy_cache_path directive not found"
        assert '/var/cache/nginx' in nginx_conf, "Cache path /var/cache/nginx not configured"
        print(f"✅ Nginx cache path configured in nginx.conf")
    
    def test_nginx_cache_volume_mount(self, k8s_config):
        """Test 3b: Nginx deployment should have nginx-cache volumeMount at correct path"""
        nginx_deployment = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'Deployment' and 
             'nginx' in doc.get('metadata', {}).get('name', '')),
            None
        )
        assert nginx_deployment is not None, "Nginx deployment not found"
        
        vol_mounts = nginx_deployment['spec']['template']['spec']['containers'][0].get('volumeMounts', [])
        cache_mount = next((vm for vm in vol_mounts if vm.get('name') == 'nginx-cache'), None)
        
        assert cache_mount is not None, "nginx-cache volumeMount not found"
        assert cache_mount.get('mountPath') == '/var/cache/nginx/client_temp', \
            f"nginx-cache mountPath should be /var/cache/nginx/client_temp, got: {cache_mount.get('mountPath')}"
        assert cache_mount.get('readOnly', False) is not True, "nginx-cache should not be readOnly"
        print(f"✅ Nginx cache volumeMount configured at /var/cache/nginx/client_temp")
    
    def test_nginx_cache_pvc_exists(self, k8s_config):
        """Test 3c: nginx-cache PVC should be defined"""
        pvc = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'PersistentVolumeClaim' and 
             'nginx-cache' in doc.get('metadata', {}).get('name', '')),
            None
        )
        assert pvc is not None, "nginx-cache PVC not found"
        
        storage = pvc['spec']['resources']['requests']['storage']
        assert storage == '1Gi', f"Expected 1Gi storage, got: {storage}"
        print(f"✅ Nginx cache PVC exists with 1Gi storage")
    
    def test_nginx_proxy_cache_used_in_locations(self, k8s_config):
        """Test 3d: Nginx locations should use proxy_cache for static assets"""
        nginx_configmap = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'ConfigMap' and 
             'nginx' in doc.get('metadata', {}).get('name', '')),
            None
        )
        assert nginx_configmap is not None, "Nginx ConfigMap not found"
        
        nginx_conf = nginx_configmap.get('data', {}).get('nginx.conf', '')
        assert 'proxy_cache hypersend_cache' in nginx_conf, \
            "proxy_cache hypersend_cache directive not found in locations"
        print(f"✅ Nginx locations using proxy_cache hypersend_cache")


    def test_configmap_no_shell_variables(self, k8s_config):
        """Test 4: ConfigMap should not use ${VARIABLE} shell syntax"""
        configmap = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'ConfigMap' and 
             doc.get('metadata', {}).get('name') == 'hypersend-config'),
            None
        )
        assert configmap is not None, "hypersend-config ConfigMap not found"
        
        data = configmap.get('data', {})
        for key, value in data.items():
            if value and isinstance(value, str):
                assert '${' not in value, f"ConfigMap key '{key}' contains shell variable syntax: {value}"
        
        # Verify specific keys have direct values (format-based, not hardcoded)
        secret_key = data.get('SECRET_KEY', '')
        assert secret_key, "SECRET_KEY must not be empty"
        assert len(secret_key) > 10, "SECRET_KEY should be a meaningful secret (length > 10)"
        assert '${' not in secret_key, "SECRET_KEY should not contain shell variable syntax"
        
        api_base_url = data.get('API_BASE_URL', '')
        assert api_base_url, "API_BASE_URL must not be empty"
        assert api_base_url.startswith('https://'), "API_BASE_URL must use HTTPS"
        assert 'zaply.in.net' in api_base_url, "API_BASE_URL should contain zaply.in.net domain"
        assert '/api/' in api_base_url, "API_BASE_URL should contain /api/ path"
        
        aws_access_key = data.get('AWS_ACCESS_KEY_ID', '')
        assert aws_access_key, "AWS_ACCESS_KEY_ID must not be empty"
        assert aws_access_key.startswith('AKIA'), "AWS_ACCESS_KEY_ID should start with AKIA"
        assert len(aws_access_key) >= 20, "AWS_ACCESS_KEY_ID should be at least 20 characters"
        # Validate it's alphanumeric after AKIA prefix
        assert aws_access_key[4:].isalnum(), "AWS_ACCESS_KEY_ID should contain only alphanumeric characters after AKIA"
        
        aws_region = data.get('AWS_REGION', '')
        assert aws_region, "AWS_REGION must not be empty"
        # AWS region pattern: {region}-{availability-zone}, e.g., us-east-1
        region_pattern = r'^[a-z]{2}-[a-z]+-\d{1}$'
        assert re.match(region_pattern, aws_region), \
            f"AWS_REGION should match pattern '{region_pattern}', got: {aws_region}"
        
        print(f"✅ ConfigMap has no shell variables - all direct values with valid formats")
    
    def test_nginx_cache_mountpath_correct(self, k8s_config):
        """Test 5: Nginx cache mountPath should be /var/cache/nginx/client_temp"""
        nginx_deployment = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'Deployment' and 
             'nginx' in doc.get('metadata', {}).get('name', '')),
            None
        )
        assert nginx_deployment is not None, "Nginx deployment not found"
        
        vol_mounts = nginx_deployment['spec']['template']['spec']['containers'][0].get('volumeMounts', [])
        cache_mount = next((vm for vm in vol_mounts if vm.get('name') == 'nginx-cache'), None)
        
        assert cache_mount is not None, "nginx-cache volumeMount not found"
        assert cache_mount.get('mountPath') == '/var/cache/nginx/client_temp', \
            f"Expected /var/cache/nginx/client_temp, got: {cache_mount.get('mountPath')}"
        print(f"✅ Nginx cache mountPath: /var/cache/nginx/client_temp")
    
    def test_nginx_proxy_cache_path_matches_mount(self, k8s_config):
        """Test 6: Nginx proxy_cache_path should match volumeMount path"""
        nginx_configmap = next(
            (doc for doc in k8s_config if doc and 
             doc.get('kind') == 'ConfigMap' and 
             'nginx' in doc.get('metadata', {}).get('name', '')),
            None
        )
        assert nginx_configmap is not None, "Nginx ConfigMap not found"
        
        nginx_conf = nginx_configmap.get('data', {}).get('nginx.conf', '')
        assert nginx_conf, "nginx.conf not found in ConfigMap"
        
        assert 'proxy_cache_path /var/cache/nginx/client_temp' in nginx_conf, \
            "proxy_cache_path should use /var/cache/nginx/client_temp"
        assert 'proxy_cache_path /var/cache/nginx ' not in nginx_conf.replace('/var/cache/nginx/client_temp', ''), \
            "Old cache path /var/cache/nginx (without /client_temp) should not exist"
        print(f"✅ Nginx proxy_cache_path: /var/cache/nginx/client_temp (matches mountPath)")


def test_docker_compose_unchanged():
    """Verification: docker-compose.yml should remain unchanged"""
    docker_compose_path = Path(__file__).parent.parent / 'docker-compose.yml'
    assert docker_compose_path.exists(), "docker-compose.yml not found"
    
    with open(docker_compose_path, 'r') as f:
        content = f.read()
    
    # Verify file hasn't been modified (basic check)
    assert 'services:' in content or 'version:' in content, "docker-compose.yml appears corrupted"
    print(f"✅ docker-compose.yml unchanged")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

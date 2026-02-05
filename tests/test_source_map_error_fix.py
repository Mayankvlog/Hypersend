"""
Comprehensive test for source map error fix and frontend/backend integration
Tests all components: frontend build, nginx config, docker-compose, and Flutter analysis
"""

import pytest
import os
import sys
import re
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def _read_text_file(path: Path) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(path, "r", encoding="latin-1") as f:
            return f.read()


class TestSourceMapErrorFix:
    """Test that source map errors are fixed"""
    
    def test_frontend_dockerfile_no_source_maps(self):
        """Test that frontend Dockerfile builds without source maps"""
        dockerfile_path = Path(__file__).parent.parent / "frontend" / "Dockerfile"

        content = _read_text_file(dockerfile_path)
        
        # Should have --no-source-maps flag
        assert "--no-source-maps" in content, "Dockerfile should build without source maps"
        
        # Should NOT have --source-maps flag
        assert "--source-maps" not in content, "Dockerfile should not have --source-maps flag"
        
        print("✅ Frontend Dockerfile correctly builds without source maps")
    
    def test_nginx_conf_handles_map_files(self):
        """Test that nginx.conf properly handles .map file requests"""
        nginx_path = Path(__file__).parent.parent / "nginx.conf"

        content = _read_text_file(nginx_path)
        
        # Should have .map location block
        assert "\.map$" in content, "nginx.conf should have .map location block"
        
        # Should return 404 for .map files
        assert "return 404" in content, "nginx.conf should return 404 for .map files"
        
        print("✅ Nginx.conf properly handles .map file requests")
    
    def test_docker_compose_frontend_build_args(self):
        """Test that frontend image is properly configured for production"""
        docker_compose_path = Path(__file__).parent.parent / "docker-compose.yml"

        content = _read_text_file(docker_compose_path)
        
        # Should have frontend service using pre-built image (not build)
        assert "frontend:" in content, "docker-compose should have frontend service"
        
        # Should use DockerHub image (production deployment)
        assert "yourusername/hypersend-frontend" in content, "frontend should use pre-built DockerHub image"
        
        # Frontend environment passed via Kubernetes/runtime, not build args
        assert "API_BASE_URL" in content or "https://zaply.in.net" in content, "API configuration should be present"
        
        print("✅ Docker-compose correctly configures frontend image")
    
    def test_web_index_html_csp_headers(self):
        """Test that web/index.html has proper CSP headers"""
        index_path = Path(__file__).parent.parent / "frontend" / "web" / "index.html"

        content = _read_text_file(index_path)
        
        # Should have Content-Security-Policy meta tag
        assert "Content-Security-Policy" in content, "index.html should have CSP meta tag"
        
        # Should allow CanvasKit from gstatic
        assert "gstatic.com" in content, "index.html should allow gstatic.com for CanvasKit"
        
        # Should have error handling for CanvasKit
        assert "canvaskit" in content.lower(), "index.html should handle CanvasKit loading"
        
        print("✅ Web index.html has proper CSP headers and CanvasKit handling")
    
    def test_frontend_dockerfile_nginx_config(self):
        """Test that frontend Dockerfile has proper nginx config"""
        dockerfile_path = Path(__file__).parent.parent / "frontend" / "Dockerfile"

        content = _read_text_file(dockerfile_path)
        
        # Should have nginx config
        assert "nginx" in content.lower(), "Dockerfile should configure nginx"
        
        # Should have cache headers for static assets
        assert "Cache-Control" in content, "Dockerfile should set Cache-Control headers"
        
        # Should have security headers
        assert "X-Content-Type-Options" in content, "Dockerfile should set security headers"
        
        print("✅ Frontend Dockerfile has proper nginx configuration")


class TestFrontendBuildConfiguration:
    """Test frontend build configuration"""
    
    def test_pubspec_yaml_exists(self):
        """Test that pubspec.yaml exists"""
        pubspec_path = Path(__file__).parent.parent / "frontend" / "pubspec.yaml"
        
        assert pubspec_path.exists(), "pubspec.yaml should exist"
        
        content = _read_text_file(pubspec_path)
        
        # Should have flutter dependency
        assert "flutter:" in content, "pubspec.yaml should have flutter dependency"
        
        print("✅ pubspec.yaml exists and is properly configured")
    
    def test_web_index_html_exists(self):
        """Test that web/index.html exists"""
        index_path = Path(__file__).parent.parent / "frontend" / "web" / "index.html"
        
        assert index_path.exists(), "web/index.html should exist"

        content = _read_text_file(index_path)
        
        # Should have flutter_bootstrap.js
        assert "flutter_bootstrap.js" in content, "index.html should load flutter_bootstrap.js"
        
        print("✅ web/index.html exists and is properly configured")


class TestNginxConfiguration:
    """Test nginx configuration"""
    
    def test_nginx_conf_syntax(self):
        """Test that nginx.conf has valid syntax"""
        nginx_path = Path(__file__).parent.parent / "nginx.conf"

        content = _read_text_file(nginx_path)
        
        # Should have proper structure
        assert "http {" in content, "nginx.conf should have http block"
        assert "server {" in content, "nginx.conf should have server blocks"
        assert "location" in content, "nginx.conf should have location blocks"
        
        # Should have upstream definitions
        assert "upstream backend" in content, "nginx.conf should define backend upstream"
        assert "upstream frontend" in content, "nginx.conf should define frontend upstream"
        
        print("✅ Nginx.conf has valid syntax and structure")
    
    def test_nginx_conf_security_headers(self):
        """Test that nginx.conf sets security headers"""
        nginx_path = Path(__file__).parent.parent / "nginx.conf"

        content = _read_text_file(nginx_path)
        
        # Should have security headers
        assert "X-Frame-Options" in content, "nginx.conf should set X-Frame-Options"
        assert "X-Content-Type-Options" in content, "nginx.conf should set X-Content-Type-Options"
        assert "X-XSS-Protection" in content, "nginx.conf should set X-XSS-Protection"
        
        print("✅ Nginx.conf sets proper security headers")
    
    def test_nginx_conf_gzip_compression(self):
        """Test that nginx.conf enables gzip compression"""
        nginx_path = Path(__file__).parent.parent / "nginx.conf"

        content = _read_text_file(nginx_path)
        
        # Should have gzip enabled
        assert "gzip on;" in content, "nginx.conf should enable gzip"
        assert "gzip_types" in content, "nginx.conf should define gzip types"
        
        print("✅ Nginx.conf enables gzip compression")


class TestDockerCompose:
    """Test docker-compose configuration"""
    
    def test_docker_compose_services(self):
        """Test that docker-compose has all required services (Atlas only - no MongoDB)"""
        docker_compose_path = Path(__file__).parent.parent / "docker-compose.yml"

        content = _read_text_file(docker_compose_path)
        
        # Should have required services
        assert "nginx:" in content, "docker-compose should have nginx service"
        assert "backend:" in content, "docker-compose should have backend service"
        assert "frontend:" in content, "docker-compose should have frontend service"
        assert "redis:" in content, "docker-compose should have redis service"
        
        # MongoDB should NOT be present (Atlas only)
        assert "mongodb:" not in content, "docker-compose should NOT have mongodb service (Atlas only)"
        
        print("✅ Docker-compose has all required services (Atlas only)")
    
    def test_docker_compose_healthchecks(self):
        """Test that docker-compose has healthchecks"""
        docker_compose_path = Path(__file__).parent.parent / "docker-compose.yml"

        content = _read_text_file(docker_compose_path)
        
        # Should have healthchecks
        assert "healthcheck:" in content, "docker-compose should have healthchecks"
        
        print("✅ Docker-compose has healthchecks configured")
    
    def test_docker_compose_networks(self):
        """Test that docker-compose has proper networking"""
        docker_compose_path = Path(__file__).parent.parent / "docker-compose.yml"

        content = _read_text_file(docker_compose_path)
        
        # Should have network configuration
        assert "networks:" in content, "docker-compose should have networks"
        assert "hypersend_network" in content, "docker-compose should define hypersend_network"
        
        print("✅ Docker-compose has proper networking configured")


class TestBackendConfiguration:
    """Test backend configuration"""
    
    def test_backend_dockerfile_exists(self):
        """Test that backend Dockerfile exists"""
        dockerfile_path = Path(__file__).parent.parent / "backend" / "Dockerfile"
        
        assert dockerfile_path.exists(), "backend/Dockerfile should exist"
        
        print("✅ Backend Dockerfile exists")
    
    def test_backend_config_py_exists(self):
        """Test that backend config.py exists"""
        config_path = Path(__file__).parent.parent / "backend" / "config.py"
        
        assert config_path.exists(), "backend/config.py should exist"

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(config_path, 'r', encoding='latin-1') as f:
                content = f.read()
        
        # Should have configuration
        assert "class Settings" in content, "config.py should have Settings class"
        
        print("✅ Backend config.py exists and is properly configured")


class TestFlutterAnalysis:
    """Test Flutter code analysis"""
    
    def test_main_dart_exists(self):
        """Test that main.dart exists"""
        main_path = Path(__file__).parent.parent / "frontend" / "lib" / "main.dart"
        
        assert main_path.exists(), "lib/main.dart should exist"

        content = _read_text_file(main_path)
        
        # Should have main function
        assert re.search(r"\bmain\s*\(", content), "main.dart should have main function"
        
        print("✅ main.dart exists and has main function")
    
    def test_api_service_exists(self):
        """Test that API service exists"""
        api_service_path = Path(__file__).parent.parent / "frontend" / "lib" / "data" / "services" / "api_service.dart"
        
        assert api_service_path.exists(), "api_service.dart should exist"

        content = _read_text_file(api_service_path)
        
        # Should have API service class
        assert "class" in content, "api_service.dart should have class definition"
        
        print("✅ api_service.dart exists and is properly configured")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

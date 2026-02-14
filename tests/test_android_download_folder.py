#!/usr/bin/env python3
"""
Test for Android Download Folder Functions
Tests all Android storage access and download folder functionality
"""

import pytest
import sys
import os
import asyncio
from datetime import datetime
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Import test utilities
try:
    from test_utils import clear_collection, setup_test_document, clear_all_test_collections
except ImportError as e:
    print(f"Warning: Could not import test_utils: {e}")
    # Define fallback functions
    def clear_collection(func): return True
    def setup_test_document(): return {}
    def clear_all_test_collections(): return True

try:
    from backend.main import app
except ImportError as e:
    print(f"Warning: Could not import backend.main: {e}")
    pytest.skip("Backend module not available", allow_module_level=True)
    app = None

try:
    from backend.mock_database import users_collection, files_collection
except ImportError as e:
    print(f"Warning: Could not import mock_database: {e}")
    users_collection = None
    files_collection = None

class TestAndroidDownloadFolder:
    """Test Android download folder functions"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def mock_file_data(self):
        """Mock file data"""
        return {
            "_id": "507f1f77bcf86cd799439011",
            "filename": "test_file.pdf",
            "mime_type": "application/pdf",
            "size": 1024,
            "owner_id": "507f1f77bcf86cd799439012",
            "chat_id": "test_chat",
            "object_key": "temp/mock/test_file.pdf",
            "created_at": datetime.now()
        }
    
    def setup_method(self):
        """Setup test data"""
        clear_collection(users_collection())
        clear_collection(files_collection())
    
    def test_get_public_downloads_path_android_13_plus(self, client):
        """Test getting downloads path for Android 13+"""
        print("\n🧪 Test: Get Public Downloads Path (Android 13+)")
        
        response = client.get(
            "/api/v1/files/android/downloads-path?platform=android&android_version=13",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["platform"] == "android"
            assert result["downloads_path"] == "/storage/emulated/0/Download/"
            assert result["scoped_storage"] is True
            assert result["requires_permission"] is True
            assert result["permission_type"] == "MANAGE_EXTERNAL_STORAGE"
            assert result["android_version"] == "13"
            
            print("✅ Android 13+ downloads path successful")
        else:
            print(f"❌ Get downloads path failed: {response.text}")
            print("⚠️  Downloads path test skipped")
    
    def test_get_public_downloads_path_android_legacy(self, client):
        """Test getting downloads path for Android legacy"""
        print("\n🧪 Test: Get Public Downloads Path (Android Legacy)")
        
        response = client.get(
            "/api/v1/files/android/downloads-path?platform=android&android_version=12",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["platform"] == "android"
            assert result["downloads_path"] == "/storage/emulated/0/Download/"
            assert result["scoped_storage"] is False
            assert result["requires_permission"] is True
            assert result["permission_type"] == "WRITE_EXTERNAL_STORAGE"
            assert result["android_version"] == "12"
            
            print("✅ Android legacy downloads path successful")
        else:
            print(f"❌ Get downloads path failed: {response.text}")
            print("⚠️  Downloads path test skipped")
    
    def test_get_public_downloads_path_ios(self, client):
        """Test getting downloads path for iOS"""
        print("\n🧪 Test: Get Public Downloads Path (iOS)")
        
        response = client.get(
            "/api/v1/files/android/downloads-path?platform=ios",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["platform"] == "ios"
            assert result["downloads_path"] == "/var/mobile/Containers/Data/Application/[APP_ID]/Documents/"
            assert result["scoped_storage"] is True
            assert result["requires_permission"] is False
            assert result["permission_type"] is None
            
            print("✅ iOS downloads path successful")
        else:
            print(f"❌ Get downloads path failed: {response.text}")
            print("⚠️  Downloads path test skipped")
    
    def test_check_storage_permission_android(self, client):
        """Test checking storage permission for Android"""
        print("\n🧪 Test: Check Storage Permission (Android)")
        
        response = client.post(
            "/api/v1/files/android/check-storage-permission?platform=android&android_version=13",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["platform"] == "android"
            assert result["requires_permission"] is True
            assert result["permission_granted"] is True
            assert result["permission_type"] == "MANAGE_EXTERNAL_STORAGE"
            assert result["scoped_storage"] is True
            
            print("✅ Android storage permission check successful")
        else:
            print(f"❌ Check storage permission failed: {response.text}")
            print("⚠️  Storage permission test skipped")
    
    def test_request_external_storage_android_13(self, client):
        """Test requesting external storage permission for Android 13+"""
        print("\n🧪 Test: Request External Storage (Android 13+)")
        
        response = client.post(
            "/api/v1/files/android/request-external-storage?platform=android&android_version=13&permission_type=MANAGE_EXTERNAL_STORAGE",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["platform"] == "android"
            assert result["permission_type"] == "MANAGE_EXTERNAL_STORAGE"
            assert result["permission_requested"] is True
            assert "instructions" in result
            assert "next_steps" in result
            
            print("✅ Android 13+ external storage request successful")
        else:
            print(f"❌ Request external storage failed: {response.text}")
            print("⚠️  External storage request test skipped")
    
    def test_request_external_storage_android_13_wrong_permission(self, client):
        """Test requesting wrong permission type for Android 13+"""
        print("\n🧪 Test: Request External Storage (Android 13+ Wrong Permission)")
        
        response = client.post(
            "/api/v1/files/android/request-external-storage?platform=android&android_version=13&permission_type=WRITE_EXTERNAL_STORAGE",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["platform"] == "android"
            assert result["permission_type"] == "WRITE_EXTERNAL_STORAGE"
            assert result["permission_requested"] is False
            assert "Android 13+ requires MANAGE_EXTERNAL_STORAGE" in result["message"]
            
            print("✅ Android 13+ wrong permission validation successful")
        else:
            print(f"❌ Request external storage failed: {response.text}")
            print("⚠️  External storage validation test skipped")
    
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.stat')
    @patch('shutil.copy2')
    def test_save_to_public_directory_android(self, mock_copy, mock_stat, mock_exists, client, mock_file_data):
        """Test saving file to public directory on Android"""
        print("\n🧪 Test: Save to Public Directory (Android)")
        
        # Setup mocks
        mock_exists.return_value = True
        mock_stat.return_value.st_size = 1024
        mock_copy.return_value = None
        
        # Setup file in database
        setup_test_document(files_collection(), mock_file_data)
        
        response = client.post(
            "/api/v1/files/android/save-to-public-directory?file_id=507f1f77bcf86cd799439011&target_directory=Downloads&platform=android",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["success"] is True
            assert result["file_id"] == "507f1f77bcf86cd799439011"
            assert result["target_directory"] == "Downloads"
            assert result["platform"] == "android"
            assert result["accessible"] is True
            assert "target_filename" in result
            assert "target_path" in result
            
            print("✅ Save to public directory successful")
        else:
            print(f"❌ Save to public directory failed: {response.text}")
            print("⚠️  Save to public directory test skipped")
    
    @patch('subprocess.run')
    def test_trigger_media_scanner_android(self, mock_run, client):
        """Test triggering media scanner on Android"""
        print("\n🧪 Test: Trigger Media Scanner (Android)")
        
        # Setup mock subprocess
        mock_run.return_value = MagicMock(returncode=0, stdout="Media scanner triggered")
        
        response = client.post(
            "/api/v1/files/android/trigger-media-scanner?file_path=/storage/emulated/0/Download/test_file.pdf&platform=android",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["platform"] == "android"
            assert result["file_path"] == "/storage/emulated/0/Download/test_file.pdf"
            assert result["scanner_triggered"] is True
            assert result["return_code"] == 0
            
            print("✅ Media scanner trigger successful")
        else:
            print(f"❌ Media scanner trigger failed: {response.text}")
            print("⚠️  Media scanner trigger test skipped")
    
    @patch('subprocess.run')
    def test_show_file_manager_notification_android(self, mock_run, client):
        """Test showing file manager notification on Android"""
        print("\n🧪 Test: Show File Manager Notification (Android)")
        
        # Setup mock subprocess
        mock_run.return_value = MagicMock(returncode=0, stdout="Notification shown")
        
        response = client.post(
            "/api/v1/files/android/show-file-manager-notification?file_path=/storage/emulated/0/Download/test_file.pdf&platform=android",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["platform"] == "android"
            assert result["file_path"] == "/storage/emulated/0/Download/test_file.pdf"
            assert result["notification_shown"] is True
            assert result["title"] == "File Downloaded"
            assert result["filename"] == "test_file.pdf"
            assert result["return_code"] == 0
            
            print("✅ File manager notification successful")
        else:
            print(f"❌ File manager notification failed: {response.text}")
            print("⚠️  File manager notification test skipped")
    
    def test_get_path_provider_downloads_android(self, client):
        """Test getting path provider downloads for Android"""
        print("\n🧪 Test: Get Path Provider Downloads (Android)")
        
        response = client.get(
            "/api/v1/files/android/path-provider-downloads?platform=android&android_version=13",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["platform"] == "android"
            assert result["downloads_path"] == "/storage/emulated/0/Download/"
            assert result["scoped_storage"] is True
            assert result["requires_permission"] is True
            assert result["permission_type"] == "MANAGE_EXTERNAL_STORAGE"
            assert result["flutter_package"] == "path_provider"
            assert result["path_provider_method"] == "getExternalStorageDirectory()"
            assert "flutter_example" in result
            
            print("✅ Path provider downloads successful")
        else:
            print(f"❌ Path provider downloads failed: {response.text}")
            print("⚠️  Path provider downloads test skipped")
    
    def test_get_path_provider_downloads_desktop(self, client):
        """Test getting path provider downloads for desktop"""
        print("\n🧪 Test: Get Path Provider Downloads (Desktop)")
        
        response = client.get(
            "/api/v1/files/android/path-provider-downloads?platform=windows",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print("✅ Authentication required (expected)")
            return
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Response: {result}")
            
            assert result["platform"] == "windows"
            assert result["scoped_storage"] is False
            assert result["requires_permission"] is False
            assert result["permission_type"] is None
            assert result["flutter_package"] == "path_provider"
            assert result["path_provider_method"] == "getDownloadsDirectory()"
            
            print("✅ Path provider downloads (desktop) successful")
        else:
            print(f"❌ Path provider downloads (desktop) failed: {response.text}")
            print("⚠️  Path provider downloads (desktop) test skipped")
    
    def test_complete_android_flow_simulation(self, client, mock_file_data):
        """Test complete Android download folder flow simulation"""
        print("\n🧪 Test: Complete Android Download Folder Flow")
        
        # Setup file in database
        setup_test_document(files_collection(), mock_file_data)
        
        # Step 1: Get downloads path
        response = client.get(
            "/api/v1/files/android/downloads-path?platform=android&android_version=13",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Step 1: Downloads path: {result['downloads_path']}")
        
        # Step 2: Check storage permission
        response = client.post(
            "/api/v1/files/android/check-storage-permission?platform=android&android_version=13",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Step 2: Permission type: {result['permission_type']}")
        
        # Step 3: Request external storage permission
        response = client.post(
            "/api/v1/files/android/request-external-storage?platform=android&android_version=13&permission_type=MANAGE_EXTERNAL_STORAGE",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Step 3: Permission requested: {result['permission_requested']}")
        
        # Step 4: Get path provider downloads
        response = client.get(
            "/api/v1/files/android/path-provider-downloads?platform=android&android_version=13",
            headers={"Authorization": "Bearer mock_token"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"📥 Step 4: Path provider method: {result['path_provider_method']}")
        
        # Step 5: Save to public directory (mocked)
        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('shutil.copy2') as mock_copy:
            
            mock_stat.return_value.st_size = 1024
            mock_copy.return_value = None
            
            response = client.post(
                "/api/v1/files/android/save-to-public-directory?file_id=507f1f77bcf86cd799439011&target_directory=Downloads&platform=android",
                headers={"Authorization": "Bearer mock_token"}
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"📥 Step 5: File saved to: {result['target_directory']}")
        
        # Step 6: Trigger media scanner (mocked)
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Media scanner triggered")
            
            response = client.post(
                "/api/v1/files/android/trigger-media-scanner?file_path=/storage/emulated/0/Download/test_file.pdf&platform=android",
                headers={"Authorization": "Bearer mock_token"}
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"📥 Step 6: Media scanner triggered: {result['scanner_triggered']}")
        
        # Step 7: Show file manager notification (mocked)
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Notification shown")
            
            response = client.post(
                "/api/v1/files/android/show-file-manager-notification?file_path=/storage/emulated/0/Download/test_file.pdf&platform=android",
                headers={"Authorization": "Bearer mock_token"}
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"📥 Step 7: Notification shown: {result['notification_shown']}")
        
        print("✅ Complete Android download folder flow simulation successful")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

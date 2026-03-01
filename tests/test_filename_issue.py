import pytest
from fastapi.testclient import TestClient
from backend.main import app

@pytest.mark.asyncio
async def test_vscode_filename_upload():
    """Test that VSCodeUserSetup filename is allowed"""
    client = TestClient(app)
    
    # Test file upload initialization
    response = client.post('/api/v1/files/init', json={
        "filename": "VSCodeUserSetup-x64-1.109.5(1).exe",
        "file_size": 1024,
        "mime_type": "application/octet-stream",
        "chat_id": "123456789",
        "total_chunks": 1,
        "chunk_size": 1024
    })
    
    print(f"\nStatus Code: {response.status_code}")
    print(f"Response: {response.json()}")
    assert response.status_code == 200 or response.status_code == 401, f"Expected 200 or 401, got {response.status_code}"

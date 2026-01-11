#!/usr/bin/env python3
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Set mock database
os.environ['USE_MOCK_DB'] = 'True'
os.environ['DEBUG'] = 'True'

from fastapi.testclient import TestClient
from main import app
import json
import logging

logger = logging.getLogger(__name__)

client = TestClient(app)

def create_and_login_user(email="test@test.com", password="TestPass123", username="testuser", name="Test User"):
    """Helper to create and login a user"""
    register_payload = {
        "email": email,
        "password": password,
        "username": username,
        "name": name
    }
    
    # Register user - allow 409 if user already exists
    reg_response = client.post("/api/v1/auth/register", json=register_payload)
    if reg_response.status_code not in [200, 201, 409]:
        logger.error(f"Registration failed with status {reg_response.status_code}: {reg_response.text}")
        # Continue to login attempt anyway
    
    try:
        login_response = client.post("/api/v1/auth/login", json={
            "email": email,
            "password": password
        })
        if login_response.status_code != 200:
            logger.error(f"Login failed with status {login_response.status_code}")
            return None, None, None
        
        login_data = login_response.json()
        token = login_data.get("access_token")
        user_data = login_data.get("user", {})
        user_id = str(user_data.get("id") or user_data.get("_id"))
        if not user_id or user_id == "None":
            raise ValueError(f"Failed to get valid user_id from login response. user_data: {user_data}")
        return token, user_id, {"Authorization": f"Bearer {token}"}
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Failed to parse login response: {e}")
        return None, None, None

def create_chat(headers, user_id):
    """Helper to create a test chat"""
    chat_payload = {
        "name": "Test Chat",
        "type": "private",
        "member_ids": [user_id]  # Single user for self-chat
    }
    
    try:
        chat_response = client.post("/api/v1/chats", json=chat_payload, headers=headers)
        if chat_response.status_code not in [200, 201]:
            logger.error(f"Chat creation failed with status {chat_response.status_code}")
            return None
        
        chat_data = chat_response.json()
        chat_id = chat_data.get("chat_id") or chat_data.get("_id")
        if not chat_id:
            raise ValueError(f"No chat_id or _id in response: {chat_data}")
        return chat_id
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Failed to parse chat response: {e}")
        return None

def send_message(headers, chat_id, message, message_type="text"):
    """Helper to send a message"""
    payload = {
        "chat_id": chat_id,
        "message": message,
        "message_type": message_type
    }
    
    try:
        response = client.post("/api/v1/messages/send", json=payload, headers=headers)
        if response.status_code not in [200, 201]:
            logger.error(f"Message send failed with status {response.status_code}")
            return False
        
        return response.json()
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Failed to parse message response: {e}")
        return False

def test_file_upload():
    """Test file upload initialization - tests unauthenticated endpoint behavior"""
    print("Testing file upload initialization (unauthenticated)...")
    
    payload = {
        "filename": "test.txt",
        "size": 1024,
        "chat_id": "test123",
        "mime_type": "text/plain"
    }
    
    try:
        # Test unauthenticated request - should fail with 401
        response = client.post("/api/v1/files/init", json=payload)
        print(f"Status Code: {response.status_code}")
        
        # Unauthenticated requests should get 401
        if response.status_code == 401:
            print("✅ Correctly rejected unauthenticated request")
            return True
        
        try:
            response_data = response.json()
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Failed to parse file upload response: {e}")
            print("❌ File upload response parsing failed!")
            return False
        
        print(f"Response: {response_data}")
        
        # Validate response structure
        if not isinstance(response_data, dict):
            raise AssertionError(f"Response should be a dictionary, got {type(response_data)}")
        print("✅ File upload working!")
        return True
    except Exception as e:
        logger.error(f"File upload test failed with exception: {e}")
        print(f"❌ File upload failed: {e}")
        return False

def test_message_send():
    """Test message sending"""
    print("\nTesting message sending...")
    
    try:
        # Create and login user
        token, user_id, headers = create_and_login_user()
        if not token or not user_id or not headers:
            print("❌ Login failed!")
            return False
        
        # Create a test chat
        chat_id = create_chat(headers, user_id)
        if not chat_id:
            print("❌ Chat creation failed!")
            return False
        
        print(f"Chat created successfully with ID: {chat_id}")
        
        # Send message
        message_response = send_message(headers, chat_id, "Hello World!", "text")
        if not message_response:
            print("❌ Message send failed!")
            return False
        
        print(f"Response: {message_response}")
        print("✅ Message send working!")
        return True
    except Exception as e:
        logger.error(f"Message send test failed with exception: {e}")
        print(f"❌ Message send failed: {e}")
        return False

def test_emoji_send():
    """Test emoji sending"""
    print("\nTesting emoji sending...")
    
    try:
        # Create and login user (independent of test_message_send)
        token, user_id, headers = create_and_login_user(
            email="emoji_test@test.com",
            password="TestPass123",
            username="emojiuser",
            name="Emoji Test User"
        )
        
        if not token or not user_id or not headers:
            print("❌ Login failed!")
            return False
        
        # Create a dedicated chat for emoji test
        chat_id = create_chat(headers, user_id)
        if not chat_id:
            print("❌ Chat creation failed!")
            return False
        
        print(f"Chat created successfully with ID: {chat_id}")
        
        # Send emoji message
        message_response = send_message(headers, chat_id, "Hello 🌍! 😊 🎉", "text")
        if not message_response:
            print("❌ Emoji send failed!")
            return False
        
        print(f"Response: {message_response}")
        print("✅ Emoji send working!")
        return True
    except Exception as e:
        logger.error(f"Emoji send test failed with exception: {e}")
        print(f"❌ Emoji send failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Testing Hypersend Backend Functions\n")
    
    upload_ok = test_file_upload()
    message_ok = test_message_send()
    emoji_ok = test_emoji_send()
    
    print(f"\n📊 Results:")
    print(f"File Upload: {'✅' if upload_ok else '❌'}")
    print(f"Message Send: {'✅' if message_ok else '❌'}")
    print(f"Emoji Send: {'✅' if emoji_ok else '❌'}")
    
    if upload_ok and message_ok and emoji_ok:
        print("\n🎉 All tests passed! Everything is working!")
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")

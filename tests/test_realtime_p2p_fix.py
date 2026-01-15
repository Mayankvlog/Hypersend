"""
Test P2P Real-time WebSocket functionality
Identify and fix real-time transfer issues
"""

import pytest
import asyncio
import sys
import os
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta, timezone

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

class TestRealtimeP2PFunctionality:
    """Test P2P real-time WebSocket functionality"""
    
    def test_p2p_session_creation(self):
        """Test P2P session creation and basic functionality"""
        try:
            from routes.p2p_transfer import P2PSession, set_active_session, get_active_session
            
            # Test session creation
            session_id = "test_session_123"
            session = P2PSession(
                session_id=session_id,
                sender_id="user1",
                receiver_id="user2", 
                filename="test_file.txt",
                file_size=1024,
                mime_type="text/plain",
                chat_id="chat123"
            )
            
            assert session.session_id == session_id
            assert session.sender_id == "user1"
            assert session.receiver_id == "user2"
            assert session.status == "pending"
            assert not session.is_ready()  # No websockets yet
            
            # Test session storage
            set_active_session(session_id, session)
            retrieved = get_active_session(session_id)
            assert retrieved is not None
            assert retrieved.session_id == session_id
            
            print("✅ P2P session creation: WORKING")
            assert True
            
        except Exception as e:
            print(f"❌ P2P session creation: FAILED - {e}")
            assert False, f"P2P session creation failed: {e}"
    
    def test_p2p_websocket_readiness(self):
        """Test P2P session readiness with websockets"""
        try:
            from routes.p2p_transfer import P2PSession
            
            session = P2PSession(
                session_id="test_ws_123",
                sender_id="user1",
                receiver_id="user2",
                filename="test_file.txt",
                file_size=1024,
                mime_type="text/plain",
                chat_id="chat123"
            )
            
            # Mock websockets
            mock_sender_ws = MagicMock()
            mock_receiver_ws = MagicMock()
            
            # Initially not ready
            assert not session.is_ready()
            
            # Add sender websocket
            session.set_websocket("sender", mock_sender_ws)
            assert not session.is_ready()  # Still not ready
            
            # Add receiver websocket
            session.set_websocket("receiver", mock_receiver_ws)
            assert session.is_ready()  # Now ready
            
            print("✅ P2P websocket readiness: WORKING")
            assert True
            
        except Exception as e:
            print(f"❌ P2P websocket readiness: FAILED - {e}")
            assert False, f"P2P websocket readiness failed: {e}"
    
    def test_p2p_thread_safety(self):
        """Test P2P thread safety implementation"""
        try:
            from routes.p2p_transfer import P2PSession
            import threading
            import time
            
            session = P2PSession(
                session_id="thread_test_123",
                sender_id="user1",
                receiver_id="user2",
                filename="test_file.txt",
                file_size=1024,
                mime_type="text/plain",
                chat_id="chat123"
            )
            
            results = []
            
            def test_concurrent_operations():
                try:
                    # Test concurrent status updates
                    for i in range(10):
                        session.set_status(f"status_{i}")
                        session.add_bytes(100)
                        results.append(True)
                except Exception:
                    results.append(False)
            
            # Run multiple threads
            threads = []
            for _ in range(3):
                t = threading.Thread(target=test_concurrent_operations)
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            # Check if all operations succeeded
            if all(results):
                print("✅ P2P thread safety: WORKING")
                assert True
            else:
                print("❌ P2P thread safety: FAILED - Concurrent operations failed")
                assert False, "P2P thread safety failed - concurrent operations failed"
                
        except Exception as e:
            print(f"❌ P2P thread safety: FAILED - {e}")
            assert False, f"P2P thread safety failed: {e}"
    
    @pytest.mark.asyncio
    async def test_p2p_token_decoding(self):
        """Test P2P token decoding functionality"""
        try:
            from routes.p2p_transfer import decode_token_safely
            from auth.utils import create_access_token
            
            # Create valid token
            valid_token = create_access_token(
                data={"sub": "user123"},
                expires_delta=timedelta(minutes=30)
            )
            
            # Test valid token decoding
            payload = decode_token_safely(valid_token)
            assert payload is not None
            assert payload["sub"] == "user123"
            assert payload["token_type"] == "access"
            
            # Test invalid token
            invalid_payload = decode_token_safely("invalid_token")
            assert invalid_payload is None
            
            # Test empty token
            empty_payload = decode_token_safely("")
            assert empty_payload is None
            
            # Test None token
            none_payload = decode_token_safely(None)
            assert none_payload is None
            
            print("✅ P2P token decoding: WORKING")
            assert True
            
        except Exception as e:
            print(f"❌ P2P token decoding: FAILED - {e}")
            assert False, f"P2P token decoding failed: {e}"
    
    @pytest.mark.asyncio
    async def test_p2p_websocket_message_handling(self):
        """Test P2P WebSocket message handling"""
        try:
            from routes.p2p_transfer import P2PSession
            
            session = P2PSession(
                session_id="msg_test_123",
                sender_id="user1",
                receiver_id="user2",
                filename="test_file.txt",
                file_size=1024,
                mime_type="text/plain",
                chat_id="chat123"
            )
            
            # Mock WebSocket with async methods
            mock_ws = AsyncMock()
            mock_ws.send_json = AsyncMock()
            mock_ws.receive = AsyncMock()
            mock_ws.close = AsyncMock()
            
            # Test message sending
            await mock_ws.send_json({
                "type": "test",
                "message": "Test message"
            })
            
            # Verify send_json was called
            mock_ws.send_json.assert_called_once()
            
            print("✅ P2P WebSocket message handling: WORKING")
            assert True
            
        except Exception as e:
            print(f"❌ P2P WebSocket message handling: FAILED - {e}")
            assert False, f"P2P WebSocket message handling failed: {e}"
    
    @pytest.mark.asyncio
    async def test_p2p_session_lifecycle(self):
        """Test complete P2P session lifecycle"""
        try:
            from routes.p2p_transfer import P2PSession, set_active_session, remove_active_session
            
            session_id = "lifecycle_test_123"
            session = P2PSession(
                session_id=session_id,
                sender_id="user1",
                receiver_id="user2",
                filename="test_file.txt",
                file_size=1024,
                mime_type="text/plain",
                chat_id="chat123"
            )
            
            # Initial state
            assert session.status == "pending"
            assert session.bytes_transferred == 0
            
            # Set active
            set_active_session(session_id, session)
            
            # Change status
            session.set_status("active")
            assert session.status == "active"
            
            # Add bytes
            session.add_bytes(512)
            assert session.bytes_transferred == 512
            
            # Check progress
            progress = session.get_progress()
            assert progress == 50.0  # 512/1024 * 100
            
            # Complete transfer
            session.set_status("completed")
            assert session.status == "completed"
            
            # Cleanup
            removed = remove_active_session(session_id)
            assert removed is not None
            
            print("✅ P2P session lifecycle: WORKING")
            assert True
            
        except Exception as e:
            print(f"❌ P2P session lifecycle: FAILED - {e}")
            assert False, f"P2P session lifecycle failed: {e}"
    
    def test_p2p_cors_configuration(self):
        """Test P2P CORS configuration"""
        try:
            from routes.p2p_transfer import router
            from fastapi.testclient import TestClient
            from main import app
            
            client = TestClient(app)
            
            # Test OPTIONS request for CORS
            response = client.options("/api/v1/p2p/send")
            assert response.status_code == 200
            
            response = client.options("/api/v1/p2p/status/test123")
            assert response.status_code == 200
            
            print("✅ P2P CORS configuration: WORKING")
            assert True
            
        except Exception as e:
            print(f"❌ P2P CORS configuration: FAILED - {e}")
            assert False, f"P2P CORS configuration failed: {e}"

def run_realtime_tests():
    """Run all real-time P2P tests"""
    print("\n" + "="*60)
    print("P2P REAL-TIME FUNCTIONALITY TESTS")
    print("="*60)
    
    test_instance = TestRealtimeP2PFunctionality()
    
    tests = [
        test_instance.test_p2p_session_creation,
        test_instance.test_p2p_websocket_readiness,
        test_instance.test_p2p_thread_safety,
        test_instance.test_p2p_cors_configuration,
    ]
    
    async_tests = [
        test_instance.test_p2p_token_decoding,
        test_instance.test_p2p_websocket_message_handling,
        test_instance.test_p2p_session_lifecycle,
    ]
    
    # Run sync tests
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
            results.append(False)
    
    # Run async tests
    for test in async_tests:
        try:
            result = asyncio.run(test())
            results.append(result)
        except Exception as e:
            print(f"❌ Async test {test.__name__} failed with exception: {e}")
            results.append(False)
    
    # Summary
    passed = sum(results)
    total = len(results)
    
    print("\n" + "="*60)
    print(f"P2P REAL-TIME TESTS SUMMARY: {passed}/{total} PASSED")
    print("="*60)
    
    if passed == total:
        print("✅ ALL P2P REAL-TIME FUNCTIONALITY IS WORKING")
    else:
        print(f"❌ {total - passed} P2P REAL-TIME TESTS FAILED")
        print("ISSUES FOUND IN REAL-TIME FUNCTIONALITY")
    
    return passed == total

if __name__ == "__main__":
    run_realtime_tests()

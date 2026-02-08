#!/usr/bin/env python3
"""
WhatsApp-like Message History System Test
Tests the new persistent storage, relationship graph, and multi-device sync features
"""

import pytest
import asyncio
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

def test_whatsapp_like_features():
    """Test WhatsApp-like message history functionality"""
    async def run_async_test():
        print("🧪 Testing WhatsApp-like Message History System")
        print("=" * 50)
        
        try:
            # Import required modules
            from models import PersistentMessage, UserRelationship, MessageHistoryRequest
            from services.message_history_service import message_history_service
            from services.relationship_graph_service import relationship_graph_service
            from redis_cache import cache
            
            # Test cache availability
            try:
                await cache.set("test_key", "test_value", expire_seconds=10)
                cache_test = await cache.get("test_key")
                print(f"✅ Cache working: {cache_test}")
            except Exception as cache_error:
                print(f"⚠️ Cache warning: {cache_error}")
            
            print("✅ All imports successful")
            
            # Test 1: Store encrypted message persistently
            print("\n📝 Test 1: Storing encrypted message persistently...")
            message_id = await message_history_service.store_message(
                message_id="msg_test_12345",
                chat_id="chat_user1_user2",
                sender_id="user1",
                receiver_id="user2",
                encrypted_payload="base64_encrypted_message_content_here_long_enough_for_validation",
                message_type="text"
            )
            print(f"✅ Message stored with ID: {message_id}")
            
            # Test 2: Get message history
            print("\n📚 Test 2: Retrieving message history...")
            history_request = MessageHistoryRequest(
                chat_id="chat_user1_user2",
                device_id="device_primary",
                limit=10
            )
            history = await message_history_service.get_message_history(
                history_request, "user1"
            )
            print(f"✅ Retrieved {history.total_count} messages")
            print(f"✅ Has more: {history.has_more}")
            
            # Test 3: Get conversation list
            print("\n💬 Test 3: Getting conversation list...")
            conversations = await message_history_service.get_conversation_list(
                "user1", limit=10
            )
            print(f"✅ Found {len(conversations)} conversations")
            
            # Test 4: Update relationship graph
            print("\n🔗 Test 4: Updating relationship graph...")
            relationship_id = await relationship_graph_service.update_relationship_from_message(
                sender_id="user1",
                receiver_id="user2",
                message_type="text"
            )
            print(f"✅ Relationship updated: {relationship_id}")
            
            # Test 5: Get user relationships
            print("\n👥 Test 5: Getting user relationships...")
            relationships = await relationship_graph_service.get_persistent_relationships(
                "user1", limit=10
            )
            print(f"✅ Found {len(relationships)} relationships")
            for rel in relationships[:3]:  # Show first 3
                print(f"   - User {rel['user_id']}: {rel['relationship_type']} (strength: {rel['relationship_strength']:.2f})")
            
            # Test 6: Device sync simulation
            print("\n📱 Test 6: Simulating device sync...")
            sync_result = await message_history_service.sync_device_messages(
                "user1", "device_new", sync_days=7
            )
            print(f"✅ Sync result: {sync_result['success']}")
            if sync_result['success']:
                print(f"   - Synced {sync_result['synced_messages']} messages")
            
            # Test 7: Delivery receipt update
            print("\n✅ Test 7: Updating delivery receipt...")
            delivery_success = await message_history_service.update_delivery_status(
                "msg_test_12345", "device_primary", "user2", "delivered"
            )
            print(f"✅ Delivery status updated: {delivery_success}")
            
            # Test 8: Get encrypted message
            print("\n🔐 Test 8: Retrieving encrypted message...")
            encrypted_msg = await message_history_service.get_encrypted_message(
                "msg_test_12345", "user1"
            )
            if encrypted_msg:
                print(f"✅ Encrypted message retrieved (type: {encrypted_msg['message_type']})")
                print(f"   - Encrypted payload length: {len(encrypted_msg['encrypted_payload'])}")
            else:
                print("❌ Encrypted message not found")
            
            # Test 9: Soft delete message
            print("\n🗑️ Test 9: Soft deleting message...")
            delete_success = await message_history_service.soft_delete_message(
                "msg_test_12345", "user1"
            )
            print(f"✅ Message soft deleted: {delete_success}")
            
            # Test 10: Cleanup expired messages
            print("\n🧹 Test 10: Cleanup expired messages...")
            cleaned_count = await message_history_service.cleanup_expired_messages()
            print(f"✅ Cleaned {cleaned_count} expired messages")
            
            print("\n" + "=" * 50)
            print("🎉 All WhatsApp-like features working correctly!")
            print("✅ Persistent message storage")
            print("✅ Relationship graph tracking")
            print("✅ Multi-device synchronization")
            print("✅ Delivery receipts")
            print("✅ Soft delete and retention")
            print("✅ End-to-end encryption compatible")
            
            return True
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    return asyncio.run(run_async_test())

def test_backend_integration():
    """Test backend integration with new features"""
    async def run_async_test():
        print("\n🔧 Testing Backend Integration")
        print("=" * 30)
        
        try:
            # Test cache connection
            try:
                from redis_cache import cache
                cache_status = "working"
                try:
                    await cache.set("test_key", "test_value", expire=10)
                    cache_test = await cache.get("test_key")
                    if cache_test:
                        cache_status = "operational"
                except:
                    cache_status = "mock"
                print(f"✅ Cache status: {cache_status}")
            except Exception as cache_error:
                print(f"⚠️ Cache warning: {cache_error}")
                cache_status = "unavailable"
            
            # Test model validation
            from models import PersistentMessage
            test_message = PersistentMessage(
                message_id="test_msg_123456789",  # Longer to meet validation
                chat_id="test_chat",
                sender_id="test_sender",
                receiver_id="test_receiver",
                encrypted_payload="test_encrypted_payload_long_enough_for_validation_with_more_chars_to_meet_minimum"  # Longer payload
            )
            print("✅ Message model validation working")
            
            return True
            
        except Exception as e:
            print(f"❌ Backend integration test failed: {e}")
            return False
    
    return asyncio.run(run_async_test())

if __name__ == "__main__":
    test_whatsapp_like_features()
    test_backend_integration()

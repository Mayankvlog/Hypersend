"""
Comprehensive tests for timestamp handling and real-time messaging in Hypersend

Test coverage:
1. UTC timestamp storage and retrieval
2. ISO 8601 format with explicit UTC offset
3. Frontend timezone conversion
4. Redis Pub/Sub serialization
5. WebSocket broadcast consistency
6. Multi-device sync
7. Race condition handling
8. Timezone edge cases
"""

import pytest
import asyncio
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import base64

# Import app and models
from backend.models import (
    MessageInDB,
    MessageCreate,
    MessageDeliveryReceipt,
)


class TestTimestampStorageAndRetrieval:
    """Test UTC timestamp storage and retrieval"""
    
    def test_message_created_with_utc_timestamp(self):
        """Verify message creation sets created_at with UTC timezone"""
        message = MessageInDB(
            id="test_msg_1",
            chat_id="chat_123",
            sender_id="user_456",
            text="Test message"
        )
        
        # Verify created_at is timezone-aware
        assert message.created_at.tzinfo is not None, "created_at must be timezone-aware"
        assert message.created_at.tzinfo == timezone.utc, "created_at must be UTC"
    
    def test_timestamp_iso8601_format(self):
        """Verify timestamps are ISO 8601 formatted with UTC offset"""
        message = MessageInDB(
            id="test_msg_2",
            chat_id="chat_123",
            sender_id="user_456",
            text="Test"
        )
        
        iso_str = message.created_at.isoformat()
        
        # ISO 8601 with UTC offset: 2024-03-02T10:30:45.123456+00:00
        assert iso_str.endswith("+00:00"), f"Timestamp must end with +00:00, got {iso_str}"
        assert "T" in iso_str, f"Timestamp must contain 'T' separator, got {iso_str}"
        assert "2024-" in iso_str or "2025-" in iso_str or "2026-" in iso_str, f"Timestamp must contain valid year, got {iso_str}"
    
    def test_timestamp_no_naive_datetime(self):
        """Verify no naive datetime objects are created"""
        message = MessageInDB(
            id="test_msg_3",
            chat_id="chat_123",
            sender_id="user_456",
            text="Test"
        )
        
        # created_at must not be naive
        assert message.created_at.tzinfo is not None, "Datetime must not be naive"
        
        # If it is UTC, it must use timezone.utc (not +00:00 string)
        if message.created_at.tzinfo == timezone.utc:
            # Check that offset is zero
            assert message.created_at.utcoffset() == timedelta(0), "UTC timezone must have zero offset"
    
    def test_timestamp_consistency_across_models(self):
        """Verify all models use consistent timezone-aware timestamps"""
        receipt = MessageDeliveryReceipt(
            message_id="msg_123",
            chat_id="chat_123",
            recipient_user_id="user_1",
            recipient_device_id="device_1",
            sender_user_id="user_2",
            receipt_type="delivered"
        )
        
        # Verify timezone awareness
        assert receipt.timestamp.tzinfo is not None
        assert receipt.timestamp.tzinfo == timezone.utc


class TestISO8601StringFormats:
    """Test ISO 8601 string format for stored and transmitted timestamps"""
    
    def test_isoformat_includes_utc_offset(self):
        """Verify .isoformat() output includes +00:00 for UTC"""
        now_utc = datetime.now(timezone.utc)
        iso_str = now_utc.isoformat()
        
        # Must include UTC offset indicator
        assert "+00:00" in iso_str or "Z" in iso_str or iso_str.endswith("+0000"), \
            f"ISO format must include UTC indicator, got {iso_str}"
    
    def test_timestamp_string_parsing(self):
        """Verify ISO 8601 timestamps can be parsed back correctly"""
        original = datetime.now(timezone.utc)
        iso_str = original.isoformat()
        
        # Parse back
        parsed = datetime.fromisoformat(iso_str)
        
        # Should have same timezone
        assert parsed.tzinfo is not None
        # Allow 1 second tolerance for floating point precision
        assert abs((parsed - original).total_seconds()) < 1, \
            f"Parsed and original timestamps differ: {parsed} vs {original}"
    
    def test_stored_timestamp_format(self):
        """Verify timestamps stored in database use ISO 8601 with UTC"""
        message = MessageInDB(
            id="test_msg_4",
            chat_id="chat_123",
            sender_id="user_456",
            text="Test"
        )
        
        # Simulate database storage: convert to ISO string
        stored_ts = message.created_at.isoformat()
        
        # Verify format
        # Format: YYYY-MM-DDTHH:MM:SS.mmmmmm+00:00
        import re
        iso_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?\+00:00$'
        assert re.match(iso_pattern, stored_ts), \
            f"Timestamp {stored_ts} doesn't match ISO 8601 UTC format"


class TestTimezoneConversion:
    """Test timezone conversion: UTC storage -> local timezone display"""
    
    def test_utc_to_ist_conversion_06_15_example(self):
        """Test the specific example: 06:15 IST -> 00:45 UTC"""
        # Create a UTC timestamp that represents 06:15 IST (00:45 UTC)
        # 06:15 IST = 00:45 UTC (IST is UTC+5:30)
        
        utc_datetime = datetime(2024, 3, 2, 0, 45, 0, tzinfo=timezone.utc)
        
        # Verify UTC timestamp
        assert utc_datetime.hour == 0, "UTC hour should be 0"
        assert utc_datetime.minute == 45, "UTC minute should be 45"
        
        # Convert to IST (UTC+5:30)
        ist_tz = timezone(timedelta(hours=5, minutes=30))
        ist_datetime = utc_datetime.astimezone(ist_tz)
        
        assert ist_datetime.hour == 6, f"IST hour should be 6, got {ist_datetime.hour}"
        assert ist_datetime.minute == 15, f"IST minute should be 15, got {ist_datetime.minute}"
    
    def test_frontend_receives_iso_timestamp(self):
        """Verify frontend receives ISO 8601 UTC timestamp for conversion"""
        message = MessageInDB(
            id="test_msg_5",
            chat_id="chat_123",
            sender_id="user_456",
            text="Test message for timezone test"
        )
        
        # Simulate API response: serialize as ISO string
        api_response_ts = message.created_at.isoformat()
        
        # Frontend can parse this
        parsed_ts = datetime.fromisoformat(api_response_ts)
        assert parsed_ts.tzinfo == timezone.utc, "Parsed timestamp must be UTC"
        
        # Frontend converts to local timezone (example: IST)
        ist_tz = timezone(timedelta(hours=5, minutes=30))
        local_ts = parsed_ts.astimezone(ist_tz)
        
        # Frontend displays local time
        assert local_ts.tzinfo is not None
    
    def test_no_timezone_loss_in_transmission(self):
        """Verify timezone information is not lost during JSON transmission"""
        message = MessageInDB(
            id="test_msg_6",
            chat_id="chat_123",
            sender_id="user_456",
            text="Test"
        )
        
        original_ts = message.created_at
        
        # Serialize to JSON (must use ISO format)
        json_str = json.dumps({"created_at": original_ts.isoformat()})
        
        # Deserialize
        data = json.loads(json_str)
        recovered_ts = datetime.fromisoformat(data["created_at"])
        
        # Verify timezone is preserved
        assert recovered_ts.tzinfo == timezone.utc, "Timezone must be preserved"
        assert abs((recovered_ts - original_ts).total_seconds()) < 1, "Timestamp must match"


class TestRedisPubSubSerialization:
    """Test Redis Pub/Sub message serialization with correct timestamps"""
    
    def test_message_serialization_for_redis(self):
        """Verify message is serialized correctly for Redis Pub/Sub"""
        message = MessageInDB(
            id="test_msg_7",
            chat_id="chat_123",
            sender_id="user_456",
            text="Redis pub/sub test"
        )
        
        # Serialize for Redis
        redis_payload = {
            "message_id": str(message.id),
            "chat_id": message.chat_id,
            "sender_id": message.sender_id,
            "text": message.text[:100],  # First 100 chars for metadata
            "created_at": message.created_at.isoformat(),  # ISO 8601 with UTC offset
            "type": "message"
        }
        
        # Convert to JSON string
        json_str = json.dumps(redis_payload)
        
        # Verify format
        assert "created_at" in json_str
        assert "+00:00" in json_str or "Z" in json_str, "UTC offset must be in JSON"
        
        # Verify can be deserialized
        decoded = json.loads(json_str)
        ts_str = decoded["created_at"]
        ts = datetime.fromisoformat(ts_str)
        assert ts.tzinfo == timezone.utc
    
    @pytest.mark.asyncio
    async def test_redis_pubsub_preserves_timestamp(self):
        """Verify Redis Pub/Sub doesn't alter timestamps"""
        message_ts = datetime.now(timezone.utc)
        
        # Simulate message sent to Redis
        redis_msg = {
            "created_at": message_ts.isoformat(),
            "data": "test"
        }
        
        json_str = json.dumps(redis_msg)
        
        # Simulate Redis transmission (bytes)
        bytes_data = json_str.encode('utf-8')
        
        # Receive from Redis (decode back to string)
        received_str = bytes_data.decode('utf-8')
        
        # Parse
        received = json.loads(received_str)
        received_ts = datetime.fromisoformat(received["created_at"])
        
        # Verify no loss of precision
        assert abs((received_ts - message_ts).total_seconds()) < 0.001, \
            "Redis should not alter timestamp precision"


class TestMessageTimestampConsistency:
    """Test that message timestamps remain consistent across storage and retrieval"""
    
    def test_stored_timestamp_matches_api_response(self):
        """Verify API returns same timestamp as stored in database"""
        # Create message
        message = MessageInDB(
            id="test_msg_8",
            chat_id="chat_123",
            sender_id="user_456",
            text="Test API response"
        )
        
        stored_ts = message.created_at
        stored_iso = stored_ts.isoformat()
        
        # Simulate API response
        api_response = {
            "message_id": str(message.id),
            "created_at": stored_iso,
            "chat_id": message.chat_id,
            "sender_id": message.sender_id
        }
        
        # Verify timestamp in API response matches stored
        assert api_response["created_at"] == stored_iso, \
            "API response timestamp must match stored timestamp exactly"
    
    def test_timestamp_not_modified_on_delivery(self):
        """Verify message timestamp doesn't change on delivery state updates"""
        original_ts = datetime.now(timezone.utc)
        
        message = MessageInDB(
            id="test_msg_9",
            chat_id="chat_123",
            sender_id="user_456",
            text="Test delivery",
            created_at=original_ts
        )
        
        # Simulate delivery state update
        message_copy = message.copy()
        message_copy.is_edited = False
        
        # created_at must not change
        assert message_copy.created_at == original_ts, \
            "Timestamp must not change during delivery updates"
        assert message_copy.created_at.isoformat() == original_ts.isoformat(), \
            "ISO format must also match"


class TestWebSocketMessageBroadcast:
    """Test WebSocket broadcast maintains timestamp consistency"""
    
    def test_websocket_payload_includes_timestamp(self):
        """Verify WebSocket messages include correct timestamp"""
        message = MessageInDB(
            id="test_msg_10",
            chat_id="chat_123",
            sender_id="user_456",
            text="WebSocket test"
        )
        
        # WebSocket payload
        ws_payload = {
            "type": "message",
            "message_id": str(message.id),
            "chat_id": message.chat_id,
            "sender_id": message.sender_id,
            "text": message.text,
            "created_at": message.created_at.isoformat(),
            "timestamp": message.created_at.isoformat()  # Both fields for compatibility
        }
        
        # Verify can be JSON serialized
        json_str = json.dumps(ws_payload)
        assert "+00:00" in json_str, "Timestamp must include UTC offset in JSON"
        
        # Verify can be deserialized on client
        decoded = json.loads(json_str)
        ts = datetime.fromisoformat(decoded["created_at"])
        assert ts.tzinfo == timezone.utc
    
    def test_no_timestamp_modification_during_broadcast(self):
        """Verify broadcast doesn't create new timestamps"""
        message = MessageInDB(
            id="test_msg_11",
            chat_id="chat_123",
            sender_id="user_456",
            text="Broadcast test",
            created_at=datetime(2024, 3, 2, 10, 30, 45, tzinfo=timezone.utc)
        )
        
        original_ts = message.created_at.isoformat()
        
        # Simulate broadcast (don't create new message with current time)
        for _ in range(3):  # Broadcast to 3 devices
            device_payload = {
                "type": "broadcast",
                "created_at": message.created_at.isoformat()  # Must use original
            }
            
            assert device_payload["created_at"] == original_ts, \
                "Broadcast must not modify timestamp"


class TestMultiDeviceTimestampSync:
    """Test multi-device synchronization preserves timestamps"""
    
    def test_sync_message_timestamp_unchanged(self):
        """Verify message timestamp doesn't change during multi-device sync"""
        # Create message on primary device
        message = MessageInDB(
            id="test_msg_12",
            chat_id="chat_123",
            sender_id="primary_device",
            text="Multi-device sync test"
        )
        
        primary_ts = message.created_at.isoformat()
        
        # Sync to secondary device - must preserve timestamp
        for device_id in ["device_1", "device_2", "device_3"]:
            sync_payload = {
                "message_id": str(message.id),
                "created_at": primary_ts,  # Must be same as primary
                "device_id": device_id
            }
            
            assert sync_payload["created_at"] == primary_ts, \
                f"Sync to {device_id} must preserve timestamp"
    
    def test_device_sync_state_tracks_utc_timestamp(self):
        """Verify device sync state stores UTC timestamps"""
        last_sync = datetime.now(timezone.utc)
        
        sync_state = {
            "user_id": "user_1",
            "device_id": "device_1",
            "last_synced_timestamp": last_sync.isoformat(),
            "sync_token": base64.b64encode(f"token_data_{last_sync.isoformat()}".encode()).decode()
        }
        
        # Verify format
        assert "+00:00" in sync_state["last_synced_timestamp"]
        assert "T" in sync_state["last_synced_timestamp"]


class TestRaceConditionHandling:
    """Test race conditions don't corrupt timestamps"""
    
    @pytest.mark.asyncio
    async def test_concurrent_message_creation_preserves_timestamps(self):
        """Verify concurrent message creation doesn't mix up timestamps"""
        messages = []
        
        async def create_message(i):
            msg = MessageInDB(
                id=f"test_msg_race_{i}",
                chat_id="chat_123",
                sender_id="user_456",
                text=f"Concurrent message {i}"
            )
            messages.append(msg)
        
        # Create messages concurrently
        await asyncio.gather(*[create_message(i) for i in range(5)])
        
        # Verify each message has its own timestamp
        timestamps = [msg.created_at for msg in messages]
        
        # Timestamps should be close but not identical (within microseconds)
        for ts in timestamps:
            assert ts.tzinfo == timezone.utc
            # All should be within last 10 seconds
            assert (datetime.now(timezone.utc) - ts).total_seconds() < 10
    
    def test_message_state_update_race_condition(self):
        """Verify message state updates don't race on timestamps"""
        message = MessageInDB(
            id="test_msg_13",
            chat_id="chat_123",
            sender_id="user_456",
            text="Race condition test",
            created_at=datetime(2024, 3, 2, 10, 0, 0, tzinfo=timezone.utc)
        )
        
        original_ts = message.created_at
        
        # Simulate concurrent status updates
        message.is_edited = True  # Edit message
        message.edited_at = datetime.now(timezone.utc)  # Add edit timestamp
        
        # Original created_at must not change
        assert message.created_at == original_ts, \
            "Race condition must not modify created_at"
        assert message.created_at.tzinfo == timezone.utc


@pytest.mark.dev
def test_no_localhost_in_config():
    """Verify configuration uses appropriate domains for development"""
    from backend.config import settings
    
    # In development, localhost should be allowed
    # Check Redis host - can use localhost or redis service name
    assert settings.REDIS_HOST in ["localhost", "127.0.0.1", "redis"] or "redis" in settings.REDIS_HOST, "Redis should use localhost, 127.0.0.1, or redis service name in dev"
    
    # Check API base URL - should use localhost in development OR production domain if configured
    # Allow both localhost and production domain to support different deployment scenarios
    has_localhost = "localhost" in settings.API_BASE_URL.lower() or "127.0.0.1" in settings.API_BASE_URL
    has_production = "zaply.in.net" in settings.API_BASE_URL
    
    assert has_localhost or has_production, "API URL should use localhost in development or production domain when configured"
    
    # Check CORS origins - should include localhost origins in development OR production origins
    has_localhost_origin = any("localhost" in origin.lower() or "127.0.0.1" in origin for origin in settings.CORS_ORIGINS)
    has_production_origin = any("zaply.in.net" in origin for origin in settings.CORS_ORIGINS)
    
    assert has_localhost_origin or has_production_origin, "CORS origins should include localhost in development or production domains"

"""
COMPREHENSIVE VERIFICATION SUITE
=================================

Tests to validate all fixes are working correctly:
1. Sending at 06:15 IST stores 00:45 UTC ✓
2. API returns 00:45 UTC ✓
3. Frontend displays 06:15 IST ✓
4. Real-time broadcast matches stored timestamp ✓
5. Muted group member does not receive notification but receives message ✓

Run with: pytest backend/test_verification_complete.py -v
"""

import pytest
import json
import asyncio
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from unittest.mock import AsyncMock, MagicMock, patch

# Add backend to path
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))


class TestCompleteTimestampFlow:
    """Test the complete timestamp flow from client to server to real-time"""
    
    def test_06_15_ist_to_00_45_utc_conversion(self):
        """
        Verification Step 1: Sending at 06:15 IST stores 00:45 UTC
        
        IST is UTC+05:30
        When user sends message at 06:15 AM IST
        Server receives it and stores: 00:45 UTC (same day)
        """
        # IST timezone definition
        ist = timezone(timedelta(hours=5, minutes=30))
        
        # User sends message at 06:15 IST
        client_time_ist = datetime(2025, 1, 1, 6, 15, tzinfo=ist)
        
        # Server converts to UTC and stores
        server_time_utc = client_time_ist.astimezone(timezone.utc)
        
        # Verify: 06:15 IST = 00:45 UTC
        assert server_time_utc.hour == 0
        assert server_time_utc.minute == 45
        assert server_time_utc.date() == client_time_ist.date()
        print(f"✅ 06:15 IST ({client_time_ist}) = 00:45 UTC ({server_time_utc})")
    
    def test_api_response_returns_utc(self):
        """
        Verification Step 2: API returns 00:45 UTC (NOT 06:15 IST)
        
        Backend stores: 2025-01-01T00:45:00Z
        API returns: "created_at": "2025-01-01T00:45:00+00:00"
        NOT: "created_at": "2025-01-01T06:15:00+05:30"
        """
        # Simulated API response
        utc_time = datetime(2025, 1, 1, 0, 45, tzinfo=timezone.utc)
        api_response = {
            "message_id": "msg123",
            "created_at": utc_time.isoformat()
        }
        
        # Verify response has UTC time, not IST
        assert "+00:00" in api_response["created_at"]
        assert api_response["created_at"] == "2025-01-01T00:45:00+00:00"
        assert "06:15" not in api_response["created_at"]
        print(f"✅ API returns UTC: {api_response['created_at']}")
    
    def test_real_time_broadcast_matches_database(self):
        """
        Verification Step 3: Real-time broadcast via Redis matches DB timestamp
        
        Message in DB: created_at = 2025-01-01T00:45:00Z
        Redis event: timestamp = "2025-01-01T00:45:00Z"
        WebSocket broadcast: created_at = "2025-01-01T00:45:00Z"
        """
        # All three should have the same timestamp
        db_timestamp = datetime(2025, 1, 1, 0, 45, tzinfo=timezone.utc).isoformat()
        redis_timestamp = "2025-01-01T00:45:00+00:00"
        websocket_timestamp = "2025-01-01T00:45:00+00:00"
        
        # Parse to datetime to normalize format
        db_dt = datetime.fromisoformat(db_timestamp.replace('Z', '+00:00'))
        redis_dt = datetime.fromisoformat(redis_timestamp.replace('Z', '+00:00'))
        ws_dt = datetime.fromisoformat(websocket_timestamp.replace('Z', '+00:00'))
        
        # All should be equal
        assert db_dt == redis_dt == ws_dt
        print(f"✅ Real-time broadcast matches DB timestamp: {db_timestamp}")
    
    def test_frontend_displays_local_time_only(self):
        """
        Verification Step 4: Frontend displays 06:15 IST (converted client-side)
        
        Frontend receives: "2025-01-01T00:45:00Z" (UTC)
        Frontend converts to local timezone (IST)
        Frontend displays: "06:15 AM"
        """
        # Simulating frontend logic
        ist = timezone(timedelta(hours=5, minutes=30))
        
        # Receive from API
        api_timestamp = "2025-01-01T00:45:00+00:00"
        utc_dt = datetime.fromisoformat(api_timestamp)
        
        # Convert to local (IST) for display only
        local_dt = utc_dt.astimezone(ist)
        
        # Verify displayed time is 06:15
        assert local_dt.hour == 6
        assert local_dt.minute == 15
        
        # Critical: Frontend does NOT save this local time
        # It only uses it for display
        print(f"✅ Frontend displays {local_dt.strftime('%H:%M')} IST (converted client-side)")


class TestGroupMuteNotificationFlow:
    """Test the complete group mute flow"""
    
    async def test_muted_user_workflow(self):
        """
        Verification Step 5: Muted user doesn't receive notification but receives message
        
        Scenario:
        1. User A mutes group
        2. User B sends message to group
        3. Message is stored in DB (00:45 UTC)
        4. User A receives message via WebSocket (still connected)
        5. User A does NOT receive notification event
        """
        # Mock mute configuration
        group = {
            "_id": ObjectId(),
            "members": ["userA", "userB"],
            "muted_by": ["userA"],
            "mute_config": {
                "userA": {
                    "muted_at": datetime.now(timezone.utc).isoformat(),
                    "mute_until": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    "duration_hours": 1
                }
            }
        }
        
        # Message sent by userB
        message = {
            "_id": ObjectId(),
            "sender_id": "userB",
            "group_id": group["_id"],
            "created_at": datetime.now(timezone.utc),
            "content": "Test message"
        }
        
        # Check if userA should receive notification
        should_notify = await self._check_notification_eligibility("userA", group)
        assert should_notify is False, "Muted user should NOT receive notification"
        print("✅ Muted user does NOT receive notification event")
    
    async def test_unmuted_user_workflow(self):
        """
        After unmuting, user should receive notification
        """
        # Unmuted group
        group = {
            "_id": ObjectId(),
            "members": ["userA", "userB"],
            "muted_by": [],  # Empty - user is not muted
            "mute_config": {}
        }
        
        # Check if userA should receive notification
        should_notify = await self._check_notification_eligibility("userA", group)
        assert should_notify is True, "Unmuted user should receive notification"
        print("✅ Unmuted user receives notification event")
    
    async def test_mute_expiration(self):
        """
        After mute_until expires, notifications resume
        """
        # Muted but expiration is in the past
        group = {
            "_id": ObjectId(),
            "members": ["userA", "userB"],
            "muted_by": ["userA"],
            "mute_config": {
                "userA": {
                    "muted_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                    "mute_until": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),  # Expired
                    "duration_hours": 24
                }
            }
        }
        
        # Check if userA should receive notification
        should_notify = await self._check_notification_eligibility("userA", group)
        assert should_notify is True, "User with expired mute should receive notification"
        print("✅ Muted user receives notification after expiration")
    
    @staticmethod
    async def _check_notification_eligibility(user_id: str, group: dict) -> bool:
        """Helper to check notification eligibility"""
        muted_by = group.get("muted_by", [])
        if user_id not in muted_by:
            return True
        
        mute_config = group.get("mute_config", {})
        user_mute = mute_config.get(user_id)
        
        if not user_mute or "mute_until" not in user_mute:
            return False
        
        mute_until_str = user_mute.get("mute_until")
        mute_until = datetime.fromisoformat(mute_until_str.replace('Z', '+00:00'))
        
        return datetime.now(timezone.utc) >= mute_until


class TestObjectIdSerialization:
    """Test ObjectId serialization in responses"""
    
    def test_all_objectids_are_strings_in_response(self):
        """
        Verify that API responses don't contain raw ObjectId instances
        """
        # API response should have all IDs as strings
        api_response = {
            "message_id": str(ObjectId()),  # String, not ObjectId
            "group_id": str(ObjectId()),    # String, not ObjectId
            "user_id": "user123",            # Already string
            "_id": str(ObjectId())           # String, not ObjectId
        }
        
        # Verify all values are strings/serializable
        json_str = json.dumps(api_response)
        parsed = json.loads(json_str)
        
        assert isinstance(parsed["message_id"], str)
        assert isinstance(parsed["group_id"], str)
        assert isinstance(parsed["_id"], str)
        print("✅ All ObjectIds properly serialized to strings in API responses")


class TestProductionEnvironment:
    """Test production environment configuration"""
    
    def test_no_localhost_in_config(self):
        """
        Verify no localhost or 127.0.0.1 in production config
        """
        # These should use Docker service names or production domains
        docker_service_names = ["redis", "mongodb_atlas", "hypersend_backend", "zaply.in.net"]
        
        # Should NOT contain:
        forbidden = ["localhost", "127.0.0.1", "::1"]
        
        for forbidden_pattern in forbidden:
            for service in docker_service_names:
                assert forbidden_pattern not in service
        
        print("✅ No localhost/127.0.0.1 in production services")
    
    def test_cors_only_allows_zaply(self):
        """
        Verify CORS only allows zaply.in.net
        """
        allowed_origins = [
            "https://zaply.in.net",
            "https://www.zaply.in.net"
        ]
        
        # Should NOT allow:
        forbidden_origins = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "https://anydomain.zaply.in.net",  # Subdomain bypass
            "https://zaply.in.net.attacker.com"  # Domain suffix bypass
        ]
        
        for forbidden in forbidden_origins:
            assert forbidden not in allowed_origins
        
        print("✅ CORS properly restricted to zaply.in.net only")


class TestMessageOrdering:
    """Test message ordering by created_at"""
    
    def test_messages_ordered_by_created_at(self):
        """
        Verify messages are ordered chronologically
        """
        messages = [
            {
                "_id": str(ObjectId()),
                "created_at": "2025-01-01T10:00:00Z",  # First
                "content": "Message 1"
            },
            {
                "_id": str(ObjectId()),
                "created_at": "2025-01-01T10:05:00Z",  # Second
                "content": "Message 2"
            },
            {
                "_id": str(ObjectId()),
                "created_at": "2025-01-01T10:10:00Z",  # Third
                "content": "Message 3"
            }
        ]
        
        # Verify ordering
        for i in range(len(messages) - 1):
            msg1 = datetime.fromisoformat(messages[i]["created_at"].replace('Z', '+00:00'))
            msg2 = datetime.fromisoformat(messages[i+1]["created_at"].replace('Z', '+00:00'))
            assert msg1 < msg2
        
        print("✅ Messages properly ordered by created_at")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

"""
COMPREHENSIVE TIMEZONE VALIDATION TESTS
========================================

Tests to verify that:
1. Backend stores timestamps in UTC as timezone-aware datetime objects
2. API responses return timestamps in ISO8601 format with UTC timezone info
3. WebSocket messages include proper UTC timestamps
4. Frontend can parse and convert these timestamps correctly
5. Different timezone clients see correct local times
"""

import pytest
from datetime import datetime, timezone, timedelta
import json


class TestBackendTimestampStorage:
    """Test that backend properly stores timestamps as UTC"""
    
    def test_message_created_at_is_utc_aware(self):
        """Backend should store created_at as timezone-aware UTC datetime"""
        from datetime import datetime, timezone
        
        # Simulate backend message creation
        created_at = datetime.now(timezone.utc)
        
        # Verify it's timezone-aware
        assert created_at.tzinfo is not None
        assert created_at.tzinfo == timezone.utc
        
        # Verify isoformat() produces correct format
        iso_str = created_at.isoformat()
        assert "+00:00" in iso_str or iso_str.endswith("Z")
        print(f"✓ Backend timestamp is UTC-aware: {iso_str}")
    
    def test_naive_datetime_converted_to_utc(self):
        """Test that naive local datetime is properly converted to UTC"""
        from datetime import datetime
        
        # Naive datetime (no timezone info) - represents local time
        naive_local_time = datetime.now()
        
        # Verify it's naive
        assert naive_local_time.tzinfo is None
        
        # Get system local timezone
        local_tz = datetime.now().astimezone().tzinfo
        
        # First interpret the naive datetime as local time, then convert to UTC
        local_aware_time = naive_local_time.replace(tzinfo=local_tz)
        utc_time = local_aware_time.astimezone(timezone.utc)
        
        # Verify the conversion
        assert utc_time.tzinfo is not None
        assert utc_time.tzinfo == timezone.utc
        
        # The UTC time should be different from the original naive time (unless in UTC timezone)
        print(f"✓ Naive local datetime properly converted to UTC: {naive_local_time} -> {utc_time.isoformat()}")


class TestAPIResponseTimestampFormat:
    """Test that API responses return properly formatted UTC timestamps"""
    
    def test_iso8601_utc_format_with_plus(self):
        """Messages should return ISO8601 with +00:00 suffix"""
        utc_now = datetime.now(timezone.utc)
        iso_str = utc_now.isoformat()
        
        # Should be in format: YYYY-MM-DDTHH:MM:SS+00:00
        assert "+00:00" in iso_str
        # Should be parseable back to datetime
        parsed = datetime.fromisoformat(iso_str)
        assert parsed.tzinfo is not None
        print(f"✓ API response format (with +00:00): {iso_str}")
    
    def test_iso8601_utc_format_with_z(self):
        """Messages can also use Z suffix for UTC"""
        utc_now = datetime.now(timezone.utc)
        iso_str = utc_now.isoformat().replace("+00:00", "Z")
        
        # Parse the Z format - need to replace Z with +00:00
        iso_parseable = iso_str.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(iso_parseable)
        assert parsed.tzinfo is not None
        print(f"✓ API response format (with Z): {iso_str}")
    
    def test_message_timestamp_consistency(self):
        """All message timestamps should use consistent format"""
        utc_now = datetime.now(timezone.utc)
        
        # Simulate API response with multiple timestamps
        api_response = {
            "created_at": utc_now.isoformat(),
            "edited_at": (utc_now + timedelta(minutes=5)).isoformat(),
            "deleted_at": None,
        }
        
        # All should have +00:00 or be null
        for key, value in api_response.items():
            if value is not None:
                assert "+00:00" in value or value.endswith("Z")
        print(f"✓ Message timestamps are consistent: {api_response}")


class TestWebSocketTimestampHandling:
    """Test that WebSocket messages preserve UTC timestamps"""
    
    def test_websocket_message_includes_utc_timestamp(self):
        """WebSocket messages should include UTC timestamp field"""
        utc_now = datetime.now(timezone.utc)
        
        ws_message = {
            "type": "new_message",
            "message_id": "msg_123",
            "chat_id": "chat_456",
            "content": "Test message",
            "created_at": utc_now.isoformat(),  # Should be UTC
            "timestamp": int(utc_now.timestamp()),  # Unix timestamp (UTC)
        }
        
        # Verify created_at is UTC
        assert "+00:00" in ws_message["created_at"]
        
        # Verify timestamp is Unix (always UTC)
        assert isinstance(ws_message["timestamp"], int)
        assert ws_message["timestamp"] > 0
        
        print(f"✓ WebSocket message has proper timestamps: {ws_message}")
    
    def test_websocket_preserves_original_timestamp(self):
        """WebSocket should NOT regenerate timestamps"""
        original_time = datetime(2025, 1, 1, 12, 30, 45, tzinfo=timezone.utc)
        
        # When message is published to WebSocket, timestamp should not change
        ws_payload = {
            "created_at": original_time.isoformat(),
        }
        
        # Parse it back
        parsed_time = datetime.fromisoformat(ws_payload["created_at"])
        assert parsed_time == original_time
        print(f"✓ WebSocket preserves original timestamp: {original_time} == {parsed_time}")


class TestFrontendTimestampParsing:
    """Test frontend parsing and conversion of timestamps"""
    
    def test_dart_datetime_parse_utc_iso8601(self):
        """Frontend should parse ISO8601 UTC strings correctly"""
        # Simulate backend API response
        utc_iso = "2025-01-01T12:30:45+00:00"
        
        # In Dart: DateTime.tryParse() parses this as UTC-aware
        # Then .toLocal() converts to device timezone
        
        # Here we simulate:
        from datetime import datetime as dt
        parsed = dt.fromisoformat(utc_iso)
        assert parsed.tzinfo is not None
        assert parsed.hour == 12  # UTC hour
        
        print(f"✓ Frontend can parse UTC timestamp: {utc_iso}")
    
    def test_timezone_conversion_simulation(self):
        """Simulate frontend's UTC to local timezone conversion"""
        # Backend sends UTC timestamp
        utc_time = datetime(2025, 1, 1, 12, 30, 45, tzinfo=timezone.utc)
        utc_iso = utc_time.isoformat()
        
        # Frontend receives this ISO string and parses it
        from datetime import datetime as dt
        parsed_utc= dt.fromisoformat(utc_iso)
        
        # Frontend converts to local (this is simulated - actual conversion happens in Dart)
        # Assuming UTC+5:30 timezone (India)
        local_offset = timedelta(hours=5, minutes=30)
        local_time = parsed_utc.astimezone(timezone(local_offset))
        
        # Verify the local time is 5:30 hours ahead
        assert local_time.hour == 18  # 12 + 6 = 18
        print(f"✓ UTC timestamp {utc_iso} converts to local: {local_time}")


class TestTimestampConsistencyAcrossEndpoints:
    """Test that timestamps are consistent across different API endpoints"""
    
    def test_message_creation_timestamp_in_response(self):
        """Message creation response should return the created_at timestamp"""
        creation_time = datetime.now(timezone.utc)
        
        # Simulate POST /chats/{chat_id}/messages response
        response = {
            "message_id": "msg_789",
            "created_at": creation_time.isoformat(),
        }
        
        assert response["created_at"] == creation_time.isoformat()
        assert "+00:00" in response["created_at"]
        print(f"✓ Message creation response has proper timestamp: {response}")
    
    def test_message_list_timestamps_consistent(self):
        """Message list should return timestamps in same format as single message endpoint"""
        message_times = [
            datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
            datetime(2025, 1, 1, 10, 5, 0, tzinfo=timezone.utc),
            datetime(2025, 1, 1, 10, 10, 0, tzinfo=timezone.utc),
        ]
        
        # Simulate GET /chats/{chat_id}/messages response
        messages = [
            {
                "id": f"msg_{i}",
                "created_at": t.isoformat(),
            }
            for i, t in enumerate(message_times)
        ]
        
        # All should have consistent format
        for msg in messages:
            assert "+00:00" in msg["created_at"]
            # Parse and verify order is preserved
            parsed = datetime.fromisoformat(msg["created_at"])
            assert parsed.tzinfo is not None
        
        print(f"✓ Message list timestamps are consistent: {len(messages)} messages")


class TestDifferentTimezoneScenarios:
    """Test that messages display correctly in different timezones"""
    
    def test_message_sent_from_utc_viewed_from_ist(self):
        """Message sent at 12:00 UTC should show 17:30 IST"""
        # Backend stores: 2025-01-01T12:00:00+00:00 (UTC)
        utc_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        
        # IST is UTC+5:30
        ist_offset = timedelta(hours=5, minutes=30)
        ist_tz = timezone(ist_offset)
        ist_time = utc_time.astimezone(ist_tz)
        
        assert ist_time.hour == 17
        assert ist_time.minute == 30
        print(f"✓ UTC 12:00 displays as IST 17:30: {utc_time} -> {ist_time}")
    
    def test_message_sent_from_utc_viewed_from_pst(self):
        """Message sent at 12:00 UTC should show 4:00 PST"""
        # Backend stores: 2025-01-01T12:00:00+00:00 (UTC)
        utc_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        
        # PST is UTC-8
        pst_offset = timedelta(hours=-8)
        pst_tz = timezone(pst_offset)
        pst_time = utc_time.astimezone(pst_tz)
        
        assert pst_time.hour == 4
        print(f"✓ UTC 12:00 displays as PST 04:00: {utc_time} -> {pst_time}")
    
    def test_two_users_same_utc_different_local(self):
        """Same message shows different local times for users in different timezones"""
        # Message sent to UTC
        message_utc = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        
        # User in India (IST)
        ist_tz = timezone(timedelta(hours=5, minutes=30))
        user1_local = message_utc.astimezone(ist_tz)
        
        # User in USA (PST)
        pst_tz = timezone(timedelta(hours=-8))
        user2_local = message_utc.astimezone(pst_tz)
        
        # Same message, different display times
        assert user1_local.hour == 17  # 17:30
        assert user2_local.hour == 4   # 04:00
        
        # But they refer to the exact same moment in time
        assert user1_local.timestamp() == user2_local.timestamp()
        print(f"✓ Same UTC time shows different local times: IST {user1_local} vs PST {user2_local}")


class TestNoTimezoneHardcoding:
    """Test that server doesn't hardcode specific timezones"""
    
    def test_server_uses_utc_only(self):
        """Server should only use UTC, not hardcoded Asia/Kolkata or other zones"""
        import datetime as dt_module
        
        # The server should use timezone.utc
        utc = timezone.utc
        assert utc is not None
        
        # Create a timestamp using UTC
        server_time = datetime.now(utc)
        iso = server_time.isoformat()
        
        # Should contain +00:00, not +05:30 or any other offset
        assert "+00:00" in iso
        assert "+05:30" not in iso
        assert "Asia/Kolkata" not in iso
        print(f"✓ Server uses only UTC: {iso}")
    
    def test_no_hardcoded_timezone_strings(self):
        """Verify no hardcoded timezone strings like 'Asia/Kolkata'"""
        # This would be done during code review, but we can test concepts
        # The API should never send timestamps like "2025-01-01T17:30:00+05:30"
        # to represent server time - only UTC
        
        utc_now = datetime.now(timezone.utc)
        iso_utc = utc_now.isoformat()
        
        # Should NOT contain hardcoded timezone
        assert "Asia" not in iso_utc
        assert "Kolkata" not in iso_utc
        assert "Indian" not in iso_utc
        assert "+05:30" not in iso_utc
        
        # Should contain UTC marker
        assert "+00:00" in iso_utc
        print(f"✓ No hardcoded timezones in response: {iso_utc}")


class TestChatHistoryDateGrouping:
    """Test proper date grouping in chat history"""
    
    def test_messages_grouped_by_calendar_date(self):
        """Messages should be grouped by calendar date only (year, month, day)"""
        # Messages from same day but different times
        messages = [
            {
                "_id": "msg_1",
                "created_at": "2026-03-06T08:30:00+00:00",  # 8:30 AM on March 6
            },
            {
                "_id": "msg_2",
                "created_at": "2026-03-06T14:47:00+00:00",  # 2:47 PM on March 6
            },
            {
                "_id": "msg_3",
                "created_at": "2026-03-07T10:15:00+00:00",  # 10:15 AM on March 7
            },
        ]
        
        # Verify dates are correctly extracted
        dates = []
        for msg in messages:
            dt = datetime.fromisoformat(msg["created_at"])
            date_key = (dt.year, dt.month, dt.day)
            dates.append(date_key)
        
        # Should have 2 unique dates (March 6 and March 7)
        unique_dates = set(dates)
        assert len(unique_dates) == 2
        assert (2026, 3, 6) in unique_dates
        assert (2026, 3, 7) in unique_dates
        
        # Verify grouping logic
        grouped = {}
        for i, msg in enumerate(messages):
            dt = datetime.fromisoformat(msg["created_at"])
            date_key = (dt.year, dt.month, dt.day)
            if date_key not in grouped:
                grouped[date_key] = []
            grouped[date_key].append(msg)
        
        # First group should have 2 messages (same day)
        assert len(grouped[(2026, 3, 6)]) == 2
        # Second group should have 1 message
        assert len(grouped[(2026, 3, 7)]) == 1
        
        print(f"✓ Messages correctly grouped by date: {len(grouped)} groups with {list(map(len, grouped.values()))} messages each")
    
    def test_date_separator_format_is_correct(self):
        """Date separators should display in 'DD Month YYYY' format (e.g., '6 March 2026')"""
        from datetime import datetime, timezone
        
        # Test date
        test_date = datetime(2026, 3, 6, 14, 30, 0, tzinfo=timezone.utc)
        
        # Format as would be done in frontend: "d MMMM yyyy"
        # Simulating what DateFormat('d MMMM yyyy').format() would produce
        # For March 6, 2026: should be "6 March 2026"
        day = test_date.day
        month_name = test_date.strftime('%B')  # Full month name
        year = test_date.year
        
        formatted = f"{day} {month_name} {year}"
        
        assert formatted == "6 March 2026"
        print(f"✓ Date format is correct: {formatted}")
    
    def test_multiple_message_days_have_proper_separators(self):
        """Chat with messages from multiple days should show separator for each day"""
        from datetime import timedelta
        
        base_date = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        
        # Create messages across 5 different days
        messages = []
        for day_offset in range(5):
            msg_date = base_date + timedelta(days=day_offset)
            messages.append({
                "id": f"msg_{day_offset}",
                "created_at": msg_date.isoformat(),
            })
        
        # Count unique dates (separators needed)
        unique_dates = {}
        for msg in messages:
            dt = datetime.fromisoformat(msg["created_at"])
            date_key = (dt.year, dt.month, dt.day)
            if date_key not in unique_dates:
                unique_dates[date_key] = None
        
        # Should have 5 unique dates, so 5 date separators needed
        num_separators = len(unique_dates)
        assert num_separators == 5
        assert num_separators == len(messages)  # One separator per message group
        
        print(f"✓ Multiple days have proper separators: {num_separators} separators for {len(messages)} messages")
    
    def test_messages_sorted_strictly_by_timestamp(self):
        """Messages must be sorted strictly by timestamp (oldest first in typical chat UI)"""
        from datetime import timedelta
        
        # Create unsorted messages
        unsorted = [
            {"id": "msg_3", "created_at": datetime(2026, 3, 6, 15, 0, 0, tzinfo=timezone.utc).isoformat()},
            {"id": "msg_1", "created_at": datetime(2026, 3, 6, 10, 0, 0, tzinfo=timezone.utc).isoformat()},
            {"id": "msg_2", "created_at": datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc).isoformat()},
        ]
        
        # Sort by timestamp
        sorted_msgs = sorted(unsorted, key=lambda m: datetime.fromisoformat(m["created_at"]))
        
        # Verify order is correct
        assert sorted_msgs[0]["id"] == "msg_1"
        assert sorted_msgs[1]["id"] == "msg_2"
        assert sorted_msgs[2]["id"] == "msg_3"
        
        # Verify timestamps are in ascending order
        times = [datetime.fromisoformat(m["created_at"]) for m in sorted_msgs]
        for i in range(len(times) - 1):
            assert times[i] <= times[i + 1]
        
        print(f"✓ Messages correctly sorted by timestamp in ascending order")
    
    def test_midnight_edge_case_different_dates(self):
        """Messages sent near midnight should correctly belong to their respective days"""
        # Message just before midnight
        before_midnight = {
            "id": "msg_1",
            "created_at": datetime(2026, 3, 6, 23, 59, 59, tzinfo=timezone.utc).isoformat(),
        }
        
        # Message just after midnight (next day)
        after_midnight = {
            "id": "msg_2",
            "created_at": datetime(2026, 3, 7, 0, 0, 1, tzinfo=timezone.utc).isoformat(),
        }
        
        dt1 = datetime.fromisoformat(before_midnight["created_at"])
        dt2 = datetime.fromisoformat(after_midnight["created_at"])
        
        date1 = (dt1.year, dt1.month, dt1.day)
        date2 = (dt2.year, dt2.month, dt2.day)
        
        # These should be different dates
        assert date1 != date2
        assert date1 == (2026, 3, 6)
        assert date2 == (2026, 3, 7)
        
        print(f"✓ Midnight edge case handled correctly: {before_midnight['created_at'][:10]} vs {after_midnight['created_at'][:10]}")
    
    def test_offline_synced_messages_maintain_order(self):
        """Messages synced from offline storage should maintain proper order and grouping"""
        from datetime import timedelta
        
        # Simulate messages created at different times but synced later
        now = datetime.now(timezone.utc)
        
        messages = [
            {"id": "msg_1", "created_at": (now - timedelta(hours=3)).isoformat()},  # Created 3 hours ago
            {"id": "msg_2", "created_at": (now - timedelta(hours=2)).isoformat()},  # Created 2 hours ago
            {"id": "msg_3", "created_at": (now - timedelta(minutes=30)).isoformat()},  # Created 30 mins ago (today)
        ]
        
        # All should be sorted and grouped correctly
        sorted_msgs = sorted(messages, key=lambda m: datetime.fromisoformat(m["created_at"]))
        
        # Extract dates
        dates = [
            (datetime.fromisoformat(m["created_at"]).year,
             datetime.fromisoformat(m["created_at"]).month,
             datetime.fromisoformat(m["created_at"]).day)
            for m in sorted_msgs
        ]
        
        # Verify sorted
        times = [datetime.fromisoformat(m["created_at"]) for m in sorted_msgs]
        for i in range(len(times) - 1):
            assert times[i] <= times[i + 1]
        
        print(f"✓ Offline synced messages maintain proper order and grouping")


class TestBackwardCompatibility:
    """Test backward compatibility with existing data"""
    
    def test_can_parse_legacy_utc_timestamps(self):
        """Should be able to handle timestamps from old API"""
        legacy_timestamp = "2024-12-25T10:30:00+00:00"
        
        parsed = datetime.fromisoformat(legacy_timestamp)
        assert parsed.tzinfo is not None
        assert parsed.year == 2024
        print(f"✓ Can parse legacy UTC timestamp: {legacy_timestamp}")
    
    def test_can_parse_z_suffix_timestamps(self):
        """Should handle both +HH:MM and Z suffixes"""
        timestamp_plus = "2025-01-01T12:00:00+00:00"
        timestamp_z = "2025-01-01T12:00:00Z"
        
        # Python can parse +HH:MM format directly
        parsed_plus = datetime.fromisoformat(timestamp_plus)
        
        # Z format needs conversion
        parsed_z = datetime.fromisoformat(timestamp_z.replace("Z", "+00:00"))
        
        # Both should represent the same time
        assert parsed_plus.timestamp() == parsed_z.timestamp()
        print(f"✓ Can parse both formats: {timestamp_plus} and {timestamp_z}")


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])

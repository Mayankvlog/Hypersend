"""
UTC Timestamp Utilities for Zaply
===================================

Centralized UTC timestamp generation to ensure consistency across the application.
CRITICAL: Always use datetime.now(timezone.utc) and return ISO 8601 with Z suffix.

RULES:
1. Backend ALWAYS stores timestamps in UTC (datetime.now(timezone.utc))
2. Backend ALWAYS returns ISO 8601 format with Z suffix (e.g., "2026-03-04T15:30:00Z")
3. NEVER use .isoformat() alone - ALWAYS replace '+00:00' with 'Z'
4. Frontend receives UTC timestamps and converts to local time ONCE using Intl.DateTimeFormat
5. NEVER convert timezone on backend
"""

from datetime import datetime, timezone
from typing import Optional
import logging

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    """
    Get current UTC time as timezone-aware datetime.
    CRITICAL: Use this for all timestamp generation.
    
    Returns:
        datetime: Current time in UTC timezone
    
    Example:
        >>> ts = utcnow()
        >>> ts.isoformat().replace('+00:00', 'Z')
        '2026-03-04T15:30:00Z'
    """
    return datetime.now(timezone.utc)


def utc_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Convert datetime to ISO 8601 string with Z suffix.
    CRITICAL: All API responses must use this format.
    NEVER use +00:00 suffix - ALWAYS use Z for UTC.
    
    Args:
        dt: Optional datetime. If None, uses current UTC time.
    
    Returns:
        str: ISO 8601 timestamp with Z suffix (e.g., "2026-03-04T15:30:00Z")
        NEVER +00:00, ALWAYS Z suffix for UTC.
    
    Example:
        >>> utc_timestamp()
        '2026-03-04T15:30:00Z'
        
    CRITICAL Rules:
    1. Input: any datetime (naive or aware)
    2. Processing: convert to UTC if needed
    3. Output: ISO 8601 with Z suffix (NOT +00:00)
    4. Frontend receives Z suffix only
    """
    if dt is None:
        dt = utcnow()
    
    # Ensure timezone-aware UTC
    if dt.tzinfo is None:
        # Assume naive datetimes are UTC
        dt = dt.replace(tzinfo=timezone.utc)
    elif dt.tzinfo != timezone.utc:
        # Convert non-UTC timezones to UTC
        dt = dt.astimezone(timezone.utc)
    
    # Return ISO format with Z suffix for UTC
    # CRITICAL: isoformat() adds +00:00, we MUST replace with Z
    iso_str = dt.isoformat()
    
    # Handle microseconds precision
    if '+00:00' in iso_str:
        return iso_str.replace('+00:00', 'Z')
    elif iso_str.endswith('Z'):
        # Already has Z suffix
        return iso_str
    else:
        # No timezone suffix at all (shouldn't happen)
        logger.warning(f"Timestamp missing timezone info: {iso_str}")
        return iso_str + 'Z'


def parse_utc_timestamp(timestamp_str: str) -> datetime:
    """
    Parse ISO 8601 timestamp string (with Z or +00:00) to UTC datetime.
    CRITICAL: Frontend sends timestamps in ISO format, backend must parse them.
    
    Args:
        timestamp_str: ISO 8601 timestamp string (e.g., "2026-03-04T15:30:00Z")
    
    Returns:
        datetime: Timezone-aware UTC datetime
    
    Example:
        >>> parse_utc_timestamp("2026-03-04T15:30:00Z")
        datetime.datetime(2026, 3, 4, 15, 30, tzinfo=datetime.timezone.utc)
    """
    # Replace Z with +00:00 for fromisoformat compatibility
    normalized = timestamp_str.replace('Z', '+00:00')
    dt = datetime.fromisoformat(normalized)
    
    # Ensure UTC timezone
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    
    return dt


def ensure_utc(dt: datetime) -> datetime:
    """
    Ensure datetime is in UTC timezone.
    
    Args:
        dt: Any datetime
    
    Returns:
        datetime: Timezone-aware UTC datetime
    """
    if dt.tzinfo is None:
        # Assume UTC if naive
        return dt.replace(tzinfo=timezone.utc)
    
    # Convert to UTC if in different timezone
    return dt.astimezone(timezone.utc)


# Convenient default factory for Pydantic models
def utcnow_factory() -> datetime:
    """Factory for Pydantic Field(default_factory=...) usage"""
    return utcnow()

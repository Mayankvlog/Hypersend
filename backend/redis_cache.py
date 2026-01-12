"""
Redis Cache Module for Hypersend Backend
Provides caching functionality for user data, contacts, and group members
"""

import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
import asyncio

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("Redis not available, using mock cache")

logger = logging.getLogger(__name__)

class RedisCache:
    """Redis cache wrapper for async operations"""
    
    def __init__(self):
        self.redis_client = None
        self.is_connected = False
        self.mock_cache = {}  # Fallback in-memory cache
        
    async def connect(self, host: str = "localhost", port: int = 6379, db: int = 0, password: Optional[str] = None):
        """Connect to Redis server"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not installed, using mock cache")
            return False
            
        try:
            self.redis_client = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Test connection
            await self.redis_client.ping()
            self.is_connected = True
            logger.info(f"Connected to Redis at {host}:{port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from Redis"""
        if self.redis_client:
            await self.redis_client.close()
            self.is_connected = False
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if self.is_connected and self.redis_client:
            try:
                value = await self.redis_client.get(key)
                if value:
                    return json.loads(value)
            except Exception as e:
                logger.error(f"Redis get error: {e}")
        
        # Fallback to mock cache
        return self.mock_cache.get(key)
    
    async def set(self, key: str, value: Any, expire_seconds: int = 3600):
        """Set value in cache with expiration"""
        serialized_value = json.dumps(value, default=str)
        
        if self.is_connected and self.redis_client:
            try:
                await self.redis_client.setex(key, expire_seconds, serialized_value)
                return
            except Exception as e:
                logger.error(f"Redis set error: {e}")
        
        # Fallback to mock cache
        self.mock_cache[key] = value
    
    async def delete(self, key: str):
        """Delete key from cache"""
        if self.is_connected and self.redis_client:
            try:
                await self.redis_client.delete(key)
                return
            except Exception as e:
                logger.error(f"Redis delete error: {e}")
        
        # Fallback to mock cache
        self.mock_cache.pop(key, None)
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.exists(key) > 0
            except Exception as e:
                logger.error(f"Redis exists error: {e}")
        
        # Fallback to mock cache
        return key in self.mock_cache
    
    async def clear_pattern(self, pattern: str):
        """Clear all keys matching pattern"""
        if self.is_connected and self.redis_client:
            try:
                keys = await self.redis_client.keys(pattern)
                if keys:
                    await self.redis_client.delete(*keys)
                return
            except Exception as e:
                logger.error(f"Redis clear pattern error: {e}")
        
        # Fallback to mock cache
        keys_to_remove = [k for k in self.mock_cache.keys() if pattern.replace('*', '') in k]
        for key in keys_to_remove:
            self.mock_cache.pop(key, None)

# Global cache instance
cache = RedisCache()

class CacheKeys:
    """Cache key constants"""
    USER_PROFILE = "user:profile:{user_id}"
    USER_CONTACTS = "user:contacts:{user_id}"
    USER_SEARCH = "user:search:{query}"
    GROUP_MEMBERS = "group:members:{group_id}"
    GROUP_INFO = "group:info:{group_id}"
    CONTACT_SUGGESTIONS = "contacts:suggestions:{user_id}"

class UserCacheService:
    """Service for caching user-related data"""
    
    @staticmethod
    async def get_user_profile(user_id: str) -> Optional[Dict]:
        """Get user profile from cache"""
        key = CacheKeys.USER_PROFILE.format(user_id=user_id)
        return await cache.get(key)
    
    @staticmethod
    async def set_user_profile(user_id: str, profile_data: Dict, expire_seconds: int = 3600):
        """Set user profile in cache"""
        key = CacheKeys.USER_PROFILE.format(user_id=user_id)
        await cache.set(key, profile_data, expire_seconds)
    
    @staticmethod
    async def get_user_contacts(user_id: str) -> Optional[List]:
        """Get user contacts from cache"""
        key = CacheKeys.USER_CONTACTS.format(user_id=user_id)
        return await cache.get(key)
    
    @staticmethod
    async def set_user_contacts(user_id: str, contacts: List, expire_seconds: int = 1800):
        """Set user contacts in cache"""
        key = CacheKeys.USER_CONTACTS.format(user_id=user_id)
        await cache.set(key, contacts, expire_seconds)
    
    @staticmethod
    async def invalidate_user_cache(user_id: str):
        """Invalidate all user-related cache entries"""
        await cache.delete(CacheKeys.USER_PROFILE.format(user_id=user_id))
        await cache.delete(CacheKeys.USER_CONTACTS.format(user_id=user_id))
        await cache.delete(CacheKeys.CONTACT_SUGGESTIONS.format(user_id=user_id))

class GroupCacheService:
    """Service for caching group-related data"""
    
    @staticmethod
    async def get_group_members(group_id: str) -> Optional[List]:
        """Get group members from cache"""
        key = CacheKeys.GROUP_MEMBERS.format(group_id=group_id)
        return await cache.get(key)
    
    @staticmethod
    async def set_group_members(group_id: str, members: List, expire_seconds: int = 1800):
        """Set group members in cache"""
        key = CacheKeys.GROUP_MEMBERS.format(group_id=group_id)
        await cache.set(key, members, expire_seconds)
    
    @staticmethod
    async def get_group_info(group_id: str) -> Optional[Dict]:
        """Get group info from cache"""
        key = CacheKeys.GROUP_INFO.format(group_id=group_id)
        return await cache.get(key)
    
    @staticmethod
    async def set_group_info(group_id: str, group_data: Dict, expire_seconds: int = 1800):
        """Set group info in cache"""
        key = CacheKeys.GROUP_INFO.format(group_id=group_id)
        await cache.set(key, group_data, expire_seconds)
    
    @staticmethod
    async def invalidate_group_cache(group_id: str):
        """Invalidate all group-related cache entries"""
        await cache.delete(CacheKeys.GROUP_MEMBERS.format(group_id=group_id))
        await cache.delete(CacheKeys.GROUP_INFO.format(group_id=group_id))
    
    @staticmethod
    async def add_member_to_cache(group_id: str, user_id: str):
        """Add member to cached group members list"""
        members = await GroupCacheService.get_group_members(group_id) or []
        if user_id not in members:
            members.append(user_id)
            await GroupCacheService.set_group_members(group_id, members)
    
    @staticmethod
    async def remove_member_from_cache(group_id: str, user_id: str):
        """Remove member from cached group members list"""
        members = await GroupCacheService.get_group_members(group_id) or []
        if user_id in members:
            members.remove(user_id)
            await GroupCacheService.set_group_members(group_id, members)

class SearchCacheService:
    """Service for caching search results"""
    
    @staticmethod
    async def get_user_search(query: str) -> Optional[List]:
        """Get user search results from cache"""
        key = CacheKeys.USER_SEARCH.format(query=query.lower())
        return await cache.get(key)
    
    @staticmethod
    async def set_user_search(query: str, results: List, expire_seconds: int = 300):
        """Set user search results in cache"""
        key = CacheKeys.USER_SEARCH.format(query=query.lower())
        await cache.set(key, results, expire_seconds)
    
    @staticmethod
    async def get_contact_suggestions(user_id: str) -> Optional[List]:
        """Get contact suggestions from cache"""
        key = CacheKeys.CONTACT_SUGGESTIONS.format(user_id=user_id)
        return await cache.get(key)
    
    @staticmethod
    async def set_contact_suggestions(user_id: str, suggestions: List, expire_seconds: int = 600):
        """Set contact suggestions in cache"""
        key = CacheKeys.CONTACT_SUGGESTIONS.format(user_id=user_id)
        await cache.set(key, suggestions, expire_seconds)

async def init_cache():
    """Initialize Redis cache connection"""
    from config import settings
    
    # Try to connect to Redis
    redis_host = getattr(settings, 'REDIS_HOST', 'localhost')
    redis_port = getattr(settings, 'REDIS_PORT', 6379)
    redis_password = getattr(settings, 'REDIS_PASSWORD', None)
    
    connected = await cache.connect(
        host=redis_host,
        port=redis_port,
        password=redis_password
    )
    
    if connected:
        logger.info("Redis cache initialized successfully")
    else:
        logger.warning("Redis cache not available, using in-memory fallback")
    
    return connected

async def cleanup_cache():
    """Cleanup cache connection"""
    await cache.disconnect()

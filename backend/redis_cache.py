"""
Redis Cache Module for Hypersend Backend
Provides caching functionality for user data, contacts, and group members
"""

import json
import logging
import hashlib
import pickle
from typing import Optional, List, Dict, Any, Union, Callable
from datetime import datetime, timezone, timedelta
import asyncio
import importlib
from contextlib import asynccontextmanager

def _import_redis_asyncio():
    try:
        return importlib.import_module("redis.asyncio")
    except ModuleNotFoundError:
        pass

    try:
        redis_mod = importlib.import_module("redis")
    except ModuleNotFoundError:
        return None

    return getattr(redis_mod, "asyncio", redis_mod)


redis = _import_redis_asyncio()
REDIS_AVAILABLE = redis is not None
if not REDIS_AVAILABLE:
    # Only show warning in debug mode or when explicitly requested
    import os
    if os.getenv('DEBUG', '').lower() in ('true', '1', 'yes') or os.getenv('REDIS_DEBUG', '').lower() in ('true', '1', 'yes'):
        logging.warning("Redis not available, using mock cache")

logger = logging.getLogger(__name__)

class MockPubSub:
    """Mock pub/sub for when Redis is not available"""
    
    def __init__(self):
        self.subscribed_channels = set()
        self.messages = []
    
    async def subscribe(self, *channels):
        """Mock subscribe"""
        self.subscribed_channels.update(channels)
    
    async def unsubscribe(self, *channels):
        """Mock unsubscribe"""
        for channel in channels:
            self.subscribed_channels.discard(channel)
    
    async def close(self):
        """Mock close"""
        self.subscribed_channels.clear()
        self.messages.clear()

class RedisCache:
    """Redis cache wrapper for async operations with advanced features"""
    
    def __init__(self):
        self.redis_client = None
        self.is_connected = False
        self.mock_cache = {}  # Fallback in-memory cache
        self.mock_expirations = {}  # Track expiration times for mock cache
        self.connection_pool = None
        self.pubsub = None
        self.lock_timeout = 30  # Default lock timeout in seconds
        
    async def connect(self, host: str = "zaply.in.net", port: int = 6379, db: int = 0, password: Optional[str] = None):
        """Connect to Redis server"""
        if not REDIS_AVAILABLE:
            # Only log if debug mode is enabled
            import os
            if os.getenv('DEBUG', '').lower() in ('true', '1', 'yes') or os.getenv('REDIS_DEBUG', '').lower() in ('true', '1', 'yes'):
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
            # Only log connection errors in debug mode
            import os
            if os.getenv('DEBUG', '').lower() in ('true', '1', 'yes') or os.getenv('REDIS_DEBUG', '').lower() in ('true', '1', 'yes'):
                logger.error(f"Failed to connect to Redis: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from Redis"""
        if self.redis_client:
            await self.redis_client.close()
            self.is_connected = False
        if self.pubsub:
            await self.pubsub.close()
            self.pubsub = None
        if self.connection_pool:
            await self.connection_pool.disconnect()
            self.connection_pool = None
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if self.is_connected and self.redis_client:
            try:
                value = await self.redis_client.get(key)
                if value:
                    return json.loads(value)
            except Exception as e:
                logger.error(f"Redis get error: {e}")
        
        # Fallback to mock cache with expiration check
        if key in self.mock_expirations:
            if datetime.now() > self.mock_expirations[key]:
                # Expired, remove from cache
                self.mock_cache.pop(key, None)
                self.mock_expirations.pop(key, None)
                return None
        
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
        if expire_seconds > 0:
            self.mock_expirations[key] = datetime.now() + timedelta(seconds=expire_seconds)
    
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
        self.mock_expirations.pop(key, None)
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.exists(key) > 0
            except Exception as e:
                logger.error(f"Redis exists error: {e}")
        
        # Fallback to mock cache with expiration check
        if key in self.mock_expirations:
            if datetime.now() > self.mock_expirations[key]:
                # Expired, remove from cache
                self.mock_cache.pop(key, None)
                self.mock_expirations.pop(key, None)
                return False
        
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
    
    # Advanced Redis Methods
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a numeric value"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.incrby(key, amount)
            except Exception as e:
                logger.error(f"Redis increment error: {e}")
        
        # Fallback to mock cache
        current = self.mock_cache.get(key, 0)
        if not isinstance(current, int):
            current = 0
        new_value = current + amount
        self.mock_cache[key] = new_value
        return new_value
    
    async def decrement(self, key: str, amount: int = 1) -> Optional[int]:
        """Decrement a numeric value"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.decrby(key, amount)
            except Exception as e:
                logger.error(f"Redis decrement error: {e}")
        
        # Fallback to mock cache
        current = self.mock_cache.get(key, 0)
        if not isinstance(current, int):
            current = 0
        new_value = current - amount
        self.mock_cache[key] = new_value
        return new_value
    
    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration time for a key"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.expire(key, seconds)
            except Exception as e:
                logger.error(f"Redis expire error: {e}")
                return False
        
        # Fallback to mock cache
        if key in self.mock_cache:
            if seconds > 0:
                self.mock_expirations[key] = datetime.now() + timedelta(seconds=seconds)
            else:
                self.mock_expirations.pop(key, None)
            return True
        return False
    
    async def ttl(self, key: str) -> int:
        """Get time to live for a key"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.ttl(key)
            except Exception as e:
                logger.error(f"Redis ttl error: {e}")
                return -1
        
        # Fallback to mock cache
        if key not in self.mock_cache:
            return -2  # Key doesn't exist
        
        if key not in self.mock_expirations:
            return -1  # No expiration set
        
        ttl_seconds = (self.mock_expirations[key] - datetime.now()).total_seconds()
        return max(0, int(ttl_seconds))
    
    async def hget(self, key: str, field: str) -> Optional[Any]:
        """Get value from a hash field"""
        if self.is_connected and self.redis_client:
            try:
                value = await self.redis_client.hget(key, field)
                if value:
                    return json.loads(value)
            except Exception as e:
                logger.error(f"Redis hget error: {e}")
        
        # Fallback to mock cache
        hash_data = self.mock_cache.get(key, {})
        if isinstance(hash_data, dict):
            return hash_data.get(field)
        return None
    
    async def hset(self, key: str, field: str, value: Any) -> bool:
        """Set value in a hash field"""
        serialized_value = json.dumps(value, default=str)
        
        if self.is_connected and self.redis_client:
            try:
                await self.redis_client.hset(key, field, serialized_value)
                return True
            except Exception as e:
                logger.error(f"Redis hset error: {e}")
        
        # Fallback to mock cache
        if key not in self.mock_cache or not isinstance(self.mock_cache[key], dict):
            self.mock_cache[key] = {}
        self.mock_cache[key][field] = value
        return True
    
    async def hgetall(self, key: str) -> Dict[str, Any]:
        """Get all fields and values from a hash"""
        if self.is_connected and self.redis_client:
            try:
                hash_data = await self.redis_client.hgetall(key)
                return {k: json.loads(v) for k, v in hash_data.items()} if hash_data else {}
            except Exception as e:
                logger.error(f"Redis hgetall error: {e}")
        
        # Fallback to mock cache
        hash_data = self.mock_cache.get(key, {})
        return hash_data if isinstance(hash_data, dict) else {}
    
    async def hdel(self, key: str, field: str) -> bool:
        """Delete field from a hash"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.hdel(key, field) > 0
            except Exception as e:
                logger.error(f"Redis hdel error: {e}")
                return False
        
        # Fallback to mock cache
        hash_data = self.mock_cache.get(key, {})
        if isinstance(hash_data, dict) and field in hash_data:
            del hash_data[field]
            return True
        return False
    
    async def lpush(self, key: str, *values: Any) -> int:
        """Push values to the left of a list"""
        serialized_values = [json.dumps(v, default=str) for v in values]
        
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.lpush(key, *serialized_values)
            except Exception as e:
                logger.error(f"Redis lpush error: {e}")
        
        # Fallback to mock cache
        if key not in self.mock_cache:
            self.mock_cache[key] = []
        elif not isinstance(self.mock_cache[key], list):
            self.mock_cache[key] = []
        
        for value in reversed(values):
            self.mock_cache[key].insert(0, value)
        return len(self.mock_cache[key])
    
    async def rpush(self, key: str, *values: Any) -> int:
        """Push values to the right of a list"""
        serialized_values = [json.dumps(v, default=str) for v in values]
        
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.rpush(key, *serialized_values)
            except Exception as e:
                logger.error(f"Redis rpush error: {e}")
        
        # Fallback to mock cache
        if key not in self.mock_cache:
            self.mock_cache[key] = []
        elif not isinstance(self.mock_cache[key], list):
            self.mock_cache[key] = []
        
        self.mock_cache[key].extend(values)
        return len(self.mock_cache[key])
    
    async def lpop(self, key: str) -> Optional[Any]:
        """Pop value from the left of a list"""
        if self.is_connected and self.redis_client:
            try:
                value = await self.redis_client.lpop(key)
                if value:
                    return json.loads(value)
            except Exception as e:
                logger.error(f"Redis lpop error: {e}")
        
        # Fallback to mock cache
        list_data = self.mock_cache.get(key, [])
        if isinstance(list_data, list) and list_data:
            return list_data.pop(0)
        return None
    
    async def rpop(self, key: str) -> Optional[Any]:
        """Pop value from the right of a list"""
        if self.is_connected and self.redis_client:
            try:
                value = await self.redis_client.rpop(key)
                if value:
                    return json.loads(value)
            except Exception as e:
                logger.error(f"Redis rpop error: {e}")
        
        # Fallback to mock cache
        list_data = self.mock_cache.get(key, [])
        if isinstance(list_data, list) and list_data:
            return list_data.pop()
        return None
    
    async def lrange(self, key: str, start: int = 0, end: int = -1) -> List[Any]:
        """Get range of elements from a list"""
        if self.is_connected and self.redis_client:
            try:
                values = await self.redis_client.lrange(key, start, end)
                return [json.loads(v) for v in values] if values else []
            except Exception as e:
                logger.error(f"Redis lrange error: {e}")
        
        # Fallback to mock cache
        list_data = self.mock_cache.get(key, [])
        if isinstance(list_data, list):
            if end == -1:
                return list_data[start:]
            return list_data[start:end+1]
        return []
    
    async def sadd(self, key: str, *members: Any) -> int:
        """Add members to a set"""
        serialized_members = [json.dumps(m, default=str) for m in members]
        
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.sadd(key, *serialized_members)
            except Exception as e:
                logger.error(f"Redis sadd error: {e}")
        
        # Fallback to mock cache
        if key not in self.mock_cache:
            self.mock_cache[key] = set()
        elif not isinstance(self.mock_cache[key], set):
            self.mock_cache[key] = set()
        
        # Convert dict members to JSON strings for hashability
        serializable_members = []
        for member in members:
            if isinstance(member, dict):
                serializable_members.append(json.dumps(member, sort_keys=True))
            else:
                serializable_members.append(member)
        
        initial_count = len(self.mock_cache[key])
        self.mock_cache[key].update(serializable_members)
        return len(self.mock_cache[key]) - initial_count
    
    async def srem(self, key: str, *members: Any) -> int:
        """Remove members from a set"""
        serialized_members = [json.dumps(m, default=str) for m in members]
        
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.srem(key, *serialized_members)
            except Exception as e:
                logger.error(f"Redis srem error: {e}")
        
        # Fallback to mock cache
        set_data = self.mock_cache.get(key, set())
        if isinstance(set_data, set):
            # Convert dict members to JSON strings for comparison
            serializable_members = []
            for member in members:
                if isinstance(member, dict):
                    serializable_members.append(json.dumps(member, sort_keys=True))
                else:
                    serializable_members.append(member)
            
            initial_count = len(set_data)
            set_data.difference_update(serializable_members)
            return initial_count - len(set_data)
        return 0
    
    async def smembers(self, key: str) -> set:
        """Get all members of a set"""
        if self.is_connected and self.redis_client:
            try:
                members = await self.redis_client.smembers(key)
                return {json.loads(m) for m in members} if members else set()
            except Exception as e:
                logger.error(f"Redis smembers error: {e}")
        
        # Fallback to mock cache
        set_data = self.mock_cache.get(key, set())
        if isinstance(set_data, set):
            # Convert JSON strings back to objects for consistency
            result = set()
            for item in set_data:
                try:
                    # Try to parse as JSON first
                    result.add(json.loads(item))
                except (json.JSONDecodeError, TypeError):
                    # If not JSON, keep as is
                    result.add(item)
            return result
        return set()
    
    async def sismember(self, key: str, member: Any) -> bool:
        """Check if member is in a set"""
        serialized_member = json.dumps(member, default=str)
        
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.sismember(key, serialized_member)
            except Exception as e:
                logger.error(f"Redis sismember error: {e}")
        
        # Fallback to mock cache
        set_data = self.mock_cache.get(key, set())
        if isinstance(set_data, set):
            # Convert dict member to JSON for comparison
            if isinstance(member, dict):
                serialized_member = json.dumps(member, sort_keys=True)
            return serialized_member in set_data
        return False
    
    async def acquire_lock(self, key: str, timeout: int = None, wait_time: int = 10) -> bool:
        """Acquire a distributed lock"""
        if timeout is None:
            timeout = self.lock_timeout
        
        if self.is_connected and self.redis_client:
            try:
                lock_key = f"lock:{key}"
                identifier = f"{id(self)}:{datetime.now().timestamp()}"
                end_time = asyncio.get_event_loop().time() + wait_time
                
                while asyncio.get_event_loop().time() < end_time:
                    if await self.redis_client.set(lock_key, identifier, nx=True, ex=timeout):
                        return True
                    await asyncio.sleep(0.1)
                return False
            except Exception as e:
                logger.error(f"Redis acquire_lock error: {e}")
        
        # Fallback to mock cache (simple in-memory lock)
        lock_key = f"lock:{key}"
        if lock_key not in self.mock_cache:
            self.mock_cache[lock_key] = {
                'locked': True,
                'expires': datetime.now() + timedelta(seconds=timeout)
            }
            return True
        return False
    
    async def release_lock(self, key: str) -> bool:
        """Release a distributed lock"""
        if self.is_connected and self.redis_client:
            try:
                lock_key = f"lock:{key}"
                await self.redis_client.delete(lock_key)
                return True
            except Exception as e:
                logger.error(f"Redis release_lock error: {e}")
                return False
        
        # Fallback to mock cache
        lock_key = f"lock:{key}"
        if lock_key in self.mock_cache:
            del self.mock_cache[lock_key]
            return True
        return False
    
    @asynccontextmanager
    async def lock(self, key: str, timeout: int = None, wait_time: int = 10):
        """Context manager for distributed locks"""
        acquired = await self.acquire_lock(key, timeout, wait_time)
        if not acquired:
            raise RuntimeError(f"Could not acquire lock for key: {key}")
        
        try:
            yield
        finally:
            await self.release_lock(key)
    
    async def publish(self, channel: str, message: Any) -> int:
        """Publish message to a channel"""
        serialized_message = json.dumps(message, default=str)
        
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.publish(channel, serialized_message)
            except Exception as e:
                logger.error(f"Redis publish error: {e}")
        
        # Fallback to mock cache (no pub/sub in mock)
        return 0
    
    async def subscribe(self, *channels: str):
        """Subscribe to channels"""
        if self.is_connected and self.redis_client:
            try:
                if not self.pubsub:
                    self.pubsub = self.redis_client.pubsub()
                await self.pubsub.subscribe(*channels)
                return self.pubsub
            except Exception as e:
                logger.error(f"Redis subscribe error: {e}")
        
        # Fallback to mock cache (return mock pubsub)
        return MockPubSub()
    
    async def get_memory_usage(self) -> Dict[str, Any]:
        """Get Redis memory usage information"""
        if self.is_connected and self.redis_client:
            try:
                info = await self.redis_client.info('memory')
                return {
                    'used_memory': info.get('used_memory', 0),
                    'used_memory_human': info.get('used_memory_human', '0B'),
                    'used_memory_rss': info.get('used_memory_rss', 0),
                    'used_memory_peak': info.get('used_memory_peak', 0),
                    'used_memory_peak_human': info.get('used_memory_peak_human', '0B'),
                    'maxmemory': info.get('maxmemory', 0),
                    'maxmemory_human': info.get('maxmemory_human', '0B')
                }
            except Exception as e:
                logger.error(f"Redis get_memory_usage error: {e}")
        
        # Fallback to mock cache
        return {
            'used_memory': 0,
            'used_memory_human': '0B',
            'used_memory_rss': 0,
            'used_memory_peak': 0,
            'used_memory_peak_human': '0B',
            'maxmemory': 0,
            'maxmemory_human': '0B'
        }
    
    # Sorted Set Methods
    
    async def zadd(self, key: str, mapping: Dict[str, float]) -> Optional[int]:
        """Add members with scores to sorted set"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.zadd(key, mapping)
            except Exception as e:
                logger.error(f"Redis zadd error: {e}")
        
        # Fallback to mock cache
        if key not in self.mock_cache:
            self.mock_cache[key] = {}
        
        sorted_set = self.mock_cache[key]
        if not isinstance(sorted_set, dict):
            sorted_set = {}
            self.mock_cache[key] = sorted_set
        
        count = 0
        for member, score in mapping.items():
            if member not in sorted_set or sorted_set[member] != score:
                count += 1
            sorted_set[member] = score
        
        return count
    
    async def zrevrange(self, key: str, start: int = 0, stop: int = -1) -> List[str]:
        """Get members from sorted set in descending order by score"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.zrevrange(key, start, stop)
            except Exception as e:
                logger.error(f"Redis zrevrange error: {e}")
        
        # Fallback to mock cache
        if key not in self.mock_cache:
            return []
        
        sorted_set = self.mock_cache[key]
        if not isinstance(sorted_set, dict):
            return []
        
        # Sort by score descending, then by member for ties
        sorted_members = sorted(sorted_set.items(), key=lambda x: (-x[1], x[0]))
        
        # Handle stop index
        if stop == -1:
            stop = len(sorted_members) - 1
        
        return [member for member, score in sorted_members[start:stop + 1]]
    
    async def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> Optional[int]:
        """Remove members from sorted set by score range"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.zremrangebyscore(key, min_score, max_score)
            except Exception as e:
                logger.error(f"Redis zremrangebyscore error: {e}")
        
        # Fallback to mock cache
        if key not in self.mock_cache:
            return 0
        
        sorted_set = self.mock_cache[key]
        if not isinstance(sorted_set, dict):
            return 0
        
        # Count and remove members within score range
        to_remove = []
        for member, score in sorted_set.items():
            if min_score <= score <= max_score:
                to_remove.append(member)
        
        for member in to_remove:
            del sorted_set[member]
        
        return len(to_remove)
    
    async def zremrangebyrank(self, key: str, start: int, stop: int) -> Optional[int]:
        """Remove members from sorted set by rank range"""
        if self.is_connected and self.redis_client:
            try:
                return await self.redis_client.zremrangebyrank(key, start, stop)
            except Exception as e:
                logger.error(f"Redis zremrangebyrank error: {e}")
        
        # Fallback to mock cache
        if key not in self.mock_cache:
            return 0
        
        sorted_set = self.mock_cache[key]
        if not isinstance(sorted_set, dict):
            return 0
        
        # Sort by score ascending (for rank-based removal)
        sorted_members = sorted(sorted_set.items(), key=lambda x: (x[1], x[0]))
        
        # Handle stop index
        if stop == -1:
            stop = len(sorted_members) - 1
        
        # Get members to remove
        to_remove = []
        for i, (member, score) in enumerate(sorted_members):
            if start <= i <= stop:
                to_remove.append(member)
        
        for member in to_remove:
            del sorted_set[member]
        
        return len(to_remove)

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

class SessionCacheService:
    """Service for caching user sessions"""
    
    @staticmethod
    async def get_session(session_id: str) -> Optional[Dict]:
        """Get session data from cache"""
        key = f"session:{session_id}"
        return await cache.get(key)
    
    @staticmethod
    async def set_session(session_id: str, session_data: Dict, expire_seconds: int = 86400):
        """Set session data in cache"""
        key = f"session:{session_id}"
        await cache.set(key, session_data, expire_seconds)
    
    @staticmethod
    async def invalidate_session(session_id: str):
        """Invalidate session"""
        key = f"session:{session_id}"
        await cache.delete(key)
    
    @staticmethod
    async def get_user_sessions(user_id: str) -> List[str]:
        """Get all active session IDs for a user"""
        key = f"user_sessions:{user_id}"
        return await cache.get(key) or []
    
    @staticmethod
    async def add_user_session(user_id: str, session_id: str):
        """Add session ID to user's active sessions"""
        key = f"user_sessions:{user_id}"
        sessions = await SessionCacheService.get_user_sessions(user_id)
        if session_id not in sessions:
            sessions.append(session_id)
            await cache.set(key, sessions, 86400)
    
    @staticmethod
    async def remove_user_session(user_id: str, session_id: str):
        """Remove session ID from user's active sessions"""
        key = f"user_sessions:{user_id}"
        sessions = await SessionCacheService.get_user_sessions(user_id)
        if session_id in sessions:
            sessions.remove(session_id)
            await cache.set(key, sessions, 86400)

class RateLimitCacheService:
    """Service for rate limiting using Redis"""
    
    @staticmethod
    async def check_rate_limit(identifier: str, limit: int, window_seconds: int) -> Dict[str, Any]:
        """Check if identifier has exceeded rate limit"""
        key = f"rate_limit:{identifier}"
        current_count = await cache.increment(key)
        
        if current_count == 1:
            # First request in window, set expiration
            await cache.expire(key, window_seconds)
        
        ttl = await cache.ttl(key)
        
        return {
            'allowed': current_count <= limit,
            'current_count': current_count,
            'limit': limit,
            'window_seconds': window_seconds,
            'remaining': max(0, limit - current_count),
            'reset_time': ttl if ttl > 0 else window_seconds
        }
    
    @staticmethod
    async def reset_rate_limit(identifier: str):
        """Reset rate limit for identifier"""
        key = f"rate_limit:{identifier}"
        await cache.delete(key)

class MessageCacheService:
    """Service for caching message data (WhatsApp-style: Ephemeral Only)
    
    CRITICAL: All messages stored in Redis with automatic TTL expiry
    Messages older than MESSAGE_TTL_MINUTES are deleted automatically
    User device is source of truth - server data disappearing is ACCEPTABLE
    """
    
    @staticmethod
    async def get_chat_messages(chat_id: str, limit: int = 50) -> List[Dict]:
        """Get cached messages for a chat from sorted set"""
        import json
        
        key = f"chat_messages:{chat_id}"
        # Get newest messages from sorted set (highest scores first)
        messages_data = await cache.zrevrange(key, 0, limit - 1)
        
        # Deserialize JSON messages
        messages = []
        for msg_data in messages_data:
            try:
                messages.append(json.loads(msg_data))
            except (json.JSONDecodeError, TypeError):
                # Skip invalid messages
                continue
        
        return messages
    
    @staticmethod
    async def add_chat_message(chat_id: str, message: Dict, max_messages: int = 1000):
        """Add message to chat cache with WhatsApp-style TTL using sorted set
        
        MANDATORY: Every message expires automatically
        TTL: MESSAGE_TTL_MINUTES (default 60 minutes)
        Behavior: Undelivered messages = lost when TTL expires (acceptable)
        Uses sorted set for per-message TTL and max_messages enforcement
        """
        import json
        import time
        from config import settings
        
        key = f"chat_messages:{chat_id}"
        ttl_seconds = settings.MESSAGE_TTL_SECONDS
        now = int(time.time())
        
        # Serialize message for Redis storage
        json_message = json.dumps(message)
        
        # Add message to Redis sorted set with current time as score
        await cache.zadd(key, {json_message: now})
        
        # Remove expired messages (older than TTL)
        await cache.zremrangebyscore(key, 0, now - ttl_seconds)
        
        # Enforce max_messages by keeping only the newest messages
        await cache.zremrangebyrank(key, 0, -max_messages - 1)
        
        # Log for debugging (optional)
        logger.debug(f"Message stored in {key} (sorted set) with per-message TTL {ttl_seconds}s, max_messages={max_messages}")
    
    @staticmethod
    async def clear_chat_messages(chat_id: str):
        """Clear cached messages for a chat"""
        key = f"chat_messages:{chat_id}"
        await cache.delete(key)

class FileCacheService:
    """Service for caching file metadata"""
    
    @staticmethod
    async def get_file_metadata(file_id: str) -> Optional[Dict]:
        """Get file metadata from cache"""
        key = f"file:metadata:{file_id}"
        return await cache.get(key)
    
    @staticmethod
    async def set_file_metadata(file_id: str, metadata: Dict, expire_seconds: int = 3600):
        """Set file metadata in cache"""
        key = f"file:metadata:{file_id}"
        await cache.set(key, metadata, expire_seconds)
    
    @staticmethod
    async def get_upload_progress(upload_id: str) -> Optional[Dict]:
        """Get upload progress from cache"""
        key = f"upload:progress:{upload_id}"
        return await cache.get(key)
    
    @staticmethod
    async def set_upload_progress(upload_id: str, progress: Dict, expire_seconds: int = 1800):
        """Set upload progress in cache"""
        key = f"upload:progress:{upload_id}"
        await cache.set(key, progress, expire_seconds)
    
    @staticmethod
    async def invalidate_file_cache(file_id: str):
        """Invalidate file-related cache entries"""
        await cache.delete(f"file:metadata:{file_id}")

class AnalyticsCacheService:
    """Service for caching analytics data"""
    
    @staticmethod
    async def increment_user_activity(user_id: str, activity_type: str):
        """Increment user activity counter"""
        key = f"analytics:activity:{user_id}:{activity_type}"
        await cache.increment(key)
        await cache.expire(key, 86400)  # 24 hours
    
    @staticmethod
    async def get_user_activity(user_id: str, activity_type: str) -> int:
        """Get user activity count"""
        key = f"analytics:activity:{user_id}:{activity_type}"
        count = await cache.get(key)
        return count if isinstance(count, int) else 0
    
    @staticmethod
    async def cache_analytics_report(report_name: str, data: Dict, expire_seconds: int = 3600):
        """Cache analytics report"""
        key = f"analytics:report:{report_name}"
        await cache.set(key, data, expire_seconds)
    
    @staticmethod
    async def get_analytics_report(report_name: str) -> Optional[Dict]:
        """Get cached analytics report"""
        key = f"analytics:report:{report_name}"
        return await cache.get(key)

class CacheUtils:
    """Utility functions for cache operations"""
    
    @staticmethod
    def generate_cache_key(*parts: str) -> str:
        """Generate a consistent cache key from parts"""
        return ":".join(str(part) for part in parts)
    
    @staticmethod
    def hash_key(key: str) -> str:
        """Generate a hash of a key for long keys"""
        return hashlib.md5(key.encode()).hexdigest()
    
    @staticmethod
    async def cache_with_fallback(
        cache_key: str,
        fallback_func: Callable,
        expire_seconds: int = 3600,
        *args,
        **kwargs
    ) -> Any:
        """Get value from cache or fallback function"""
        # Try cache first
        cached_value = await cache.get(cache_key)
        if cached_value is not None:
            return cached_value
        
        # Execute fallback function
        try:
            if asyncio.iscoroutinefunction(fallback_func):
                value = await fallback_func(*args, **kwargs)
            else:
                value = fallback_func(*args, **kwargs)
            
            # Cache the result
            await cache.set(cache_key, value, expire_seconds)
            return value
        except Exception as e:
            logger.error(f"Cache fallback error for key {cache_key}: {e}")
            raise
    
    @staticmethod
    async def invalidate_related_cache(user_id: str = None, group_id: str = None, chat_id: str = None):
        """Invalidate cache entries related to user, group, or chat"""
        patterns = []
        
        if user_id:
            patterns.extend([
                f"user:profile:{user_id}",
                f"user:contacts:{user_id}",
                f"contacts:suggestions:{user_id}",
                f"user_sessions:{user_id}",
                f"analytics:activity:{user_id}:*"
            ])
        
        if group_id:
            patterns.extend([
                f"group:members:{group_id}",
                f"group:info:{group_id}"
            ])
        
        if chat_id:
            patterns.extend([
                f"chat_messages:{chat_id}"
            ])
        
        for pattern in patterns:
            if "*" in pattern:
                await cache.clear_pattern(pattern)
            else:
                await cache.delete(pattern)
    
    @staticmethod
    async def get_cache_stats() -> Dict[str, Any]:
        """Get cache statistics"""
        stats = {
            'redis_connected': cache.is_connected,
            'mock_cache_size': len(cache.mock_cache),
            'memory_usage': await cache.get_memory_usage()
        }
        
        if cache.is_connected:
            try:
                info = await cache.redis_client.info()
                stats.update({
                    'total_commands_processed': info.get('total_commands_processed', 0),
                    'total_connections_received': info.get('total_connections_received', 0),
                    'keyspace_hits': info.get('keyspace_hits', 0),
                    'keyspace_misses': info.get('keyspace_misses', 0),
                    'connected_clients': info.get('connected_clients', 0),
                    'uptime_in_seconds': info.get('uptime_in_seconds', 0)
                })
                
                # Calculate hit rate
                hits = stats['keyspace_hits']
                misses = stats['keyspace_misses']
                total = hits + misses
                stats['hit_rate'] = (hits / total * 100) if total > 0 else 0
            except Exception as e:
                logger.error(f"Error getting Redis stats: {e}")
        
        return stats

async def init_cache():
    """Initialize Redis cache connection"""
    from config import settings
    
    # Try to connect to Redis
    redis_host = getattr(settings, 'REDIS_HOST', 'zaply.in.net')
    redis_port = getattr(settings, 'REDIS_PORT', 6379)
    redis_password = getattr(settings, 'REDIS_PASSWORD', None)
    redis_db = getattr(settings, 'REDIS_DB', 0)
    
    connected = await cache.connect(
        host=redis_host,
        port=redis_port,
        password=redis_password if redis_password else None,
        db=redis_db
    )
    
    if connected:
        logger.info("Redis cache initialized successfully")
    else:
        # Only show warning in debug mode or when explicitly requested
        import os
        if os.getenv('DEBUG', '').lower() in ('true', '1', 'yes') or os.getenv('REDIS_DEBUG', '').lower() in ('true', '1', 'yes'):
            logger.warning("Redis cache not available, using in-memory fallback")
    
    return connected

async def cleanup_cache():
    """Cleanup cache connection"""
    await cache.disconnect()


class MessageQueueService:
    """
    WhatsApp-style ephemeral message queue service.
    Messages are stored in Redis with TTL only.
    No persistence - messages disappear on restart.
    """
    
    @staticmethod
    async def enqueue_message(message_data: dict, ttl_minutes: int = 60):
        """
        Enqueue message with automatic TTL expiration.
        WhatsApp behavior: Messages auto-delete after TTL.
        """
        key = f"message_queue:{message_data.get('chat_id')}"
        message_id = message_data.get('id')
        message_key = f"message:{message_id}"
        
        # Store full message temporarily (for delivery)
        await cache.set(message_key, message_data, expire_seconds=ttl_minutes * 60)
        
        # Add to queue for immediate delivery
        await cache.lpush(key, message_id)
        
        # Set queue TTL to match message TTL
        await cache.expire(key, ttl_minutes * 60)
        
        # Publish for real-time delivery
        await cache.publish(f"chat:{message_data.get('chat_id')}", {
            'type': 'new_message',
            'message_id': message_id,
            'chat_id': message_data.get('chat_id'),
            'sender_id': message_data.get('sender_id')
        })
    
    @staticmethod
    async def dequeue_message(chat_id: str):
        """
        Dequeue message for delivery.
        Returns message data or None if queue is empty.
        """
        key = f"message_queue:{chat_id}"
        
        # Get next message ID from queue
        message_id = await cache.lpop(key)
        if not message_id:
            return None
        
        # Get full message data
        message_key = f"message:{message_id}"
        message_data = await cache.get(message_key)
        
        return message_data
    
    @staticmethod
    async def get_pending_messages(chat_id: str, limit: int = 50):
        """
        Get all pending messages for a chat.
        Used when user comes online.
        """
        key = f"message_queue:{chat_id}"
        
        # Get all message IDs from queue
        message_ids = await cache.lrange(key, 0, limit - 1)
        if not message_ids:
            return []
        
        # Get full message data for each ID
        messages = []
        for message_id in message_ids:
            message_key = f"message:{message_id}"
            message_data = await cache.get(message_key)
            if message_data:
                messages.append(message_data)
        
        return messages
    
    @staticmethod
    async def acknowledge_message(message_id: str):
        """
        Acknowledge message delivery and delete from Redis.
        WhatsApp behavior: Delete immediately after ACK.
        """
        message_key = f"message:{message_id}"
        await cache.delete(message_key)


class EphemeralFileService:
    """
    WhatsApp-style ephemeral file metadata service.
    Files are stored in S3 with 24h TTL, metadata in Redis with TTL.
    """
    
    @staticmethod
    async def store_file_metadata(file_data: dict, ttl_hours: int = 24):
        """
        Store file metadata with TTL.
        Actual file stored in S3 with lifecycle rules.
        """
        file_id = file_data.get('id')
        file_key = f"file_metadata:{file_id}"
        
        # Store metadata with TTL
        await cache.set(file_key, file_data, expire_seconds=ttl_hours * 3600)
        
        # Add to user's active files list
        user_id = file_data.get('owner_id')
        user_files_key = f"user_files:{user_id}"
        await cache.sadd(user_files_key, file_id)
        await cache.expire(user_files_key, ttl_hours * 3600)
    
    @staticmethod
    async def get_file_metadata(file_id: str) -> Optional[dict]:
        """
        Get file metadata if not expired.
        """
        file_key = f"file_metadata:{file_id}"
        return await cache.get(file_key)
    
    @staticmethod
    async def acknowledge_file(file_id: str):
        """
        Acknowledge file download and delete metadata.
        WhatsApp behavior: Delete metadata immediately after receiver ACK.
        S3 file will be deleted by lifecycle rules or immediate delete.
        """
        file_key = f"file_metadata:{file_id}"
        file_data = await cache.get(file_key)
        
        if file_data:
            # Remove from user's active files
            user_id = file_data.get('owner_id')
            user_files_key = f"user_files:{user_id}"
            await cache.srem(user_files_key, file_id)
            
            # Delete metadata
            await cache.delete(file_key)
            
            # Trigger S3 deletion (if immediate delete is enabled)
            return file_data
        
        return None


class WhatsAppSessionService:
    """
    WhatsApp-style multi-device session service.
    Sessions are ephemeral, no chat history sync.
    """
    
    @staticmethod
    async def create_session(user_id: str, device_info: dict, ttl_days: int = 30):
        """
        Create ephemeral session for device.
        No chat history sync - device must fetch fresh.
        """
        session_id = f"session:{user_id}:{device_info.get('device_id', 'unknown')}"
        session_data = {
            'user_id': user_id,
            'device_info': device_info,
            'created_at': datetime.utcnow().isoformat(),
            'last_active': datetime.utcnow().isoformat(),
            'has_history': False  # WhatsApp: No history sync
        }
        
        # Store session with TTL
        await cache.set(session_id, session_data, expire_seconds=ttl_days * 86400)
        
        # Add to user's active sessions
        user_sessions_key = f"user_sessions:{user_id}"
        await cache.sadd(user_sessions_key, session_id)
        await cache.expire(user_sessions_key, ttl_days * 86400)
        
        return session_id
    
    @staticmethod
    async def get_session(session_id: str) -> Optional[dict]:
        """
        Get session data if not expired.
        """
        return await cache.get(session_id)
    
    @staticmethod
    async def update_session_activity(session_id: str):
        """
        Update session last activity time.
        """
        session_data = await cache.get(session_id)
        if session_data:
            session_data['last_active'] = datetime.utcnow().isoformat()
            await cache.set(session_id, session_data)
    
    @staticmethod
    async def revoke_session(session_id: str):
        """
        Revoke session immediately.
        """
        session_data = await cache.get(session_id)
        if session_data:
            user_id = session_data.get('user_id')
            user_sessions_key = f"user_sessions:{user_id}"
            await cache.srem(user_sessions_key, session_id)
            await cache.delete(session_id)


# Add new services to the existing cache module
cache.MessageQueueService = MessageQueueService
cache.EphemeralFileService = EphemeralFileService
cache.WhatsAppSessionService = WhatsAppSessionService

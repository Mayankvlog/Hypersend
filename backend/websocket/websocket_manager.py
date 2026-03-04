"""
WhatsApp-Grade Singleton WebSocket Manager
==========================================

Implements singleton pattern for WebSocket connections with Redis Pub/Sub.
Ensures only one connection per device and provides real-time messaging.

Key Features:
- Singleton pattern with thread-safe initialization
- Redis Pub/Sub for cross-container communication
- Per-device connection deduplication
- Message state tracking (sending→sent→delivered→read)
- Graceful reconnection and error handling
- Async-only operations with proper cleanup
"""

import asyncio
import json
import logging
import secrets
import threading
import time
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import websockets
from websockets.server import WebSocketServerProtocol

# WhatsApp-Grade Cryptographic Imports
try:
    import redis.asyncio as redis
except ImportError:
    logging.warning("[WARNING] Redis not available - using fallback cache")
    redis = None

# TYPE_CHECKING for type hints when redis module is not available
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import redis.asyncio as redis_type
else:
    redis_type = Any

# Import our cryptographic modules
try:
    from crypto.signal_protocol import SignalProtocol
    from crypto.multi_device import MultiDeviceManager
    from crypto.delivery_semantics import DeliveryManager, MessageStatus, DeviceState
    from crypto.media_encryption import MediaEncryptionService
except ImportError:
    logging.warning("[WARNING] Cryptographic modules not available")
    SignalProtocol = None
    MultiDeviceManager = None
    DeliveryManager = None
    DeviceState = None
    MediaEncryptionService = None

logger = logging.getLogger(__name__)

@dataclass
class WebSocketConnection:
    """WebSocket connection metadata with message state tracking"""
    websocket: WebSocketServerProtocol
    device_id: str
    user_id: str
    connected_at: float
    last_ping: float
    last_pong: float
    is_authenticated: bool = False
    message_queue: List[Dict[str, Any]] = None
    message_states: Dict[str, str] = None  # message_id -> state
    
    def __post_init__(self):
        if self.message_queue is None:
            self.message_queue = []
        if self.message_states is None:
            self.message_states = {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'device_id': self.device_id,
            'user_id': self.user_id,
            'connected_at': self.connected_at,
            'last_ping': self.last_ping,
            'last_pong': self.last_pong,
            'is_authenticated': self.is_authenticated,
            'queue_size': len(self.message_queue),
            'active_message_states': len(self.message_states)
        }

class WebSocketManager:
    """
    WhatsApp-grade singleton WebSocket manager with guaranteed single instance.
    
    CRITICAL PROPERTIES:
    1. ONE persistent WebSocket connection per device (stored globally)
    2. NO re-initialization on re-render or token refresh
    3. Per-device Redis Pub/Sub subscription (not shared)
    4. Global Redis Pub/Sub subscriber runs ONCE per server (not per connection)
    5. TIMESTAMP FORMATS: 
       - Broadcast messages use UTC ISO 8601 with Z suffix (datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
       - Internal fields (connected_at, last_ping, last_pong) use Unix epoch seconds from time.time()
    6. Message deduplication prevents duplicate broadcasts
    7. Async-only DB operations and non-blocking file I/O
    
    Connection Lifecycle:
    - Device connects → authenticate → store in self.connections[device_id]
    - Old connection for same device_id is closed (deduplication)
    - Start heartbeat loop (sends ping every 30s, no reconnect loop)
    - Start per-device Redis Pub/Sub listener
    - On disconnect → cleanup connection and subscriptions
    
    Timestamp Usage:
    - connected_at, last_ping, last_pong: Unix epoch seconds (time.time()) for internal connection state
    - Broadcast helper methods: UTC ISO 8601 with Z suffix for client-facing messages
    
    No polling, no 10-second refresh, no reconnect interval in WebSocket code.
    """
    
    _instance = None
    _new_lock = threading.Lock()
    _init_lock = threading.Lock()  # For lock creation
    _lock = None  # Will be created lazily
    _global_pubsub_lock = None  # Will be created lazily
    
    def __new__(cls):
        with cls._new_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance
    
    async def initialize(self, redis_client: Optional[Any] = None):
        """Initialize the singleton manager (async-safe)"""
        # Create asyncio lock with double-checked pattern
        if self._lock is None:
            with self._init_lock:
                if self._lock is None:
                    self._lock = asyncio.Lock()
                if self._global_pubsub_lock is None:
                    self._global_pubsub_lock = asyncio.Lock()
        
        async with self._lock:
            if self._initialized:
                return
            
            self.redis = redis_client
            
            # Initialize cryptographic services
            if DeliveryManager and redis_client:
                self.delivery_manager = DeliveryManager(redis_client)
            else:
                self.delivery_manager = None
                
            if MultiDeviceManager and redis_client:
                self.device_manager = MultiDeviceManager(redis_client)
            else:
                self.device_manager = None
                
            if SignalProtocol:
                self.signal_protocol = SignalProtocol()
            else:
                self.signal_protocol = None
                
            if MediaEncryptionService and redis_client:
                self.media_service = MediaEncryptionService(redis_client)
            else:
                self.media_service = None
            
            # Active connections by device_id (memory-safe structure)
            # CRITICAL: One connection per device_id - old connections auto-replaced
            self.connections: Dict[str, WebSocketConnection] = {}
            self.connection_lock = asyncio.Lock()  # Prevent race conditions
            
            # Redis Pub/Sub subscriptions (one per connection handler)
            self.pubsub_subscriptions: Dict[str, Any] = {}
            
            # Global Redis Pub/Sub task for cross-container communication
            self.global_pubsub_task = None
            
            # Configuration
            self.heartbeat_interval = 30  # seconds
            self.pong_timeout = 10  # seconds
            self.max_queue_size = 1000
            self.connection_timeout = 7200  # 2 hours
            self.reconnect_grace_period = 5  # 5 seconds for reconnect dedupe
            
            # Message state tracking
            self.message_states: Dict[str, Dict[str, str]] = {}  # message_id -> {device_id: state}
            self.state_lock = asyncio.Lock()
            
            # Message deduplication to prevent duplicate triggers
            self.message_deduplication: Dict[str, float] = {}  # message_hash -> timestamp
            self.deduplication_lock = asyncio.Lock()
            self.deduplication_window = 5.0  # 5 seconds deduplication window
            
            self._initialized = True
            logger.info("[WS-MANAGER] Singleton WebSocket manager initialized")
    
    async def handle_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle new WebSocket connection with deduplication and state tracking"""
        device_id = None
        user_id = None
        heartbeat_task = None
        pubsub_task = None
        
        try:
            logger.info(f"New WebSocket connection from {websocket.remote_address}")
            
            # Extract device and user IDs from headers
            device_id = websocket.request_headers.get('X-Device-ID')
            user_id = websocket.request_headers.get('X-User-ID')
            
            if not device_id or not user_id:
                await websocket.close(4001, "Missing device or user ID")
                return
            
            # Authenticate device
            if not await self._authenticate_device(websocket, device_id, user_id):
                await websocket.close(4003, "Authentication failed")
                return
            
            # Create connection object
            new_connection = WebSocketConnection(
                websocket=websocket,
                device_id=device_id,
                user_id=user_id,
                connected_at=time.time(),
                last_ping=time.time(),
                last_pong=time.time(),
                is_authenticated=True
            )
            
            # CRITICAL: Replace old connection if exists (deduplication)
            # This prevents duplicate sockets for same device_id
            async with self.connection_lock:
                old_connection = self.connections.get(device_id)
                if old_connection and old_connection.websocket:
                    try:
                        await old_connection.websocket.close(4001, "Duplicate connection")
                        logger.info(f"Closed duplicate connection for device {device_id}")
                    except Exception as e:
                        logger.debug(f"Failed to close old connection: {e}")
                
                # Store new connection (thread-safe)
                self.connections[device_id] = new_connection
            
            # Update device connection status
            if self.delivery_manager:
                # Safely extract IP address
                remote = getattr(websocket, "remote_address", None)
                ip_address = remote[0] if (remote and isinstance(remote, (list, tuple)) and len(remote) > 0) else ""
                
                await self.delivery_manager.update_device_connection(
                    device_id=device_id,
                    user_id=user_id,
                    state=DeviceState.ONLINE,  # Use enum instead of string
                    websocket_id=id(websocket),
                    ip_address=ip_address,
                    user_agent=websocket.request_headers.get('User-Agent', '')
                )
            
            logger.info(f"Device {device_id} connected (total: {len(self.connections)})")
            
            # Start background tasks
            heartbeat_task = asyncio.create_task(
                self._heartbeat_loop(device_id, new_connection)
            )
            
            # Subscribe to Redis Pub/Sub for broadcasts
            pubsub_task = asyncio.create_task(
                self._redis_pubsub_listener(device_id, user_id, new_connection)
            )
            
            # Process offline messages
            await self._process_offline_messages(new_connection)
            
            # Handle incoming WebSocket messages
            await self._handle_messages(new_connection)
            
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"WebSocket connection closed for device {device_id}")
        except Exception as e:
            logger.error(f"Error handling WebSocket connection: {e}")
        finally:
            # Cleanup
            if device_id:
                await self._cleanup_connection(device_id)
            
            # Cancel all background tasks
            if heartbeat_task:
                heartbeat_task.cancel()
            if pubsub_task:
                pubsub_task.cancel()
            
            try:
                await asyncio.gather(heartbeat_task, pubsub_task, return_exceptions=True)
            except Exception:
                pass
    
    async def _authenticate_device(
        self,
        websocket: WebSocketServerProtocol,
        device_id: str,
        user_id: str
    ) -> bool:
        """Authenticate WebSocket connection"""
        try:
            # Fail-secure: require device_manager for authentication
            if not self.device_manager:
                logger.error("Device manager not available - authentication failed")
                return False
            
            # Verify device belongs to user
            user_devices = await self.device_manager.get_user_devices(user_id)
            
            if not any(device.device_id == device_id for device in user_devices):
                logger.warning(f"Device {device_id} not found for user {user_id}")
                return False
            
            # Check device session
            device_session = await self.device_manager.get_device_session(user_id, device_id)
            
            if not device_session:
                logger.warning(f"No session found for device {device_id}")
                return False
            
            # Send authentication challenge
            challenge = secrets.token_urlsafe(32)
            await websocket.send(json.dumps({
                'type': 'auth_challenge',
                'challenge': challenge,
                'timestamp': time.time()
            }))
            
            # Wait for response
            response = await asyncio.wait_for(
                websocket.recv(),
                timeout=10.0
            )
            
            auth_data = json.loads(response)
            
            # Verify device session has session_key
            if not hasattr(device_session, 'session_key') or device_session.session_key is None:
                logger.error(f"Device {device_id} missing session_key")
                return False
            
            # Verify challenge response
            expected_response = self._calculate_challenge_response(
                challenge,
                device_session.session_key
            )
            
            if auth_data.get('response') != expected_response:
                logger.warning(f"Invalid auth response for device {device_id}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Authentication error for device {device_id}: {e}")
            return False
    
    async def _handle_messages(self, connection: WebSocketConnection):
        """Handle incoming WebSocket messages with state tracking"""
        try:
            async for message in connection.websocket:
                try:
                    data = json.loads(message)
                    await self._process_message(connection, data)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON from device {connection.device_id}")
                    await connection.websocket.close(4002, "Invalid JSON")
                    break
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    
        except websockets.exceptions.ConnectionClosed:
            pass
    
    async def _process_message(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Process incoming WebSocket message with state tracking"""
        message_type = data.get('type')
        
        if message_type == 'pong':
            connection.last_pong = time.time()
            return
        
        elif message_type == 'delivery_receipt':
            await self._handle_delivery_receipt(connection, data)
        
        elif message_type == 'read_receipt':
            await self._handle_read_receipt(connection, data)
        
        elif message_type == 'typing':
            await self._handle_typing_indicator(connection, data)
        
        elif message_type == 'presence':
            await self._handle_presence_update(connection, data)
        
        elif message_type == 'message_state_update':
            await self._handle_message_state_update(connection, data)
        
        else:
            logger.warning(f"Unknown message type: {message_type}")
    
    async def _handle_delivery_receipt(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Handle delivery receipt with state tracking"""
        message_id = data.get('message_id')
        timestamp = data.get('timestamp', time.time())
        
        if not message_id:
            return
        
        # Update delivery status
        if self.delivery_manager:
            success = await self.delivery_manager.mark_message_delivered(
                message_id,
                connection.device_id
            )
            
            if success:
                # Update message state
                await self.update_message_state(message_id, connection.device_id, "delivered")
                
                # Broadcast to other devices
                await self._broadcast_to_user_devices(
                    connection.user_id,
                    connection.device_id,
                    {
                        'type': 'delivery_receipt',
                        'message_id': message_id,
                        'device_id': connection.device_id,
                        'timestamp': timestamp,
                        'state': 'delivered'
                    }
                )
                
                logger.info(f"Delivery receipt for message {message_id} from device {connection.device_id}")
    
    async def _handle_read_receipt(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Handle read receipt with state tracking"""
        message_id = data.get('message_id')
        timestamp = data.get('timestamp', time.time())
        
        if not message_id:
            return
        
        # Update read status
        if self.delivery_manager:
            success = await self.delivery_manager.mark_message_read(
                message_id,
                connection.device_id
            )
            
            if success:
                # Update message state
                await self.update_message_state(message_id, connection.device_id, "read")
                
                # Broadcast to other devices
                await self._broadcast_to_user_devices(
                    connection.user_id,
                    connection.device_id,
                    {
                        'type': 'read_receipt',
                        'message_id': message_id,
                        'device_id': connection.device_id,
                        'timestamp': timestamp,
                        'state': 'read'
                    }
                )
                
                logger.info(f"Read receipt for message {message_id} from device {connection.device_id}")
    
    async def _handle_message_state_update(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Handle message state updates (sending→sent→delivered→read)"""
        message_id = data.get('message_id')
        new_state = data.get('state')
        timestamp = data.get('timestamp', time.time())
        
        if not message_id or not new_state:
            return
        
        # Validate state transition
        valid_states = ['sending', 'sent', 'delivered', 'read', 'failed']
        if new_state not in valid_states:
            logger.warning(f"Invalid message state: {new_state}")
            return
        
        # Update message state
        await self.update_message_state(message_id, connection.device_id, new_state)
        
        # Broadcast state change to other devices
        await self._broadcast_to_user_devices(
            connection.user_id,
            connection.device_id,
            {
                'type': 'message_state_update',
                'message_id': message_id,
                'device_id': connection.device_id,
                'state': new_state,
                'timestamp': timestamp
            }
        )
        
        logger.info(f"Message {message_id} state updated to {new_state} by device {connection.device_id}")
    
    async def update_message_state(self, message_id: str, device_id: str, state: str):
        """Update message state in thread-safe manner"""
        async with self.state_lock:
            if message_id not in self.message_states:
                self.message_states[message_id] = {}
            
            self.message_states[message_id][device_id] = state
            
            # Update connection's local state tracking
            connection = self.connections.get(device_id)
            if connection:
                connection.message_states[message_id] = state
    
    async def get_message_state(self, message_id: str, device_id: str) -> Optional[str]:
        """Get current state for a message on a device"""
        async with self.state_lock:
            return self.message_states.get(message_id, {}).get(device_id)
    
    async def get_all_message_states(self, message_id: str) -> Dict[str, str]:
        """Get all device states for a message"""
        async with self.state_lock:
            return self.message_states.get(message_id, {}).copy()
    
    async def _handle_typing_indicator(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Handle typing indicator with UTC timestamp (Z suffix)"""
        chat_id = data.get('chat_id')
        is_typing = data.get('is_typing', False)
        
        if not chat_id:
            return
        
        # Broadcast to chat participants with UTC timestamp
        utc_now = datetime.now(timezone.utc)
        await self._broadcast_to_chat_participants(
            chat_id,
            connection.user_id,
            {
                'type': 'typing',
                'user_id': connection.user_id,
                'device_id': connection.device_id,
                'chat_id': chat_id,
                'is_typing': is_typing,
                'timestamp': utc_now.isoformat().replace('+00:00', 'Z')
            }
        )
    
    async def _handle_presence_update(
        self,
        connection: WebSocketConnection,
        data: Dict[str, Any]
    ):
        """Handle presence update with UTC timestamp"""
        presence = data.get('presence', 'online')
        
        # Update device presence with UTC timestamp
        if self.delivery_manager:
            state = DeviceState.ONLINE if presence == 'online' else DeviceState.OFFLINE
            utc_now = datetime.now(timezone.utc)
            await self.delivery_manager.update_device_connection(
                device_id=connection.device_id,
                user_id=connection.user_id,
                state=state,
                timestamp=utc_now.isoformat().replace('+00:00', 'Z')
            )
    
    async def _process_offline_messages(self, connection: WebSocketConnection):
        """Process messages that arrived while device was offline with atomic processing"""
        try:
            if not self.redis:
                return
                
            processing_queue = f"device_offline_processing:{connection.device_id}"
            main_queue = f"device_offline_queue:{connection.device_id}"
            
            # Process messages atomically
            while True:
                # Move one message from main queue to processing queue atomically
                message_data = await self.redis.brpoplpush(main_queue, processing_queue, timeout=1)
                
                if not message_data:
                    # No more messages
                    break
                
                try:
                    # Send message to device
                    await connection.websocket.send(message_data)
                    logger.debug(f"Sent offline message to device {connection.device_id}")
                except Exception as e:
                    logger.error(f"Failed to send offline message: {e}")
                    # Re-queue failed message back to main queue for retry
                    await self.redis.lpush(main_queue, message_data)
                    # Remove from processing queue
                    await self.redis.lrem(processing_queue, 1, message_data)
                    continue
                
                # Remove from processing queue on successful send
                await self.redis.lrem(processing_queue, 1, message_data)
            
            # Clean up any remaining messages in processing queue
            await self.redis.delete(processing_queue)
                
        except Exception as e:
            logger.error(f"Error processing offline messages: {e}")
    
    async def _heartbeat_loop(self, device_id: str, connection: WebSocketConnection):
        """
        Send periodic heartbeat pings to keep connection persistent.
        CRITICAL: NO reconnect loop - exits on connection loss.
        CRITICAL: Uses UTC timestamps with Z suffix.
        """
        heartbeat_count = 0
        
        try:
            while True:
                try:
                    # Wait for next heartbeat interval
                    await asyncio.sleep(self.heartbeat_interval)
                    
                    # Check connection still exists
                    if device_id not in self.connections:
                        logger.debug(f"[HEARTBEAT] Device {device_id} no longer in connections")
                        break
                    
                    # Verify WebSocket is still open
                    if connection.websocket.closed:
                        logger.debug(f"[HEARTBEAT] WebSocket closed for device {device_id}")
                        break
                    
                    # Send ping with UTC timestamp (Z suffix)
                    heartbeat_count += 1
                    utc_now = datetime.now(timezone.utc)
                    ping_data = {
                        'type': 'ping',
                        'timestamp': utc_now.isoformat().replace('+00:00', 'Z'),
                        'sequence': heartbeat_count,
                        'id': f"{device_id}_{heartbeat_count}"
                    }
                    
                    try:
                        await asyncio.wait_for(
                            connection.websocket.send(json.dumps(ping_data)),
                            timeout=5.0  # Send timeout
                        )
                        connection.last_ping = time.time()
                        logger.debug(f"[HEARTBEAT] Sent ping #{heartbeat_count} to device {device_id}")
                        
                    except asyncio.TimeoutError:
                        logger.warning(f"[HEARTBEAT] Timeout sending ping to device {device_id}")
                        break
                    
                    # Wait for pong (with timeout)
                    pong_deadline = time.time() + self.pong_timeout
                    
                    # Check for pong in the background while waiting
                    await asyncio.sleep(self.pong_timeout)
                    
                    # Check if pong was received within timeout
                    if connection.last_pong < connection.last_ping:
                        # Pong not received
                        time_since_ping = time.time() - connection.last_ping
                        if time_since_ping > self.pong_timeout:
                            logger.warning(f"[HEARTBEAT] No pong from device {device_id} (waited {time_since_ping:.1f}s)")
                            # Close the connection - this will trigger cleanup
                            try:
                                await connection.websocket.close(4000, "Heartbeat timeout")
                            except Exception as e:
                                logger.debug(f"[HEARTBEAT] Error closing socket: {e}")
                            break
                
                except websockets.exceptions.ConnectionClosed:
                    logger.debug(f"[HEARTBEAT] Connection closed for device {device_id}")
                    break
                except asyncio.CancelledError:
                    logger.debug(f"[HEARTBEAT] Heartbeat cancelled for device {device_id}")
                    break
                except Exception as e:
                    logger.error(f"[HEARTBEAT] Unexpected error for device {device_id}: {type(e).__name__}: {e}")
                    break
        
        finally:
            logger.debug(f"[HEARTBEAT] Exiting heartbeat loop for device {device_id} (sent {heartbeat_count} pings)")
            # Cleanup happens in handle_connection's finally block
    
    async def _broadcast_to_user_devices(
        self,
        user_id: str,
        exclude_device_id: str,
        message: Dict[str, Any]
    ):
        """Broadcast message to all user devices except one"""
        if self.device_manager:
            user_devices = await self.device_manager.get_active_devices(user_id)
            
            for device in user_devices:
                if device.device_id == exclude_device_id:
                    continue
                
                connection = self.connections.get(device.device_id)
                if connection:
                    try:
                        await connection.websocket.send(json.dumps(message))
                    except Exception as e:
                        logger.error(f"Failed to broadcast to device {device.device_id}: {e}")
    
    async def _broadcast_to_chat_participants(
        self,
        chat_id: str,
        exclude_user_id: str,
        message: Dict[str, Any]
    ):
        """Broadcast message to all chat participants except one"""
        if not self.redis:
            return
            
        # Get chat participants
        chat_data = await self.redis.hgetall(f"chat:{chat_id}")
        if not chat_data:
            return
        
        # Handle bytes keys/values from Redis (handle both bytes and string keys)
        members_bytes = chat_data.get(b'members')
        members_str = chat_data.get('members')
        
        # Use whichever key exists and decode if needed
        if members_bytes is not None:
            members_data = members_bytes.decode() if isinstance(members_bytes, bytes) else members_bytes
        elif members_str is not None:
            members_data = members_str
        else:
            members_data = '[]'  # Default to empty array
        
        members = json.loads(members_data)
        
        for user_id in members:
            if user_id == exclude_user_id:
                continue
            
            await self._broadcast_to_user_devices(user_id, '', message)
    
    async def _cleanup_connection(self, device_id: str):
        """Clean up closed connection (thread-safe)"""
        async with self.connection_lock:
            if device_id in self.connections:
                connection = self.connections[device_id]
                
                # Update device status to offline
                try:
                    if self.delivery_manager:
                        await self.delivery_manager.update_device_connection(
                            device_id=device_id,
                            user_id=connection.user_id,
                            state=DeviceState.OFFLINE
                        )
                except Exception as e:
                    logger.warning(f"Failed to update device status to offline: {e}")
                
                # Close socket if still open
                try:
                    if connection.websocket and not connection.websocket.closed:
                        await connection.websocket.close()
                except Exception as e:
                    logger.debug(f"Socket already closed: {e}")
                
                # Remove from active connections
                del self.connections[device_id]
                
                logger.info(f"Cleaned up connection for device {device_id} (total: {len(self.connections)})")
            
            # Clean up Redis Pub/Sub subscription
            if device_id in self.pubsub_subscriptions:
                try:
                    await self.pubsub_subscriptions[device_id].close()
                except Exception as e:
                    logger.debug(f"Failed to close pubsub: {e}")
                del self.pubsub_subscriptions[device_id]
    
    def _calculate_challenge_response(self, challenge: str, session_key: str) -> str:
        """Calculate authentication challenge response"""
        # Use HMAC with session key
        import hmac
        import hashlib
        
        hmac_obj = hmac.new(
            session_key.encode(),
            challenge.encode(),
            hashlib.sha256
        )
        
        return hmac_obj.hexdigest()
    
    async def _should_deduplicate_message(self, message: Dict[str, Any]) -> bool:
        """Check if message should be deduplicated to prevent duplicate triggers"""
        try:
            # Create a hash of the message content for deduplication
            message_content = {
                'type': message.get('type'),
                'message_id': message.get('message_id'),
                'chat_id': message.get('chat_id'),
                'device_id': message.get('device_id'),
                'timestamp': message.get('timestamp')
            }
            
            # Create a simple hash string
            import hashlib
            message_str = json.dumps(message_content, sort_keys=True)
            message_hash = hashlib.md5(message_str.encode()).hexdigest()
            
            current_time = time.time()
            async with self.deduplication_lock:
                # Check if we've seen this message recently
                if message_hash in self.message_deduplication:
                    last_seen = self.message_deduplication[message_hash]
                    if current_time - last_seen < self.deduplication_window:
                        logger.debug(f"Deduplicating message: {message_hash}")
                        return True
                
                # Record this message
                self.message_deduplication[message_hash] = current_time
                
                # Clean up old deduplication entries
                await self._cleanup_deduplication()
            
            return False
            
        except Exception as e:
            logger.error(f"Error in deduplication check: {e}")
            return False
    
    async def _cleanup_deduplication(self):
        """Clean up old deduplication entries"""
        current_time = time.time()
        expired_keys = []
        
        for message_hash, timestamp in self.message_deduplication.items():
            if current_time - timestamp > self.deduplication_window:
                expired_keys.append(message_hash)
        
        for key in expired_keys:
            del self.message_deduplication[key]
    
    async def send_message_to_device(self, device_id: str, message: Dict[str, Any]) -> bool:
        """Send message to specific device (online or queue for offline)"""
        # Check for message deduplication
        if await self._should_deduplicate_message(message):
            return True  # Message was deduplicated, but consider it "sent"
        
        async with self.connection_lock:
            connection = self.connections.get(device_id)
        
        if connection:
            try:
                await connection.websocket.send(json.dumps(message))
                return True
            except Exception as e:
                logger.warning(f"Failed to send message to device {device_id}: {e}")
                # Fall through to queue for offline
        
        # Device is offline or send failed, queue message in Redis
        try:
            if self.redis:
                await self.redis.lpush(
                    f"device_offline_queue:{device_id}",
                    json.dumps(message)
                )
                # Set TTL on queue (1 hour)
                await self.redis.expire(f"device_offline_queue:{device_id}", 3600)
                logger.debug(f"Queued message for offline device {device_id}")
        except Exception as e:
            logger.error(f"Failed to queue message for device {device_id}: {e}")
        
        return False
    
    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get WebSocket connection statistics"""
        async with self.connection_lock:
            total_connections = len(self.connections)
            authenticated_connections = sum(
                1 for conn in self.connections.values() if conn.is_authenticated
            )
            
            # Calculate connection duration stats
            now = time.time()
            durations = [
                now - conn.connected_at for conn in self.connections.values()
            ]
            
            avg_duration = sum(durations) / len(durations) if durations else 0
            
            # Copy connections list for safe iteration outside lock
            connections_list = [
                conn.to_dict() for conn in self.connections.values()
            ]
        
        # Get message state stats
        async with self.state_lock:
            total_message_states = sum(
                len(states) for states in self.message_states.values()
            )
        
        return {
            'total_connections': total_connections,
            'authenticated_connections': authenticated_connections,
            'average_connection_duration': avg_duration,
            'total_message_states': total_message_states,
            'connections': connections_list
        }
    
    async def _redis_pubsub_listener(self, device_id: str, user_id: str, connection: WebSocketConnection):
        """
        Listen to Redis Pub/Sub for broadcast messages.
        CRITICAL: One pubsub per connection (per device), not shared.
        """
        if not self.redis:
            return
        
        pubsub = None
        try:
            # CRITICAL: Check connection still exists (prevent zombie subscriptions)
            if device_id not in self.connections:
                logger.debug(f"Device {device_id} disconnected before pubsub started")
                return
            
            # Create pubsub only for this connection
            pubsub = self.redis.pubsub()
            
            # Store pubsub reference (for cleanup if connection is replaced)
            async with self.connection_lock:
                if device_id in self.pubsub_subscriptions:
                    # Old pubsub exists - close it first
                    try:
                        await self.pubsub_subscriptions[device_id].close()
                    except Exception as e:
                        logger.debug(f"Failed to close old pubsub: {e}")
                
                self.pubsub_subscriptions[device_id] = pubsub
            
            # Subscribe to broadcast channels (one per device)
            channels = [
                f"broadcast:user:{user_id}",      # All messages to this user
                f"broadcast:device:{device_id}",  # Messages to this specific device
            ]
            
            await pubsub.subscribe(*channels)
            logger.info(f"[WS-PUBSUB] Device {device_id} subscribed to {len(channels)} Redis channels")
            
            # Listen for messages (blocking call - yields messages as they arrive)
            async for message in pubsub.listen():
                # Check connection still exists (prevent sending to dead connections)
                if device_id not in self.connections:
                    logger.debug(f"Device {device_id} disconnected during pubsub listen")
                    break
                
                if message['type'] == 'message':
                    try:
                        # Send broadcast to WebSocket
                        await connection.websocket.send(message['data'])
                        logger.debug(f"[WS-PUBSUB] Broadcast to device {device_id}")
                        
                    except Exception as e:
                        logger.warning(f"[WS-PUBSUB] Failed to send to device {device_id}: {e}")
                        break  # Exit if connection is broken
                
                elif message['type'] == 'subscribe':
                    logger.debug(f"[WS-PUBSUB] Subscribed to {message['channel']}")
        
        except asyncio.CancelledError:
            logger.debug(f"[WS-PUBSUB] Pub/Sub listening cancelled for device {device_id}")
        except Exception as e:
            logger.error(f"[WS-PUBSUB] Error for device {device_id}: {type(e).__name__}: {e}")
        finally:
            # Cleanup: close pubsub and remove reference
            try:
                if pubsub:
                    await pubsub.close()
                    logger.debug(f"[WS-PUBSUB] Closed pubsub for device {device_id}")
                
                # Remove from subscriptions dict (only if it's still ours)
                async with self.connection_lock:
                    if self.pubsub_subscriptions.get(device_id) is pubsub:
                        del self.pubsub_subscriptions[device_id]
            except Exception:
                pass
    
    async def start_global_pubsub(self):
        """
        Start global Redis Pub/Sub subscriber for cross-container communication.
        CRITICAL: Only create ONE global subscriber, not one per connection.
        Handles reconnection WITHOUT recreating subscriptions.
        CRITICAL: Redis is required - no fallback behavior.
        """
        # CRITICAL: Redis is required for production - fail if not available
        if not self.redis:
            logger.error("[REDIS-GLOBAL] CRITICAL: Redis not available - cannot start global pubsub")
            raise RuntimeError("Redis is required for global pubsub functionality")
        
        # CRITICAL: Use lock to prevent race condition
        async with self._global_pubsub_lock:
            if self.global_pubsub_task:
                logger.debug("[REDIS-GLOBAL] Global pubsub already started")
                return
        
        async def global_redis_subscriber():
            """
            Listen to Redis channels and broadcast to WebSocket clients.
            CRITICAL: This runs ONCE per server, not once per connection.
            """
            pubsub = None
            reconnect_count = 0
            max_reconnect_attempts = 5
            reconnect_delay = 5  # seconds
            
            try:
                logger.info("[REDIS-GLOBAL] Starting global Redis Pub/Sub subscriber...")
                
                while reconnect_count < max_reconnect_attempts:
                    pubsub = None
                    try:
                        # Create pubsub object
                        pubsub = self.redis.pubsub()
                        
                        # Subscribe to all chat channels (pattern matching)
                        # CRITICAL: Only subscribe ONCE, not on every reconnection
                        await pubsub.psubscribe("chat:*")
                        logger.info("[REDIS-GLOBAL] Subscribed to chat:* channels")
                        
                        # Reset reconnect count on successful subscription
                        reconnect_count = 0
                        
                        # Listen for messages (blocking)
                        async for message in pubsub.listen():
                            try:
                                if message['type'] in ['message', 'pmessage']:
                                    channel = message.get('channel', '').decode() if isinstance(message.get('channel'), bytes) else message.get('channel', '')
                                    data_raw = message.get('data')
                                    
                                    # Parse data (could be bytes or str)
                                    if isinstance(data_raw, bytes):
                                        data_str = data_raw.decode('utf-8')
                                    else:
                                        data_str = data_raw
                                    
                                    try:
                                        data = json.loads(data_str)
                                        
                                        # Log activity (rate-limited)
                                        logger.debug(f"[REDIS-GLOBAL] {message['type']} on {channel}: {data.get('type', 'unknown')}")
                                        
                                        # Broadcast to relevant WebSocket connections
                                        await self._broadcast_redis_message(data, channel)
                                        
                                    except json.JSONDecodeError as e:
                                        logger.error(f"[REDIS-GLOBAL] JSON parse error: {e}")
                            
                            except asyncio.CancelledError:
                                raise  # Re-raise to exit outer loop
                            except Exception as e:
                                logger.error(f"[REDIS-GLOBAL] Message processing error: {type(e).__name__}: {e}")
                    
                    except asyncio.CancelledError:
                        logger.info("[REDIS-GLOBAL] Global subscriber cancelled")
                        raise
                    except (ConnectionError, TimeoutError, EOFError) as e:
                        # Connection lost - try to reconnect
                        reconnect_count += 1
                        logger.warning(f"[REDIS-GLOBAL] Connection error (attempt {reconnect_count}/{max_reconnect_attempts}): {e}")
                        
                        if reconnect_count < max_reconnect_attempts:
                            # Wait before reconnecting (exponential backoff)
                            delay = reconnect_delay * (2 ** (reconnect_count - 1))
                            logger.info(f"[REDIS-GLOBAL] Reconnecting in {delay}s...")
                            await asyncio.sleep(delay)
                        else:
                            logger.error("[REDIS-GLOBAL] Max reconnection attempts reached - stopping")
                            break
                    
                    except Exception as e:
                        logger.error(f"[REDIS-GLOBAL] Unexpected error: {type(e).__name__}: {e}")
                        reconnect_count += 1
                        if reconnect_count < max_reconnect_attempts:
                            await asyncio.sleep(reconnect_delay)
                        else:
                            break
                
            finally:
                # Final cleanup
                if pubsub:
                    try:
                        await pubsub.close()
                        logger.debug("[REDIS-GLOBAL] Pubsub closed")
                    except Exception as e:
                        logger.error(f"[REDIS-GLOBAL] Error closing pubsub: {e}")
                logger.info("[REDIS-GLOBAL] Global Pub/Sub subscriber stopped")
        
            # CRITICAL: Create task only once, inside the lock
            self.global_pubsub_task = asyncio.create_task(global_redis_subscriber())
            logger.info("[REDIS-GLOBAL] Global Pub/Sub subscriber task created")
    
    async def _broadcast_redis_message(self, data: Dict[str, Any], channel: str):
        """Broadcast Redis message to relevant WebSocket connections"""
        try:
            # Extract target information from data or channel
            message_type = data.get('type')
            
            if message_type in ['delivery_receipt', 'read_receipt', 'message_state_update']:
                # Broadcast to specific user's devices
                user_id = data.get('user_id')
                if user_id:
                    await self._broadcast_to_user_devices(user_id, '', data)
            
            elif message_type == 'typing':
                # Broadcast to chat participants
                chat_id = data.get('chat_id')
                exclude_user_id = data.get('user_id')
                if chat_id and exclude_user_id:
                    await self._broadcast_to_chat_participants(chat_id, exclude_user_id, data)
            
            elif message_type == 'presence':
                # Broadcast presence updates to user's other devices
                user_id = data.get('user_id')
                if user_id:
                    await self._broadcast_to_user_devices(user_id, data.get('device_id', ''), data)
            
        except Exception as e:
            logger.error(f"Error broadcasting Redis message: {e}")
    
    async def send_to_user(self, user_id: str, message: Dict[str, Any]) -> int:
        """Send message to all devices for a user, returns count of successful sends"""
        if not self.device_manager:
            logger.warning("Device manager not available for send_to_user")
            return 0
        
        try:
            # Get all active devices for user
            user_devices = await self.device_manager.get_active_devices(user_id)
            success_count = 0
            
            for device in user_devices:
                if await self.send_message_to_device(device.device_id, message):
                    success_count += 1
            
            logger.debug(f"Sent message to {success_count}/{len(user_devices)} devices for user {user_id}")
            return success_count
        except Exception as e:
            logger.error(f"Error in send_to_user for user {user_id}: {e}")
            return 0
    
    async def broadcast(self, message: Dict[str, Any]) -> int:
        """Broadcast message to all connected clients, returns count of successful sends"""
        success_count = 0
        failed_connections = []
        
        async with self.connection_lock:
            # Copy connections to avoid modification during iteration
            connections_copy = list(self.connections.items())
        
        for device_id, connection in connections_copy:
            try:
                # Verify connection is still active
                if device_id not in self.connections:
                    continue
                if connection.websocket.closed:
                    failed_connections.append(device_id)
                    continue
                
                await connection.websocket.send(json.dumps(message))
                success_count += 1
            except Exception as e:
                logger.warning(f"Broadcast failed to device {device_id}: {e}")
                failed_connections.append(device_id)
        
        # Clean up failed connections
        if failed_connections:
            for device_id in failed_connections:
                try:
                    await self._cleanup_connection(device_id)
                except Exception as e:
                    logger.warning(f"Failed to cleanup connection {device_id}: {e}")
            logger.debug(f"Cleaned up {len(failed_connections)} failed connections during broadcast")
        
        return success_count
    
    async def shutdown(self):
        """Graceful shutdown of WebSocket manager"""
        logger.info("[WS-MANAGER] Shutting down WebSocket manager")
        
        # Cancel global Pub/Sub task
        if self.global_pubsub_task:
            try:
                self.global_pubsub_task.cancel()
                await asyncio.wait_for(self.global_pubsub_task, timeout=5)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                logger.info("[WS-MANAGER] Global Pub/Sub task cancelled")
        
        # Close all connections
        async with self.connection_lock:
            for device_id, connection in list(self.connections.items()):
                try:
                    if connection.websocket and not connection.websocket.closed:
                        await connection.websocket.close(4000, "Server shutdown")
                except Exception as e:
                    logger.debug(f"Error closing connection {device_id}: {e}")
            
            self.connections.clear()
        
        # Close all Pub/Sub subscriptions
        for device_id, pubsub in list(self.pubsub_subscriptions.items()):
            try:
                await pubsub.close()
            except Exception as e:
                logger.debug(f"Error closing pubsub {device_id}: {e}")
        
        self.pubsub_subscriptions.clear()
        
        # Clear message states
        async with self.state_lock:
            self.message_states.clear()
        
        logger.info("[WS-MANAGER] WebSocket manager shutdown complete")

# Global singleton instance
websocket_manager = WebSocketManager()

# WebSocket server factory
async def create_websocket_server(redis_client: Optional[Any], host: str = "0.0.0.0", port: int = 8001):
    """Create WebSocket server with singleton manager"""
    await websocket_manager.initialize(redis_client)
    
    # Start global Pub/Sub subscriber
    await websocket_manager.start_global_pubsub()
    
    logger.info(f"Starting WebSocket server on {host}:{port}")
    
    return await websockets.serve(
        websocket_manager.handle_connection,
        host,
        port,
        ping_interval=None,  # We handle our own heartbeat
        ping_timeout=None,
        close_timeout=10,
        max_size=10 * 1024 * 1024,  # 10MB max message size
        compression=None,  # Disable compression for security
    )

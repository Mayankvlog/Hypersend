"""
WhatsApp-Grade WebSocket Delivery Handler (Legacy Compatibility)
==============================================================

This module provides backward compatibility while delegating to the new singleton WebSocketManager.
New code should use websocket_manager.py directly.

Security Properties:
- Per-device WebSocket connections
- Real-time delivery tracking
- Connection recovery and resumption
- Heartbeat/ping-pong for connection health
- Graceful degradation on connection loss
"""

import asyncio
import json
import time
import logging
import secrets
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import websockets
from websockets.server import WebSocketServerProtocol

# Import the new singleton WebSocket manager
from .websocket_manager import websocket_manager

logger = logging.getLogger(__name__)

# Legacy WebSocketDeliveryHandler class for backward compatibility
class WebSocketDeliveryHandler:
    """WhatsApp-grade WebSocket delivery handler (legacy compatibility wrapper)"""
    
    def __init__(self, redis_client: Optional[Any]):
        self.redis = redis_client
        # Initialize the singleton manager
        asyncio.create_task(websocket_manager.initialize(redis_client))
    
    async def handle_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle new WebSocket connection using singleton manager"""
        await websocket_manager.handle_connection(websocket, path)
    
    async def send_message_to_device(self, device_id: str, message: Dict[str, Any]) -> bool:
        """Send message to specific device using singleton manager"""
        return await websocket_manager.send_message_to_device(device_id, message)
    
    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get WebSocket connection statistics using singleton manager"""
        return await websocket_manager.get_connection_stats()

# WebSocket server factory (legacy compatibility)
async def create_websocket_server(redis_client: Optional[Any], host: str = "0.0.0.0", port: int = 8001):
    """Create WebSocket server using singleton manager"""
    return await websocket_manager.create_websocket_server(redis_client, host, port)

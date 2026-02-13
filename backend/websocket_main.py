#!/usr/bin/env python3
"""
WebSocket Service Entry Point
============================

Dedicated WebSocket service for real-time message delivery.
This service only handles WebSocket connections and does not
run the full FastAPI application.

Usage:
    python websocket_main.py
    uvicorn websocket_main:app --host 0.0.0.0 --port 8001
"""

import asyncio
import logging
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import threading
import time
import http.server
import socketserver

# Add current directory to Python path for Docker
sys.path.insert(0, str(Path(__file__).parent))

# Load environment variables
print("[WS_STARTUP] Loading environment variables...")
env_paths = [
    Path(__file__).parent / ".env",
    Path(__file__).parent.parent / ".env"
]

for env_path in env_paths:
    if env_path.exists():
        print(f"[WS_STARTUP] Loading .env from: {env_path}")
        load_dotenv(dotenv_path=env_path)
        break
else:
    print("[WS_STARTUP] No .env file found, using environment variables")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SimpleHealthHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP health check handler"""
    
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy", "service": "websocket"}')
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress health check logs
        pass

def start_health_server():
    """Start simple HTTP server for health checks"""
    port = int(os.getenv("WS_HEALTH_PORT", "8002"))
    try:
        # Create socket server with reuse address
        httpd = socketserver.TCPServer(("", port), SimpleHealthHandler)
        httpd.allow_reuse_address = True
        print(f"[WS_HEALTH] Health check server started on port {port}")
        httpd.serve_forever()
    except OSError as e:
        if e.errno == 48:  # Address already in use
            print(f"[WS_HEALTH] Port {port} already in use, skipping health server")
        else:
            print(f"[WS_HEALTH] Health server OS error: {e}")
            sys.exit(1)
    except Exception as e:
        print(f"[WS_HEALTH] Health server error: {e}")
        sys.exit(1)

async def main():
    """Main WebSocket service entry point"""
    try:
        print("[WS_STARTUP] Starting WebSocket service...")
        
        # Start health check server in background thread
        try:
            health_thread = threading.Thread(target=start_health_server, daemon=True)
            health_thread.start()
            print("[WS_STARTUP] Health check server thread started")
        except Exception as e:
            print(f"[WS_STARTUP] Warning: Failed to start health server: {e}")
            print("[WS_STARTUP] Continuing without health check server...")
        
        # Import Redis
        try:
            import redis.asyncio as redis
        except ImportError:
            print("[WS_STARTUP] ERROR: Redis not available - websocket service requires Redis")
            sys.exit(1)
        
        # Connect to Redis
        redis_host = os.getenv("REDIS_HOST", "redis")
        redis_port = int(os.getenv("REDIS_PORT", "6379"))
        redis_password = os.getenv("REDIS_PASSWORD", "")
        
        print(f"[WS_STARTUP] Connecting to Redis at {redis_host}:{redis_port}")
        
        try:
            if redis_password and redis_password.strip():
                redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    password=redis_password,
                    decode_responses=True
                )
            else:
                redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    password=None,  # Explicitly pass None instead of empty string
                    decode_responses=True
                )
            
            # Test Redis connection
            await redis_client.ping()
            print("[WS_STARTUP] ✓ Redis connection successful")
            
        except Exception as e:
            print(f"[WS_STARTUP] ✗ Redis connection failed: {e}")
            sys.exit(1)
        
        # Import and create WebSocket server
        try:
            from websocket.delivery_handler import create_websocket_server
            
            ws_host = os.getenv("WS_HOST", "0.0.0.0")
            ws_port = int(os.getenv("WS_PORT", "8001"))
            
            print(f"[WS_STARTUP] Starting WebSocket server on {ws_host}:{ws_port}")
            
            websocket_server = await create_websocket_server(
                redis_client,
                host=ws_host,
                port=ws_port
            )
            
            print(f"[WS_STARTUP] ✓ WebSocket server started successfully on port {ws_port}")
            
            # Keep the server running indefinitely
            print("[WS_STARTUP] WebSocket service is running... Press Ctrl+C to stop")
            try:
                # Keep the event loop alive
                while True:
                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                print("[WS_STARTUP] WebSocket service cancelled")
            finally:
                websocket_server.close()
                await websocket_server.wait_closed()
            
        except Exception as e:
            print(f"[WS_STARTUP] ✗ Failed to start WebSocket server: {e}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n[WS_STARTUP] WebSocket service stopped by user")
    except Exception as e:
        print(f"[WS_STARTUP] ✗ Unexpected error: {e}")
        sys.exit(1)
    finally:
        # Cleanup Redis connection
        if 'redis_client' in locals():
            await redis_client.close()
            print("[WS_STARTUP] Redis connection closed")

if __name__ == "__main__":
    asyncio.run(main())

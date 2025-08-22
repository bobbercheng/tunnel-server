#!/usr/bin/env python3
"""
Simple WebSocket echo server for testing WebSocket tunneling functionality.
"""

import asyncio
import websockets
import json
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def echo_handler(websocket, path):
    """Handle WebSocket connections with echo functionality"""
    client_addr = websocket.remote_address
    logger.info(f"🔗 New WebSocket connection from {client_addr} on path: {path}")
    
    try:
        # Send welcome message
        welcome_msg = {
            "type": "welcome",
            "message": "Connected to WebSocket test server!",
            "timestamp": datetime.now().isoformat(),
            "path": path
        }
        await websocket.send(json.dumps(welcome_msg))
        
        # Echo loop
        async for message in websocket:
            logger.info(f"📨 Received from {client_addr}: {message}")
            
            try:
                # Try to parse as JSON
                data = json.loads(message)
                response = {
                    "type": "echo",
                    "original": data,
                    "echo": f"Server echoes: {data}",
                    "timestamp": datetime.now().isoformat()
                }
                response_msg = json.dumps(response)
            except json.JSONDecodeError:
                # Handle plain text
                response_msg = f"Echo: {message} (received at {datetime.now().isoformat()})"
            
            logger.info(f"📤 Sending to {client_addr}: {response_msg}")
            await websocket.send(response_msg)
            
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"🔚 Connection closed: {client_addr}")
    except Exception as e:
        logger.error(f"❌ Error handling connection {client_addr}: {e}")

async def main():
    """Start the WebSocket server"""
    host = "127.0.0.1"
    port = 5000
    
    logger.info(f"🚀 Starting WebSocket echo server on ws://{host}:{port}")
    logger.info("📡 Ready to test WebSocket tunneling!")
    logger.info("🔗 Connect via: ws://localhost:9998/your-custom-url/")
    
    async with websockets.serve(echo_handler, host, port):
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped by user")
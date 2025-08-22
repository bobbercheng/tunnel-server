#!/usr/bin/env python3
"""
Simple HTTP server that simulates LibreChat's streaming API endpoint
for testing SSE (Server-Sent Events) functionality.
"""

import time
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class StreamingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/api/agents/chat/google'):
            self.handle_streaming_chat()
        else:
            self.send_error(404, "Not Found")
    
    def do_POST(self):
        if self.path.startswith('/api/agents/chat/google'):
            self.handle_streaming_chat()
        else:
            self.send_error(404, "Not Found")
    
    def handle_streaming_chat(self):
        """Simulate LibreChat's streaming chat API with SSE"""
        print(f"[SSE TEST] Handling streaming request: {self.path}")
        
        # Send SSE headers
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        # Send streaming data
        chunks = [
            "Hello! I'm a",
            " streaming",
            " response",
            " from the",
            " LibreChat",
            " simulation",
            " server.",
            " This tests",
            " SSE streaming",
            " through the",
            " tunnel!",
            " 🚀"
        ]
        
        for i, chunk in enumerate(chunks):
            # Format as SSE data
            data = json.dumps({
                "delta": {"content": chunk},
                "chunk_id": i,
                "done": False
            })
            
            sse_data = f"data: {data}\n\n"
            print(f"[SSE TEST] Sending chunk {i}: {chunk}")
            
            try:
                self.wfile.write(sse_data.encode('utf-8'))
                self.wfile.flush()
                time.sleep(0.5)  # Simulate realistic streaming delay
            except Exception as e:
                print(f"[SSE TEST] Error sending chunk: {e}")
                break
        
        # Send final message
        final_data = json.dumps({
            "delta": {"content": ""},
            "done": True
        })
        try:
            self.wfile.write(f"data: {final_data}\n\n".encode('utf-8'))
            self.wfile.flush()
            print("[SSE TEST] Streaming completed successfully!")
        except Exception as e:
            print(f"[SSE TEST] Error sending final chunk: {e}")

    def log_message(self, format, *args):
        """Custom logging"""
        print(f"[HTTP] {format % args}")

if __name__ == "__main__":
    server = HTTPServer(("localhost", 4000), StreamingHandler)
    print("🎯 Starting LibreChat simulation server on http://localhost:4000")
    print("📡 SSE streaming endpoint: /api/agents/chat/google")
    print("🔄 Server will stream test data with SSE format...")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
        server.shutdown()
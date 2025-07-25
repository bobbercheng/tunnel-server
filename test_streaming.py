#!/usr/bin/env python3
"""
Simple test server that provides a Server-Sent Events (SSE) endpoint
to test streaming through the tunnel.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import time
import threading

class SSEHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/stream':
            self.send_sse_response()
        elif self.path == '/':
            self.send_simple_response()
        else:
            self.send_error(404)

    def send_sse_response(self):
        """Send a Server-Sent Events response similar to your actual service"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.end_headers()

        # Send multiple events like your actual service
        events = [
            {"type": "status", "message": "RAGBasedSystem"},
            {"type": "timing", "label": "get_sql_query_RAG", "duration": 0.26616907119750977},
            {"type": "status", "message": "textToSql"},
            {"type": "timing", "label": "get_sql_query", "duration": 1.448843002319336},
            {"type": "status", "message": "sqlExecution"},
            {"type": "timing", "label": "execute_sql_query", "duration": 0.010889768600463867},
            {"type": "status", "message": "answerSummary"},
            {"type": "timing", "label": "get_summary_response", "duration": 2.4401695728302},
            {"type": "final_result", "data": {"status": "success", "answer": "Test data"}}
        ]

        for i, event in enumerate(events):
            data = f"data: {json.dumps(event)}\n\n"
            self.wfile.write(data.encode('utf-8'))
            self.wfile.flush()
            time.sleep(0.5)  # Simulate processing time

        # End the stream
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def send_simple_response(self):
        """Send a simple HTML response"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Test Server</title></head>
        <body>
            <h1>Test Server Running</h1>
            <p>Visit <a href="/stream">/stream</a> for SSE testing</p>
        </body>
        </html>
        """
        self.wfile.write(html.encode('utf-8'))

    def log_message(self, format, *args):
        """Override to add timestamp to logs"""
        timestamp = time.strftime('[%Y-%m-%d %H:%M:%S]')
        print(f"{timestamp} {format % args}")

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 3001), SSEHandler)
    print("Starting test server on http://127.0.0.1:3001")
    print("Visit http://127.0.0.1:3001/stream for SSE testing")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown() 
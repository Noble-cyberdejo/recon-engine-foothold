import http.server
import threading
import time

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><title>Test Service</title><body>hi</body></html>')
    def log_message(self, *a):
        pass

server = http.server.HTTPServer(('127.0.0.1', 8765), Handler)
print("Test server running on 127.0.0.1:8765 — leave this window open")
server.serve_forever()
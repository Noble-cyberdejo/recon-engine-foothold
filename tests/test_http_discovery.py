"""Tests for adaptive HTTP discovery helpers against a fake, generic HTTP
server — again deliberately generic, not the assignment target."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from recon_engine.tools.http_discovery import fetch_robots_disallowed, fetch_json, fetch_authenticated


def _make_handler():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            return

        def do_GET(self):
            if self.path == "/robots.txt":
                body = b"User-agent: *\nDisallow: /diag-info\nDisallow: /secret.txt\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/diag-info":
                payload = json.dumps({"username": "svc", "password": "hunter2"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)
            elif self.path == "/secret.txt":
                auth = self.headers.get("Authorization")
                key = self.headers.get("X-Route-Key")
                if auth is None or key != "proofvalue":
                    self.send_response(403)
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"FLAG-EXAMPLE\n")
            else:
                self.send_response(404)
                self.end_headers()
    return Handler


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _make_handler())
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


def test_http_01_robots_disallow_treated_as_breadcrumbs(server):
    port = server.server_address[1]
    paths = fetch_robots_disallowed(f"http://127.0.0.1:{port}", "127.0.0.1")
    assert "/diag-info" in paths
    assert "/secret.txt" in paths


def test_http_02_json_hint_followed(server):
    port = server.server_address[1]
    data = fetch_json(f"http://127.0.0.1:{port}", "127.0.0.1", "/diag-info")
    assert data == {"username": "svc", "password": "hunter2"}


def test_http_03_authenticated_fetch_requires_route_key(server):
    port = server.server_address[1]
    denied = fetch_authenticated(f"http://127.0.0.1:{port}", "127.0.0.1", "/secret.txt", "svc", "hunter2")
    assert denied.status == 403

    allowed = fetch_authenticated(
        f"http://127.0.0.1:{port}", "127.0.0.1", "/secret.txt", "svc", "hunter2",
        extra_headers={"X-Route-Key": "proofvalue"},
    )
    assert allowed.status == 200
    assert "FLAG-EXAMPLE" in allowed.body

"""
recon_engine.tools.http_discovery
====================================
Adaptive HTTP helpers: pull candidate paths out of robots.txt, follow
JSON hints, and issue authenticated follow-up requests. No target-specific
path names beyond /robots.txt and /user.txt (the latter is the documented
assessment objective, not a discovered secret).
"""
from __future__ import annotations

import base64
import json
import urllib.request
import urllib.error
from dataclasses import dataclass


@dataclass
class HttpResult:
    status: int
    body: str
    headers: dict[str, str]


def _do_request(url: str, host_header: str, extra_headers: dict[str, str] | None,
                 timeout: float) -> HttpResult:
    headers = {"Host": host_header}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return HttpResult(resp.status, body, dict(resp.headers))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return HttpResult(e.code, body, dict(e.headers or {}))
    except Exception:
        return HttpResult(0, "", {})


def fetch_robots_disallowed(base_url: str, host_header: str, timeout: float = 4.0) -> list[str]:
    result = _do_request(f"{base_url}/robots.txt", host_header, None, timeout)
    if result.status != 200:
        return []
    paths = []
    for line in result.body.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                paths.append(path)
    return paths


def fetch_json(base_url: str, host_header: str, path: str, timeout: float = 4.0) -> dict | None:
    result = _do_request(f"{base_url}{path}", host_header, None, timeout)
    if result.status != 200:
        return None
    try:
        return json.loads(result.body)
    except json.JSONDecodeError:
        return None


def fetch_authenticated(base_url: str, host_header: str, path: str, username: str,
                         password: str, extra_headers: dict[str, str] | None = None,
                         timeout: float = 4.0) -> HttpResult:
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}"}
    if extra_headers:
        headers.update(extra_headers)
    return _do_request(f"{base_url}{path}", host_header, headers, timeout)

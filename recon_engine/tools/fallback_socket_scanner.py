"""
recon_engine.tools.fallback_socket_scanner
=============================================
Pure-Python fallback discovery path used when an external tool (nmap,
naabu, httpx) is missing. Per the tool-interface brief: "If one external
tool is missing, a documented fallback must complete the supported
discovery path." This module has no third-party dependencies -- only
the standard library -- so it always works regardless of what's
installed on the host.

Every function here takes an already scope-approved (host, port) pair.
Scope checking happens in the orchestrator, never here.
"""
from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass
from typing import Optional


@dataclass
class PortProbeResult:
    host: str
    port: int
    protocol: str
    open: bool
    banner: str = ""


def probe_tcp_port(host: str, port: int, timeout: float = 2.0) -> PortProbeResult:
    """Attempt a raw TCP connect + best-effort banner grab. This is the
    fallback for both naabu (port discovery) and nmap (service ID) when
    neither binary is available."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            try:
                sock.settimeout(timeout)
                data = sock.recv(256)
                banner = data.decode("utf-8", errors="replace").strip()
            except (socket.timeout, OSError):
                pass  # no banner offered -- still a confirmed open port
            return PortProbeResult(host=host, port=port, protocol="tcp", open=True, banner=banner)
    except (ConnectionRefusedError, OSError, socket.timeout):
        return PortProbeResult(host=host, port=port, protocol="tcp", open=False)


@dataclass
class HttpProbeResult:
    host: str
    port: int
    scheme: str
    status: Optional[int]
    length: int
    title: str
    body_hash: str
    redirect: Optional[str] = None


def _extract_title(body: str) -> str:
    lower = body.lower()
    start = lower.find("<title>")
    end = lower.find("</title>")
    if start == -1 or end == -1 or end <= start:
        return ""
    return body[start + len("<title>"):end].strip()


def probe_http(host: str, port: int, scheme: str = "http",
                host_header: Optional[str] = None, timeout: float = 3.0) -> HttpProbeResult:
    """Fallback HTTP(S) fingerprinting used when httpx isn't available.
    Uses only http.client/ssl from the standard library. host_header lets
    the caller drive virtual-host enumeration by sending a different Host:
    header than the literal connection target."""
    import hashlib

    conn: http.client.HTTPConnection
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # lab-local, self-signed is expected
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    headers = {"Host": host_header} if host_header else {}
    try:
        conn.request("GET", "/", headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        text = body.decode("utf-8", errors="replace")
        redirect = resp.getheader("Location")
        return HttpProbeResult(
            host=host, port=port, scheme=scheme,
            status=resp.status,
            length=len(body),
            title=_extract_title(text),
            body_hash=hashlib.sha256(body).hexdigest(),
            redirect=redirect,
        )
    except (OSError, socket.timeout, http.client.HTTPException):
        return HttpProbeResult(host=host, port=port, scheme=scheme, status=None,
                                length=0, title="", body_hash="")
    finally:
        conn.close()
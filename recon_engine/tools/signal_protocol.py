"""
recon_engine.tools.signal_protocol
====================================
Generic client for a line-oriented TCP service that self-describes its
command set via a capabilities probe (CAPS). Adapts to whatever commands
the service advertises instead of hardcoding a fixed verb list.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field


@dataclass
class SignalSession:
    banner: str = ""
    capabilities: list[str] = field(default_factory=list)
    raw_caps_response: str = ""


def _read_line(sock: socket.socket, timeout: float, maxlen: int = 4096) -> str:
    sock.settimeout(timeout)
    try:
        data = sock.recv(maxlen)
    except socket.timeout:
        return ""
    return data.decode("utf-8", errors="replace")


def open_signal_session(host: str, port: int, timeout: float = 4.0) -> SignalSession | None:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    session = SignalSession()
    try:
        session.banner = _read_line(sock, timeout).strip()
        if not session.banner:
            return None
        sock.sendall(b"CAPS\r\n")
        resp = _read_line(sock, timeout).strip()
        session.raw_caps_response = resp
        if resp.lower().startswith("commands="):
            body = resp.split(";", 1)[0]
            _, _, cmd_list = body.partition("=")
            session.capabilities = [c.strip().upper() for c in cmd_list.split(",") if c.strip()]
        return session
    finally:
        sock.close()


def issue_route(host: str, port: int, timeout: float = 4.0) -> dict[str, str] | None:
    session = open_signal_session(host, port, timeout)
    if session is None or "ROUTE" not in session.capabilities:
        return None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        _read_line(sock, timeout)
        sock.sendall(b"ROUTE\r\n")
        resp = _read_line(sock, timeout).strip()
    finally:
        sock.close()
    fields: dict[str, str] = {}
    for part in resp.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields or None

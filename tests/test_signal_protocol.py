"""Tests for the generic signal-protocol adapter against a fake, generic
line-oriented service — deliberately not the assignment target, so these
tests prove the adapter's general logic rather than memorizing one target."""
import socket
import threading
import time

import pytest

from recon_engine.tools.signal_protocol import open_signal_session, issue_route


def _fake_server(port_holder, commands_line, route_line, ready_event, stop_event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    srv.settimeout(0.5)
    port_holder.append(srv.getsockname()[1])
    ready_event.set()
    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        conn.settimeout(2)
        try:
            conn.sendall(b"FAKE/1 READY\r\n")
            line = conn.recv(128).decode().strip()
            if line == "CAPS":
                conn.sendall(commands_line)
            elif line == "ROUTE":
                conn.sendall(route_line)
            else:
                conn.sendall(b"ERR unsupported command\r\n")
        except OSError:
            pass
        finally:
            conn.close()
    srv.close()


def _start(commands_line, route_line):
    port_holder = []
    ready = threading.Event()
    stop = threading.Event()
    t = threading.Thread(target=_fake_server, args=(port_holder, commands_line, route_line, ready, stop), daemon=True)
    t.start()
    ready.wait(timeout=2)
    return port_holder[0], stop


def test_signal_01_capabilities_discovered_generically():
    port, stop = _start(b"commands=CAPS,ROUTE,QUIT; framing=line; auth=none\r\n", b"")
    try:
        session = open_signal_session("127.0.0.1", port)
        assert session is not None
        assert "ROUTE" in session.capabilities
        assert "CAPS" in session.capabilities
    finally:
        stop.set()


def test_signal_02_route_parsed_when_advertised():
    port, stop = _start(
        b"commands=CAPS,ROUTE; framing=line; auth=none\r\n",
        b"route=example.internal;proof=deadbeef\r\n",
    )
    try:
        result = issue_route("127.0.0.1", port)
        assert result == {"route": "example.internal", "proof": "deadbeef"}
    finally:
        stop.set()


def test_signal_03_route_not_attempted_when_not_advertised():
    port, stop = _start(b"commands=CAPS,QUIT; framing=line; auth=none\r\n", b"")
    try:
        result = issue_route("127.0.0.1", port)
        assert result is None
    finally:
        stop.set()


def test_signal_04_non_signal_port_returns_none():
    # Nothing listening -> should fail closed, not raise
    session = open_signal_session("127.0.0.1", 1)
    assert session is None

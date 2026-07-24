"""
recon_engine.parsers.line_proto
=================================
Parses one line of the "line" tool output format:

    <ip>:<port> <service> <product>

into the fixture's expected shape: ip, port, service, product.

Matches PARSE-04. Deliberately regex-free / split-based: no shell string
concatenation is used anywhere in this module or its callers.
"""
from __future__ import annotations

from .errors import MalformedToolOutput


def parse_line(line: str, source_file: str = "") -> dict:
    line = line.strip()
    if not line:
        raise MalformedToolOutput("empty line", source_file=source_file)

    parts = line.split(" ", 2)
    if len(parts) < 3:
        raise MalformedToolOutput(f"expected '<ip>:<port> <service> <product>', got: {line!r}",
                                   source_file=source_file)

    addr, service, product = parts
    if ":" not in addr:
        raise MalformedToolOutput(f"missing ':' in address token: {addr!r}",
                                   source_file=source_file)

    ip, _, port_str = addr.rpartition(":")
    if not ip or not port_str.isdigit():
        raise MalformedToolOutput(f"could not parse ip/port from {addr!r}",
                                   source_file=source_file)

    return {
        "ip": ip,
        "port": int(port_str),
        "service": service,
        "product": product,
    }
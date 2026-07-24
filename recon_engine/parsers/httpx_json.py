"""
recon_engine.parsers.httpx_json
=================================
Parses one httpx JSON record into the fixture's expected shape:
scheme, host, port, status.

Matches PARSE-03.
"""
from __future__ import annotations
from urllib.parse import urlparse

from .errors import RequiredFieldMissing, MalformedToolOutput

REQUIRED = ("url", "status_code")

DEFAULT_PORTS = {"http": 80, "https": 443}


def parse_record(record: dict, source_file: str = "") -> dict:
    missing = [f for f in REQUIRED if f not in record or record[f] in (None, "")]
    if missing:
        raise RequiredFieldMissing(f"httpx record missing field(s): {missing}",
                                    source_file=source_file)

    parsed = urlparse(record["url"])
    if not parsed.scheme or not parsed.hostname:
        raise MalformedToolOutput(f"could not parse url: {record['url']!r}",
                                   source_file=source_file)

    port = parsed.port or DEFAULT_PORTS.get(parsed.scheme)
    if port is None:
        raise MalformedToolOutput(f"no port and unknown scheme: {parsed.scheme!r}",
                                   source_file=source_file)

    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": port,
        "status": int(record["status_code"]),
        # kept for vhost enrichment even though not part of the bare fixture-expected shape
        "title": record.get("title"),
        "tech": record.get("tech", []),
    }
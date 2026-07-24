"""
recon_engine.parsers.naabu_json
=================================
Parses one naabu JSON record into the fixture's expected shape:
host, ip, port, transport.

Matches PARSE-02.
"""
from __future__ import annotations

from .errors import RequiredFieldMissing

REQUIRED = ("host", "port", "protocol")


def parse_record(record: dict, source_file: str = "") -> dict:
    missing = [f for f in REQUIRED if f not in record or record[f] in (None, "")]
    if missing:
        raise RequiredFieldMissing(f"naabu record missing field(s): {missing}",
                                    source_file=source_file)
    return {
        "host": record["host"],
        "ip": record.get("ip", record["host"]),
        "port": int(record["port"]),
        "transport": record["protocol"],
    }
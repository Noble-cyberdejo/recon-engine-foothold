"""
recon_engine.schema
====================
The single versioned schema that every parser normalizes tool output into.
See tool-interface brief: "parse XML, JSON, and line-oriented tool output
into one versioned schema without shell string concatenation."
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional
import json

SCHEMA_VERSION = "1.0"

REQUIRED_FIELDS = (
    "observed_at",
    "target",
    "port",
    "protocol",
    "service",
    "source_tool",
    "source_file",
    "confidence",
    "notes",
)

VHOST_FIELDS = ("status", "length", "title", "redirect", "baseline_diff")

VALID_CONFIDENCE = ("high", "medium", "low")


class SchemaError(ValueError):
    """Raised when a NormalizedRecord would violate the required schema."""


@dataclass
class NormalizedRecord:
    observed_at: str          # ISO8601 UTC, e.g. 2026-07-22T18:03:11Z
    target: str                # host or ip as seen in the raw artifact
    port: int
    protocol: str               # tcp | udp
    service: str                # e.g. https, ssh, unknown
    source_tool: str             # nmap | naabu | httpx | line | fallback-socket-scanner
    source_file: str             # path under raw/<tool>/... this record was derived from
    confidence: str              # high | medium | low
    notes: str = ""
    schema_version: str = SCHEMA_VERSION

    # vhost-only, optional
    status: Optional[int] = None
    length: Optional[int] = None
    title: Optional[str] = None
    redirect: Optional[str] = None
    baseline_diff: Optional[dict] = None

    def __post_init__(self):
        if self.confidence not in VALID_CONFIDENCE:
            raise SchemaError(
                f"confidence must be one of {VALID_CONFIDENCE}, got {self.confidence!r}"
            )
        if not isinstance(self.port, int):
            raise SchemaError(f"port must be int, got {type(self.port)}")
        for f in ("target", "protocol", "service", "source_tool", "source_file"):
            if not getattr(self, f):
                raise SchemaError(f"required field '{f}' is empty")

    def dedupe_key(self) -> str:
        """Canonical identity key: host:port:protocol (see DEDUPE-01/02)."""
        return f"{self.target}:{self.port}:{self.protocol}"

    def to_json_line(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @staticmethod
    def from_dict(d: dict) -> "NormalizedRecord":
        missing = [f for f in REQUIRED_FIELDS if f not in d or d[f] in (None, "")]
        if missing:
            raise SchemaError(f"missing required field(s): {missing}")
        known = {k: v for k, v in d.items() if k in NormalizedRecord.__dataclass_fields__}
        return NormalizedRecord(**known)
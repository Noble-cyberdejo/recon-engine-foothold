"""
recon_engine.scope
===================
Scope enforcement, split into two independently testable layers:

  1. ScopeEngine -- generic CIDR/hostname/port allow-list matching
     (SCOPE-01..04). This is a reusable component; it must accept
     whatever candidate addresses staff's hidden fixtures throw at it,
     including non-loopback documentation-range addresses used purely
     to exercise the matching logic. It has no opinion about loopback.

  2. LoopbackGuard -- the assignment-specific hard policy: per Rules of
     Engagement (A1 Recon Target), only 127.0.0.1 endpoints marked IN in
     the *real* scope.csv are ever authorized for actual network activity.
     Nothing read from scope.csv can widen this. The orchestrator composes
     ScopeEngine + LoopbackGuard for any real socket/tool call; ScopeEngine
     alone is what the published/hidden scope fixtures exercise.

Every check (allow or deny) is meant to be logged by the caller to
request-ledger.csv -- neither class touches the network itself, they only
answer "may I?".
"""
from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass
from typing import Iterable, Optional

LOOPBACK_NETWORKS = (ipaddress.ip_network("127.0.0.0/8"),)


class ScopeViolation(Exception):
    """Raised (never silently swallowed) when a caller attempts to act
    outside scope. Callers must catch this ONLY to log-and-abort, never
    to retry or reinterpret."""


@dataclass(frozen=True)
class ScopeRule:
    kind: str             # "cidr" | "hostname" | "port"
    value: str            # e.g. "192.0.2.0/28", "target.invalid", "tcp/1-9000"


def _load_rules_from_csv(path: str) -> list[ScopeRule]:
    rules: list[ScopeRule] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Expected columns: kind,value,direction  (direction: IN | OUT)
            direction = row.get("direction", "IN").strip().upper()
            if direction != "IN":
                continue  # OUT rows (the decoy) are never added as allow rules
            rules.append(ScopeRule(kind=row["kind"].strip(), value=row["value"].strip()))
    return rules


class ScopeEngine:
    """Pure allow-list matcher: CIDR, hostname, and port-range rules.
    Deliberately has no opinion about loopback -- that's LoopbackGuard's job.
    This is what SCOPE-01..04 exercise directly."""

    def __init__(self, rules: Iterable[ScopeRule]):
        self.rules = list(rules)
        self._cidrs = []
        self._hostnames = {r.value for r in self.rules if r.kind == "hostname"}
        self._port_ranges = []
        
        # Validate and load CIDR rules
        for r in self.rules:
            if r.kind == "cidr":
                try:
                    ipaddress.ip_network(r.value, strict=False)
                    self._cidrs.append(r.value)
                except ValueError as e:
                    raise ValueError(f"Invalid CIDR in scope rules: {r.value!r} — {e}")
        
        # Load and validate port ranges
        for r in self.rules:
            if r.kind == "port":
                transport, _, rng = r.value.partition("/")
                lo, _, hi = rng.partition("-")
                try:
                    lo_int = int(lo)
                    hi_int = int(hi) if hi else lo_int
                    if not (0 < lo_int <= 65535 and 0 < hi_int <= 65535 and lo_int <= hi_int):
                        raise ValueError(f"port range out of bounds: {lo}-{hi}")
                    self._port_ranges.append((transport, lo_int, hi_int))
                except ValueError as e:
                    raise ValueError(f"Invalid port rule: {r.value!r} — {e}")

    @classmethod
    def from_csv(cls, path: str) -> "ScopeEngine":
        return cls(_load_rules_from_csv(path))

    def _host_allowed(self, host: str) -> bool:
        if host in self._hostnames:
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        for cidr in self._cidrs:
            if ip in ipaddress.ip_network(cidr):
                return True
        return False

    def _port_allowed(self, port: int, transport: str) -> bool:
        if not self._port_ranges:
            return True  # no port rules published -> port not restricted beyond host/CIDR
        for t, lo, hi in self._port_ranges:
            if t == transport and lo <= port <= hi:
                return True
        return False

    def check(self, host: str, port: int, transport: str = "tcp") -> bool:
        """Return True if (host, port, transport) matches an allow rule.
        Pure matching logic only -- no loopback opinion."""
        if not self._host_allowed(host):
            return False
        if not self._port_allowed(port, transport):
            return False
        return True


class LoopbackGuard:
    """Assignment-specific hard policy: nothing outside 127.0.0.0/8 is ever
    authorized, no matter what any scope.csv (real or tampered) claims.
    Hostnames are never trusted as loopback -- they must resolve and the
    resolved address must still pass this guard before connecting."""

    @staticmethod
    def is_loopback_literal(host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in LOOPBACK_NETWORKS)


class CompositeScope:
    """What the orchestrator actually uses for real network activity:
    ScopeEngine allow-list AND LoopbackGuard, both must pass."""

    def __init__(self, engine: ScopeEngine):
        self.engine = engine

    def check(self, host: str, port: int, transport: str = "tcp") -> bool:
        if not LoopbackGuard.is_loopback_literal(host):
            return False
        return self.engine.check(host, port, transport)

    def require(self, host: str, port: int, transport: str = "tcp") -> None:
        if not self.check(host, port, transport):
            raise ScopeViolation(f"{host}:{port}/{transport} is out of scope")

"""
recon_engine.scope
===================
Scope enforcement, split into two independently testable layers.

CSV FORMAT SUPPORT: two scope.csv shapes are supported transparently:
  - The published-fixture-style format: columns kind,value,direction
  - The real local_lab.py format: columns asset,scope,notes, where
    asset is either "host:port" or a bare CIDR, and scope is IN/OUT.
The loader auto-detects which shape a file uses from its header row.
"""
from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass
from typing import Iterable, Optional

LOOPBACK_NETWORKS = (ipaddress.ip_network("127.0.0.0/8"),)


class ScopeViolation(Exception):
    pass


@dataclass(frozen=True)
class ScopeRule:
    kind: str
    value: str


def _rules_from_fixture_style_rows(rows):
    rules = []
    for row in rows:
        direction = row.get("direction", "IN").strip().upper()
        if direction != "IN":
            continue
        rules.append(ScopeRule(kind=row["kind"].strip(), value=row["value"].strip()))
    return rules


def _rules_from_lab_style_rows(rows):
    rules = []
    hosts = set()
    for row in rows:
        direction = row.get("scope", "IN").strip().upper()
        if direction != "IN":
            continue
        asset = row["asset"].strip()
        if ":" in asset:
            host, _, port = asset.rpartition(":")
            hosts.add(host)
            rules.append(ScopeRule(kind="port", value=f"tcp/{port}-{port}"))
        else:
            try:
                ipaddress.ip_network(asset, strict=False)
                rules.append(ScopeRule(kind="cidr", value=asset))
            except ValueError:
                hosts.add(asset)
    for h in hosts:
        rules.append(ScopeRule(kind="hostname", value=h))
    return rules


def _load_rules_from_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = set(reader.fieldnames or [])

    if {"kind", "value"}.issubset(fieldnames):
        return _rules_from_fixture_style_rows(rows)
    elif {"asset", "scope"}.issubset(fieldnames):
        return _rules_from_lab_style_rows(rows)
    else:
        raise ValueError(f"Unrecognized scope.csv format in {path!r}: columns {fieldnames!r}")


class ScopeEngine:
    def __init__(self, rules):
        self.rules = list(rules)
        self._cidrs = []
        self._hostnames = {r.value for r in self.rules if r.kind == "hostname"}
        self._port_ranges = []

        for r in self.rules:
            if r.kind == "cidr":
                try:
                    ipaddress.ip_network(r.value, strict=False)
                    self._cidrs.append(r.value)
                except ValueError as e:
                    raise ValueError(f"Invalid CIDR in scope rules: {r.value!r} -- {e}")

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
                    raise ValueError(f"Invalid port rule: {r.value!r} -- {e}")

    @classmethod
    def from_csv(cls, path):
        return cls(_load_rules_from_csv(path))

    def _host_allowed(self, host):
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

    def _port_allowed(self, port, transport):
        if not self._port_ranges:
            return True
        for t, lo, hi in self._port_ranges:
            if t == transport and lo <= port <= hi:
                return True
        return False

    def check(self, host, port, transport="tcp"):
        if not self._host_allowed(host):
            return False
        if not self._port_allowed(port, transport):
            return False
        return True


class LoopbackGuard:
    @staticmethod
    def is_loopback_literal(host):
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in LOOPBACK_NETWORKS)


class CompositeScope:
    def __init__(self, engine):
        self.engine = engine

    def check(self, host, port, transport="tcp"):
        if not LoopbackGuard.is_loopback_literal(host):
            return False
        return self.engine.check(host, port, transport)

    def require(self, host, port, transport="tcp"):
        if not self.check(host, port, transport):
            raise ScopeViolation(f"{host}:{port}/{transport} is out of scope")

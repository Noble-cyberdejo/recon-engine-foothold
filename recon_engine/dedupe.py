"""
recon_engine.dedupe
=====================
Deterministic deduplication of normalized records.

Canonical identity key is host:port:protocol (NormalizedRecord.dedupe_key).
Same key collapses to one record (last-write-wins on data, first-seen
order preserved for stable output ordering). A different protocol on the
same host:port is a distinct record.

Matches DEDUPE-01 (two identical keys -> 1 record) and DEDUPE-02 (tcp vs
udp on the same host:port -> 2 records).
"""
from __future__ import annotations

from typing import Iterable
from .schema import NormalizedRecord


class Deduplicator:
    def __init__(self):
        self._order: list[str] = []
        self._records: dict[str, NormalizedRecord] = {}

    def add(self, record: NormalizedRecord) -> None:
        key = record.dedupe_key()
        if key not in self._records:
            self._order.append(key)
        self._records[key] = record  # last-write-wins

    def add_all(self, records: Iterable[NormalizedRecord]) -> None:
        for r in records:
            self.add(r)

    def count(self) -> int:
        return len(self._records)

    def values(self) -> list[NormalizedRecord]:
        return [self._records[k] for k in self._order]
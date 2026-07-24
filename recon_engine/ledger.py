"""
recon_engine.ledger
=====================
request-ledger.csv writer. Per the tool-interface brief, the ledger is
"independent corroboration" for requests reaching authorized services --
but the engine itself, via scope.py, is what must actually stop
out-of-scope traffic before any socket opens. The ledger's job is purely
to make that provable after the fact: every attempted (host, port,
protocol) tuple is logged, whether allowed or denied, with a timestamp
and the stage that attempted it.

One row per attempt, append-only, flushed immediately (not buffered)
so a crash mid-run still leaves a truthful ledger for the resumed run
to reconcile against.
"""
from __future__ import annotations

import csv
import os
from datetime import datetime, timezone

FIELDS = ("observed_at", "stage", "host", "port", "protocol", "decision", "reason")


class RequestLedger:
    def __init__(self, path: str):
        self.path = path
        self._new = not os.path.exists(path)
        self._fh = open(path, "a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._fh, fieldnames=FIELDS)
        if self._new:
            self._writer.writeheader()
            self._fh.flush()

    def record(self, stage: str, host: str, port: int, protocol: str,
               decision: str, reason: str = "") -> None:
        assert decision in ("allow", "deny")
        row = {
            "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "stage": stage,
            "host": host,
            "port": port,
            "protocol": protocol,
            "decision": decision,
            "reason": reason,
        }
        self._writer.writerow(row)
        self._fh.flush()  # durability over a crash/interrupt

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "RequestLedger":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @staticmethod
    def read_all(path: str) -> list[dict]:
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
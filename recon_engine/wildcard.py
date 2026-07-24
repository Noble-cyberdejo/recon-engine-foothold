"""
recon_engine.wildcard
========================
Two independent noise-suppression mechanisms:

1. DNS wildcard detection (WILDCARD-01/02): probe a few random, almost-certainly-
   nonexistent subdomains. If they all resolve to the same address, that address
   is a wildcard sink; future candidate resolutions matching it are suppressed,
   any differing resolution is retained (it's real signal).

2. Vhost baseline diffing (WILDCARD-03/04): compare a candidate virtual-host
   response (status, byte length, body hash) against a captured baseline for
   the same target. An exact match on all three is suppressed as generic
   catch-all noise; any difference is retained.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class DNSWildcardDetector:
    def __init__(self):
        self._sink: Optional[str] = None

    def calibrate(self, random_responses: list[str]) -> Optional[str]:
        """Feed 2+ random-subdomain resolution results. If they agree,
        record that address as the wildcard sink and return it."""
        if random_responses and len(set(random_responses)) == 1:
            self._sink = random_responses[0]
            return self._sink
        self._sink = None
        return None

    def evaluate(self, candidate_response: str) -> str:
        """Return 'suppress' if candidate matches the calibrated wildcard
        sink, else 'retain'."""
        if self._sink is not None and candidate_response == self._sink:
            return "suppress"
        return "retain"


@dataclass(frozen=True)
class VhostSnapshot:
    status: int
    bytes: int
    body_hash: str


class VhostBaselineDiffer:
    def __init__(self):
        self._baselines: dict[str, VhostSnapshot] = {}

    def set_baseline(self, target: str, snapshot: VhostSnapshot) -> None:
        self._baselines[target] = snapshot

    def evaluate(self, target: str, candidate: VhostSnapshot) -> tuple[str, Optional[dict]]:
        """Return (decision, baseline_diff) where decision is 'suppress' or
        'retain'. baseline_diff is populated (non-None) whenever retained,
        describing exactly what differed -- this is the required
        baseline-difference field on vhost normalized records."""
        baseline = self._baselines.get(target)
        if baseline is None:
            # no baseline captured yet -> nothing to compare against, retain
            return "retain", None

        if (candidate.status == baseline.status
                and candidate.bytes == baseline.bytes
                and candidate.body_hash == baseline.body_hash):
            return "suppress", None

        diff = {}
        if candidate.status != baseline.status:
            diff["status"] = {"baseline": baseline.status, "candidate": candidate.status}
        if candidate.bytes != baseline.bytes:
            diff["bytes"] = {"baseline": baseline.bytes, "candidate": candidate.bytes}
        if candidate.body_hash != baseline.body_hash:
            diff["body_hash"] = {"baseline": baseline.body_hash, "candidate": candidate.body_hash}
        return "retain", diff
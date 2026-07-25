"""
recon_engine.checkpoint
=========================
Stage-completion tracking so an interrupted run can resume without
repeating completed probes. Pipeline stages, in fixed order, per the
tool-interface brief and RESUME-01/02 fixtures:

    dns -> probe -> ports -> fingerprint

The checkpoint file lives alongside run.json in --output. It records
which stages have fully completed. On resume, the orchestrator asks
`next_stage()` where to continue.

Determinism note: for the resumed/fallback run to produce the same
normalized result hash as an uninterrupted run, resuming must only ever
*skip* completed stages -- it must never re-order, re-timestamp already
emitted records, or re-run a stage partially. A stage is atomic: it is
only marked complete after all of its records are written to
normalized/assets.jsonl and flushed.
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Optional

STAGES = ("dns", "probe", "ports", "fingerprint")


class Checkpoint:
    def __init__(self, path: str):
        self.path = path
        self.completed: list[str] = []
        self.pending: list[str] = list(STAGES)
        if os.path.exists(path):
            self._load()
        else:
            self._save()

    def _load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.completed = data.get("completed", [])
        self.pending = [s for s in STAGES if s not in self.completed]

    def _save(self) -> None:
        """Atomically save checkpoint to avoid partial writes on crash."""
        data = {"completed": self.completed, "pending": self.pending}
        # Write to temp file first, then rename (atomic on POSIX)
        dir_path = os.path.dirname(self.path) or "."
        with tempfile.NamedTemporaryFile(
            mode="w", dir=dir_path, delete=False, encoding="utf-8"
        ) as tmp:
            json.dump(data, tmp, indent=2)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = tmp.name
        os.replace(tmp_path, self.path)  # Atomic rename

    def mark_complete(self, stage: str) -> None:
        if stage not in STAGES:
            raise ValueError(f"unknown stage {stage!r}")
        if stage not in self.completed:
            self.completed.append(stage)
        self.pending = [s for s in STAGES if s not in self.completed]
        self._save()

    def next_stage(self) -> Optional[str]:
        """Return the next stage to run, or None if the pipeline is
        already fully complete. Matches RESUME-01 (mid-pipeline) and
        RESUME-02 (fully complete -> None)."""
        for s in STAGES:
            if s not in self.completed:
                return s
        return None

    def is_complete(self, stage: str) -> bool:
        return stage in self.completed

    @classmethod
    def from_state(cls, path: str, completed: list[str]) -> "Checkpoint":
        """Helper for tests/fixtures: build a Checkpoint pre-seeded with a
        given completed-stage list without touching disk state twice."""
        cp = cls.__new__(cls)
        cp.path = path
        cp.completed = list(completed)
        cp.pending = [s for s in STAGES if s not in completed]
        return cp

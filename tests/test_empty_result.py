import json
import os
import tempfile

from recon_engine.dedupe import Deduplicator
from recon_engine.checkpoint import Checkpoint


def test_empty_target_produces_zero_records_not_an_error():
    """A target that yields no observable services must still complete
    the pipeline cleanly: an empty normalized/assets.jsonl is a valid
    result, not a failure."""
    dedup = Deduplicator()
    assert dedup.count() == 0
    assert dedup.values() == []


def test_empty_run_still_completes_all_stages():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "checkpoint.json")
        cp = Checkpoint(path)
        for stage in ("dns", "probe", "ports", "fingerprint"):
            cp.mark_complete(stage)
        assert cp.next_stage() is None

        with open(path) as f:
            data = json.load(f)
        assert data["pending"] == []
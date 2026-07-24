import json
import os
import tempfile

from recon_engine.checkpoint import Checkpoint, STAGES

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "parser-fixtures.json")


def load_fixtures():
    with open(FIXTURES_PATH) as f:
        return json.load(f)["fixtures"]


FIXTURES = {fx["id"]: fx for fx in load_fixtures()}


def test_resume_01_mid_pipeline_next_stage():
    fx = FIXTURES["RESUME-01"]
    cp = Checkpoint.from_state("unused", completed=fx["completed"])
    assert cp.next_stage() == fx["expected_next"]
    assert cp.pending == fx["pending"]


def test_resume_02_fully_complete_next_stage_none():
    fx = FIXTURES["RESUME-02"]
    cp = Checkpoint.from_state("unused", completed=fx["completed"])
    assert cp.next_stage() == fx["expected_next"]


def test_checkpoint_persists_across_restart():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "checkpoint.json")
        cp1 = Checkpoint(path)
        cp1.mark_complete("dns")
        cp1.mark_complete("probe")

        # Simulate a fresh process restarting and reading the same file
        cp2 = Checkpoint(path)
        assert cp2.completed == ["dns", "probe"]
        assert cp2.next_stage() == "ports"


def test_stage_order_is_fixed():
    assert STAGES == ("dns", "probe", "ports", "fingerprint")
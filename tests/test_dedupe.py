import json
import os

from recon_engine.dedupe import Deduplicator
from recon_engine.schema import NormalizedRecord

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "parser-fixtures.json")


def load_fixtures():
    with open(FIXTURES_PATH) as f:
        return json.load(f)["fixtures"]


FIXTURES = {fx["id"]: fx for fx in load_fixtures()}


def _record_for(record_id: str) -> NormalizedRecord:
    host, port, protocol = record_id.split(":")
    return NormalizedRecord(
        observed_at="2026-07-22T00:00:00Z",
        target=host,
        port=int(port),
        protocol=protocol,
        service="unknown",
        source_tool="test",
        source_file="test",
        confidence="high",
        notes="",
    )


def test_dedupe_01_same_key_collapses():
    fx = FIXTURES["DEDUPE-01"]
    dedup = Deduplicator()
    dedup.add_all(_record_for(i) for i in fx["input_ids"])
    assert dedup.count() == fx["expected_count"]


def test_dedupe_02_different_protocol_distinct():
    fx = FIXTURES["DEDUPE-02"]
    dedup = Deduplicator()
    dedup.add_all(_record_for(i) for i in fx["input_ids"])
    assert dedup.count() == fx["expected_count"]
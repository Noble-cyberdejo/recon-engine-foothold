import json
import os

from recon_engine.wildcard import DNSWildcardDetector, VhostBaselineDiffer, VhostSnapshot

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "parser-fixtures.json")


def load_fixtures():
    with open(FIXTURES_PATH) as f:
        return json.load(f)["fixtures"]


FIXTURES = {fx["id"]: fx for fx in load_fixtures()}


def test_wildcard_01_dns_suppress():
    fx = FIXTURES["WILDCARD-01"]
    det = DNSWildcardDetector()
    det.calibrate(fx["random_responses"])
    assert det.evaluate(fx["candidate_response"]) == fx["expected"]


def test_wildcard_02_dns_retain():
    fx = FIXTURES["WILDCARD-02"]
    det = DNSWildcardDetector()
    det.calibrate(fx["random_responses"])
    assert det.evaluate(fx["candidate_response"]) == fx["expected"]


def test_wildcard_03_vhost_suppress():
    fx = FIXTURES["WILDCARD-03"]
    differ = VhostBaselineDiffer()
    differ.set_baseline("t", VhostSnapshot(**fx["baseline"]))
    decision, diff = differ.evaluate("t", VhostSnapshot(**fx["candidate"]))
    assert decision == fx["expected"]
    assert diff is None


def test_wildcard_04_vhost_retain_with_diff():
    fx = FIXTURES["WILDCARD-04"]
    differ = VhostBaselineDiffer()
    differ.set_baseline("t", VhostSnapshot(**fx["baseline"]))
    decision, diff = differ.evaluate("t", VhostSnapshot(**fx["candidate"]))
    assert decision == fx["expected"]
    assert diff is not None
    assert "status" in diff and "bytes" in diff and "body_hash" in diff
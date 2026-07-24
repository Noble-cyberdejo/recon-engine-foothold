import os
import tempfile

from recon_engine.ledger import RequestLedger


def test_ledger_writes_allow_and_deny_rows():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "request-ledger.csv")
        with RequestLedger(path) as ledger:
            ledger.record("probe", "127.0.0.1", 8080, "tcp", "allow")
            ledger.record("probe", "127.0.0.99", 9999, "tcp", "deny", reason="not IN-marked")

        rows = RequestLedger.read_all(path)
        assert len(rows) == 2
        assert rows[0]["decision"] == "allow"
        assert rows[1]["decision"] == "deny"
        assert rows[1]["reason"] == "not IN-marked"


def test_ledger_appends_across_reopen_for_resume():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "request-ledger.csv")
        with RequestLedger(path) as ledger:
            ledger.record("dns", "127.0.0.1", 53, "udp", "allow")

        # Simulated resume: reopen the same ledger file, must append not overwrite
        with RequestLedger(path) as ledger:
            ledger.record("probe", "127.0.0.1", 8080, "tcp", "allow")

        rows = RequestLedger.read_all(path)
        assert len(rows) == 2
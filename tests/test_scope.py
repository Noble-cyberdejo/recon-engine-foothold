import json
import os
import pytest

from recon_engine.scope import ScopeEngine, ScopeRule, ScopeViolation, CompositeScope, LoopbackGuard

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "parser-fixtures.json")


def load_fixtures():
    with open(FIXTURES_PATH) as f:
        return json.load(f)["fixtures"]


FIXTURES = {fx["id"]: fx for fx in load_fixtures()}


# --- Generic ScopeEngine matching logic (SCOPE-01..04, exactly as published) ---

def test_scope_01_cidr_allow():
    fx = FIXTURES["SCOPE-01"]
    engine = ScopeEngine([ScopeRule(kind="cidr", value=fx["scope"][0])])
    assert engine.check(fx["candidate"], 1) == (fx["expected"] == "allow")


def test_scope_02_cidr_deny_outside_range():
    fx = FIXTURES["SCOPE-02"]
    engine = ScopeEngine([ScopeRule(kind="cidr", value=fx["scope"][0])])
    assert engine.check(fx["candidate"], 1) == (fx["expected"] == "allow")


def test_scope_03_hostname_deny_wrong_host():
    fx = FIXTURES["SCOPE-03"]
    engine = ScopeEngine([ScopeRule(kind="hostname", value=fx["scope"][0])])
    assert engine.check(fx["candidate"], 1) == (fx["expected"] == "allow")


def test_scope_04_port_deny_outside_range():
    fx = FIXTURES["SCOPE-04"]
    engine = ScopeEngine([ScopeRule(kind="cidr", value="0.0.0.0/0"),
                          ScopeRule(kind="port", value=fx["scope"][0])])
    transport, port_str = fx["candidate"].split("/")
    assert engine.check("192.0.2.1", int(port_str), transport) == (fx["expected"] == "allow")


# --- Assignment-specific hard policy (real lab use, not published fixtures) ---

def test_decoy_never_reached_require_raises():
    """The out-of-scope decoy must raise before any socket would be opened.
    Only specific IN-marked loopback ports are allowed; the decoy port is
    not one of them, even though it's on the loopback interface."""
    engine = ScopeEngine([ScopeRule(kind="cidr", value="127.0.0.0/8"),
                          ScopeRule(kind="port", value="tcp/8000-8100")])
    scope = CompositeScope(engine)
    with pytest.raises(ScopeViolation):
        scope.require("127.0.0.1", 9999)  # decoy port: loopback but not IN-marked
    # sanity: an actually-allowed loopback endpoint passes
    assert scope.check("127.0.0.1", 8080) is True


def test_non_loopback_always_denied_even_if_in_csv():
    """Hard guard: nothing outside 127.0.0.0/8 is ever in scope for real
    network activity, no matter what a (hypothetically tampered) scope.csv
    claims."""
    engine = ScopeEngine([ScopeRule(kind="cidr", value="8.8.8.0/24")])
    scope = CompositeScope(engine)
    assert scope.check("8.8.8.8", 53) is False


def test_loopback_guard_literal_check():
    assert LoopbackGuard.is_loopback_literal("127.0.0.1") is True
    assert LoopbackGuard.is_loopback_literal("192.0.2.1") is False
    assert LoopbackGuard.is_loopback_literal("not-an-ip") is False
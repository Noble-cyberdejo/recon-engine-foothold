import json
import os
import pytest

from recon_engine.tools.adapter_base import simulate_tool_exit, ToolExecutionError

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "parser-fixtures.json")


def load_fixtures():
    with open(FIXTURES_PATH) as f:
        return json.load(f)["fixtures"]


FIXTURES = {fx["id"]: fx for fx in load_fixtures()}


def test_failure_01_missing_tool_uses_fallback():
    fx = FIXTURES["FAILURE-01"]
    result = simulate_tool_exit(fx["tool"], fx["exit_code"], fx["fallback_available"])
    assert result == fx["expected"]


def test_failure_02_required_tool_no_fallback_raises():
    fx = FIXTURES["FAILURE-02"]
    with pytest.raises(ToolExecutionError):
        simulate_tool_exit(fx["tool"], fx["exit_code"], fx["fallback_available"])
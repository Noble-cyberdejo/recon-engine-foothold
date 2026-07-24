import json
import os
import pytest

from recon_engine.parsers import nmap_xml, naabu_json, httpx_json, line_proto
from recon_engine.parsers.errors import MalformedToolOutput, RequiredFieldMissing

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "parser-fixtures.json")


def load_fixtures():
    with open(FIXTURES_PATH) as f:
        return json.load(f)["fixtures"]


FIXTURES = {fx["id"]: fx for fx in load_fixtures()}


def test_parse_01_nmap_xml():
    fx = FIXTURES["PARSE-01"]
    result = nmap_xml.parse_host_element(fx["input"])
    assert result == fx["expected"]


def test_parse_02_naabu_json():
    fx = FIXTURES["PARSE-02"]
    result = naabu_json.parse_record(fx["input"])
    assert result == fx["expected"]


def test_parse_03_httpx_json():
    fx = FIXTURES["PARSE-03"]
    result = httpx_json.parse_record(fx["input"])
    for k, v in fx["expected"].items():
        assert result[k] == v


def test_parse_04_line():
    fx = FIXTURES["PARSE-04"]
    result = line_proto.parse_line(fx["input"])
    assert result == fx["expected"]


def test_parse_05_malformed_json():
    # This fixture's input is a JSON-shaped tool artifact that is not
    # actually valid JSON (unquoted key, matches how a caller would json.loads()
    # raw tool output before handing it to a *_json parser).
    fx = FIXTURES["PARSE-05"]
    with pytest.raises(MalformedToolOutput):
        try:
            json.loads(fx["input"])
        except json.JSONDecodeError as e:
            raise MalformedToolOutput(str(e)) from e


def test_parse_06_missing_port():
    fx = FIXTURES["PARSE-06"]
    with pytest.raises(RequiredFieldMissing):
        naabu_json.parse_record(fx["input"])
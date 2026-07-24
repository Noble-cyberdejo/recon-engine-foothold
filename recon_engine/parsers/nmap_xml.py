"""
recon_engine.parsers.nmap_xml
==============================
Parses a single <host> element of nmap XML output into the fixture's
expected shape: host, port, transport, service, state.

Matches PARSE-01.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .errors import MalformedToolOutput, RequiredFieldMissing


def parse_host_element(xml_text: str, source_file: str = "") -> dict:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise MalformedToolOutput(f"invalid nmap XML: {e}", source_file=source_file) from e

    addr_el = root.find("address")
    if addr_el is None or "addr" not in addr_el.attrib:
        raise RequiredFieldMissing("missing <address addr=...> in nmap host element",
                                    source_file=source_file)
    host = addr_el.attrib["addr"]

    port_el = root.find("./ports/port")
    if port_el is None or "portid" not in port_el.attrib:
        raise RequiredFieldMissing("missing <port portid=...> in nmap host element",
                                    source_file=source_file)

    try:
        port = int(port_el.attrib["portid"])
    except ValueError as e:
        raise MalformedToolOutput(f"non-numeric portid: {port_el.attrib.get('portid')!r}",
                                   source_file=source_file) from e

    transport = port_el.attrib.get("protocol")
    if not transport:
        raise RequiredFieldMissing("missing protocol attribute on <port>", source_file=source_file)

    state_el = port_el.find("state")
    state = state_el.attrib.get("state") if state_el is not None else None
    if not state:
        raise RequiredFieldMissing("missing <state state=...>", source_file=source_file)

    service_el = port_el.find("service")
    service = service_el.attrib.get("name") if service_el is not None else None
    if not service:
        raise RequiredFieldMissing("missing <service name=...>", source_file=source_file)

    return {
        "host": host,
        "port": port,
        "transport": transport,
        "service": service,
        "state": state,
    }


def parse_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return parse_host_element(f.read(), source_file=path)
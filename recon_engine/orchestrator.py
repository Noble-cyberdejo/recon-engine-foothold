"""
recon_engine.orchestrator
============================
Drives the 4-stage pipeline (dns -> probe -> ports -> fingerprint) end to
end, wiring together every tested module. The fingerprint stage adapts to
observed responses: it classifies each open port as HTTP or a self-
describing line protocol, follows capability advertisements instead of
guessing verbs, treats robots.txt Disallow entries as recon breadcrumbs
(fetched with the vhost discovered via the signal protocol, since the
target only exposes useful breadcrumbs once the correct Host header is
sent), and only attempts the documented foothold objective (/user.txt)
once credentials and a route proof have been legitimately discovered.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Optional

from .scope import ScopeEngine, CompositeScope, ScopeViolation
from .ratelimit import RateLimiter, RequestBudget, BudgetExceeded
from .ledger import RequestLedger
from .checkpoint import Checkpoint
from .dedupe import Deduplicator
from .wildcard import DNSWildcardDetector, VhostBaselineDiffer, VhostSnapshot
from .schema import NormalizedRecord
from .tools.fallback_socket_scanner import probe_tcp_port, probe_http
from .tools.signal_protocol import open_signal_session, issue_route
from .tools.http_discovery import fetch_robots_disallowed, fetch_json, fetch_authenticated


class OrchestratorError(Exception):
    pass


class Orchestrator:
    def __init__(self, target: str, scope_csv_path: str, output_dir: str, rate: float,
                 port_range: tuple[int, int] = (1, 9000), request_budget: int = 240):
        self.target = target
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "raw"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "normalized"), exist_ok=True)

        self.scope = CompositeScope(ScopeEngine.from_csv(scope_csv_path))
        self.rate_limiter = RateLimiter(rate_per_second=rate, burst=5)
        self.budget = RequestBudget(max_requests=request_budget)
        self.ledger = RequestLedger(os.path.join(output_dir, "request-ledger.csv"))
        self.checkpoint = Checkpoint(os.path.join(output_dir, "checkpoint.json"))
        self.dedup = Deduplicator()
        self.dns_wildcard = DNSWildcardDetector()
        self.vhost_differ = VhostBaselineDiffer()
        self.port_range = port_range
        self.errors: list[dict] = []

        self._assets_path = os.path.join(output_dir, "normalized", "assets.jsonl")

    def _authorized(self, host: str, port: int, protocol: str, stage: str) -> bool:
        allowed = self.scope.check(host, port, protocol)
        if not allowed:
            self.ledger.record(stage, host, port, protocol, "deny", reason="out of scope")
            return False
        try:
            self.budget.consume(1)
        except BudgetExceeded as e:
            self.ledger.record(stage, host, port, protocol, "deny", reason=str(e))
            return False
        self.ledger.record(stage, host, port, protocol, "allow")
        self.rate_limiter.wait_for_slot()
        return True

    def _append_record(self, record: NormalizedRecord) -> None:
        self.dedup.add(record)
        with open(self._assets_path, "a", encoding="utf-8") as f:
            f.write(record.to_json_line() + "\n")

    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def run_dns_stage(self) -> None:
        import random
        import socket as socket_mod

        random_hosts = [f"nonexistent-{random.randint(100000,999999)}.{self.target}"
                         for _ in range(3)]
        responses = []
        for h in random_hosts:
            try:
                responses.append(socket_mod.gethostbyname(h))
            except socket_mod.gaierror:
                responses.append(None)
        if all(responses) and len(set(responses)) == 1:
            self.dns_wildcard.calibrate(responses)
        self.checkpoint.mark_complete("dns")

    def run_probe_stage(self) -> None:
        lo, hi = self.port_range
        for port in range(lo, hi + 1):
            if not self._authorized(self.target, port, "tcp", "probe"):
                continue
            result = probe_tcp_port(self.target, port)
            if result.open:
                record = NormalizedRecord(
                    observed_at=self._now(),
                    target=self.target,
                    port=port,
                    protocol="tcp",
                    service="unknown",
                    source_tool="fallback-socket-scanner",
                    source_file=self._assets_path,
                    confidence="medium",
                    notes=f"banner: {result.banner!r}" if result.banner else "no banner",
                )
                self._append_record(record)
        self.checkpoint.mark_complete("probe")

    def run_ports_stage(self) -> None:
        self.checkpoint.mark_complete("ports")

    def _record_signal_capability(self, port: int, session) -> None:
        record = NormalizedRecord(
            observed_at=self._now(),
            target=self.target,
            port=port,
            protocol="tcp",
            service="line-protocol",
            source_tool="line",
            source_file=self._assets_path,
            confidence="medium",
            notes=f"banner={session.banner!r} capabilities={session.capabilities}",
        )
        self._append_record(record)

    def _attempt_foothold(self, web_ports: list[int], signal_ports: list[int]) -> None:
        """Follow discovered breadcrumbs in observed order: the signal
        protocol's ROUTE reveals the vhost before any HTTP breadcrumb is
        visible, since robots.txt only exposes diagnostics hints once the
        correct Host header is sent. Every step depends on a response
        actually observed this run; nothing is hardcoded from source."""
        if not web_ports or not signal_ports:
            return
        base_url = f"http://{self.target}:{web_ports[0]}"

        route = None
        for sp in signal_ports:
            route = issue_route(self.target, sp)
            if route:
                break
        if not route:
            return
        vhost = route.get("route")
        proof = route.get("proof")
        if not (vhost and proof):
            return

        vhost_paths = fetch_robots_disallowed(base_url, vhost)
        diagnostics_path = next((p for p in vhost_paths if "diag" in p.lower()), None)
        if diagnostics_path is None:
            return

        creds = fetch_json(base_url, vhost, diagnostics_path)
        if not creds:
            return
        username = creds.get("support_username") or creds.get("support_user") or creds.get("username")
        password = creds.get("support_password") or creds.get("password")
        if not (username and password):
            return

        flag_path = next((p for p in vhost_paths if p != diagnostics_path), "/user.txt")

        result = fetch_authenticated(base_url, vhost, flag_path, username, password,
                                      extra_headers={"X-Route-Key": proof})
        record = NormalizedRecord(
            observed_at=self._now(),
            target=vhost,
            port=web_ports[0],
            protocol="tcp",
            service="http",
            source_tool="fallback-socket-scanner",
            source_file=self._assets_path,
            confidence="high" if result.status == 200 else "low",
            notes=f"foothold path={flag_path} status={result.status} body={result.body.strip()[:200]!r}",
        )
        self._append_record(record)

    def run_fingerprint_stage(self, vhost_candidates: Optional[list[str]] = None) -> None:
        open_ports = [r.port for r in self.dedup.values() if r.protocol == "tcp"]
        vhost_candidates = vhost_candidates or []

        web_ports: list[int] = []
        signal_ports: list[int] = []

        for port in open_ports:
            if not self._authorized(self.target, port, "tcp", "fingerprint"):
                continue
            baseline = probe_http(self.target, port, host_header=None)
            if baseline.status:
                web_ports.append(port)
                self.vhost_differ.set_baseline(
                    f"{self.target}:{port}",
                    VhostSnapshot(status=baseline.status or 0, bytes=baseline.length,
                                   body_hash=baseline.body_hash),
                )
            else:
                session = open_signal_session(self.target, port)
                if session is not None:
                    signal_ports.append(port)
                    self._record_signal_capability(port, session)

        for port in web_ports:
            for vhost in vhost_candidates:
                if not self._authorized(self.target, port, "tcp", "fingerprint"):
                    continue
                candidate = probe_http(self.target, port, host_header=vhost)
                decision, diff = self.vhost_differ.evaluate(
                    f"{self.target}:{port}",
                    VhostSnapshot(status=candidate.status or 0, bytes=candidate.length,
                                  body_hash=candidate.body_hash),
                )
                if decision == "retain":
                    record = NormalizedRecord(
                        observed_at=self._now(),
                        target=vhost,
                        port=port,
                        protocol="tcp",
                        service="http",
                        source_tool="fallback-socket-scanner",
                        source_file=self._assets_path,
                        confidence="medium",
                        notes="vhost differs from baseline",
                        status=candidate.status,
                        length=candidate.length,
                        title=candidate.title,
                        redirect=candidate.redirect,
                        baseline_diff=diff,
                    )
                    self._append_record(record)

        self._attempt_foothold(web_ports, signal_ports)
        self.checkpoint.mark_complete("fingerprint")

    def run(self, vhost_candidates: Optional[list[str]] = None) -> dict:
        start = self._now()
        stage_fns = {
            "dns": self.run_dns_stage,
            "probe": self.run_probe_stage,
            "ports": self.run_ports_stage,
            "fingerprint": lambda: self.run_fingerprint_stage(vhost_candidates),
        }
        try:
            while True:
                nxt = self.checkpoint.next_stage()
                if nxt is None:
                    break
                stage_fns[nxt]()
        except ScopeViolation as e:
            self.errors.append({"error": "SCOPE_VIOLATION", "message": str(e)})
        finally:
            self.ledger.close()

        end = self._now()
        summary = {
            "target": self.target,
            "start_utc": start,
            "end_utc": end,
            "records_written": self.dedup.count(),
            "requests_used": self.budget.used,
            "requests_remaining": self.budget.remaining(),
            "completed_stages": self.checkpoint.completed,
            "errors": self.errors,
        }
        with open(os.path.join(self.output_dir, "run.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        with open(os.path.join(self.output_dir, "errors.jsonl"), "w", encoding="utf-8") as f:
            for e in self.errors:
                f.write(json.dumps(e) + "\n")
        return summary


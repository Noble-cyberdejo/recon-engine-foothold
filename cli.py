#!/usr/bin/env python3
"""
recon-engine CLI
==================
Required invocation (per tool-interface brief):

    recon-engine --target 127.0.0.1 --scope lab-runtime/scope.csv --output run/ --rate 25

Never uses shell string concatenation; argparse handles all inputs, and
every argument flows into typed objects (Orchestrator, ScopeEngine) rather
than being interpolated into a command string anywhere.
"""
from __future__ import annotations

import argparse
import sys

from recon_engine.orchestrator import Orchestrator
from recon_engine.report import render_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="recon-engine",
                                      description="Resumable, scope-safe recon engine")
    parser.add_argument("--target", required=True, help="Target host or IP (must be in scope)")
    parser.add_argument("--scope", required=True, help="Path to scope.csv")
    parser.add_argument("--output", required=True, help="Output directory (run/)")
    parser.add_argument("--rate", required=True, type=float, help="Requests per second")
    parser.add_argument("--port-range", default="1-9000",
                         help="Port range to probe, e.g. 1-9000 (default: 1-9000)")
    parser.add_argument("--budget", type=int, default=240, help="Hard request budget cap")
    parser.add_argument("--vhost", action="append", default=[],
                         help="A vhost candidate to test (repeatable)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    lo_str, _, hi_str = args.port_range.partition("-")
    port_range = (int(lo_str), int(hi_str))

    try:
        orchestrator = Orchestrator(
            target=args.target,
            scope_csv_path=args.scope,
            output_dir=args.output,
            rate=args.rate,
            port_range=port_range,
            request_budget=args.budget,
        )
    except FileNotFoundError as e:
        print(f"error: could not read scope file: {e}", file=sys.stderr)
        return 2

    summary = orchestrator.run(vhost_candidates=args.vhost)

    render_report(
        assets_jsonl_path=f"{args.output}/normalized/assets.jsonl",
        run_json_path=f"{args.output}/run.json",
        output_html_path=f"{args.output}/report.html",
    )

    print(f"Run complete. Records: {summary['records_written']}, "
          f"requests used: {summary['requests_used']}/{summary['requests_used'] + summary['requests_remaining']}, "
          f"stages: {summary['completed_stages']}")
    if summary["errors"]:
        print(f"Errors encountered: {len(summary['errors'])} (see errors.jsonl)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
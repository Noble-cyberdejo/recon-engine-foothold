"""
recon_engine.report
======================
Renders report.html from normalized/assets.jsonl. Deliberately simple,
dependency-free HTML -- no templating engine, just an f-string table.
"""
from __future__ import annotations

import html
import json


def render_report(assets_jsonl_path: str, run_json_path: str, output_html_path: str) -> None:
    records = []
    try:
        with open(assets_jsonl_path, encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: skipping malformed JSON at line {line_num}: {e}")
                    continue
    except FileNotFoundError:
        records = []

    try:
        with open(run_json_path, encoding="utf-8") as f:
            run_meta = json.load(f)
    except FileNotFoundError:
        run_meta = {}

    rows = "\n".join(
        f"<tr><td>{html.escape(str(r.get('target','')))}</td>"
        f"<td>{html.escape(str(r.get('port','')))}</td>"
        f"<td>{html.escape(str(r.get('protocol','')))}</td>"
        f"<td>{html.escape(str(r.get('service','')))}</td>"
        f"<td>{html.escape(str(r.get('source_tool','')))}</td>"
        f"<td>{html.escape(str(r.get('confidence','')))}</td>"
        f"<td>{html.escape(str(r.get('notes','')))}</td></tr>"
        for r in records
    )

    doc = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Recon Engine Report</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
th {{ background: #222; color: #fff; }}
</style>
</head>
<body>
<h1>Recon Engine Report</h1>
<p>Target: {html.escape(str(run_meta.get('target','')))}</p>
<p>Run window: {html.escape(str(run_meta.get('start_utc','')))} &ndash; {html.escape(str(run_meta.get('end_utc','')))}</p>
<p>Records: {len(records)} | Requests used: {run_meta.get('requests_used','?')} | Completed stages: {', '.join(run_meta.get('completed_stages', []))}</p>
<table>
<tr><th>Target</th><th>Port</th><th>Protocol</th><th>Service</th><th>Source Tool</th><th>Confidence</th><th>Notes</th></tr>
{rows}
</table>
</body>
</html>
"""
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(doc)

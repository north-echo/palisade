"""Report rendering helpers."""

from __future__ import annotations

import json
import sqlite3
from html import escape


def render_text_report(
    scan: sqlite3.Row, devices: list[sqlite3.Row], findings: list[sqlite3.Row]
) -> str:
    """Render a human-readable text report."""
    lines = [
        f"scan-id: {scan['scan_id']}",
        f"status: {scan['status']}",
        f"started-at: {scan['started_at']}",
        f"completed-at: {scan['completed_at'] or 'incomplete'}",
        f"target-spec: {scan['target_spec']}",
        f"kev-scope: {scan['kev_scope']}",
        f"concurrency: {scan['concurrency']}",
        f"devices: {len(devices)}",
        f"findings: {len(findings)}",
        "",
        "Devices:",
    ]
    for device in devices:
        lines.append(
            f"- {device['ip_address']}:{device['port']} vendor={device['vendor'] or 'unknown'} "
            f"product={device['product'] or 'unknown'} version={device['version'] or 'unknown'} "
            f"method={device['fingerprint_method']}"
        )
    lines.append("")
    lines.append("Findings:")
    for finding in findings:
        lines.append(
            f"- {finding['cve_id']} vendor={finding['vendor']} product={finding['product']} "
            f"version={finding['version_detected'] or 'unknown'} "
            f"fixed={finding['version_fixed'] or 'unknown'} "
            f"sources={finding['kev_sources'] or 'unknown'}"
        )
        if finding["evidence_urls"]:
            lines.append(f"  evidence={finding['evidence_urls']}")
    return "\n".join(lines)


def render_json_report(
    scan: sqlite3.Row, devices: list[sqlite3.Row], findings: list[sqlite3.Row]
) -> str:
    """Render a machine-readable JSON report."""
    payload = {
        "scan": dict(scan),
        "devices": [dict(device) for device in devices],
        "findings": [dict(finding) for finding in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_html_report(
    scan: sqlite3.Row, devices: list[sqlite3.Row], findings: list[sqlite3.Row]
) -> str:
    """Render a self-contained HTML report."""
    device_items = "".join(
        "<li>"
        f"{escape(str(device['ip_address']))}:{escape(str(device['port']))} "
        f"{escape(str(device['vendor'] or 'unknown'))} "
        f"{escape(str(device['product'] or 'unknown'))} "
        f"{escape(str(device['version'] or 'unknown'))}"
        "</li>"
        for device in devices
    )
    finding_items = "".join(
        "<li>"
        f"{escape(str(finding['cve_id']))} "
        f"{escape(str(finding['vendor']))} "
        f"{escape(str(finding['product']))} "
        f"{escape(str(finding['version_detected'] or 'unknown'))} "
        f"sources={escape(str(finding['kev_sources'] or 'unknown'))}"
        "</li>"
        for finding in findings
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PALISADE Report {escape(str(scan['scan_id']))}</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; line-height: 1.4; }}
    h1, h2 {{ margin-bottom: 0.4rem; }}
    ul {{ padding-left: 1.25rem; }}
    .meta dt {{ font-weight: 700; }}
    .meta dd {{ margin: 0 0 0.6rem 0; }}
  </style>
</head>
<body>
  <h1>PALISADE Report</h1>
  <dl class="meta">
    <dt>Scan ID</dt><dd>{escape(str(scan['scan_id']))}</dd>
    <dt>Status</dt><dd>{escape(str(scan['status']))}</dd>
    <dt>Started</dt><dd>{escape(str(scan['started_at']))}</dd>
    <dt>Completed</dt><dd>{escape(str(scan['completed_at'] or 'incomplete'))}</dd>
    <dt>Target Spec</dt><dd>{escape(str(scan['target_spec']))}</dd>
    <dt>KEV Scope</dt><dd>{escape(str(scan['kev_scope']))}</dd>
    <dt>Concurrency</dt><dd>{escape(str(scan['concurrency']))}</dd>
  </dl>
  <h2>Devices</h2>
  <ul>{device_items}</ul>
  <h2>Findings</h2>
  <ul>{finding_items}</ul>
</body>
</html>
"""


def render_report(
    report_format: str, scan: sqlite3.Row, devices: list[sqlite3.Row], findings: list[sqlite3.Row]
) -> str:
    """Dispatch to the requested renderer."""
    if report_format == "text":
        return render_text_report(scan, devices, findings)
    if report_format == "json":
        return render_json_report(scan, devices, findings)
    if report_format == "html":
        return render_html_report(scan, devices, findings)
    raise ValueError(f"Unsupported report format: {report_format}")

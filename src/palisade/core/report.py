"""Report rendering helpers."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from html import escape

from palisade.core.controls import (
    CISA_CPGS,
    WATERISAC_FUNDAMENTALS,
    ControlDefinition,
    render_control_labels,
    summarize_control_coverage,
)


@dataclass(frozen=True)
class ReportFilters:
    """Filters applied to report rows."""

    vendor: str | None = None
    source: str | None = None
    cve_id: str | None = None
    findings_only: bool = False


@dataclass(frozen=True)
class ReportDiff:
    """Delta between two scans."""

    baseline_scan_id: str
    current_scan_id: str
    new_findings: list[sqlite3.Row]
    resolved_findings: list[sqlite3.Row]
    unchanged_findings: list[sqlite3.Row]


def filter_report_rows(
    devices: list[sqlite3.Row],
    findings: list[sqlite3.Row],
    filters: ReportFilters,
) -> tuple[list[sqlite3.Row], list[sqlite3.Row]]:
    """Return filtered device and finding rows for reporting."""
    filtered_findings = findings
    if filters.vendor is not None:
        filtered_findings = [
            row
            for row in filtered_findings
            if str(row["vendor"]).lower() == filters.vendor.lower()
        ]
    if filters.source is not None:
        source_lower = filters.source.lower()
        filtered_findings = [
            row
            for row in filtered_findings
            if source_lower in {
                item.strip().lower()
                for item in str(row["kev_sources"] or "").split(",")
                if item.strip()
            }
        ]
    if filters.cve_id is not None:
        filtered_findings = [
            row for row in filtered_findings if str(row["cve_id"]).lower() == filters.cve_id.lower()
        ]

    if filters.findings_only:
        return [], filtered_findings

    filtered_devices = devices
    if filters.vendor is not None:
        filtered_devices = [
            row
            for row in filtered_devices
            if row["vendor"] is not None and str(row["vendor"]).lower() == filters.vendor.lower()
        ]
    return filtered_devices, filtered_findings


def build_report_metadata(scan: sqlite3.Row, filters: ReportFilters) -> dict[str, object]:
    """Build common report metadata."""
    return {
        "scan_id": scan["scan_id"],
        "status": scan["status"],
        "started_at": scan["started_at"],
        "completed_at": scan["completed_at"] or "incomplete",
        "target_spec": scan["target_spec"],
        "kev_scope": scan["kev_scope"],
        "concurrency": scan["concurrency"],
        "filters": {
            "vendor": filters.vendor,
            "source": filters.source,
            "cve_id": filters.cve_id,
            "findings_only": filters.findings_only,
        },
    }


def render_text_report(
    scan: sqlite3.Row,
    devices: list[sqlite3.Row],
    findings: list[sqlite3.Row],
    *,
    filters: ReportFilters | None = None,
    diff: ReportDiff | None = None,
) -> str:
    """Render a human-readable text report."""
    active_filters = filters or ReportFilters()
    lines = [
        f"scan-id: {scan['scan_id']}",
        f"status: {scan['status']}",
        f"started-at: {scan['started_at']}",
        f"completed-at: {scan['completed_at'] or 'incomplete'}",
        f"target-spec: {scan['target_spec']}",
        f"kev-scope: {scan['kev_scope']}",
        f"concurrency: {scan['concurrency']}",
        f"filter-vendor: {active_filters.vendor or 'none'}",
        f"filter-source: {active_filters.source or 'none'}",
        f"filter-cve: {active_filters.cve_id or 'none'}",
        f"findings-only: {'yes' if active_filters.findings_only else 'no'}",
        f"devices: {len(devices)}",
        f"findings: {len(findings)}",
    ]
    if diff is not None:
        lines.extend(
            [
                f"baseline-scan-id: {diff.baseline_scan_id}",
                f"new-findings: {len(diff.new_findings)}",
                f"resolved-findings: {len(diff.resolved_findings)}",
                f"unchanged-findings: {len(diff.unchanged_findings)}",
            ]
        )
    lines.extend(["", "Devices:"])
    for device in devices:
        lines.append(
            f"- asset={device['asset_id'] or 'unknown'} "
            f"{device['ip_address']}:{device['port']} vendor={device['vendor'] or 'unknown'} "
            f"product={device['product'] or 'unknown'} version={device['version'] or 'unknown'} "
            f"method={device['fingerprint_method']}"
        )
    lines.append("")
    lines.append("Findings:")
    for finding in findings:
        lines.append(
            f"- asset={finding['asset_id'] or 'unknown'} "
            f"{finding['cve_id']} vendor={finding['vendor']} product={finding['product']} "
            f"version={finding['version_detected'] or 'unknown'} "
            f"fixed={finding['version_fixed'] or 'unknown'} "
            f"sources={finding['kev_sources'] or 'unknown'}"
        )
        cpg_labels = "; ".join(render_control_labels(str(finding["cpg_ids"] or ""), CISA_CPGS))
        waterisac_labels = "; ".join(
            render_control_labels(
                str(finding["waterisac_ids"] or ""), WATERISAC_FUNDAMENTALS
            )
        )
        if cpg_labels:
            lines.append(f"  cisa-cpgs={cpg_labels}")
        if waterisac_labels:
            lines.append(f"  waterisac={waterisac_labels}")
        if finding["evidence_urls"]:
            lines.append(f"  evidence={finding['evidence_urls']}")
    lines.extend(render_control_summary_lines(findings))
    if diff is not None:
        append_diff_text(lines, diff)
    return "\n".join(lines)


def append_diff_text(lines: list[str], diff: ReportDiff) -> None:
    """Append diff sections to a text report."""
    lines.append("")
    lines.append("Diff:")
    lines.append(f"New Findings: {len(diff.new_findings)}")
    for finding in diff.new_findings:
        lines.append(f"- {finding['cve_id']} {finding['vendor']} {finding['product']}")
    lines.append(f"Resolved Findings: {len(diff.resolved_findings)}")
    for finding in diff.resolved_findings:
        lines.append(f"- {finding['cve_id']} {finding['vendor']} {finding['product']}")


def render_json_report(
    scan: sqlite3.Row,
    devices: list[sqlite3.Row],
    findings: list[sqlite3.Row],
    *,
    filters: ReportFilters | None = None,
    diff: ReportDiff | None = None,
) -> str:
    """Render a machine-readable JSON report."""
    active_filters = filters or ReportFilters()
    payload: dict[str, object] = {
        "scan": build_report_metadata(scan, active_filters),
        "devices": [dict(device) for device in devices],
        "findings": [dict(finding) for finding in findings],
        "control_summary": build_control_summary_payload(findings),
    }
    if diff is not None:
        payload["diff"] = {
            "baseline_scan_id": diff.baseline_scan_id,
            "current_scan_id": diff.current_scan_id,
            "new_findings": [dict(row) for row in diff.new_findings],
            "resolved_findings": [dict(row) for row in diff.resolved_findings],
            "unchanged_findings": [dict(row) for row in diff.unchanged_findings],
        }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_html_report(
    scan: sqlite3.Row,
    devices: list[sqlite3.Row],
    findings: list[sqlite3.Row],
    *,
    filters: ReportFilters | None = None,
    diff: ReportDiff | None = None,
) -> str:
    """Render a self-contained HTML report."""
    active_filters = filters or ReportFilters()
    device_items = "".join(
        "<li>"
        f"asset={escape(str(device['asset_id'] or 'unknown'))} "
        f"{escape(str(device['ip_address']))}:{escape(str(device['port']))} "
        f"{escape(str(device['vendor'] or 'unknown'))} "
        f"{escape(str(device['product'] or 'unknown'))} "
        f"{escape(str(device['version'] or 'unknown'))}"
        "</li>"
        for device in devices
    )
    finding_items = "".join(
        render_finding_html(finding) for finding in findings
    )
    control_summary = build_control_summary_payload(findings)
    cpg_items = "".join(
        f"<li>{escape(item)}</li>" for item in control_summary["cisa_cpgs"]
    )
    waterisac_items = "".join(
        f"<li>{escape(item)}</li>" for item in control_summary["waterisac_fundamentals"]
    )
    diff_block = ""
    if diff is not None:
        diff_block = (
            "<h2>Diff</h2>"
            f"<p>Baseline Scan: {escape(diff.baseline_scan_id)}</p>"
            f"<p>New Findings: {len(diff.new_findings)} | "
            f"Resolved Findings: {len(diff.resolved_findings)} | "
            f"Unchanged Findings: {len(diff.unchanged_findings)}</p>"
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
    <dt>Filter Vendor</dt><dd>{escape(str(active_filters.vendor or 'none'))}</dd>
    <dt>Filter Source</dt><dd>{escape(str(active_filters.source or 'none'))}</dd>
    <dt>Filter CVE</dt><dd>{escape(str(active_filters.cve_id or 'none'))}</dd>
  </dl>
  <h2>Devices</h2>
  <ul>{device_items}</ul>
  <h2>Findings</h2>
  <ul>{finding_items}</ul>
  <h2>Control Alignment</h2>
  <h3>CISA CPGs</h3>
  <ul>{cpg_items}</ul>
  <h3>WaterISAC Fundamentals</h3>
  <ul>{waterisac_items}</ul>
  {diff_block}
</body>
</html>
"""


def render_control_summary_lines(findings: list[sqlite3.Row]) -> list[str]:
    """Render control summary lines for text reports."""
    summary = build_control_summary_payload(findings)
    lines = ["", "Control Alignment:"]
    lines.append(
        "CISA CPGs: "
        + (", ".join(summary["cisa_cpgs"]) if summary["cisa_cpgs"] else "none")
    )
    lines.append(
        "WaterISAC Fundamentals: "
        + (
            ", ".join(summary["waterisac_fundamentals"])
            if summary["waterisac_fundamentals"]
            else "none"
        )
    )
    return lines


def build_control_summary_payload(findings: list[sqlite3.Row]) -> dict[str, list[str]]:
    """Build control coverage summary across findings."""
    cpg_ids = summarize_control_coverage(findings, "cpg_ids")
    waterisac_ids = summarize_control_coverage(findings, "waterisac_ids")
    return {
        "cisa_cpgs": render_control_labels(cpg_ids, CISA_CPGS),
        "waterisac_fundamentals": render_control_labels(
            waterisac_ids, WATERISAC_FUNDAMENTALS
        ),
    }


def render_finding_controls(
    finding: sqlite3.Row, field_name: str, definitions: dict[str, ControlDefinition]
) -> str:
    """Render a finding control field for HTML output."""
    labels = render_control_labels(str(finding[field_name] or ""), definitions)
    return "; ".join(labels) if labels else "none"


def render_finding_html(finding: sqlite3.Row) -> str:
    """Render a single finding list item for HTML reports."""
    return (
        "<li>"
        f"asset={escape(str(finding['asset_id'] or 'unknown'))} "
        f"{escape(str(finding['cve_id']))} "
        f"{escape(str(finding['vendor']))} "
        f"{escape(str(finding['product']))} "
        f"{escape(str(finding['version_detected'] or 'unknown'))} "
        f"sources={escape(str(finding['kev_sources'] or 'unknown'))}"
        f"<br>cisa-cpgs={escape(render_finding_controls(finding, 'cpg_ids', CISA_CPGS))}"
        "<br>waterisac="
        f"{escape(render_finding_controls(finding, 'waterisac_ids', WATERISAC_FUNDAMENTALS))}"
        "</li>"
    )


def render_report(
    report_format: str,
    scan: sqlite3.Row,
    devices: list[sqlite3.Row],
    findings: list[sqlite3.Row],
    *,
    filters: ReportFilters | None = None,
    diff: ReportDiff | None = None,
) -> str:
    """Dispatch to the requested renderer."""
    if report_format == "text":
        return render_text_report(scan, devices, findings, filters=filters, diff=diff)
    if report_format == "json":
        return render_json_report(scan, devices, findings, filters=filters, diff=diff)
    if report_format == "html":
        return render_html_report(scan, devices, findings, filters=filters, diff=diff)
    raise ValueError(f"Unsupported report format: {report_format}")

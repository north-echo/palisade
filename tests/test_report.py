from __future__ import annotations

from pathlib import Path

import pytest

from palisade.core.db import initialize_db_path
from palisade.core.device import DeviceFingerprint
from palisade.core.kev import KevRecord, upsert_kev_records
from palisade.core.report import ReportFilters, filter_report_rows, render_report
from palisade.edge_audit.scanner import EdgeAuditScanner, ScanOptions


def make_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[EdgeAuditScanner, str]:
    connection = initialize_db_path(tmp_path / "palisade.db")
    upsert_kev_records(
        connection,
        [
            KevRecord(
                cve_id="CVE-2024-21762",
                vendor_project="Fortinet",
                product="FortiOS",
                vulnerability_name="Fortinet issue",
                date_added="2026-04-08",
                short_description=None,
                required_action="Patch now",
                due_date=None,
                known_ransomware_use="Unknown",
                notes=None,
                source="cisa_kev",
                source_record_id="CVE-2024-21762",
                source_confidence="authoritative_public",
                source_url="https://www.cisa.gov/kev",
            )
        ],
    )
    scanner = EdgeAuditScanner(connection)

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ports, config
        return [
            DeviceFingerprint(
                ip=ip,
                port=443,
                vendor="Fortinet",
                product="FortiOS",
                version="7.2.4",
                method="http_header",
                raw_data="fixture",
                confidence="high",
            )
        ]

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)
    result = scanner.scan(["192.0.2.17"], ScanOptions())
    return scanner, result.scan_id


def test_render_text_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner, scan_id = make_scan(tmp_path, monkeypatch)
    scan = scanner.get_scan(scan_id)
    assert scan is not None
    devices, findings = scanner.get_scan_rows(scan_id)

    report = render_report("text", scan, devices, findings)

    assert "scan-id:" in report
    assert "Devices:" in report
    assert "Findings:" in report
    assert "kev-scope:" in report
    assert "sources=cisa_kev" in report
    assert "asset=" in report
    assert "CISA CPGs: 1.A Mitigate Known Exploited Vulnerabilities" in report
    assert "WaterISAC Fundamentals:" in report
    assert "waterisac=2 Minimize Control System Exposure" in report


def test_render_json_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner, scan_id = make_scan(tmp_path, monkeypatch)
    scan = scanner.get_scan(scan_id)
    assert scan is not None
    devices, findings = scanner.get_scan_rows(scan_id)

    report = render_report("json", scan, devices, findings)

    assert '"scan"' in report
    assert '"devices"' in report
    assert '"findings"' in report
    assert '"control_summary"' in report
    assert '"waterisac_fundamentals"' in report


def test_render_html_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner, scan_id = make_scan(tmp_path, monkeypatch)
    scan = scanner.get_scan(scan_id)
    assert scan is not None
    devices, findings = scanner.get_scan_rows(scan_id)

    report = render_report("html", scan, devices, findings)

    assert "<html" in report
    assert "PALISADE Report" in report
    assert "<ul>" in report
    assert "sources=cisa_kev" in report
    assert "asset=" in report
    assert "Control Alignment" in report
    assert "Minimize Control System Exposure" in report


def test_filter_report_rows_filters_by_vendor_and_findings_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanner, scan_id = make_scan(tmp_path, monkeypatch)
    scan = scanner.get_scan(scan_id)
    assert scan is not None
    devices, findings = scanner.get_scan_rows(scan_id)

    filtered_devices, filtered_findings = filter_report_rows(
        devices,
        findings,
        ReportFilters(vendor="Fortinet", findings_only=True),
    )

    assert filtered_devices == []
    assert len(filtered_findings) == 1


def test_render_text_report_with_diff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner, first_scan_id = make_scan(tmp_path, monkeypatch)
    second_scan = scanner.get_scan(first_scan_id)
    assert second_scan is not None
    devices, findings = scanner.get_scan_rows(first_scan_id)
    diff = scanner.diff_scans(first_scan_id, first_scan_id)

    report = render_report(
        "text",
        second_scan,
        devices,
        findings,
        filters=ReportFilters(source="cisa_kev"),
        diff=diff,
    )

    assert "filter-source: cisa_kev" in report
    assert "Diff:" in report

from __future__ import annotations

from pathlib import Path

import pytest

from palisade.core.db import initialize_db_path
from palisade.core.device import DeviceFingerprint
from palisade.core.kev import KevRecord, upsert_kev_records
from palisade.core.report import render_report
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


def test_render_json_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner, scan_id = make_scan(tmp_path, monkeypatch)
    scan = scanner.get_scan(scan_id)
    assert scan is not None
    devices, findings = scanner.get_scan_rows(scan_id)

    report = render_report("json", scan, devices, findings)

    assert '"scan"' in report
    assert '"devices"' in report
    assert '"findings"' in report


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

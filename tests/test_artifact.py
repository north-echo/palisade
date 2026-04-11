from __future__ import annotations

from pathlib import Path

import pytest

from palisade.core.artifact import export_scan_bundle, import_scan_bundle
from palisade.core.db import initialize_db_path
from palisade.core.device import DeviceFingerprint
from palisade.core.kev import KevRecord, upsert_kev_records
from palisade.edge_audit.scanner import EdgeAuditScanner, ScanOptions


def make_bundle_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, str]:
    db_path = tmp_path / "source.db"
    connection = initialize_db_path(db_path)
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
    result = scanner.scan(["192.0.2.40"], ScanOptions())
    bundle_path = tmp_path / "artifacts" / "scan.zip"
    export_scan_bundle(connection, result.scan_id, bundle_path)
    return bundle_path, result.scan_id


def test_export_scan_bundle_writes_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle_path, _scan_id = make_bundle_scan(tmp_path, monkeypatch)

    assert bundle_path.exists()
    assert bundle_path.stat().st_size > 0


def test_import_scan_bundle_restores_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle_path, original_scan_id = make_bundle_scan(tmp_path, monkeypatch)
    connection = initialize_db_path(tmp_path / "dest.db")

    imported_scan_id = import_scan_bundle(connection, bundle_path)
    scanner = EdgeAuditScanner(connection)
    scan = scanner.get_scan(imported_scan_id)
    assert scan is not None
    devices, findings = scanner.get_scan_rows(imported_scan_id)

    assert imported_scan_id == original_scan_id
    assert len(devices) == 1
    assert len(findings) == 1
    assert devices[0]["asset_id"] is not None
    assert findings[0]["asset_id"] == devices[0]["asset_id"]
    assert findings[0]["waterisac_ids"] == "2,5,9"

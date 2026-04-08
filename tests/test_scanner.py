from __future__ import annotations

from pathlib import Path

import pytest

from palisade.core.db import initialize_db_path
from palisade.core.device import DeviceFingerprint
from palisade.core.kev import KevRecord, upsert_kev_records
from palisade.edge_audit.scanner import (
    EdgeAuditScanner,
    ScanOptions,
    expand_targets,
    parse_ports,
    parse_targets,
    result_to_json,
)


def test_parse_targets_from_cli_and_file(tmp_path: Path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("192.0.2.20\n192.0.2.21\n", encoding="utf-8")

    targets = parse_targets("192.0.2.10,192.0.2.11", target_file)

    assert targets == ["192.0.2.10", "192.0.2.11", "192.0.2.20", "192.0.2.21"]


def test_expand_targets_expands_cidr() -> None:
    targets = expand_targets(["192.0.2.0/30", "example.test"])

    assert targets == ["192.0.2.1", "192.0.2.2", "example.test"]


def test_parse_ports_defaults_and_custom_values() -> None:
    assert parse_ports(None) == (443, 4443, 8443, 10443)
    assert parse_ports("443,8443") == (443, 8443)


def test_scan_discover_only_persists_devices_without_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")
    scanner = EdgeAuditScanner(connection)

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ports, config
        return [
            DeviceFingerprint(
                ip=ip,
                port=443,
                vendor="SonicWall",
                product="SonicOS",
                version="7.0.1-5035",
                method="http_header",
                raw_data="fixture",
                confidence="high",
            )
        ]

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)

    result = scanner.scan(["192.0.2.10"], ScanOptions(discover_only=True))

    assert len(result.devices) == 1
    assert result.findings == []
    history = scanner.list_history()
    assert len(history) == 1
    assert history[0]["device_count"] == 1
    assert history[0]["finding_count"] == 0


def test_scan_matches_signatures_and_persists_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
        catalog_version="2026.04.08",
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

    result = scanner.scan(["192.0.2.11"], ScanOptions())

    assert len(result.devices) == 1
    assert len(result.findings) == 1
    assert result.findings[0].cve_id == "CVE-2024-21762"

    devices, findings = scanner.get_scan_rows(result.scan_id)
    assert len(devices) == 1
    assert len(findings) == 1
    assert findings[0]["vendor"] == "Fortinet"
    assert findings[0]["kev_sources"] == "cisa_kev"


def test_scan_uses_strict_scope_to_exclude_supplemental_only_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
                source="vulncheck_kev",
                source_record_id="VC-21762",
                source_confidence="commercial_evidence_based",
                source_url="https://vulncheck.example.test/CVE-2024-21762",
            )
        ],
    )
    scanner = EdgeAuditScanner(connection)

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ip, ports, config
        return [
            DeviceFingerprint(
                ip="192.0.2.11",
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

    strict_result = scanner.scan(["192.0.2.11"], ScanOptions(kev_scope="strict"))
    expanded_result = scanner.scan(["192.0.2.11"], ScanOptions(kev_scope="expanded"))

    assert strict_result.findings == []
    assert len(expanded_result.findings) == 1
    assert expanded_result.findings[0].kev_sources == ("vulncheck_kev",)


def test_scan_vendor_filter_excludes_non_matching_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")
    scanner = EdgeAuditScanner(connection)

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ip, ports, config
        return [
            DeviceFingerprint(
                ip="192.0.2.12",
                port=443,
                vendor="F5",
                product="BIG-IP",
                version="17.1.0",
                method="http_header",
                raw_data="fixture",
                confidence="high",
            )
        ]

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)

    result = scanner.scan(["192.0.2.12"], ScanOptions(vendor_filter="Cisco"))

    assert result.devices == []
    assert result.findings == []


def test_result_to_json_contains_devices_and_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")
    scanner = EdgeAuditScanner(connection)

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ports, config
        return [
            DeviceFingerprint(
                ip=ip,
                port=443,
                vendor="Palo Alto Networks",
                product="PAN-OS",
                version="11.0.2",
                method="http_header",
                raw_data="fixture",
                confidence="high",
            )
        ]

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)

    result = scanner.scan(["192.0.2.13"], ScanOptions())
    payload = result_to_json(result)

    assert '"scan_id"' in payload
    assert '"devices"' in payload
    assert '"findings"' in payload


def test_scan_records_concurrency_in_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")
    scanner = EdgeAuditScanner(connection)

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ip, ports, config
        return []

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)

    scanner.scan(["192.0.2.13", "192.0.2.14"], ScanOptions(concurrency=2))
    history = scanner.list_history()

    assert history[0]["concurrency"] == 2


def test_scan_matches_citrix_signatures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")
    upsert_kev_records(
        connection,
        [
            KevRecord(
                cve_id="CVE-2023-4966",
                vendor_project="Citrix",
                product="NetScaler ADC",
                vulnerability_name="Citrix Bleed",
                date_added="2026-04-08",
                short_description=None,
                required_action="Patch now",
                due_date=None,
                known_ransomware_use="Unknown",
                notes=None,
                source="cisa_kev",
                source_record_id="CVE-2023-4966",
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
                vendor="Citrix",
                product="NetScaler ADC",
                version="14.1-6.50",
                method="http_header",
                raw_data="fixture",
                confidence="high",
            )
        ]

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)

    result = scanner.scan(["192.0.2.30"], ScanOptions())

    assert len(result.findings) == 1
    assert result.findings[0].cve_id == "CVE-2023-4966"


def test_diff_scans_reports_new_and_resolved_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    call_count = {"count": 0}

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ip, ports, config
        call_count["count"] += 1
        if call_count["count"] == 1:
            return [
                DeviceFingerprint(
                    ip="192.0.2.20",
                    port=443,
                    vendor="Fortinet",
                    product="FortiOS",
                    version="7.2.4",
                    method="http_header",
                    raw_data="fixture",
                    confidence="high",
                )
            ]
        return []

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)

    first = scanner.scan(["192.0.2.20"], ScanOptions())
    second = scanner.scan(["192.0.2.20"], ScanOptions())
    diff = scanner.diff_scans(first.scan_id, second.scan_id)

    assert diff.baseline_scan_id == first.scan_id
    assert diff.current_scan_id == second.scan_id
    assert len(diff.new_findings) == 0
    assert len(diff.resolved_findings) == 1

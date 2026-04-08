from __future__ import annotations

from pathlib import Path

import pytest

from palisade.core.db import initialize_db_path
from palisade.core.kev import KevRecord, upsert_kev_records
from palisade.core.mock_lab import FIXTURE_ROOT, start_named_fixture_servers
from palisade.edge_audit.scanner import EdgeAuditScanner, ScanOptions


def test_mock_lab_http_targets_work_with_real_scanner(tmp_path: Path) -> None:
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
            ),
            KevRecord(
                cve_id="CVE-2024-40766",
                vendor_project="SonicWall",
                product="SonicOS",
                vulnerability_name="SonicWall issue",
                date_added="2026-04-08",
                short_description=None,
                required_action="Patch now",
                due_date=None,
                known_ransomware_use="Known",
                notes=None,
                source="cisa_kev",
                source_record_id="CVE-2024-40766",
                source_confidence="authoritative_public",
                source_url="https://www.cisa.gov/kev",
            ),
            KevRecord(
                cve_id="CVE-2023-4966",
                vendor_project="Citrix",
                product="NetScaler ADC",
                vulnerability_name="Citrix issue",
                date_added="2026-04-08",
                short_description=None,
                required_action="Patch now",
                due_date=None,
                known_ransomware_use="Unknown",
                notes=None,
                source="vulncheck_kev",
                source_record_id="CVE-2023-4966",
                source_confidence="commercial_evidence_based",
                source_url="https://example.test/citrix",
            ),
        ],
    )
    scanner = EdgeAuditScanner(connection)
    try:
        stack, servers = start_named_fixture_servers(
            {
                "fortinet": FIXTURE_ROOT / "http_fortinet.txt",
                "sonicwall": FIXTURE_ROOT / "http_sonicwall.txt",
                "citrix": FIXTURE_ROOT / "http_citrix.txt",
            }
        )
    except PermissionError:
        pytest.skip("Local socket binding is not permitted in this environment")

    with stack:
        ports = tuple(server.port for server in servers)
        result = scanner.scan(["127.0.0.1"], ScanOptions(ports=ports, kev_scope="expanded"))

    assert len(result.devices) >= 3
    vendors = {device.vendor for device in result.devices}
    assert "Fortinet" in vendors
    assert "SonicWall" in vendors
    assert "Citrix" in vendors

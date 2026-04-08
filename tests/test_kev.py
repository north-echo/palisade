from __future__ import annotations

from pathlib import Path

from palisade.core.db import initialize_db_path
from palisade.core.kev import (
    KevRecord,
    count_kev_records,
    export_kev_json_file,
    get_sync_status,
    import_kev_json_file,
    import_kev_payload,
    list_kev_sources,
    load_kev_json,
    parse_kev_payload,
    query_by_cve,
    query_by_product,
    query_by_vendor,
    query_edge_devices,
    sync_source_adapter,
)
from palisade.core.kev_sources import (
    FileKevSourceAdapter,
    SourceFetchResult,
    VulnCheckConfig,
    VulnCheckKevSourceAdapter,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kev_sample.json"


def test_parse_kev_payload_returns_records_and_catalog_version() -> None:
    payload = load_kev_json(FIXTURE_PATH)

    records, catalog_version = parse_kev_payload(payload)

    assert len(records) == 3
    assert catalog_version == "2026.04.08"
    assert records[0].cve_id == "CVE-2024-40766"


def test_import_kev_json_file_persists_records_and_metadata(tmp_path: Path) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")

    count = import_kev_json_file(connection, FIXTURE_PATH)
    status = get_sync_status(connection)

    assert count == 3
    assert count_kev_records(connection) == 3
    assert status["catalog_version"] == "2026.04.08"
    assert status["total_count"] == 3
    assert status["last_sync"] is not None
    assert status["sources_enabled"] == "cisa_kev"


def test_import_kev_payload_persists_records(tmp_path: Path) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")
    payload = load_kev_json(FIXTURE_PATH)

    count = import_kev_payload(connection, payload)

    assert count == 3
    assert count_kev_records(connection) == 3


def test_export_kev_json_file_round_trips(tmp_path: Path) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")
    export_path = tmp_path / "exports" / "kev.json"

    import_kev_json_file(connection, FIXTURE_PATH)
    export_kev_json_file(connection, export_path)

    exported = load_kev_json(export_path)
    assert exported["catalogVersion"] == "2026.04.08"
    assert len(exported["vulnerabilities"]) == 3


def test_kev_queries_return_expected_rows(tmp_path: Path) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")
    import_kev_json_file(connection, FIXTURE_PATH)

    sonicwall_rows = query_by_vendor(connection, "sonicwall")
    fortios_rows = query_by_product(connection, "fortinet", "FortiOS")
    cve_row = query_by_cve(connection, "CVE-2024-3400")
    edge_rows = query_edge_devices(connection)

    assert len(sonicwall_rows) == 1
    assert sonicwall_rows[0]["product"] == "SonicOS"
    assert len(fortios_rows) == 1
    assert fortios_rows[0]["cve_id"] == "CVE-2024-21762"
    assert cve_row is not None
    assert cve_row["vendor_project"] == "Palo Alto Networks"
    assert len(edge_rows) == 3


def test_kev_source_rows_are_recorded(tmp_path: Path) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")
    import_kev_json_file(connection, FIXTURE_PATH)

    sources = list_kev_sources(connection)

    assert len(sources) == 1
    assert sources[0]["source"] == "cisa_kev"
    assert sources[0]["cve_count"] == 3


def test_sync_source_adapter_imports_normalized_records(tmp_path: Path) -> None:
    connection = initialize_db_path(tmp_path / "palisade.db")
    payload = load_kev_json(FIXTURE_PATH)
    records, catalog_version = parse_kev_payload(payload)

    class FakeSourceAdapter:
        def fetch(self) -> SourceFetchResult:
            return SourceFetchResult(
                source="fake_source",
                catalog_version=catalog_version,
                records=[
                    KevRecord(
                        **{
                            **record.__dict__,
                            "source": "fake_source",
                            "source_confidence": "test_source",
                        }
                    )
                    for record in records
                ],
            )

    source_name, count = sync_source_adapter(connection, FakeSourceAdapter())

    assert source_name == "fake_source"
    assert count == 3
    assert get_sync_status(connection)["sources_enabled"] == "fake_source"


def test_vulncheck_adapter_is_placeholder() -> None:
    adapter = VulnCheckKevSourceAdapter(VulnCheckConfig(api_token="test-token"))

    try:
        adapter.fetch()
    except NotImplementedError as exc:
        assert "not implemented yet" in str(exc)
    else:
        raise AssertionError("Expected VulnCheck adapter to be a placeholder")


def test_file_source_adapter_loads_supplemental_records(tmp_path: Path) -> None:
    supplemental_path = tmp_path / "supplemental.json"
    supplemental_path.write_text(
        """
        {
          "catalogVersion": "test-1",
          "records": [
            {
              "cve_id": "CVE-2099-0002",
              "vendor_project": "Citrix",
              "product": "NetScaler ADC",
              "vulnerability_name": "Example exploited vulnerability",
              "date_added": "2026-01-01",
              "short_description": "Example description",
              "required_action": "Patch immediately",
              "due_date": "2026-01-15",
              "known_ransomware_use": "Unknown",
              "notes": "Supplemental source note",
              "source": "vulncheck_kev",
              "source_record_id": "VC-1",
              "source_confidence": "commercial_evidence_based",
              "source_url": "https://example.test/vc-1"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    adapter = FileKevSourceAdapter(supplemental_path)
    result = adapter.fetch()

    assert result.catalog_version == "test-1"
    assert len(result.records) == 1
    assert result.records[0].source == "vulncheck_kev"

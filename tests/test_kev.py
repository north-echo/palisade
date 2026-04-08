from __future__ import annotations

from pathlib import Path

import pytest

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
    default_source_adapters,
    parse_backup_download_url,
    parse_vulncheck_records,
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


def test_parse_vulncheck_backup_url() -> None:
    url = parse_backup_download_url(
        {"data": [{"url": "https://downloads.example.test/vulncheck-kev.json"}]}
    )

    assert url == "https://downloads.example.test/vulncheck-kev.json"


def test_parse_vulncheck_records_normalizes_entries() -> None:
    records = parse_vulncheck_records(
        {
            "_timestamp": "2026-04-08T10:00:00Z",
            "data": [
                {
                    "vendorProject": "Citrix",
                    "product": "NetScaler ADC",
                    "shortDescription": "Example description",
                    "vulnerabilityName": "Citrix example issue",
                    "required_action": "Patch now",
                    "knownRansomwareCampaignUse": "Unknown",
                    "cve": ["CVE-2099-0002"],
                    "vulncheck_xdb": [
                        {"xdb_url": "https://vulncheck.example.test/xdb/1"}
                    ],
                    "vulncheck_reported_exploitation": [
                        {"url": "https://evidence.example.test/post"}
                    ],
                    "reported_exploited_by_vulncheck_canaries": True,
                    "dueDate": "2026-04-10T00:00:00Z",
                    "cisa_date_added": "2026-04-11T00:00:00Z",
                    "date_added": "2026-04-08T00:00:00Z",
                }
            ],
        },
        "https://downloads.example.test/vulncheck-kev.json",
    )

    assert len(records) == 1
    assert records[0].source == "vulncheck_kev"
    assert records[0].source_url == "https://evidence.example.test/post"
    assert records[0].date_added == "2026-04-08"
    assert records[0].due_date == "2026-04-10"
    assert records[0].notes is not None


def test_vulncheck_adapter_fetches_backup_and_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = VulnCheckKevSourceAdapter(VulnCheckConfig(api_token="test-token"))

    def fake_fetch_json_url(
        url: str, *, bearer_token: str | None = None, timeout: int = 30
    ) -> dict[str, object]:
        del timeout
        assert bearer_token == "test-token"
        if url.endswith("/v3/backup/vulncheck-kev"):
            return {"data": [{"url": "https://downloads.example.test/vulncheck-kev.json"}]}
        return {
            "_timestamp": "2026-04-08T10:00:00Z",
            "data": [
                {
                    "vendorProject": "Citrix",
                    "product": "NetScaler ADC",
                    "shortDescription": "Example description",
                    "vulnerabilityName": "Citrix example issue",
                    "required_action": "Patch now",
                    "knownRansomwareCampaignUse": "Unknown",
                    "cve": ["CVE-2099-0002"],
                    "date_added": "2026-04-08T00:00:00Z",
                }
            ],
        }

    monkeypatch.setattr("palisade.core.kev_sources.fetch_json_url", fake_fetch_json_url)
    result = adapter.fetch()

    assert result.source == "vulncheck_kev"
    assert len(result.records) == 1
    assert result.records[0].cve_id == "CVE-2099-0002"


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


def test_default_source_adapters_include_vulncheck_when_env_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULNCHECK_API_TOKEN", "env-token")

    adapters = default_source_adapters()

    assert len(adapters) == 2
    assert adapters[0].source_name == "cisa_kev"
    assert adapters[1].source_name == "vulncheck_kev"

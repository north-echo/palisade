"""Controlled validation helpers for replay-lab scans."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from palisade.core.db import initialize_db_path
from palisade.core.kev import import_kev_json_file, sync_source_adapter
from palisade.core.kev_sources import FileKevSourceAdapter
from palisade.core.mock_lab import default_http_fixtures, start_named_fixture_servers
from palisade.edge_audit.scanner import EdgeAuditScanner, ScanOptions

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class ValidationResult:
    """Replay-lab validation output paths and summary values."""

    output_dir: Path
    db_path: Path
    summary_path: Path
    json_path: Path
    scan_id: str
    device_count: int
    finding_count: int
    expected_fixture_count: int
    matched_vendors: tuple[str, ...]


def run_http_fixture_validation(output_dir: Path) -> ValidationResult:
    """Run scanner validation against the default HTTP replay fixtures."""
    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = output_dir / "validation.db"
    summary_path = output_dir / "validation-summary.md"
    json_path = output_dir / "validation-summary.json"

    connection = initialize_db_path(db_path)
    import_kev_json_file(connection, PROJECT_ROOT / "demo" / "data" / "kev_demo.json")
    sync_source_adapter(
        connection,
        FileKevSourceAdapter(PROJECT_ROOT / "demo" / "data" / "supplemental_citrix_demo.json"),
    )
    scanner = EdgeAuditScanner(connection)
    fixtures = default_http_fixtures()
    stack, servers = start_named_fixture_servers(fixtures)
    with stack:
        result = scanner.scan(
            ["127.0.0.1"],
            ScanOptions(
                ports=tuple(server.port for server in servers),
                kev_scope="expanded",
                concurrency=1,
            ),
        )

    matched_vendors = tuple(
        sorted(
            {
                str(device.vendor)
                for device in result.devices
                if device.vendor is not None and device.method == "http_header"
            }
        )
    )
    payload = {
        "scan_id": result.scan_id,
        "device_count": len(result.devices),
        "finding_count": len(result.findings),
        "expected_fixture_count": len(fixtures),
        "matched_vendors": list(matched_vendors),
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path.write_text(render_validation_summary(payload), encoding="utf-8")
    return ValidationResult(
        output_dir=output_dir,
        db_path=db_path,
        summary_path=summary_path,
        json_path=json_path,
        scan_id=result.scan_id,
        device_count=len(result.devices),
        finding_count=len(result.findings),
        expected_fixture_count=len(fixtures),
        matched_vendors=matched_vendors,
    )


def render_validation_summary(payload: dict[str, object]) -> str:
    """Render a markdown summary for replay-lab validation."""
    return (
        "# PALISADE Validation Summary\n\n"
        f"- Scan ID: `{payload['scan_id']}`\n"
        f"- Devices detected: `{payload['device_count']}`\n"
        f"- Findings generated: `{payload['finding_count']}`\n"
        f"- Expected HTTP fixtures: `{payload['expected_fixture_count']}`\n"
        f"- Matched vendors: `{', '.join(cast_list_of_str(payload['matched_vendors']))}`\n"
    )


def cast_list_of_str(value: object) -> list[str]:
    """Validate a list of strings for summary rendering."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("Expected a list of strings")
    return value

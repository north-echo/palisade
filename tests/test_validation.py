from __future__ import annotations

from pathlib import Path

import pytest

from palisade.core.validation import render_validation_summary, run_http_fixture_validation


def test_render_validation_summary_includes_key_fields() -> None:
    summary = render_validation_summary(
        {
            "scan_id": "scan-1",
            "device_count": 7,
            "finding_count": 3,
            "expected_fixture_count": 7,
            "matched_vendors": ["Cisco", "Citrix", "Fortinet"],
        }
    )

    assert "PALISADE Validation Summary" in summary
    assert "scan-1" in summary
    assert "Cisco, Citrix, Fortinet" in summary


def test_run_http_fixture_validation_writes_outputs(tmp_path: Path) -> None:
    try:
        result = run_http_fixture_validation(tmp_path / "validation-out")
    except PermissionError:
        pytest.skip("Local socket binding is not permitted in this environment")

    assert result.db_path.exists()
    assert result.summary_path.exists()
    assert result.json_path.exists()
    assert result.expected_fixture_count == 7

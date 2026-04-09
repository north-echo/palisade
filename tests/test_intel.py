from __future__ import annotations

import json
from pathlib import Path

from palisade.core.intel import diff_intel_artifacts, validate_intel_artifact


def test_validate_intel_artifact_accepts_repo_templates() -> None:
    intel_dir = Path(__file__).resolve().parents[1] / "intel"

    for path in sorted(intel_dir.glob("*.json")):
        assert validate_intel_artifact(path) == []


def test_validate_intel_artifact_reports_missing_fields(tmp_path: Path) -> None:
    path = tmp_path / "vendor_priority.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "generated_at": "2026-04-09T00:00:00Z",
                "source_project": "test",
                "entries": [{"vendor": "VendorOnly"}],
            }
        ),
        encoding="utf-8",
    )

    errors = validate_intel_artifact(path)

    assert errors
    assert any("missing field: product_family" in error for error in errors)


def test_diff_intel_artifacts_reports_added_and_changed_entries(tmp_path: Path) -> None:
    baseline_dir = tmp_path / "baseline"
    candidate_dir = tmp_path / "candidate"
    baseline_dir.mkdir()
    candidate_dir.mkdir()
    baseline = baseline_dir / "advisory_watchlist.json"
    baseline_payload = {
        "schema_version": "1.0",
        "generated_at": "2026-04-09T00:00:00Z",
        "source_project": "test",
        "entries": [
            {
                "cve_id": "CVE-2099-0001",
                "vendor": "VendorA",
                "product": "ProductA",
                "source": "watchlist",
                "source_url": "https://example.test/a",
                "exploitation_signal": "scan",
                "ics_relevance": "possible",
                "confidence": "medium",
                "notes": "baseline",
            }
        ],
    }
    candidate_payload = {
        **baseline_payload,
        "entries": [
            {
                "cve_id": "CVE-2099-0001",
                "vendor": "VendorA",
                "product": "ProductA",
                "source": "watchlist",
                "source_url": "https://example.test/a",
                "exploitation_signal": "scan",
                "ics_relevance": "possible",
                "confidence": "medium",
                "notes": "updated",
            },
            {
                "cve_id": "CVE-2099-0002",
                "vendor": "VendorB",
                "product": "ProductB",
                "source": "watchlist",
                "source_url": "https://example.test/b",
                "exploitation_signal": "probe",
                "ics_relevance": "likely",
                "confidence": "high",
                "notes": "new",
            },
        ],
    }
    baseline.write_text(json.dumps(baseline_payload), encoding="utf-8")
    real_candidate = candidate_dir / "advisory_watchlist.json"
    real_candidate.write_text(json.dumps(candidate_payload), encoding="utf-8")

    diff = diff_intel_artifacts(baseline, real_candidate)

    assert diff["added_count"] == 1
    assert diff["changed_count"] == 1
    assert diff["removed_count"] == 0

from __future__ import annotations

import json
from pathlib import Path

from palisade.edge_audit.signatures.loader import (
    DEFAULT_SIGNATURE_PATH,
    load_signatures,
    query_signature_by_cve,
    query_signatures,
)


def test_load_default_signatures() -> None:
    signatures = load_signatures()

    assert len(signatures) == 6
    assert query_signature_by_cve(signatures, "CVE-2024-3400") is not None


def test_query_signatures_by_vendor_and_product() -> None:
    signatures = load_signatures()

    results = query_signatures(signatures, "fortinet", "FortiOS")

    assert len(results) == 1
    assert results[0].cve_id == "CVE-2024-21762"


def test_load_custom_signature_file(tmp_path: Path) -> None:
    custom_path = tmp_path / "custom.json"
    custom_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "signatures": [
                    {
                        "cve_id": "CVE-2099-0001",
                        "vendor": "f5",
                        "product": "BIG-IP",
                        "product_families": [],
                        "affected_versions": {"operator": "exact", "version": "1.2.3"},
                        "fixed_version": "1.2.4",
                        "references": [],
                        "cpg_ids": ["1.A"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    signatures = load_signatures(custom_path)

    assert len(signatures) == 1
    assert signatures[0].cve_id == "CVE-2099-0001"


def test_default_signature_path_exists() -> None:
    assert DEFAULT_SIGNATURE_PATH.exists()

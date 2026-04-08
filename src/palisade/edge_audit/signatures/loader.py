"""Signature loading and query helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

DEFAULT_SIGNATURE_PATH: Final[Path] = Path(__file__).with_name("kev_edge.json")


@dataclass(frozen=True)
class Signature:
    """Typed representation of a KEV-derived signature."""

    cve_id: str
    vendor: str
    product: str
    product_families: tuple[str, ...]
    affected_versions: dict[str, object]
    fixed_version: str | None
    kev_date_added: str | None
    known_ransomware_use: str | None
    severity: str | None
    remediation: str | None
    references: tuple[str, ...]
    cpg_ids: tuple[str, ...]


def load_signatures(path: Path | None = None) -> list[Signature]:
    """Load signatures from a JSON file."""
    source = path or DEFAULT_SIGNATURE_PATH
    payload = json.loads(source.read_text(encoding="utf-8"))
    return parse_signatures(payload)


def parse_signatures(payload: dict[str, Any]) -> list[Signature]:
    """Parse signature payload JSON into typed signatures."""
    signatures = payload.get("signatures")
    if not isinstance(signatures, list):
        raise ValueError("Signature payload is missing a valid 'signatures' list")

    return [parse_signature(item) for item in signatures]


def parse_signature(payload: dict[str, Any]) -> Signature:
    """Parse a single signature object."""
    affected = payload.get("affected_versions")
    if not isinstance(affected, dict):
        raise ValueError("Signature affected_versions must be an object")

    families = payload.get("product_families", [])
    refs = payload.get("references", [])
    cpg_ids = payload.get("cpg_ids", [])
    if not isinstance(families, list) or not all(isinstance(item, str) for item in families):
        raise ValueError("Signature product_families must be a list of strings")
    if not isinstance(refs, list) or not all(isinstance(item, str) for item in refs):
        raise ValueError("Signature references must be a list of strings")
    if not isinstance(cpg_ids, list) or not all(isinstance(item, str) for item in cpg_ids):
        raise ValueError("Signature cpg_ids must be a list of strings")

    return Signature(
        cve_id=require_str(payload, "cve_id"),
        vendor=require_str(payload, "vendor"),
        product=require_str(payload, "product"),
        product_families=tuple(families),
        affected_versions=affected,
        fixed_version=optional_str(payload, "fixed_version"),
        kev_date_added=optional_str(payload, "kev_date_added"),
        known_ransomware_use=optional_str(payload, "known_ransomware_use"),
        severity=optional_str(payload, "severity"),
        remediation=optional_str(payload, "remediation"),
        references=tuple(refs),
        cpg_ids=tuple(cpg_ids),
    )


def query_signatures(signatures: list[Signature], vendor: str, product: str) -> list[Signature]:
    """Return signatures matching a vendor/product pair."""
    return [
        signature
        for signature in signatures
        if signature.vendor.lower() == vendor.lower()
        and signature.product.lower() == product.lower()
    ]


def query_signature_by_cve(signatures: list[Signature], cve_id: str) -> Signature | None:
    """Return a single signature by CVE ID."""
    for signature in signatures:
        if signature.cve_id == cve_id:
            return signature
    return None


def require_str(payload: dict[str, object], key: str) -> str:
    """Return a required string field."""
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Signature field {key!r} must be a non-empty string")
    return value


def optional_str(payload: dict[str, object], key: str) -> str | None:
    """Return an optional string field."""
    value = payload.get(key)
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError(f"Signature field {key!r} must be a string when present")
    return value

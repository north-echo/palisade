"""Source adapter interfaces for exploited-vulnerability feeds."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from palisade.core.kev import KevRecord


@dataclass(frozen=True)
class SourceFetchResult:
    """Normalized source adapter result."""

    source: str
    catalog_version: str | None
    records: list[KevRecord]


class KevSourceAdapter(Protocol):
    """Interface for exploited-vulnerability source adapters."""

    source_name: str

    def fetch(self) -> SourceFetchResult:
        """Fetch and normalize records from the source."""


class CisaKevSourceAdapter:
    """Source adapter for CISA KEV."""

    source_name = "cisa_kev"

    def fetch(self) -> SourceFetchResult:
        from palisade.core.kev import fetch_kev_feed, parse_kev_payload

        payload = fetch_kev_feed()
        records, catalog_version = parse_kev_payload(payload)
        return SourceFetchResult(
            source=self.source_name,
            catalog_version=catalog_version,
            records=records,
        )


class FileKevSourceAdapter:
    """Adapter for local supplemental exploited-vulnerability data files."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.source_name = f"file:{path.stem}"

    def fetch(self) -> SourceFetchResult:
        from palisade.core.kev import load_kev_json

        payload = load_kev_json(self.path)
        catalog_version = payload.get("catalogVersion")
        if catalog_version is not None and not isinstance(catalog_version, str):
            raise ValueError("Supplemental source catalogVersion must be a string when present")

        records_payload = payload.get("records")
        if not isinstance(records_payload, list):
            raise ValueError("Supplemental source file must contain a 'records' list")

        records: list[KevRecord] = []
        for item in records_payload:
            if not isinstance(item, dict):
                raise ValueError("Supplemental source records must be JSON objects")
            source = require_string(item, "source")
            records.append(
                KevRecord(
                    cve_id=require_string(item, "cve_id"),
                    vendor_project=require_string(item, "vendor_project"),
                    product=require_string(item, "product"),
                    vulnerability_name=require_string(item, "vulnerability_name"),
                    date_added=require_string(item, "date_added"),
                    short_description=optional_string(item, "short_description"),
                    required_action=optional_string(item, "required_action"),
                    due_date=optional_string(item, "due_date"),
                    known_ransomware_use=optional_string(item, "known_ransomware_use"),
                    notes=optional_string(item, "notes"),
                    source=source,
                    source_record_id=optional_string(item, "source_record_id"),
                    source_confidence=require_string(item, "source_confidence"),
                    source_url=optional_string(item, "source_url"),
                )
            )
        return SourceFetchResult(
            source=self.source_name,
            catalog_version=catalog_version,
            records=records,
        )


@dataclass(frozen=True)
class VulnCheckConfig:
    """Configuration for a future VulnCheck adapter."""

    api_token: str
    base_url: str = "https://api.vulncheck.com"


class VulnCheckKevSourceAdapter:
    """Placeholder adapter shape for future VulnCheck integration."""

    source_name = "vulncheck_kev"

    def __init__(self, config: VulnCheckConfig) -> None:
        self.config = config

    def fetch(self) -> SourceFetchResult:
        raise NotImplementedError(
            "VulnCheck KEV integration is not implemented yet. "
            "This adapter defines the source interface and configuration shape only."
        )


def default_source_adapters() -> list[KevSourceAdapter]:
    """Return the default enabled source adapters."""
    return [CisaKevSourceAdapter()]


def require_string(payload: dict[str, object], key: str) -> str:
    """Return a required string field."""
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Supplemental source field {key!r} must be a non-empty string")
    return value


def optional_string(payload: dict[str, object], key: str) -> str | None:
    """Return an optional string field."""
    value = payload.get(key)
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError(f"Supplemental source field {key!r} must be a string when present")
    return value

"""Source adapter interfaces for exploited-vulnerability feeds."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.request import Request, urlopen

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
    """Configuration for VulnCheck KEV access."""

    api_token: str
    base_url: str = "https://api.vulncheck.com"
    timeout: int = 30


class VulnCheckKevSourceAdapter:
    """Source adapter for VulnCheck KEV."""

    source_name = "vulncheck_kev"

    def __init__(self, config: VulnCheckConfig) -> None:
        self.config = config

    def fetch(self) -> SourceFetchResult:
        backup_payload = fetch_json_url(
            f"{self.config.base_url}/v3/backup/vulncheck-kev",
            bearer_token=self.config.api_token,
            timeout=self.config.timeout,
        )
        download_url = parse_backup_download_url(backup_payload)
        payload = fetch_json_url(
            download_url,
            bearer_token=self.config.api_token,
            timeout=self.config.timeout,
        )
        records = parse_vulncheck_records(payload, download_url)
        return SourceFetchResult(
            source=self.source_name,
            catalog_version=optional_top_level_timestamp(payload),
            records=records,
        )


def default_source_adapters() -> list[KevSourceAdapter]:
    """Return the default enabled source adapters."""
    adapters: list[KevSourceAdapter] = [CisaKevSourceAdapter()]
    api_token = os.getenv("VULNCHECK_API_TOKEN")
    if api_token:
        adapters.append(VulnCheckKevSourceAdapter(VulnCheckConfig(api_token=api_token)))
    return adapters


def fetch_json_url(
    url: str, *, bearer_token: str | None = None, timeout: int = 30
) -> dict[str, object]:
    """Fetch and decode JSON from a URL."""
    headers = {"Accept": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("Expected a JSON object response from the source endpoint")
    return payload


def parse_backup_download_url(payload: dict[str, object]) -> str:
    """Extract the first download URL from a VulnCheck backup response."""
    data = payload.get("data")
    if not isinstance(data, list) or not data:
        raise ValueError("VulnCheck backup response is missing a valid data list")
    first = data[0]
    if not isinstance(first, dict):
        raise ValueError("VulnCheck backup entries must be objects")
    url = first.get("url")
    if not isinstance(url, str) or not url:
        raise ValueError("VulnCheck backup entry is missing a download URL")
    return url


def parse_vulncheck_records(payload: dict[str, object], source_url: str) -> list[KevRecord]:
    """Normalize VulnCheck KEV JSON into internal records."""
    data = payload.get("data")
    if not isinstance(data, list):
        raise ValueError("VulnCheck KEV payload is missing a valid data list")

    records: list[KevRecord] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("VulnCheck KEV entries must be objects")
        cves = item.get("cve")
        if not isinstance(cves, list) or not cves or not all(isinstance(cve, str) for cve in cves):
            raise ValueError("VulnCheck KEV entry is missing a valid cve list")
        evidence_urls = collect_evidence_urls(item)
        record_url = evidence_urls[0] if evidence_urls else source_url
        for cve_id in cves:
            records.append(
                KevRecord(
                    cve_id=cve_id,
                    vendor_project=require_string(item, "vendorProject"),
                    product=require_string(item, "product"),
                    vulnerability_name=require_string(item, "vulnerabilityName"),
                    date_added=normalize_date_string(require_string(item, "date_added")),
                    short_description=optional_string(item, "shortDescription"),
                    required_action=optional_string(item, "required_action"),
                    due_date=normalize_optional_date(optional_string(item, "dueDate")),
                    known_ransomware_use=optional_string(item, "knownRansomwareCampaignUse"),
                    notes=build_vulncheck_notes(item),
                    source="vulncheck_kev",
                    source_record_id=cve_id,
                    source_confidence="commercial_evidence_based",
                    source_url=record_url,
                )
            )
    return records


def collect_evidence_urls(payload: dict[str, object]) -> list[str]:
    """Return evidence URLs from a VulnCheck entry."""
    urls: list[str] = []
    for key, field_name in (
        ("vulncheck_reported_exploitation", "url"),
        ("vulncheck_xdb", "xdb_url"),
    ):
        items = payload.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            value = item.get(field_name)
            if isinstance(value, str) and value and value not in urls:
                urls.append(value)
    return urls


def build_vulncheck_notes(payload: dict[str, object]) -> str | None:
    """Build a compact notes string from VulnCheck-specific evidence fields."""
    note_parts: list[str] = []
    if payload.get("reported_exploited_by_vulncheck_canaries") is True:
        note_parts.append("VulnCheck canaries reported exploitation")
    cisa_date_added = optional_string(payload, "cisa_date_added")
    if cisa_date_added is not None:
        note_parts.append(f"CISA date added: {normalize_date_string(cisa_date_added)}")
    evidence_urls = collect_evidence_urls(payload)
    if evidence_urls:
        note_parts.append(f"evidence URLs: {len(evidence_urls)}")
    if not note_parts:
        return None
    return "; ".join(note_parts)


def optional_top_level_timestamp(payload: dict[str, object]) -> str | None:
    """Return a compact top-level timestamp if present."""
    value = payload.get("_timestamp")
    if isinstance(value, str) and value:
        return value
    return None


def normalize_date_string(value: str) -> str:
    """Convert an RFC3339 or date string to YYYY-MM-DD when possible."""
    if len(value) >= 10:
        return value[:10]
    return value


def normalize_optional_date(value: str | None) -> str | None:
    """Normalize optional date strings."""
    if value is None:
        return None
    return normalize_date_string(value)


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

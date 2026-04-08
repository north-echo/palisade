"""CISA KEV parsing and storage helpers."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast
from urllib.request import urlopen

KEV_FEED_URL: Final[str] = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


@dataclass(frozen=True)
class KevRecord:
    """Normalized KEV record stored in SQLite."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str | None
    required_action: str | None
    due_date: str | None
    known_ransomware_use: str | None
    notes: str | None
    source: str = "cisa_kev"
    source_record_id: str | None = None
    source_confidence: str = "authoritative_public"
    source_url: str | None = KEV_FEED_URL


def fetch_kev_feed(url: str = KEV_FEED_URL, timeout: int = 30) -> dict[str, Any]:
    """Fetch the KEV feed from CISA."""
    with urlopen(url, timeout=timeout) as response:
        return cast(dict[str, Any], json.load(response))


def load_kev_json(path: Path) -> dict[str, Any]:
    """Load KEV JSON from disk."""
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def write_kev_json(path: Path, payload: dict[str, Any]) -> None:
    """Write KEV JSON to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_kev_payload(payload: dict[str, Any]) -> tuple[list[KevRecord], str | None]:
    """Parse KEV feed JSON into normalized records and catalog version."""
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("KEV payload is missing a valid 'vulnerabilities' list")

    records: list[KevRecord] = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            raise ValueError("KEV vulnerability entries must be JSON objects")
        records.append(
            KevRecord(
                cve_id=require_str(item, "cveID"),
                vendor_project=require_str(item, "vendorProject"),
                product=require_str(item, "product"),
                vulnerability_name=require_str(item, "vulnerabilityName"),
                date_added=require_str(item, "dateAdded"),
                short_description=optional_str(item, "shortDescription"),
                required_action=optional_str(item, "requiredAction"),
                due_date=optional_str(item, "dueDate"),
                known_ransomware_use=optional_str(item, "knownRansomwareCampaignUse"),
                notes=optional_str(item, "notes"),
                source="cisa_kev",
                source_record_id=require_str(item, "cveID"),
                source_confidence="authoritative_public",
                source_url=KEV_FEED_URL,
            )
        )

    catalog_version = optional_str(payload, "catalogVersion")
    return records, catalog_version


def require_str(payload: dict[str, Any], key: str) -> str:
    """Return a required string field."""
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"KEV payload field {key!r} must be a non-empty string")
    return value


def optional_str(payload: dict[str, Any], key: str) -> str | None:
    """Return an optional string field."""
    value = payload.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"KEV payload field {key!r} must be a string when present")
    return value


def upsert_kev_records(
    connection: sqlite3.Connection,
    records: list[KevRecord],
    *,
    catalog_version: str | None = None,
) -> None:
    """Insert or update KEV records and metadata."""
    with connection:
        connection.executemany(
            """
            INSERT INTO kev_vulnerabilities (
                cve_id,
                vendor_project,
                product,
                vulnerability_name,
                date_added,
                short_description,
                required_action,
                due_date,
                known_ransomware_use,
                notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                vendor_project = excluded.vendor_project,
                product = excluded.product,
                vulnerability_name = excluded.vulnerability_name,
                date_added = excluded.date_added,
                short_description = excluded.short_description,
                required_action = excluded.required_action,
                due_date = excluded.due_date,
                known_ransomware_use = excluded.known_ransomware_use,
                notes = excluded.notes,
                fetched_at = datetime('now')
            """,
            [
                (
                    record.cve_id,
                    record.vendor_project,
                    record.product,
                    record.vulnerability_name,
                    record.date_added,
                    record.short_description,
                    record.required_action,
                    record.due_date,
                    record.known_ransomware_use,
                    record.notes,
                )
                for record in records
            ],
        )
        connection.executemany(
            """
            INSERT INTO kev_sources(
                cve_id,
                source,
                source_record_id,
                source_confidence,
                source_url,
                catalog_version,
                last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(cve_id, source) DO UPDATE SET
                source_record_id = excluded.source_record_id,
                source_confidence = excluded.source_confidence,
                source_url = excluded.source_url,
                catalog_version = excluded.catalog_version,
                last_seen_at = datetime('now')
            """,
            [
                (
                    record.cve_id,
                    record.source,
                    record.source_record_id,
                    record.source_confidence,
                    record.source_url,
                    catalog_version,
                )
                for record in records
            ],
        )
        set_meta(connection, "last_sync", current_db_timestamp(connection))
        set_meta(connection, "total_count", str(len(records)))
        if catalog_version is not None:
            set_meta(connection, "catalog_version", catalog_version)
        existing_sources = get_meta(connection, "kev_sources_enabled")
        existing_set = (
            {item for item in existing_sources.split(",") if item}
            if existing_sources is not None
            else set()
        )
        source_names = existing_set | {record.source for record in records}
        set_meta(connection, "kev_sources_enabled", ",".join(sorted(source_names)))


def import_kev_json_file(connection: sqlite3.Connection, path: Path) -> int:
    """Load KEV JSON from disk and store it in SQLite."""
    payload = load_kev_json(path)
    return import_kev_payload(connection, payload)


def import_kev_payload(connection: sqlite3.Connection, payload: dict[str, Any]) -> int:
    """Load KEV JSON payload and store it in SQLite."""
    records, catalog_version = parse_kev_payload(payload)
    upsert_kev_records(connection, records, catalog_version=catalog_version)
    return len(records)


def sync_kev_feed(connection: sqlite3.Connection, *, url: str = KEV_FEED_URL) -> int:
    """Fetch the live KEV feed and store it in SQLite."""
    payload = fetch_kev_feed(url=url)
    return import_kev_payload(connection, payload)


def sync_source_adapter(
    connection: sqlite3.Connection, adapter: object
) -> tuple[str, int]:
    """Fetch from a source adapter and store normalized records."""
    fetch = getattr(adapter, "fetch")
    result = fetch()
    source = str(getattr(result, "source"))
    catalog_version = getattr(result, "catalog_version")
    records = getattr(result, "records")
    if not isinstance(records, list) or not all(isinstance(item, KevRecord) for item in records):
        raise ValueError("Source adapter returned invalid record payload")
    upsert_kev_records(connection, records, catalog_version=catalog_version)
    return source, len(records)


def export_kev_json_file(connection: sqlite3.Connection, path: Path) -> None:
    """Export locally stored KEV records to JSON."""
    payload = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": get_meta(connection, "catalog_version"),
        "count": count_kev_records(connection),
        "vulnerabilities": [
            {
                "cveID": row["cve_id"],
                "vendorProject": row["vendor_project"],
                "product": row["product"],
                "vulnerabilityName": row["vulnerability_name"],
                "dateAdded": row["date_added"],
                "shortDescription": row["short_description"] or "",
                "requiredAction": row["required_action"] or "",
                "dueDate": row["due_date"] or "",
                "knownRansomwareCampaignUse": row["known_ransomware_use"] or "",
                "notes": row["notes"] or "",
            }
            for row in connection.execute(
                """
                SELECT
                    cve_id,
                    vendor_project,
                    product,
                    vulnerability_name,
                    date_added,
                    short_description,
                    required_action,
                    due_date,
                    known_ransomware_use,
                    notes
                FROM kev_vulnerabilities
                ORDER BY date_added DESC, cve_id ASC
                """
            ).fetchall()
        ],
    }
    write_kev_json(path, payload)


def get_sync_status(connection: sqlite3.Connection) -> dict[str, str | int | None]:
    """Return KEV sync status fields."""
    return {
        "catalog_version": get_meta(connection, "catalog_version"),
        "last_sync": get_meta(connection, "last_sync"),
        "total_count": count_kev_records(connection),
        "sources_enabled": get_meta(connection, "kev_sources_enabled"),
    }


def count_kev_records(connection: sqlite3.Connection) -> int:
    """Return the number of KEV records stored locally."""
    row = connection.execute(
        "SELECT COUNT(*) AS count FROM kev_vulnerabilities"
    ).fetchone()
    assert row is not None
    return int(row["count"])


def get_meta(connection: sqlite3.Connection, key: str) -> str | None:
    """Return a metadata value."""
    row = connection.execute("SELECT value FROM kev_meta WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    return str(row["value"])


def set_meta(connection: sqlite3.Connection, key: str, value: str) -> None:
    """Set a metadata key."""
    connection.execute(
        """
        INSERT INTO kev_meta(key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )


def current_db_timestamp(connection: sqlite3.Connection) -> str:
    """Return the current SQLite timestamp string."""
    row = connection.execute("SELECT datetime('now') AS now").fetchone()
    assert row is not None
    return str(row["now"])


def query_by_vendor(connection: sqlite3.Connection, vendor: str) -> list[sqlite3.Row]:
    """Return KEV rows for a vendor."""
    return connection.execute(
        """
        SELECT *
        FROM kev_vulnerabilities
        WHERE lower(vendor_project) = lower(?)
        ORDER BY date_added DESC, cve_id ASC
        """,
        (vendor,),
    ).fetchall()


def query_by_product(
    connection: sqlite3.Connection, vendor: str, product: str
) -> list[sqlite3.Row]:
    """Return KEV rows for a vendor/product pair."""
    return connection.execute(
        """
        SELECT *
        FROM kev_vulnerabilities
        WHERE lower(vendor_project) = lower(?) AND lower(product) = lower(?)
        ORDER BY date_added DESC, cve_id ASC
        """,
        (vendor, product),
    ).fetchall()


def query_by_cve(connection: sqlite3.Connection, cve_id: str) -> sqlite3.Row | None:
    """Return a single KEV row by CVE."""
    row: sqlite3.Row | None = connection.execute(
        "SELECT * FROM kev_vulnerabilities WHERE cve_id = ?",
        (cve_id,),
    ).fetchone()
    return row


def query_edge_devices(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return KEV rows for the supported edge-focused vendors."""
    vendors = ("Cisco", "F5", "Fortinet", "Ivanti", "Palo Alto Networks", "SonicWall")
    placeholders = ", ".join("?" for _ in vendors)
    return connection.execute(
        f"""
        SELECT *
        FROM kev_vulnerabilities
        WHERE vendor_project IN ({placeholders})
        ORDER BY date_added DESC, cve_id ASC
        """,
        vendors,
    ).fetchall()


def list_kev_sources(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return configured KEV source associations."""
    return connection.execute(
        """
        SELECT
            source,
            source_confidence,
            catalog_version,
            COUNT(*) AS cve_count
        FROM kev_sources
        GROUP BY source, source_confidence, catalog_version
        ORDER BY source
        """
    ).fetchall()

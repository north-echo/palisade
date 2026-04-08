"""SQLite helpers for PALISADE state."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Final

SCHEMA_VERSION: Final[int] = 3

SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kev_vulnerabilities (
        cve_id TEXT PRIMARY KEY,
        vendor_project TEXT NOT NULL,
        product TEXT NOT NULL,
        vulnerability_name TEXT NOT NULL,
        date_added TEXT NOT NULL,
        short_description TEXT,
        required_action TEXT,
        due_date TEXT,
        known_ransomware_use TEXT,
        notes TEXT,
        fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_kev_vendor ON kev_vulnerabilities(vendor_project)",
    "CREATE INDEX IF NOT EXISTS idx_kev_product ON kev_vulnerabilities(product)",
    "CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_vulnerabilities(date_added)",
    """
    CREATE TABLE IF NOT EXISTS kev_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kev_sources (
        cve_id TEXT NOT NULL REFERENCES kev_vulnerabilities(cve_id),
        source TEXT NOT NULL,
        source_record_id TEXT,
        source_confidence TEXT NOT NULL,
        source_url TEXT,
        catalog_version TEXT,
        first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (cve_id, source)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_kev_sources_source ON kev_sources(source)",
    """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        target_spec TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'running',
        kev_scope TEXT NOT NULL DEFAULT 'expanded',
        concurrency INTEGER NOT NULL DEFAULT 1,
        device_count INTEGER DEFAULT 0,
        finding_count INTEGER DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        asset_id TEXT,
        scan_id TEXT NOT NULL REFERENCES scans(scan_id),
        ip_address TEXT NOT NULL,
        port INTEGER,
        vendor TEXT,
        product TEXT,
        version TEXT,
        fingerprint_method TEXT,
        raw_fingerprint TEXT,
        discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_devices_scan ON devices(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_devices_asset ON devices(asset_id)",
    """
    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(scan_id),
        device_id TEXT NOT NULL REFERENCES devices(device_id),
        asset_id TEXT,
        cve_id TEXT NOT NULL,
        vendor TEXT NOT NULL,
        product TEXT NOT NULL,
        version_detected TEXT,
        version_fixed TEXT,
        confidence TEXT NOT NULL,
        kev_sources TEXT,
        kev_source_confidences TEXT,
        evidence_urls TEXT,
        cpg_ids TEXT,
        remediation TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id)",
)


def connect_db(path: Path) -> sqlite3.Connection:
    """Return a SQLite connection for the given path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_db(connection: sqlite3.Connection) -> None:
    """Create the database schema if it does not already exist."""
    with connection:
        for statement in SCHEMA_STATEMENTS:
            connection.execute(statement)
        ensure_schema_compatibility(connection)
        connection.execute(
            """
            INSERT OR IGNORE INTO schema_migrations(version)
            VALUES (?)
            """,
            (SCHEMA_VERSION,),
        )


def ensure_schema_compatibility(connection: sqlite3.Connection) -> None:
    """Apply additive compatibility changes for older local databases."""
    ensure_column(
        connection,
        "scans",
        "kev_scope",
        "ALTER TABLE scans ADD COLUMN kev_scope TEXT NOT NULL DEFAULT 'expanded'",
    )
    ensure_column(
        connection,
        "scans",
        "concurrency",
        "ALTER TABLE scans ADD COLUMN concurrency INTEGER NOT NULL DEFAULT 1",
    )
    ensure_column(
        connection,
        "devices",
        "asset_id",
        "ALTER TABLE devices ADD COLUMN asset_id TEXT",
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_devices_asset ON devices(asset_id)")
    ensure_column(
        connection,
        "findings",
        "asset_id",
        "ALTER TABLE findings ADD COLUMN asset_id TEXT",
    )
    ensure_column(
        connection,
        "findings",
        "kev_sources",
        "ALTER TABLE findings ADD COLUMN kev_sources TEXT",
    )
    ensure_column(
        connection,
        "findings",
        "kev_source_confidences",
        "ALTER TABLE findings ADD COLUMN kev_source_confidences TEXT",
    )
    ensure_column(
        connection,
        "findings",
        "evidence_urls",
        "ALTER TABLE findings ADD COLUMN evidence_urls TEXT",
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id)")
    backfill_asset_ids(connection)


def ensure_column(
    connection: sqlite3.Connection, table_name: str, column_name: str, statement: str
) -> None:
    """Add a column if it does not already exist."""
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing_columns = {str(row["name"]) for row in rows}
    if column_name in existing_columns:
        return
    connection.execute(statement)


def backfill_asset_ids(connection: sqlite3.Connection) -> None:
    """Populate asset identifiers for existing device and finding rows when missing."""
    from palisade.core.asset import compute_asset_id_from_fields

    device_rows = connection.execute(
        """
        SELECT device_id, ip_address, port, vendor, product, version, raw_fingerprint
        FROM devices
        WHERE asset_id IS NULL
        """
    ).fetchall()
    if device_rows:
        connection.executemany(
            """
            UPDATE devices
            SET asset_id = ?
            WHERE device_id = ?
            """,
            [
                (
                    compute_asset_id_from_fields(
                        ip=str(row["ip_address"]),
                        port=int(row["port"]),
                        vendor=str(row["vendor"]) if row["vendor"] is not None else None,
                        product=str(row["product"]) if row["product"] is not None else None,
                        version=str(row["version"]) if row["version"] is not None else None,
                        raw_data=str(row["raw_fingerprint"] or ""),
                    ),
                    str(row["device_id"]),
                )
                for row in device_rows
            ],
        )
    connection.execute(
        """
        UPDATE findings
        SET asset_id = (
            SELECT devices.asset_id
            FROM devices
            WHERE devices.device_id = findings.device_id
        )
        WHERE asset_id IS NULL
        """
    )


def initialize_db_path(path: Path) -> sqlite3.Connection:
    """Open and initialize a database at the given path."""
    connection = connect_db(path)
    initialize_db(connection)
    return connection


def get_applied_migrations(connection: sqlite3.Connection) -> list[int]:
    """Return applied schema migration versions."""
    rows = connection.execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    ).fetchall()
    return [int(row["version"]) for row in rows]

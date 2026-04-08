"""SQLite helpers for PALISADE state."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Final

SCHEMA_VERSION: Final[int] = 1

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
        device_count INTEGER DEFAULT 0,
        finding_count INTEGER DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
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
    """
    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(scan_id),
        device_id TEXT NOT NULL REFERENCES devices(device_id),
        cve_id TEXT NOT NULL,
        vendor TEXT NOT NULL,
        product TEXT NOT NULL,
        version_detected TEXT,
        version_fixed TEXT,
        confidence TEXT NOT NULL,
        cpg_ids TEXT,
        remediation TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id)",
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
        connection.execute(
            """
            INSERT OR IGNORE INTO schema_migrations(version)
            VALUES (?)
            """,
            (SCHEMA_VERSION,),
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

from __future__ import annotations

import sqlite3
from pathlib import Path

from palisade.core.db import (
    SCHEMA_VERSION,
    get_applied_migrations,
    initialize_db,
    initialize_db_path,
)


def table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        """,
        (table_name,),
    ).fetchone()
    return row is not None


def test_initialize_db_creates_expected_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "palisade.db"
    connection = initialize_db_path(db_path)

    assert table_exists(connection, "schema_migrations")
    assert table_exists(connection, "kev_vulnerabilities")
    assert table_exists(connection, "kev_meta")
    assert table_exists(connection, "kev_sources")
    assert table_exists(connection, "scans")
    assert table_exists(connection, "devices")
    assert table_exists(connection, "findings")


def test_initialize_db_records_schema_version_once(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "palisade.db"
    connection = initialize_db_path(db_path)

    initialize_db(connection)

    assert get_applied_migrations(connection) == [SCHEMA_VERSION]


def test_initialize_db_creates_parent_directory(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "state" / "palisade.db"

    initialize_db_path(db_path)

    assert db_path.exists()

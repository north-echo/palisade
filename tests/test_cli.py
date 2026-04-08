from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from palisade import __version__, cli
from palisade.cli import main
from palisade.core.device import DeviceFingerprint
from palisade.core.kev import import_kev_json_file


def test_cli_help_renders() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "kev-sync" in result.output
    assert "edge-audit" in result.output
    assert "report" in result.output


def test_cli_version_renders() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_edge_audit_help_renders() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["edge-audit", "--help"])
    assert result.exit_code == 0
    assert "--target" in result.output
    assert "--discover" in result.output


def test_kev_sync_import_then_status(tmp_path: Path) -> None:
    runner = CliRunner()
    fixture_path = Path(__file__).parent / "fixtures" / "kev_sample.json"
    db_path = tmp_path / "palisade.db"
    result = runner.invoke(
        main,
        [
            "--db-path",
            str(db_path),
            "kev-sync",
            "--import",
            str(fixture_path),
            "--status",
        ],
    )
    assert result.exit_code == 0
    assert "imported 3 KEV records" in result.output
    assert "catalog-version: 2026.04.08" in result.output
    assert "total-count: 3" in result.output
    assert "sources: cisa_kev" in result.output


def test_kev_sync_live_fetch_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    db_path = tmp_path / "palisade.db"
    fixture_path = Path(__file__).parent / "fixtures" / "kev_sample.json"

    def fake_sync_kev_feed(connection: sqlite3.Connection) -> int:
        return import_kev_json_file(connection, fixture_path)

    monkeypatch.setattr(cli, "sync_kev_feed", fake_sync_kev_feed)
    result = runner.invoke(main, ["--db-path", str(db_path), "kev-sync"])

    assert result.exit_code == 0
    assert "synced 3 KEV records" in result.output


def test_kev_sync_offline_reports_local_status(tmp_path: Path) -> None:
    runner = CliRunner()
    fixture_path = Path(__file__).parent / "fixtures" / "kev_sample.json"
    db_path = tmp_path / "palisade.db"

    runner.invoke(
        main,
        ["--db-path", str(db_path), "kev-sync", "--import", str(fixture_path)],
    )
    result = runner.invoke(main, ["--db-path", str(db_path), "kev-sync", "--offline"])

    assert result.exit_code == 0
    assert "offline mode requested" in result.output
    assert "total-count: 3" in result.output
    assert "sources: cisa_kev" in result.output


def test_edge_audit_json_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    db_path = tmp_path / "palisade.db"

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ports, config
        return [
            DeviceFingerprint(
                ip=ip,
                port=443,
                vendor="Fortinet",
                product="FortiOS",
                version="7.2.4",
                method="http_header",
                raw_data="fixture",
                confidence="high",
            )
        ]

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)
    result = runner.invoke(
        main,
        ["--db-path", str(db_path), "edge-audit", "--target", "192.0.2.15", "--output", "json"],
    )

    assert result.exit_code == 0
    assert '"devices"' in result.output
    assert '"findings"' in result.output


def test_edge_audit_history_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    db_path = tmp_path / "palisade.db"

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ports, config
        return [
            DeviceFingerprint(
                ip=ip,
                port=443,
                vendor="Palo Alto Networks",
                product="PAN-OS",
                version="11.0.2",
                method="http_header",
                raw_data="fixture",
                confidence="high",
            )
        ]

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)
    scan_result = runner.invoke(
        main,
        ["--db-path", str(db_path), "edge-audit", "--target", "192.0.2.16"],
    )
    assert scan_result.exit_code == 0

    history_result = runner.invoke(main, ["--db-path", str(db_path), "edge-audit", "--history"])
    assert history_result.exit_code == 0
    assert "status=completed" in history_result.output


def test_report_latest_json_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    db_path = tmp_path / "palisade.db"

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ports, config
        return [
            DeviceFingerprint(
                ip=ip,
                port=443,
                vendor="Fortinet",
                product="FortiOS",
                version="7.2.4",
                method="http_header",
                raw_data="fixture",
                confidence="high",
            )
        ]

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)
    runner.invoke(
        main,
        ["--db-path", str(db_path), "edge-audit", "--target", "192.0.2.18"],
    )
    result = runner.invoke(
        main,
        ["--db-path", str(db_path), "report", "--latest", "--format", "json"],
    )

    assert result.exit_code == 0
    assert '"scan"' in result.output
    assert '"findings"' in result.output


def test_report_writes_html_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    db_path = tmp_path / "palisade.db"
    output_path = tmp_path / "report.html"

    def fake_fingerprint_host(
        ip: str, ports: list[int], *, config: object | None = None
    ) -> list[DeviceFingerprint]:
        del ports, config
        return [
            DeviceFingerprint(
                ip=ip,
                port=443,
                vendor="Palo Alto Networks",
                product="PAN-OS",
                version="11.0.2",
                method="http_header",
                raw_data="fixture",
                confidence="high",
            )
        ]

    monkeypatch.setattr("palisade.edge_audit.scanner.fingerprint_host", fake_fingerprint_host)
    runner.invoke(
        main,
        ["--db-path", str(db_path), "edge-audit", "--target", "192.0.2.19"],
    )
    result = runner.invoke(
        main,
        [
            "--db-path",
            str(db_path),
            "report",
            "--latest",
            "--format",
            "html",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert "wrote html report" in result.output

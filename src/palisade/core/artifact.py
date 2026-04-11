"""Scan artifact export and import helpers."""

from __future__ import annotations

import json
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, cast

from palisade.core.report import render_report
from palisade.edge_audit.scanner import EdgeAuditScanner

BUNDLE_VERSION: Final[str] = "1"


def export_scan_bundle(
    connection: sqlite3.Connection,
    scan_id: str,
    output_path: Path,
) -> Path:
    """Export a scan and derived reports into a zip bundle."""
    scanner = EdgeAuditScanner(connection)
    scan = scanner.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"Unknown scan id: {scan_id}")
    devices, findings = scanner.get_scan_rows(scan_id)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(
            "manifest.json",
            json.dumps(
                {
                    "bundle_version": BUNDLE_VERSION,
                    "exported_at": utc_now(),
                    "scan_id": scan_id,
                    "device_count": len(devices),
                    "finding_count": len(findings),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
        bundle.writestr("scan.json", json.dumps(dict(scan), indent=2, sort_keys=True) + "\n")
        bundle.writestr(
            "devices.json",
            json.dumps([dict(device) for device in devices], indent=2, sort_keys=True) + "\n",
        )
        bundle.writestr(
            "findings.json",
            json.dumps([dict(finding) for finding in findings], indent=2, sort_keys=True) + "\n",
        )
        bundle.writestr("reports/report.txt", render_report("text", scan, devices, findings))
        bundle.writestr("reports/report.json", render_report("json", scan, devices, findings))
        bundle.writestr("reports/report.html", render_report("html", scan, devices, findings))
    return output_path


def import_scan_bundle(connection: sqlite3.Connection, input_path: Path) -> str:
    """Import a previously exported scan bundle."""
    with zipfile.ZipFile(input_path, "r") as bundle:
        scan = load_bundle_object(bundle, "scan.json")
        devices = load_bundle_list(bundle, "devices.json")
        findings = load_bundle_list(bundle, "findings.json")

    scan_id = require_string(scan, "scan_id")
    with connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO scans(
                scan_id, started_at, completed_at, target_spec, status, kev_scope,
                concurrency, device_count, finding_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                require_string(scan, "started_at"),
                optional_string(scan, "completed_at"),
                require_string(scan, "target_spec"),
                require_string(scan, "status"),
                require_string(scan, "kev_scope"),
                require_int(scan, "concurrency"),
                require_int(scan, "device_count"),
                require_int(scan, "finding_count"),
            ),
        )
        connection.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        connection.execute("DELETE FROM devices WHERE scan_id = ?", (scan_id,))
        connection.executemany(
            """
            INSERT INTO devices(
                device_id, asset_id, scan_id, ip_address, port, vendor, product, version,
                fingerprint_method, raw_fingerprint, discovered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    require_string(device, "device_id"),
                    optional_string(device, "asset_id"),
                    scan_id,
                    require_string(device, "ip_address"),
                    require_int(device, "port"),
                    optional_string(device, "vendor"),
                    optional_string(device, "product"),
                    optional_string(device, "version"),
                    optional_string(device, "fingerprint_method"),
                    optional_string(device, "raw_fingerprint"),
                    require_string(device, "discovered_at"),
                )
                for device in devices
            ],
        )
        connection.executemany(
            """
            INSERT INTO findings(
                finding_id, scan_id, device_id, asset_id, cve_id, vendor, product,
                version_detected, version_fixed, confidence, kev_sources,
                kev_source_confidences, evidence_urls, cpg_ids, waterisac_ids,
                remediation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    require_string(finding, "finding_id"),
                    scan_id,
                    require_string(finding, "device_id"),
                    optional_string(finding, "asset_id"),
                    require_string(finding, "cve_id"),
                    require_string(finding, "vendor"),
                    require_string(finding, "product"),
                    optional_string(finding, "version_detected"),
                    optional_string(finding, "version_fixed"),
                    require_string(finding, "confidence"),
                    optional_string(finding, "kev_sources"),
                    optional_string(finding, "kev_source_confidences"),
                    optional_string(finding, "evidence_urls"),
                    optional_string(finding, "cpg_ids"),
                    optional_string(finding, "waterisac_ids"),
                    optional_string(finding, "remediation"),
                    require_string(finding, "created_at"),
                )
                for finding in findings
            ],
        )
    return scan_id


def load_bundle_object(bundle: zipfile.ZipFile, name: str) -> dict[str, Any]:
    """Load a JSON object from a bundle."""
    payload = json.loads(bundle.read(name).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Bundle entry {name} must be a JSON object")
    return cast(dict[str, Any], payload)


def load_bundle_list(bundle: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    """Load a list of JSON objects from a bundle."""
    payload = json.loads(bundle.read(name).decode("utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"Bundle entry {name} must be a JSON list")
    if not all(isinstance(item, dict) for item in payload):
        raise ValueError(f"Bundle entry {name} must contain JSON objects")
    return cast(list[dict[str, Any]], payload)


def require_string(payload: dict[str, Any], key: str) -> str:
    """Return a required string field."""
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Bundle field {key!r} must be a non-empty string")
    return value


def optional_string(payload: dict[str, Any], key: str) -> str | None:
    """Return an optional string field."""
    value = payload.get(key)
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError(f"Bundle field {key!r} must be a string when present")
    return value


def require_int(payload: dict[str, Any], key: str) -> int:
    """Return a required integer field."""
    value = payload.get(key)
    if not isinstance(value, int):
        raise ValueError(f"Bundle field {key!r} must be an integer")
    return value


def utc_now() -> str:
    """Return a UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()

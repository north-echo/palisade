"""Edge-audit scanner orchestration."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from palisade.core.device import DeviceFingerprint, ProbeConfig, fingerprint_host
from palisade.core.version import is_affected
from palisade.edge_audit.signatures.loader import Signature, load_signatures, query_signatures


@dataclass(frozen=True)
class ScanFinding:
    """A matched exposure finding."""

    cve_id: str
    vendor: str
    product: str
    version_detected: str
    version_fixed: str | None
    confidence: str
    remediation: str | None
    cpg_ids: tuple[str, ...]


@dataclass(frozen=True)
class ScanResult:
    """Scanner output."""

    scan_id: str
    targets: list[str]
    devices: list[DeviceFingerprint]
    findings: list[ScanFinding]


@dataclass(frozen=True)
class ScanOptions:
    """Scan-time options."""

    discover_only: bool = False
    vendor_filter: str | None = None
    ports: tuple[int, ...] = (443, 4443, 8443, 10443)
    connection_timeout: float = 5.0
    read_timeout: float = 10.0


class EdgeAuditScanner:
    """Main orchestration for edge-audit scans."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        signatures: list[Signature] | None = None,
    ) -> None:
        self.connection = connection
        self.signatures = signatures if signatures is not None else load_signatures()

    def scan(self, targets: list[str], options: ScanOptions) -> ScanResult:
        """Run a scan against expanded targets."""
        scan_id = str(uuid.uuid4())
        expanded_targets = expand_targets(targets)
        self._create_scan(scan_id, ",".join(targets))

        devices: list[DeviceFingerprint] = []
        findings: list[ScanFinding] = []

        try:
            for target in expanded_targets:
                fingerprints = fingerprint_host(
                    target,
                    list(options.ports),
                    config=ProbeConfig(
                        connection_timeout=options.connection_timeout,
                        read_timeout=options.read_timeout,
                    ),
                )
                for fingerprint in fingerprints:
                    if options.vendor_filter and (
                        fingerprint.vendor is None
                        or fingerprint.vendor.lower() != options.vendor_filter.lower()
                    ):
                        continue
                    device_id = self._insert_device(scan_id, fingerprint)
                    devices.append(fingerprint)
                    if options.discover_only:
                        continue
                    findings.extend(self._match_and_store_findings(scan_id, device_id, fingerprint))
        except Exception:
            self._update_scan(scan_id, "failed", len(devices), len(findings))
            raise

        self._update_scan(scan_id, "completed", len(devices), len(findings))
        return ScanResult(
            scan_id=scan_id,
            targets=expanded_targets,
            devices=devices,
            findings=findings,
        )

    def list_history(self) -> list[sqlite3.Row]:
        """List previous scans."""
        return self.connection.execute(
            """
            SELECT
                scan_id,
                started_at,
                completed_at,
                target_spec,
                status,
                device_count,
                finding_count
            FROM scans
            ORDER BY started_at DESC
            """
        ).fetchall()

    def get_scan_rows(self, scan_id: str) -> tuple[list[sqlite3.Row], list[sqlite3.Row]]:
        """Return persisted device and finding rows for a scan."""
        devices = self.connection.execute(
            "SELECT * FROM devices WHERE scan_id = ? ORDER BY discovered_at, ip_address, port",
            (scan_id,),
        ).fetchall()
        findings = self.connection.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY created_at, cve_id",
            (scan_id,),
        ).fetchall()
        return devices, findings

    def get_scan(self, scan_id: str) -> sqlite3.Row | None:
        """Return a single scan row."""
        row: sqlite3.Row | None = self.connection.execute(
            "SELECT * FROM scans WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        return row

    def get_latest_scan_id(self) -> str | None:
        """Return the most recent scan ID."""
        row = self.connection.execute(
            "SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return str(row["scan_id"])

    def _create_scan(self, scan_id: str, target_spec: str) -> None:
        started_at = utc_now()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO scans(scan_id, started_at, target_spec, status)
                VALUES (?, ?, ?, 'running')
                """,
                (scan_id, started_at, target_spec),
            )

    def _update_scan(
        self, scan_id: str, status: str, device_count: int, finding_count: int
    ) -> None:
        completed_at = utc_now()
        with self.connection:
            self.connection.execute(
                """
                UPDATE scans
                SET completed_at = ?, status = ?, device_count = ?, finding_count = ?
                WHERE scan_id = ?
                """,
                (completed_at, status, device_count, finding_count, scan_id),
            )

    def _insert_device(self, scan_id: str, fingerprint: DeviceFingerprint) -> str:
        device_id = str(uuid.uuid4())
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO devices(
                    device_id, scan_id, ip_address, port, vendor, product, version,
                    fingerprint_method, raw_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    scan_id,
                    fingerprint.ip,
                    fingerprint.port,
                    fingerprint.vendor,
                    fingerprint.product,
                    fingerprint.version,
                    fingerprint.method,
                    fingerprint.raw_data,
                ),
            )
        return device_id

    def _match_and_store_findings(
        self, scan_id: str, device_id: str, fingerprint: DeviceFingerprint
    ) -> list[ScanFinding]:
        if (
            fingerprint.vendor is None
            or fingerprint.product is None
            or fingerprint.version is None
        ):
            return []

        signatures = query_signatures(self.signatures, fingerprint.vendor, fingerprint.product)
        findings: list[ScanFinding] = []
        for signature in signatures:
            if not is_affected(
                fingerprint.version,
                {
                    "vendor": signature.vendor,
                    "affected_versions": signature.affected_versions,
                },
            ):
                continue
            finding = ScanFinding(
                cve_id=signature.cve_id,
                vendor=fingerprint.vendor,
                product=fingerprint.product,
                version_detected=fingerprint.version,
                version_fixed=signature.fixed_version,
                confidence=fingerprint.confidence,
                remediation=signature.remediation,
                cpg_ids=signature.cpg_ids,
            )
            self._insert_finding(scan_id, device_id, finding)
            findings.append(finding)
        return findings

    def _insert_finding(self, scan_id: str, device_id: str, finding: ScanFinding) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO findings(
                    finding_id, scan_id, device_id, cve_id, vendor, product,
                    version_detected, version_fixed, confidence, cpg_ids, remediation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    scan_id,
                    device_id,
                    finding.cve_id,
                    finding.vendor,
                    finding.product,
                    finding.version_detected,
                    finding.version_fixed,
                    finding.confidence,
                    ",".join(finding.cpg_ids),
                    finding.remediation,
                ),
            )


def parse_targets(target: str | None, target_file: Path | None) -> list[str]:
    """Parse CLI target inputs into raw target tokens."""
    values: list[str] = []
    if target:
        values.extend(part.strip() for part in target.split(",") if part.strip())
    if target_file is not None:
        values.extend(
            line.strip()
            for line in target_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    if not values:
        raise ValueError("At least one target or target file must be provided")
    return values


def expand_targets(targets: list[str]) -> list[str]:
    """Expand CIDR targets while leaving single hosts unchanged."""
    expanded: list[str] = []
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            expanded.append(target)
            continue
        if network.num_addresses == 1:
            expanded.append(str(network.network_address))
        else:
            expanded.extend(str(host) for host in network.hosts())
    return expanded


def parse_ports(value: str | None) -> tuple[int, ...]:
    """Parse comma-separated ports."""
    if value is None:
        return (443, 4443, 8443, 10443)
    ports = tuple(int(part.strip()) for part in value.split(",") if part.strip())
    if not ports:
        raise ValueError("At least one port must be provided")
    return ports


def result_to_json(result: ScanResult) -> str:
    """Render a scan result as JSON."""
    payload = {
        "scan_id": result.scan_id,
        "targets": result.targets,
        "devices": [asdict(device) for device in result.devices],
        "findings": [asdict(finding) for finding in result.findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def utc_now() -> str:
    """Return a UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()

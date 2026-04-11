"""Edge-audit scanner orchestration."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from palisade.core.asset import compute_asset_id
from palisade.core.controls import derive_waterisac_ids
from palisade.core.device import DeviceFingerprint, ProbeConfig, fingerprint_host
from palisade.core.report import ReportDiff
from palisade.core.version import is_affected
from palisade.edge_audit.signatures.loader import Signature, load_signatures, query_signatures


@dataclass(frozen=True)
class ScanFinding:
    """A matched exposure finding."""

    cve_id: str
    asset_id: str
    vendor: str
    product: str
    version_detected: str
    version_fixed: str | None
    confidence: str
    kev_sources: tuple[str, ...]
    kev_source_confidences: tuple[str, ...]
    evidence_urls: tuple[str, ...]
    remediation: str | None
    cpg_ids: tuple[str, ...]
    waterisac_ids: tuple[str, ...]


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
    kev_scope: str = "expanded"
    concurrency: int = 1


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
        self._create_scan(scan_id, ",".join(targets), options)

        devices: list[DeviceFingerprint] = []
        findings: list[ScanFinding] = []

        try:
            for _, fingerprints in self._fingerprint_targets(expanded_targets, options):
                for fingerprint in fingerprints:
                    if options.vendor_filter and (
                        fingerprint.vendor is None
                        or fingerprint.vendor.lower() != options.vendor_filter.lower()
                    ):
                        continue
                    asset_id = compute_asset_id(fingerprint)
                    device_id = self._insert_device(scan_id, asset_id, fingerprint)
                    devices.append(fingerprint)
                    if options.discover_only:
                        continue
                    findings.extend(
                        self._match_and_store_findings(
                            scan_id, device_id, asset_id, fingerprint, options.kev_scope
                        )
                    )
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
                kev_scope,
                concurrency,
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

    def get_previous_scan_id(self, scan_id: str) -> str | None:
        """Return the scan ID immediately before the given scan."""
        row = self.connection.execute(
            """
            SELECT previous.scan_id
            FROM scans AS current
            JOIN scans AS previous
              ON previous.started_at < current.started_at
            WHERE current.scan_id = ?
            ORDER BY previous.started_at DESC
            LIMIT 1
            """,
            (scan_id,),
        ).fetchone()
        if row is None:
            return None
        return str(row["scan_id"])

    def diff_scans(self, baseline_scan_id: str, current_scan_id: str) -> ReportDiff:
        """Return a finding-level diff between two scans."""
        _, baseline_findings = self.get_scan_rows(baseline_scan_id)
        _, current_findings = self.get_scan_rows(current_scan_id)
        baseline_index = {finding_identity(row): row for row in baseline_findings}
        current_index = {finding_identity(row): row for row in current_findings}

        new_keys = sorted(current_index.keys() - baseline_index.keys())
        resolved_keys = sorted(baseline_index.keys() - current_index.keys())
        unchanged_keys = sorted(current_index.keys() & baseline_index.keys())
        return ReportDiff(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
            new_findings=[current_index[key] for key in new_keys],
            resolved_findings=[baseline_index[key] for key in resolved_keys],
            unchanged_findings=[current_index[key] for key in unchanged_keys],
        )

    def _create_scan(self, scan_id: str, target_spec: str, options: ScanOptions) -> None:
        started_at = utc_now()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO scans(
                    scan_id, started_at, target_spec, kev_scope, concurrency, status
                )
                VALUES (?, ?, ?, ?, ?, 'running')
                """,
                (scan_id, started_at, target_spec, options.kev_scope, options.concurrency),
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

    def _insert_device(
        self, scan_id: str, asset_id: str, fingerprint: DeviceFingerprint
    ) -> str:
        device_id = str(uuid.uuid4())
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO devices(
                    device_id, asset_id, scan_id, ip_address, port, vendor, product, version,
                    fingerprint_method, raw_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    asset_id,
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
        self,
        scan_id: str,
        device_id: str,
        asset_id: str,
        fingerprint: DeviceFingerprint,
        kev_scope: str,
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
            source_rows = self._get_source_rows(signature.cve_id, kev_scope)
            if not source_rows:
                continue
            finding = ScanFinding(
                cve_id=signature.cve_id,
                asset_id=asset_id,
                vendor=fingerprint.vendor,
                product=fingerprint.product,
                version_detected=fingerprint.version,
                version_fixed=signature.fixed_version,
                confidence=fingerprint.confidence,
                kev_sources=tuple(str(row["source"]) for row in source_rows),
                kev_source_confidences=tuple(
                    str(row["source_confidence"]) for row in source_rows
                ),
                evidence_urls=tuple(
                    str(row["source_url"])
                    for row in source_rows
                    if row["source_url"] is not None and str(row["source_url"])
                ),
                remediation=signature.remediation,
                cpg_ids=signature.cpg_ids,
                waterisac_ids=derive_waterisac_ids(signature.cpg_ids),
            )
            self._insert_finding(scan_id, device_id, finding)
            findings.append(finding)
        return findings

    def _insert_finding(self, scan_id: str, device_id: str, finding: ScanFinding) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO findings(
                    finding_id, scan_id, device_id, asset_id, cve_id, vendor, product,
                    version_detected, version_fixed, confidence, kev_sources,
                    kev_source_confidences, evidence_urls, cpg_ids, waterisac_ids, remediation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    scan_id,
                    device_id,
                    finding.asset_id,
                    finding.cve_id,
                    finding.vendor,
                    finding.product,
                    finding.version_detected,
                    finding.version_fixed,
                    finding.confidence,
                    ",".join(finding.kev_sources),
                    ",".join(finding.kev_source_confidences),
                    "\n".join(finding.evidence_urls),
                    ",".join(finding.cpg_ids),
                    ",".join(finding.waterisac_ids),
                    finding.remediation,
                ),
            )

    def _fingerprint_targets(
        self, expanded_targets: list[str], options: ScanOptions
    ) -> list[tuple[str, list[DeviceFingerprint]]]:
        probe_config = ProbeConfig(
            connection_timeout=options.connection_timeout,
            read_timeout=options.read_timeout,
        )
        if options.concurrency <= 1 or len(expanded_targets) <= 1:
            return [
                (
                    target,
                    fingerprint_host(target, list(options.ports), config=probe_config),
                )
                for target in expanded_targets
            ]

        def run_target(target: str) -> tuple[str, list[DeviceFingerprint]]:
            return target, fingerprint_host(target, list(options.ports), config=probe_config)

        with ThreadPoolExecutor(max_workers=options.concurrency) as executor:
            return list(executor.map(run_target, expanded_targets))

    def _get_source_rows(self, cve_id: str, kev_scope: str) -> list[sqlite3.Row]:
        all_rows = self.connection.execute(
            """
            SELECT source, source_confidence, source_url
            FROM kev_sources
            WHERE cve_id = ?
            ORDER BY source
            """,
            (cve_id,),
        ).fetchall()
        if kev_scope == "strict":
            rows = [row for row in all_rows if str(row["source"]) == "cisa_kev"]
            if rows:
                return rows
            if all_rows:
                return []
            return self._fallback_source_rows("cisa_kev_bundle")

        if all_rows:
            return all_rows
        return self._fallback_source_rows("signature_bundle")

    def _fallback_source_rows(self, source_name: str) -> list[sqlite3.Row]:
        row = self.connection.execute(
            """
            SELECT
                ? AS source,
                'bundled_signature' AS source_confidence,
                NULL AS source_url
            """,
            (source_name,),
        ).fetchone()
        assert row is not None
        return [row]


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


def finding_identity(row: sqlite3.Row) -> tuple[str, str, str, str]:
    """Return a stable finding identity for diffing."""
    return (
        str(row["asset_id"] or ""),
        str(row["cve_id"]),
        str(row["vendor"]),
        str(row["product"]),
    )

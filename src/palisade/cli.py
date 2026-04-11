"""Command-line interface for PALISADE."""

from __future__ import annotations

import os
from pathlib import Path

import click

from palisade import __version__
from palisade.core.artifact import export_scan_bundle, import_scan_bundle
from palisade.core.config import (
    config_to_json,
    load_config,
    resolve_config_path,
    write_default_config,
)
from palisade.core.db import initialize_db_path
from palisade.core.kev import (
    export_kev_json_file,
    get_sync_status,
    import_kev_json_file,
    sync_source_adapter,
)
from palisade.core.kev_sources import (
    FileKevSourceAdapter,
    VulnCheckConfig,
    VulnCheckKevSourceAdapter,
    default_source_adapters,
)
from palisade.core.report import ReportFilters, filter_report_rows, render_report
from palisade.edge_audit.scanner import (
    EdgeAuditScanner,
    ScanOptions,
    parse_ports,
    parse_targets,
    result_to_json,
)


def default_db_path() -> Path:
    """Return the default local SQLite path."""
    return Path("data") / "palisade.db"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="palisade")
@click.option("--verbose", is_flag=True, help="Enable verbose console output.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    help="Path to a PALISADE JSON config file.",
)
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default=None,
    show_default=str(default_db_path()),
    help="Path to the local SQLite database.",
)
@click.pass_context
def main(
    ctx: click.Context, verbose: bool, config_path: Path | None, db_path: Path | None
) -> None:
    """PALISADE operator-first OT security toolkit."""
    ctx.ensure_object(dict)
    config = load_config(config_path)
    ctx.obj["verbose"] = verbose
    ctx.obj["config"] = config
    ctx.obj["config_path"] = resolve_config_path(config_path)
    ctx.obj["db_path"] = db_path if db_path is not None else config.db_path


@main.command("kev-sync")
@click.option("--status", is_flag=True, help="Show KEV sync status.")
@click.option("--offline", is_flag=True, help="Use existing local KEV data only.")
@click.option(
    "--export",
    "export_path",
    type=click.Path(path_type=Path),
    help="Export KEV cache to a file.",
)
@click.option(
    "--import",
    "import_path",
    type=click.Path(path_type=Path),
    help="Import KEV cache from a file.",
)
@click.option(
    "--supplemental-source",
    "supplemental_source_paths",
    type=click.Path(path_type=Path),
    multiple=True,
    help="Import one or more supplemental exploited-vulnerability source files.",
)
@click.option(
    "--vulncheck-token",
    envvar="VULNCHECK_API_TOKEN",
    help="Enable VulnCheck KEV sync using the provided API token.",
)
@click.pass_context
def kev_sync(
    ctx: click.Context,
    status: bool,
    offline: bool,
    export_path: Path | None,
    import_path: Path | None,
    supplemental_source_paths: tuple[Path, ...],
    vulncheck_token: str | None,
) -> None:
    """Synchronize the local KEV cache."""
    db_path = ctx.obj["db_path"]
    config = ctx.obj["config"]
    connection = initialize_db_path(db_path)

    if import_path is not None:
        imported_count = import_kev_json_file(connection, import_path)
        click.echo(f"imported {imported_count} KEV records into {db_path}")

    supplemental_total = 0
    for supplemental_path in supplemental_source_paths:
        source_name, synced_count = sync_source_adapter(
            connection, FileKevSourceAdapter(supplemental_path)
        )
        supplemental_total += synced_count
        click.echo(f"imported {synced_count} records from {source_name} into {db_path}")

    if export_path is not None:
        export_kev_json_file(connection, export_path)
        click.echo(f"exported KEV cache to {export_path}")

    if status:
        kev_status = get_sync_status(connection)
        click.echo(f"db-path: {db_path}")
        click.echo(f"catalog-version: {kev_status['catalog_version'] or 'unknown'}")
        click.echo(f"last-sync: {kev_status['last_sync'] or 'never'}")
        click.echo(f"total-count: {kev_status['total_count']}")
        click.echo(f"sources: {kev_status['sources_enabled'] or 'none'}")
        return

    if import_path is not None or export_path is not None or supplemental_total > 0:
        return

    if offline:
        kev_status = get_sync_status(connection)
        click.echo("offline mode requested; using existing local KEV data")
        click.echo(f"db-path: {db_path}")
        click.echo(f"catalog-version: {kev_status['catalog_version'] or 'unknown'}")
        click.echo(f"last-sync: {kev_status['last_sync'] or 'never'}")
        click.echo(f"total-count: {kev_status['total_count']}")
        click.echo(f"sources: {kev_status['sources_enabled'] or 'none'}")
        return

    try:
        total_synced = 0
        synced_sources: list[str] = []
        for adapter in build_source_adapters(vulncheck_token or config.vulncheck_token):
            source_name, synced_count = sync_source_adapter(connection, adapter)
            synced_sources.append(source_name)
            total_synced += synced_count
    except Exception as exc:
        raise click.ClickException(f"KEV sync failed: {exc}") from exc

    click.echo(f"synced {total_synced} KEV records into {db_path}")
    click.echo(f"sources: {', '.join(synced_sources)}")


@main.command("edge-audit")
@click.option("--target", help="Single IP, hostname, or CIDR target.")
@click.option("--target-file", type=click.Path(path_type=Path), help="Read targets from file.")
@click.option("--discover", is_flag=True, help="Fingerprint only without signature matching.")
@click.option("--vendor", help="Restrict matching to a specific vendor.")
@click.option("--ports", help="Comma-separated management ports.")
@click.option("--timeout", type=int, help="Connection timeout in seconds.")
@click.option("--concurrency", type=int, help="Maximum concurrent connections.")
@click.option(
    "--kev-scope",
    type=click.Choice(["strict", "expanded"]),
    default=None,
    help="Use only CISA-backed KEV sources or include supplemental sources too.",
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json", "html"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option("--report", is_flag=True, help="Generate a saved report artifact.")
@click.option("--cpg-map", is_flag=True, help="Include CPG mapping in output.")
@click.option("--history", is_flag=True, help="List previous scans.")
@click.option("--scan-id", help="Show a specific historical scan.")
@click.option("--diff", "show_diff", is_flag=True, help="Show diff against the previous scan.")
@click.pass_context
def edge_audit(
    ctx: click.Context,
    target: str | None,
    target_file: Path | None,
    discover: bool,
    vendor: str | None,
    ports: str | None,
    timeout: int | None,
    concurrency: int | None,
    kev_scope: str | None,
    output_format: str,
    report: bool,
    cpg_map: bool,
    history: bool,
    scan_id: str | None,
    show_diff: bool,
) -> None:
    """Run non-intrusive edge-device exposure triage."""
    db_path = ctx.obj["db_path"]
    config = ctx.obj["config"]
    del report
    connection = initialize_db_path(db_path)
    scanner = EdgeAuditScanner(connection)

    if history:
        rows = scanner.list_history()
        if scan_id is not None:
            scan = scanner.get_scan(scan_id)
            if scan is None:
                raise click.ClickException(f"Unknown scan id: {scan_id}")
            devices, findings = scanner.get_scan_rows(scan_id)
            click.echo(f"scan-id: {scan_id}")
            click.echo(f"devices: {len(devices)}")
            click.echo(f"findings: {len(findings)}")
            if show_diff:
                baseline_scan_id = scanner.get_previous_scan_id(scan_id)
                if baseline_scan_id is None:
                    raise click.ClickException("No previous scan available for diffing")
                diff = scanner.diff_scans(baseline_scan_id, scan_id)
                click.echo(f"baseline-scan-id: {baseline_scan_id}")
                click.echo(f"new-findings: {len(diff.new_findings)}")
                click.echo(f"resolved-findings: {len(diff.resolved_findings)}")
            return
        for row in rows:
            click.echo(
                f"{row['scan_id']} status={row['status']} devices={row['device_count']} "
                f"findings={row['finding_count']} scope={row['kev_scope']} "
                f"concurrency={row['concurrency']} target={row['target_spec']}"
            )
        return

    try:
        targets = parse_targets(target, target_file)
        if output_format == "html":
            raise ValueError("edge-audit does not support html output; use the report command")
        scan_options = ScanOptions(
            discover_only=discover,
            vendor_filter=vendor,
            ports=parse_ports(ports),
            connection_timeout=float(timeout) if timeout is not None else 5.0,
            read_timeout=float(timeout) if timeout is not None else 10.0,
            kev_scope=kev_scope or config.default_kev_scope,
            concurrency=validate_concurrency(concurrency, default=config.default_concurrency),
        )
        result = scanner.scan(targets, scan_options)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    if output_format == "json":
        click.echo(result_to_json(result))
        return

    click.echo(f"scan-id: {result.scan_id}")
    click.echo(f"targets: {', '.join(result.targets)}")
    click.echo(f"devices: {len(result.devices)}")
    click.echo(f"findings: {len(result.findings)}")
    for device in result.devices:
        click.echo(
            f"device {device.ip}:{device.port} vendor={device.vendor or 'unknown'} "
            f"product={device.product or 'unknown'} version={device.version or 'unknown'} "
            f"confidence={device.confidence}"
        )
    for finding in result.findings:
        click.echo(
            f"finding {finding.cve_id} vendor={finding.vendor} product={finding.product} "
            f"version={finding.version_detected} fixed={finding.version_fixed or 'unknown'} "
            f"sources={','.join(finding.kev_sources)}"
        )
        if cpg_map:
            click.echo(f"  cisa-cpgs={','.join(finding.cpg_ids) or 'none'}")
            click.echo(f"  waterisac={','.join(finding.waterisac_ids) or 'none'}")


@main.command("report")
@click.option("--scan-id", help="Generate a report for a specific scan.")
@click.option("--latest", is_flag=True, help="Generate a report for the most recent scan.")
@click.option("--compare-to", help="Compare the selected scan to a baseline scan id.")
@click.option("--previous", is_flag=True, help="Compare the selected scan to the previous scan.")
@click.option("--vendor", help="Filter report rows to a vendor.")
@click.option("--source", help="Filter report findings to a KEV source.")
@click.option("--cve", "cve_id", help="Filter report findings to a CVE.")
@click.option("--findings-only", is_flag=True, help="Suppress device rows in the report.")
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["text", "json", "html"]),
    default="text",
    show_default=True,
    help="Report format.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    help="Write report to a file.",
)
@click.pass_context
def report_command(
    ctx: click.Context,
    scan_id: str | None,
    latest: bool,
    compare_to: str | None,
    previous: bool,
    vendor: str | None,
    source: str | None,
    cve_id: str | None,
    findings_only: bool,
    report_format: str,
    output_path: Path | None,
) -> None:
    """Generate a report from persisted scan data."""
    db_path = ctx.obj["db_path"]
    connection = initialize_db_path(db_path)
    scanner = EdgeAuditScanner(connection)

    if latest:
        selected_scan_id = scanner.get_latest_scan_id()
    else:
        selected_scan_id = scan_id

    if selected_scan_id is None:
        raise click.ClickException("No scan available for reporting")

    scan = scanner.get_scan(selected_scan_id)
    if scan is None:
        raise click.ClickException(f"Unknown scan id: {selected_scan_id}")

    devices, findings = scanner.get_scan_rows(selected_scan_id)
    filters = ReportFilters(
        vendor=vendor,
        source=source,
        cve_id=cve_id,
        findings_only=findings_only,
    )
    filtered_devices, filtered_findings = filter_report_rows(devices, findings, filters)
    diff = None
    if compare_to is not None and previous:
        raise click.ClickException("Use either --compare-to or --previous, not both")
    baseline_scan_id = compare_to
    if previous:
        baseline_scan_id = scanner.get_previous_scan_id(selected_scan_id)
        if baseline_scan_id is None:
            raise click.ClickException("No previous scan available for diffing")
    if baseline_scan_id is not None:
        baseline_scan = scanner.get_scan(baseline_scan_id)
        if baseline_scan is None:
            raise click.ClickException(f"Unknown scan id: {baseline_scan_id}")
        diff = scanner.diff_scans(baseline_scan_id, selected_scan_id)
    report_body = render_report(
        report_format,
        scan,
        filtered_devices,
        filtered_findings,
        filters=filters,
        diff=diff,
    )

    if output_path is not None:
        output_path.write_text(report_body, encoding="utf-8")
        click.echo(f"wrote {report_format} report to {output_path}")
        return

    click.echo(report_body)


@main.group("config")
def config_group() -> None:
    """Manage PALISADE config."""


@config_group.command("show")
@click.pass_context
def config_show_command(ctx: click.Context) -> None:
    """Show the resolved PALISADE config."""
    click.echo(config_to_json(ctx.obj["config"]))


@config_group.command("init")
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    help="Write a starter config file to this path.",
)
@click.pass_context
def config_init_command(ctx: click.Context, output_path: Path | None) -> None:
    """Write a starter config file."""
    target_path = output_path if output_path is not None else ctx.obj["config_path"]
    write_default_config(target_path)
    click.echo(f"wrote starter config to {target_path}")


@main.command("scan-export")
@click.option("--scan-id", help="Export a specific scan.")
@click.option("--latest", is_flag=True, help="Export the most recent scan.")
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    help="Write the scan bundle to this zip file.",
)
@click.pass_context
def scan_export_command(
    ctx: click.Context, scan_id: str | None, latest: bool, output_path: Path | None
) -> None:
    """Export a persisted scan as a bundle."""
    db_path = ctx.obj["db_path"]
    config = ctx.obj["config"]
    connection = initialize_db_path(db_path)
    scanner = EdgeAuditScanner(connection)

    selected_scan_id = scanner.get_latest_scan_id() if latest else scan_id
    if selected_scan_id is None:
        raise click.ClickException("No scan available for export")
    selected_output_path = (
        output_path
        if output_path is not None
        else config.default_artifact_dir / f"{selected_scan_id}.zip"
    )

    try:
        export_scan_bundle(connection, selected_scan_id, selected_output_path)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"exported scan bundle to {selected_output_path}")


@main.command("scan-import")
@click.option(
    "--input",
    "input_path",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Read a scan bundle zip file.",
)
@click.pass_context
def scan_import_command(ctx: click.Context, input_path: Path) -> None:
    """Import a persisted scan bundle."""
    db_path = ctx.obj["db_path"]
    connection = initialize_db_path(db_path)
    try:
        scan_id = import_scan_bundle(connection, input_path)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"imported scan bundle for scan-id {scan_id}")


def build_source_adapters(vulncheck_token: str | None) -> list[object]:
    """Return enabled remote source adapters for the current CLI invocation."""
    adapters: list[object] = list(default_source_adapters())
    if vulncheck_token and "VULNCHECK_API_TOKEN" not in os.environ:
        adapters.append(VulnCheckKevSourceAdapter(VulnCheckConfig(api_token=vulncheck_token)))
    return adapters


def validate_concurrency(value: int | None, *, default: int = 1) -> int:
    """Return a valid concurrency setting."""
    if value is None:
        return default
    if value < 1:
        raise ValueError("Concurrency must be at least 1")
    return value

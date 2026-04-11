"""Control mapping definitions for CISA CPGs and WaterISAC Fundamentals."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class ControlDefinition:
    """Human-readable metadata for a mapped control."""

    control_id: str
    title: str
    framework: str
    description: str


CISA_CPGS: Final[dict[str, ControlDefinition]] = {
    "1.A": ControlDefinition(
        control_id="1.A",
        title="Mitigate Known Exploited Vulnerabilities",
        framework="CISA CPG",
        description="Reduce risk from vulnerabilities known to be actively exploited.",
    ),
    "1.E": ControlDefinition(
        control_id="1.E",
        title="Network Segmentation",
        framework="CISA CPG",
        description="Segment environments to reduce operational and security blast radius.",
    ),
    "2.A": ControlDefinition(
        control_id="2.A",
        title="Change Default Passwords",
        framework="CISA CPG",
        description="Eliminate default credentials on exposed or operational systems.",
    ),
    "2.F": ControlDefinition(
        control_id="2.F",
        title="Network Monitoring and Defense",
        framework="CISA CPG",
        description="Monitor network activity and detect malicious or abnormal behavior.",
    ),
    "5.A": ControlDefinition(
        control_id="5.A",
        title="Inventory Assets",
        framework="CISA CPG",
        description="Maintain awareness of critical systems and connected assets.",
    ),
    "7.A": ControlDefinition(
        control_id="7.A",
        title="Incident Reporting",
        framework="CISA CPG",
        description="Ensure incidents can be escalated and reported appropriately.",
    ),
    "7.B": ControlDefinition(
        control_id="7.B",
        title="Incident Response Plan",
        framework="CISA CPG",
        description="Maintain an incident response process and response readiness.",
    ),
}


WATERISAC_FUNDAMENTALS: Final[dict[str, ControlDefinition]] = {
    "2": ControlDefinition(
        control_id="2",
        title="Minimize Control System Exposure",
        framework="WaterISAC Fundamental",
        description="Reduce unnecessary exposure of operational and management systems.",
    ),
    "4": ControlDefinition(
        control_id="4",
        title="Implement System Monitoring for Threat Detection and Alerting",
        framework="WaterISAC Fundamental",
        description="Collect and use monitoring data for threat detection and alerting.",
    ),
    "5": ControlDefinition(
        control_id="5",
        title="Account for Critical Assets",
        framework="WaterISAC Fundamental",
        description="Maintain an understanding of critical assets and their exposure.",
    ),
    "9": ControlDefinition(
        control_id="9",
        title="Embrace Risk-Based Vulnerability Management",
        framework="WaterISAC Fundamental",
        description="Prioritize vulnerability response based on risk and active threats.",
    ),
    "12": ControlDefinition(
        control_id="12",
        title="Participate in Information Sharing and Collaboration Communities",
        framework="WaterISAC Fundamental",
        description="Use sector and partner communities to improve cybersecurity posture.",
    ),
}


EDGE_AUDIT_WATERISAC_DEFAULTS: Final[tuple[str, ...]] = ("2", "5", "9")


def derive_waterisac_ids(cpg_ids: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Return WaterISAC fundamentals implied by the current finding context."""
    derived = set(EDGE_AUDIT_WATERISAC_DEFAULTS)
    if "2.F" in cpg_ids:
        derived.add("4")
    if "7.A" in cpg_ids or "7.B" in cpg_ids:
        derived.add("12")
    return tuple(sorted(derived, key=_waterisac_sort_key))


def render_control_labels(
    control_ids: str | tuple[str, ...] | list[str], definitions: dict[str, ControlDefinition]
) -> list[str]:
    """Render ids with titles for report output."""
    ids = normalize_control_ids(control_ids)
    labels: list[str] = []
    for control_id in ids:
        definition = definitions.get(control_id)
        if definition is None:
            labels.append(control_id)
            continue
        labels.append(f"{control_id} {definition.title}")
    return labels


def normalize_control_ids(
    control_ids: str | tuple[str, ...] | list[str] | None
) -> tuple[str, ...]:
    """Normalize control ids from stored text or in-memory tuples."""
    if control_ids in (None, ""):
        return ()
    if isinstance(control_ids, str):
        return tuple(part.strip() for part in control_ids.split(",") if part.strip())
    assert control_ids is not None
    iterable: Sequence[str] = tuple(control_ids)
    return tuple(part.strip() for part in iterable if part.strip())


def summarize_control_coverage(findings: Sequence[sqlite3.Row], field_name: str) -> list[str]:
    """Return a sorted unique list of control ids referenced by findings."""
    values: set[str] = set()
    for finding in findings:
        raw = finding[field_name]
        values.update(normalize_control_ids(raw))
    return sorted(values, key=_control_sort_key)


def _control_sort_key(value: str) -> tuple[int, str]:
    if "." in value:
        prefix, suffix = value.split(".", 1)
        return (int(prefix) if prefix.isdigit() else 999, suffix)
    return (int(value) if value.isdigit() else 999, value)


def _waterisac_sort_key(value: str) -> tuple[int, str]:
    return (int(value) if value.isdigit() else 999, value)

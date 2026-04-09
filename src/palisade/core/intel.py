"""Intel handoff validation and diff helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final


@dataclass(frozen=True)
class IntelArtifactSpec:
    """Schema requirements for an intel handoff artifact."""

    filename: str
    key_fields: tuple[str, ...]
    required_entry_fields: tuple[str, ...]


INTEL_SPECS: Final[dict[str, IntelArtifactSpec]] = {
    "vendor_priority.json": IntelArtifactSpec(
        filename="vendor_priority.json",
        key_fields=("vendor", "product_family", "signal_type"),
        required_entry_fields=(
            "vendor",
            "product_family",
            "observation_count",
            "first_seen",
            "last_seen",
            "signal_type",
            "confidence",
            "source_refs",
            "notes",
        ),
    ),
    "advisory_watchlist.json": IntelArtifactSpec(
        filename="advisory_watchlist.json",
        key_fields=("cve_id", "vendor", "product"),
        required_entry_fields=(
            "cve_id",
            "vendor",
            "product",
            "source",
            "source_url",
            "exploitation_signal",
            "ics_relevance",
            "confidence",
            "notes",
        ),
    ),
    "platform_patterns.json": IntelArtifactSpec(
        filename="platform_patterns.json",
        key_fields=("vendor", "product", "pattern_type", "pattern"),
        required_entry_fields=(
            "vendor",
            "product",
            "pattern_type",
            "pattern",
            "confidence",
            "example_context",
            "source_refs",
        ),
    ),
    "default_creds_candidates.json": IntelArtifactSpec(
        filename="default_creds_candidates.json",
        key_fields=("vendor", "product", "protocol", "username", "password"),
        required_entry_fields=(
            "vendor",
            "product",
            "protocol",
            "username",
            "password",
            "source",
            "confidence",
            "notes",
        ),
    ),
}

TOP_LEVEL_FIELDS: Final[tuple[str, ...]] = (
    "schema_version",
    "generated_at",
    "source_project",
    "entries",
)


def load_intel_artifact(path: Path) -> dict[str, object]:
    """Load a JSON intel artifact."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a top-level JSON object")
    return payload


def validate_intel_artifact(path: Path) -> list[str]:
    """Return validation errors for an intel artifact."""
    spec = get_intel_spec(path)
    try:
        payload = load_intel_artifact(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [str(exc)]

    errors: list[str] = []
    for field in TOP_LEVEL_FIELDS:
        if field not in payload:
            errors.append(f"missing top-level field: {field}")

    entries = payload.get("entries")
    if not isinstance(entries, list):
        errors.append("top-level field 'entries' must be a list")
        return errors

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"entry {index} must be an object")
            continue
        for field in spec.required_entry_fields:
            if field not in entry:
                errors.append(f"entry {index} missing field: {field}")
                continue
            if field.endswith("_refs"):
                if not isinstance(entry[field], list):
                    errors.append(f"entry {index} field {field} must be a list")
            elif field == "observation_count":
                if not isinstance(entry[field], int):
                    errors.append(f"entry {index} field {field} must be an integer")
            else:
                if not isinstance(entry[field], (str, int, float)) and entry[field] is not None:
                    errors.append(f"entry {index} field {field} has unsupported type")
        key = artifact_entry_key(spec, entry)
        if any(not part for part in key):
            errors.append(f"entry {index} has empty key fields")
    return errors


def diff_intel_artifacts(baseline_path: Path, candidate_path: Path) -> dict[str, object]:
    """Return a structured diff between two intel artifacts of the same type."""
    baseline_spec = get_intel_spec(baseline_path)
    candidate_spec = get_intel_spec(candidate_path)
    if baseline_spec.filename != candidate_spec.filename:
        raise ValueError("intel diff requires matching artifact types")

    baseline = load_intel_artifact(baseline_path)
    candidate = load_intel_artifact(candidate_path)
    baseline_entries = typed_entries(baseline)
    candidate_entries = typed_entries(candidate)

    baseline_index = {
        artifact_entry_key(baseline_spec, entry): entry for entry in baseline_entries
    }
    candidate_index = {
        artifact_entry_key(candidate_spec, entry): entry for entry in candidate_entries
    }

    added_keys = sorted(candidate_index.keys() - baseline_index.keys())
    removed_keys = sorted(baseline_index.keys() - candidate_index.keys())
    common_keys = sorted(candidate_index.keys() & baseline_index.keys())
    changed_keys = [
        key
        for key in common_keys
        if normalize_entry(candidate_index[key])
        != normalize_entry(baseline_index[key])
    ]

    return {
        "artifact": baseline_spec.filename,
        "baseline_count": len(baseline_entries),
        "candidate_count": len(candidate_entries),
        "added_count": len(added_keys),
        "removed_count": len(removed_keys),
        "changed_count": len(changed_keys),
        "added": [candidate_index[key] for key in added_keys],
        "removed": [baseline_index[key] for key in removed_keys],
        "changed": [
            {
                "key": list(key),
                "baseline": baseline_index[key],
                "candidate": candidate_index[key],
            }
            for key in changed_keys
        ],
    }


def get_intel_spec(path: Path) -> IntelArtifactSpec:
    """Return the artifact spec for a path."""
    spec = INTEL_SPECS.get(path.name)
    if spec is None:
        raise ValueError(f"Unsupported intel artifact type: {path.name}")
    return spec


def artifact_entry_key(spec: IntelArtifactSpec, entry: dict[str, object]) -> tuple[str, ...]:
    """Build a stable comparison key for an entry."""
    return tuple(str(entry.get(field, "")).strip() for field in spec.key_fields)


def typed_entries(payload: dict[str, object]) -> list[dict[str, object]]:
    """Return entries with a safe type assertion."""
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ValueError("top-level field 'entries' must be a list")
    typed: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("all entries must be objects")
        typed.append(entry)
    return typed


def normalize_entry(entry: dict[str, object]) -> str:
    """Return a stable serialized form for diff comparisons."""
    return json.dumps(entry, sort_keys=True)

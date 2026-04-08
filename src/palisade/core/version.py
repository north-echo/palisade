"""Vendor-aware version parsing and comparison."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import total_ordering
from typing import Final


@total_ordering
@dataclass(frozen=True)
class ParsedVersion:
    """Comparable vendor-aware version."""

    vendor: str
    parts: tuple[int | str, ...]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, ParsedVersion):
            return NotImplemented
        if self.vendor != other.vendor:
            raise ValueError("Cannot compare versions across vendors")
        return compare_parts(self.parts, other.parts) < 0


SEMVER_RE: Final[re.Pattern[str]] = re.compile(r"[0-9]+(?:\.[0-9A-Za-z]+)+")
SONICWALL_RE: Final[re.Pattern[str]] = re.compile(
    r"[0-9]+(?:\.[0-9A-Za-z]+)+(?:-[0-9A-Za-z]+)?"
)
ASA_RE: Final[re.Pattern[str]] = re.compile(r"([0-9]+)\.([0-9]+)\(([0-9]+)\)")


def parse_version(vendor: str, version_string: str) -> ParsedVersion:
    """Normalize a vendor version string into a comparable structure."""
    vendor_key = normalize_vendor(vendor)
    text = version_string.strip()
    if not text:
        raise ValueError("Version string must not be empty")

    if vendor_key == "sonicwall":
        return ParsedVersion(vendor_key, parse_sonicwall(text))
    if vendor_key in {"fortinet", "f5", "paloalto", "ivanti"}:
        return ParsedVersion(vendor_key, parse_semver_like(text))
    if vendor_key == "cisco":
        return ParsedVersion(vendor_key, parse_cisco(text))
    raise ValueError(f"Unsupported vendor version parser: {vendor}")


def is_affected(device_version: str, signature: Mapping[str, object]) -> bool:
    """Return whether a device version matches a signature's affected range."""
    vendor = require_signature_str(signature, "vendor")
    affected = signature.get("affected_versions")
    if not isinstance(affected, Mapping):
        raise ValueError("Signature is missing affected_versions")

    operator = require_signature_str(affected, "operator")
    parsed_device = parse_version(vendor, device_version)

    if operator == "lt":
        boundary = parse_version(vendor, require_signature_str(affected, "version"))
        return parsed_device < boundary
    if operator == "le":
        boundary = parse_version(vendor, require_signature_str(affected, "version"))
        return parsed_device <= boundary
    if operator == "exact":
        boundary = parse_version(vendor, require_signature_str(affected, "version"))
        return parsed_device == boundary
    if operator == "range":
        lower = parse_version(vendor, require_signature_str(affected, "from"))
        upper = parse_version(vendor, require_signature_str(affected, "to"))
        return lower <= parsed_device <= upper
    raise ValueError(f"Unsupported version operator: {operator}")


def normalize_vendor(vendor: str) -> str:
    """Normalize vendor names to internal keys."""
    key = vendor.strip().lower()
    aliases = {
        "palo alto networks": "paloalto",
        "paloalto": "paloalto",
        "fortinet": "fortinet",
        "f5": "f5",
        "cisco": "cisco",
        "ivanti": "ivanti",
        "sonicwall": "sonicwall",
    }
    if key not in aliases:
        raise ValueError(f"Unsupported vendor: {vendor}")
    return aliases[key]


def parse_semver_like(text: str) -> tuple[int | str, ...]:
    """Parse a semantic-like dotted version."""
    match = SEMVER_RE.search(text)
    if match is None:
        raise ValueError(f"Unable to parse semantic-like version from {text!r}")
    return tuple(coerce_part(part) for part in match.group(0).split("."))


def parse_sonicwall(text: str) -> tuple[int | str, ...]:
    """Parse SonicWall dotted versions with optional build suffix."""
    match = SONICWALL_RE.search(text)
    if match is None:
        raise ValueError(f"Unable to parse SonicWall version from {text!r}")
    parts: list[int | str] = []
    for part in match.group(0).split("."):
        if "-" in part:
            base, suffix = part.split("-", 1)
            parts.append(int(base))
            parts.extend(split_alpha_numeric(suffix))
        else:
            parts.append(coerce_part(part))
    return tuple(parts)


def parse_cisco(text: str) -> tuple[int | str, ...]:
    """Parse Cisco ASA style versions like 9.18(2)."""
    match = ASA_RE.search(text)
    if match is None:
        return parse_semver_like(text)
    return tuple(int(part) for part in match.groups())


def split_alpha_numeric(value: str) -> list[int | str]:
    """Split a mixed string into comparable int/str chunks."""
    parts = re.findall(r"[0-9]+|[A-Za-z]+", value)
    return [coerce_part(part) for part in parts]


def coerce_part(part: str) -> int | str:
    """Convert numeric version components to ints."""
    return int(part) if part.isdigit() else part.lower()


def compare_parts(left: tuple[int | str, ...], right: tuple[int | str, ...]) -> int:
    """Compare two heterogeneous version tuples."""
    for left_part, right_part in zip(left, right):
        if left_part == right_part:
            continue
        if isinstance(left_part, int) and isinstance(right_part, int):
            return -1 if left_part < right_part else 1
        left_key = (0, left_part) if isinstance(left_part, int) else (1, left_part)
        right_key = (0, right_part) if isinstance(right_part, int) else (1, right_part)
        return -1 if left_key < right_key else 1

    if len(left) == len(right):
        return 0
    return -1 if len(left) < len(right) else 1


def require_signature_str(payload: Mapping[str, object], key: str) -> str:
    """Return a required string field from signature data."""
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Signature field {key!r} must be a non-empty string")
    return value

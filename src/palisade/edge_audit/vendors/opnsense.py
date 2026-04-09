"""OPNsense fingerprint matching."""

from __future__ import annotations

import re
from typing import cast

from palisade.core.device import Confidence, DeviceFingerprint, FingerprintMethod

OPNSENSE_VERSION_RE = re.compile(
    r"OPNsense[^0-9]*([0-9]+(?:\.[0-9A-Za-z]+)+)",
    re.IGNORECASE,
)


def match_opnsense(
    ip: str, port: int, method: str, raw_data: str
) -> DeviceFingerprint | None:
    """Match OPNsense devices from raw probe data."""
    lowered = raw_data.lower()
    indicators = (
        "opnsense",
        "opnsense-logo",
        "opnsense csrf",
        "/ui/core/firmware",
    )
    if not any(indicator in lowered for indicator in indicators):
        return None

    version_match = OPNSENSE_VERSION_RE.search(raw_data)
    version = version_match.group(1) if version_match is not None else None
    confidence: Confidence = "high" if version is not None else "medium"

    return DeviceFingerprint(
        ip=ip,
        port=port,
        vendor="OPNsense",
        product="OPNsense",
        version=version,
        method=cast(FingerprintMethod, method),
        raw_data=raw_data,
        confidence=confidence,
    )

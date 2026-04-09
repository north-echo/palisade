"""pfSense fingerprint matching."""

from __future__ import annotations

import re
from typing import cast

from palisade.core.device import Confidence, DeviceFingerprint, FingerprintMethod

PFSENSE_VERSION_RE = re.compile(
    r"(?:pfSense(?:\s+(?:Plus|Community Edition))?|Netgate)[^0-9]*([0-9]+(?:\.[0-9A-Za-z]+)+)",
    re.IGNORECASE,
)


def match_pfsense(
    ip: str, port: int, method: str, raw_data: str
) -> DeviceFingerprint | None:
    """Match pfSense devices from raw probe data."""
    lowered = raw_data.lower()
    indicators = (
        "pfsense",
        "x-pfsense",
        "/themes/pfsense_ng",
        "netgate",
    )
    if not any(indicator in lowered for indicator in indicators):
        return None

    version_match = PFSENSE_VERSION_RE.search(raw_data)
    version = version_match.group(1) if version_match is not None else None
    confidence: Confidence = "high" if version is not None else "medium"

    return DeviceFingerprint(
        ip=ip,
        port=port,
        vendor="pfSense",
        product="pfSense",
        version=version,
        method=cast(FingerprintMethod, method),
        raw_data=raw_data,
        confidence=confidence,
    )

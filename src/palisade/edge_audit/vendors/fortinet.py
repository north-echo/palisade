"""Fortinet fingerprint matching."""

from __future__ import annotations

import re
from typing import cast

from palisade.core.device import Confidence, DeviceFingerprint, FingerprintMethod

FORTINET_VERSION_RE = re.compile(
    r"(?:FortiOS|FortiGate|Version:)[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)",
    re.IGNORECASE,
)


def match_fortinet(
    ip: str, port: int, method: str, raw_data: str
) -> DeviceFingerprint | None:
    """Match Fortinet devices from raw probe data."""
    lowered = raw_data.lower()
    indicators = (
        "fortinet",
        "fortigate",
        "fortios",
        "apscookie_",
        "/remote/login",
    )
    if not any(indicator in lowered for indicator in indicators):
        return None

    version_match = FORTINET_VERSION_RE.search(raw_data)
    version = version_match.group(1) if version_match is not None else None
    product = "FortiOS"
    confidence: Confidence = "high" if version is not None else "medium"

    return DeviceFingerprint(
        ip=ip,
        port=port,
        vendor="Fortinet",
        product=product,
        version=version,
        method=cast(FingerprintMethod, method),
        raw_data=raw_data,
        confidence=confidence,
    )

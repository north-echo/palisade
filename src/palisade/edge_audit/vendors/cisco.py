"""Cisco fingerprint matching."""

from __future__ import annotations

import re
from typing import cast

from palisade.core.device import Confidence, DeviceFingerprint, FingerprintMethod

CISCO_VERSION_RE = re.compile(
    r"(?:Cisco ASA|Adaptive Security Appliance|Version)[^0-9]*([0-9]+\.[0-9]+\([0-9]+\))",
    re.IGNORECASE,
)


def match_cisco(
    ip: str, port: int, method: str, raw_data: str
) -> DeviceFingerprint | None:
    """Match Cisco edge devices from raw probe data."""
    lowered = raw_data.lower()
    indicators = (
        "+cscoe+",
        "cisco asa",
        "adaptive security appliance",
        "asdm",
        "cisco systems",
    )
    if not any(indicator in lowered for indicator in indicators):
        return None

    version_match = CISCO_VERSION_RE.search(raw_data)
    version = version_match.group(1) if version_match is not None else None
    product = "ASA"
    confidence: Confidence = "high" if version is not None else "medium"

    return DeviceFingerprint(
        ip=ip,
        port=port,
        vendor="Cisco",
        product=product,
        version=version,
        method=cast(FingerprintMethod, method),
        raw_data=raw_data,
        confidence=confidence,
    )

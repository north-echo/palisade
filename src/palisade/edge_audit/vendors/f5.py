"""F5 fingerprint matching."""

from __future__ import annotations

import re
from typing import cast

from palisade.core.device import Confidence, DeviceFingerprint, FingerprintMethod

F5_VERSION_RE = re.compile(
    r"(?:BIG-IP|BIG-IQ|Version:)[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)",
    re.IGNORECASE,
)


def match_f5(ip: str, port: int, method: str, raw_data: str) -> DeviceFingerprint | None:
    """Match F5 devices from raw probe data."""
    lowered = raw_data.lower()
    indicators = (
        "big-ip",
        "big-iq",
        "bigipserver",
        "/tmui/login.jsp",
        "f5 networks",
    )
    if not any(indicator in lowered for indicator in indicators):
        return None

    version_match = F5_VERSION_RE.search(raw_data)
    version = version_match.group(1) if version_match is not None else None
    product = "BIG-IP"
    confidence: Confidence = "high" if version is not None else "medium"

    return DeviceFingerprint(
        ip=ip,
        port=port,
        vendor="F5",
        product=product,
        version=version,
        method=cast(FingerprintMethod, method),
        raw_data=raw_data,
        confidence=confidence,
    )

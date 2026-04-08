"""SonicWall fingerprint matching."""

from __future__ import annotations

import re
from typing import cast

from palisade.core.device import Confidence, DeviceFingerprint, FingerprintMethod

SONICWALL_VERSION_RE = re.compile(
    r"(?:SonicOS|sonicos|firmware version)[^0-9]*([0-9]+(?:\.[0-9A-Za-z]+)+(?:-[0-9A-Za-z]+)?)",
    re.IGNORECASE,
)


def match_sonicwall(
    ip: str, port: int, method: str, raw_data: str
) -> DeviceFingerprint | None:
    """Match SonicWall devices from raw probe data."""
    lowered = raw_data.lower()
    indicators = (
        "sonicwall",
        "sonicwall nsa",
        "sonicwall tz",
        "/auth.html",
        "sonicos",
    )
    if not any(indicator in lowered for indicator in indicators):
        return None

    version_match = SONICWALL_VERSION_RE.search(raw_data)
    version = version_match.group(1) if version_match is not None else None
    product = "SonicOS"
    confidence: Confidence = "high" if version is not None else "medium"

    return DeviceFingerprint(
        ip=ip,
        port=port,
        vendor="SonicWall",
        product=product,
        version=version,
        method=cast(FingerprintMethod, method),
        raw_data=raw_data,
        confidence=confidence,
    )

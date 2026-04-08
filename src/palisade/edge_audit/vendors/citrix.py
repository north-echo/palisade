"""Citrix fingerprint matching."""

from __future__ import annotations

import re
from typing import cast

from palisade.core.device import Confidence, DeviceFingerprint, FingerprintMethod

CITRIX_VERSION_RE = re.compile(
    r"(?:netscaler|adc|gateway|build|version)[^0-9]*([0-9]+\.[0-9]+(?:-[0-9]+(?:\.[0-9]+)?)?)",
    re.IGNORECASE,
)


def match_citrix(
    ip: str, port: int, method: str, raw_data: str
) -> DeviceFingerprint | None:
    """Match Citrix NetScaler devices from raw probe data."""
    lowered = raw_data.lower()
    indicators = (
        "citrix",
        "netscaler",
        "x-citrix-application",
        "ns_af=",
        "nsc_aaac",
        "/vpn/index.html",
        "/logon/logonpoint",
    )
    if not any(indicator in lowered for indicator in indicators):
        return None

    version_match = CITRIX_VERSION_RE.search(raw_data)
    version = version_match.group(1) if version_match is not None else None
    confidence: Confidence = "high" if version is not None else "medium"

    return DeviceFingerprint(
        ip=ip,
        port=port,
        vendor="Citrix",
        product="NetScaler ADC",
        version=version,
        method=cast(FingerprintMethod, method),
        raw_data=raw_data,
        confidence=confidence,
    )

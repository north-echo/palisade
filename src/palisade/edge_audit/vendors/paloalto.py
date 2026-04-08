"""Palo Alto fingerprint matching."""

from __future__ import annotations

import re
from typing import cast

from palisade.core.device import Confidence, DeviceFingerprint, FingerprintMethod

PALOALTO_VERSION_RE = re.compile(
    r"(?:PAN-OS|GlobalProtect|Version:)[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)",
    re.IGNORECASE,
)


def match_paloalto(
    ip: str, port: int, method: str, raw_data: str
) -> DeviceFingerprint | None:
    """Match Palo Alto devices from raw probe data."""
    lowered = raw_data.lower()
    indicators = (
        "palo alto",
        "pan-os",
        "globalprotect",
        "/global-protect/login.esp",
    )
    if not any(indicator in lowered for indicator in indicators):
        return None

    version_match = PALOALTO_VERSION_RE.search(raw_data)
    version = version_match.group(1) if version_match is not None else None
    product = "PAN-OS"
    confidence: Confidence = "high" if version is not None else "medium"

    return DeviceFingerprint(
        ip=ip,
        port=port,
        vendor="Palo Alto Networks",
        product=product,
        version=version,
        method=cast(FingerprintMethod, method),
        raw_data=raw_data,
        confidence=confidence,
    )

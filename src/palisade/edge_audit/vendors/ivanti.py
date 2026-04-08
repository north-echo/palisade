"""Ivanti fingerprint matching."""

from __future__ import annotations

import re
from typing import cast

from palisade.core.device import Confidence, DeviceFingerprint, FingerprintMethod

IVANTI_VERSION_RE = re.compile(
    r"(?:Ivanti Connect Secure|Pulse Secure|Version:)[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)",
    re.IGNORECASE,
)


def match_ivanti(
    ip: str, port: int, method: str, raw_data: str
) -> DeviceFingerprint | None:
    """Match Ivanti devices from raw probe data."""
    lowered = raw_data.lower()
    indicators = (
        "ivanti",
        "connect secure",
        "pulse secure",
        "/dana-na/auth/",
        "dsid=",
    )
    if not any(indicator in lowered for indicator in indicators):
        return None

    version_match = IVANTI_VERSION_RE.search(raw_data)
    version = version_match.group(1) if version_match is not None else None
    product = "Connect Secure"
    confidence: Confidence = "high" if version is not None else "medium"

    return DeviceFingerprint(
        ip=ip,
        port=port,
        vendor="Ivanti",
        product=product,
        version=version,
        method=cast(FingerprintMethod, method),
        raw_data=raw_data,
        confidence=confidence,
    )

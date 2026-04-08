"""Asset identity helpers."""

from __future__ import annotations

import hashlib
import re
from uuid import NAMESPACE_URL, uuid5

from palisade.core.device import DeviceFingerprint


def compute_asset_id(fingerprint: DeviceFingerprint) -> str:
    """Return a stable asset identifier for a fingerprinted device."""
    asset_key = build_asset_key(
        ip=fingerprint.ip,
        port=fingerprint.port,
        vendor=fingerprint.vendor,
        product=fingerprint.product,
        version=fingerprint.version,
        raw_data=fingerprint.raw_data,
    )
    return str(uuid5(NAMESPACE_URL, asset_key))


def compute_asset_id_from_fields(
    *,
    ip: str,
    port: int,
    vendor: str | None,
    product: str | None,
    version: str | None,
    raw_data: str,
) -> str:
    """Return a stable asset identifier from stored device fields."""
    return str(
        uuid5(
            NAMESPACE_URL,
            build_asset_key(
                ip=ip,
                port=port,
                vendor=vendor,
                product=product,
                version=version,
                raw_data=raw_data,
            ),
        )
    )


def build_asset_key(
    *,
    ip: str,
    port: int,
    vendor: str | None,
    product: str | None,
    version: str | None,
    raw_data: str,
) -> str:
    """Build a stable asset key from network location and fingerprint evidence."""
    normalized = normalize_fingerprint_evidence(raw_data).encode("utf-8")
    evidence_hash = hashlib.sha256(normalized).hexdigest()[:16]
    return "|".join(
        [
            ip,
            str(port),
            vendor or "unknown",
            product or "unknown",
            version or "unknown",
            evidence_hash,
        ]
    )


def normalize_fingerprint_evidence(raw_data: str) -> str:
    """Normalize raw fingerprint text into a stable comparison shape."""
    normalized = raw_data.strip().lower()
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized

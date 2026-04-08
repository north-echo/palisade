"""Vendor matcher registry for fingerprint probes."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from palisade.core.device import DeviceFingerprint

Matcher = Callable[[str, int, str, str], object]

_MATCHERS: list[Matcher] | None = None


def match_fingerprint(
    ip: str, port: int, method: str, raw_data: str
) -> DeviceFingerprint | None:
    """Return the first vendor match for raw probe data."""
    for matcher in get_matchers():
        result = matcher(ip, port, method, raw_data)
        if result is not None:
            return cast("DeviceFingerprint", result)
    return None


def get_matchers() -> list[Matcher]:
    """Return the configured vendor matcher list."""
    global _MATCHERS
    if _MATCHERS is None:
        from palisade.edge_audit.vendors.cisco import match_cisco
        from palisade.edge_audit.vendors.citrix import match_citrix
        from palisade.edge_audit.vendors.f5 import match_f5
        from palisade.edge_audit.vendors.fortinet import match_fortinet
        from palisade.edge_audit.vendors.ivanti import match_ivanti
        from palisade.edge_audit.vendors.paloalto import match_paloalto
        from palisade.edge_audit.vendors.sonicwall import match_sonicwall

        _MATCHERS = [
            match_citrix,
            match_sonicwall,
            match_fortinet,
            match_f5,
            match_cisco,
            match_paloalto,
            match_ivanti,
        ]
    return _MATCHERS

from __future__ import annotations

from palisade.core.version import is_affected, parse_version


def test_parse_sonicwall_version() -> None:
    parsed = parse_version("sonicwall", "SonicOS 7.0.1-5035")
    assert parsed.parts == (7, 0, 1, 5035)


def test_parse_fortinet_version() -> None:
    parsed = parse_version("fortinet", "FortiOS 7.2.4")
    assert parsed.parts == (7, 2, 4)


def test_parse_cisco_version() -> None:
    parsed = parse_version("cisco", "Cisco ASA Version 9.18(2)")
    assert parsed.parts == (9, 18, 2)


def test_exact_operator() -> None:
    signature = {
        "vendor": "fortinet",
        "affected_versions": {"operator": "exact", "version": "7.2.4"},
    }
    assert is_affected("7.2.4", signature)
    assert not is_affected("7.2.5", signature)


def test_lt_operator() -> None:
    signature = {
        "vendor": "sonicwall",
        "affected_versions": {"operator": "lt", "version": "7.0.1-5036"},
    }
    assert is_affected("7.0.1-5035", signature)
    assert not is_affected("7.0.1-5036", signature)


def test_le_operator() -> None:
    signature = {
        "vendor": "paloalto",
        "affected_versions": {"operator": "le", "version": "11.0.3"},
    }
    assert is_affected("11.0.3", signature)
    assert not is_affected("11.0.4", signature)


def test_range_operator() -> None:
    signature = {
        "vendor": "ivanti",
        "affected_versions": {"operator": "range", "from": "22.5.0", "to": "22.5.2"},
    }
    assert is_affected("22.5.1", signature)
    assert not is_affected("22.5.3", signature)

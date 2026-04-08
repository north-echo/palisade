from __future__ import annotations

from pathlib import Path

from palisade.edge_audit.vendors.cisco import match_cisco
from palisade.edge_audit.vendors.citrix import match_citrix
from palisade.edge_audit.vendors.f5 import match_f5
from palisade.edge_audit.vendors.fortinet import match_fortinet
from palisade.edge_audit.vendors.ivanti import match_ivanti
from palisade.edge_audit.vendors.paloalto import match_paloalto
from palisade.edge_audit.vendors.registry import match_fingerprint
from palisade.edge_audit.vendors.sonicwall import match_sonicwall

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def test_match_sonicwall_http_fixture() -> None:
    raw_data = load_fixture("http_sonicwall.txt")

    result = match_sonicwall("192.0.2.60", 443, "http_header", raw_data)

    assert result is not None
    assert result.vendor == "SonicWall"
    assert result.product == "SonicOS"
    assert result.version == "7.0.1-5035"
    assert result.confidence == "high"


def test_match_citrix_http_fixture() -> None:
    raw_data = load_fixture("http_citrix.txt")

    result = match_citrix("192.0.2.59", 443, "http_header", raw_data)

    assert result is not None
    assert result.vendor == "Citrix"
    assert result.product == "NetScaler ADC"
    assert result.version == "14.1-6.50"
    assert result.confidence == "high"


def test_match_fortinet_http_fixture() -> None:
    raw_data = load_fixture("http_fortinet.txt")

    result = match_fortinet("192.0.2.61", 443, "http_header", raw_data)

    assert result is not None
    assert result.vendor == "Fortinet"
    assert result.product == "FortiOS"
    assert result.version == "7.2.4"
    assert result.confidence == "high"


def test_match_fortinet_banner_fixture() -> None:
    raw_data = load_fixture("banner_fortinet.txt")

    result = match_fortinet("192.0.2.62", 22, "banner", raw_data)

    assert result is not None
    assert result.version == "7.0.12"
    assert result.method == "banner"


def test_registry_matches_sonicwall_fixture() -> None:
    raw_data = load_fixture("tls_sonicwall.json")

    result = match_fingerprint("192.0.2.63", 443, "tls_cert", raw_data)

    assert result is not None
    assert result.vendor == "SonicWall"
    assert result.product == "SonicOS"
    assert result.version is None
    assert result.confidence == "medium"


def test_match_f5_http_fixture() -> None:
    raw_data = load_fixture("http_f5.txt")

    result = match_f5("192.0.2.64", 443, "http_header", raw_data)

    assert result is not None
    assert result.vendor == "F5"
    assert result.product == "BIG-IP"
    assert result.version == "17.1.0"
    assert result.confidence == "high"


def test_match_cisco_http_fixture() -> None:
    raw_data = load_fixture("http_cisco.txt")

    result = match_cisco("192.0.2.65", 443, "http_header", raw_data)

    assert result is not None
    assert result.vendor == "Cisco"
    assert result.product == "ASA"
    assert result.version == "9.18(2)"
    assert result.confidence == "high"


def test_match_cisco_banner_fixture() -> None:
    raw_data = load_fixture("banner_cisco.txt")

    result = match_cisco("192.0.2.66", 22, "banner", raw_data)

    assert result is not None
    assert result.method == "banner"
    assert result.version == "9.18(2)"


def test_registry_matches_f5_fixture() -> None:
    raw_data = load_fixture("http_f5.txt")

    result = match_fingerprint("192.0.2.67", 443, "http_header", raw_data)

    assert result is not None
    assert result.vendor == "F5"
    assert result.product == "BIG-IP"


def test_match_paloalto_http_fixture() -> None:
    raw_data = load_fixture("http_paloalto.txt")

    result = match_paloalto("192.0.2.68", 443, "http_header", raw_data)

    assert result is not None
    assert result.vendor == "Palo Alto Networks"
    assert result.product == "PAN-OS"
    assert result.version == "11.0.2"
    assert result.confidence == "high"


def test_match_ivanti_http_fixture() -> None:
    raw_data = load_fixture("http_ivanti.txt")

    result = match_ivanti("192.0.2.69", 443, "http_header", raw_data)

    assert result is not None
    assert result.vendor == "Ivanti"
    assert result.product == "Connect Secure"
    assert result.version == "22.5.1"
    assert result.confidence == "high"


def test_match_ivanti_banner_fixture() -> None:
    raw_data = load_fixture("banner_ivanti.txt")

    result = match_ivanti("192.0.2.70", 22, "banner", raw_data)

    assert result is not None
    assert result.method == "banner"
    assert result.version == "22.5.1"


def test_registry_matches_paloalto_fixture() -> None:
    raw_data = load_fixture("http_paloalto.txt")

    result = match_fingerprint("192.0.2.71", 443, "http_header", raw_data)

    assert result is not None
    assert result.vendor == "Palo Alto Networks"
    assert result.product == "PAN-OS"

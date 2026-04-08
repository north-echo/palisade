from __future__ import annotations

import http.client
import socket
from typing import Any

import pytest

from palisade.core.device import (
    DeviceFingerprint,
    ProbeConfig,
    fingerprint_banner,
    fingerprint_host,
    fingerprint_http,
    fingerprint_tls,
)


def test_fingerprint_tls_returns_none_on_connection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_timeout(*args: Any, **kwargs: Any) -> None:
        raise socket.timeout("timed out")

    monkeypatch.setattr("palisade.core.device.socket.create_connection", raise_timeout)

    result = fingerprint_tls("192.0.2.10", 443)

    assert result is None


def test_fingerprint_http_returns_none_on_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenConnection:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            del host, port, timeout

        def request(self, method: str, path: str) -> None:
            del method, path
            raise http.client.HTTPException("bad response")

        def close(self) -> None:
            return None

    monkeypatch.setattr("palisade.core.device.http.client.HTTPConnection", BrokenConnection)

    result = fingerprint_http("192.0.2.20", 80)

    assert result is None


def test_fingerprint_banner_returns_none_on_socket_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_refused(*args: Any, **kwargs: Any) -> None:
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr("palisade.core.device.socket.create_connection", raise_refused)

    result = fingerprint_banner("192.0.2.30", 22)

    assert result is None


def test_fingerprint_host_collects_non_none_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tls_fingerprint = DeviceFingerprint(
        ip="192.0.2.40",
        port=443,
        vendor="Example",
        product="TLS Appliance",
        version=None,
        method="tls_cert",
        raw_data="cert",
        confidence="low",
    )
    banner_fingerprint = DeviceFingerprint(
        ip="192.0.2.40",
        port=22,
        vendor="Example",
        product="SSH Appliance",
        version=None,
        method="banner",
        raw_data="banner",
        confidence="low",
    )

    def fake_tls(
        ip: str, port: int, *, config: ProbeConfig | None = None
    ) -> DeviceFingerprint | None:
        del ip, config
        if port == 443:
            return tls_fingerprint
        return None

    def fake_http(
        ip: str, port: int, *, config: ProbeConfig | None = None
    ) -> DeviceFingerprint | None:
        del ip, port, config
        return None

    def fake_banner(
        ip: str, port: int, *, config: ProbeConfig | None = None
    ) -> DeviceFingerprint | None:
        del ip, config
        if port == 22:
            return banner_fingerprint
        return None

    monkeypatch.setattr("palisade.core.device.fingerprint_tls", fake_tls)
    monkeypatch.setattr("palisade.core.device.fingerprint_http", fake_http)
    monkeypatch.setattr("palisade.core.device.fingerprint_banner", fake_banner)

    results = fingerprint_host("192.0.2.40", [22, 443])

    assert results == [banner_fingerprint, tls_fingerprint]


def test_fingerprint_http_uses_matcher_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = DeviceFingerprint(
        ip="192.0.2.50",
        port=80,
        vendor="Example",
        product="Web Appliance",
        version="1.0",
        method="http_header",
        raw_data="matched",
        confidence="medium",
    )

    class FakeResponse:
        status = 200
        reason = "OK"

        def getheaders(self) -> list[tuple[str, str]]:
            return [("Server", "ExampleWeb")]

        def read(self, size: int) -> bytes:
            del size
            return b"<html>Example</html>"

    class FakeConnection:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            del host, port, timeout

        def request(self, method: str, path: str) -> None:
            del method, path

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            return None

    def fake_match(ip: str, port: int, method: str, raw_data: str) -> DeviceFingerprint | None:
        assert ip == "192.0.2.50"
        assert port == 80
        assert method == "http_header"
        assert "Server: ExampleWeb" in raw_data
        return expected

    monkeypatch.setattr("palisade.core.device.http.client.HTTPConnection", FakeConnection)
    monkeypatch.setattr("palisade.core.device.match_fingerprint", fake_match)

    result = fingerprint_http("192.0.2.50", 80)

    assert result == expected

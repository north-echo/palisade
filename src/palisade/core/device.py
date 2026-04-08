"""Non-intrusive device fingerprinting helpers."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
from dataclasses import dataclass
from typing import Final, Literal

from palisade.edge_audit.vendors.registry import match_fingerprint

Confidence = Literal["high", "medium", "low"]
FingerprintMethod = Literal["tls_cert", "http_header", "banner"]

DEFAULT_TLS_PORTS: Final[tuple[int, ...]] = (443, 4443, 8443, 10443)
DEFAULT_BANNER_PORTS: Final[tuple[int, ...]] = (22, 23, 443, 4443, 8443, 10443)


@dataclass(frozen=True)
class DeviceFingerprint:
    """A best-effort fingerprint for a network-visible device."""

    ip: str
    port: int
    vendor: str | None
    product: str | None
    version: str | None
    method: FingerprintMethod
    raw_data: str
    confidence: Confidence


@dataclass(frozen=True)
class ProbeConfig:
    """Timeout configuration for non-intrusive probes."""

    connection_timeout: float = 5.0
    read_timeout: float = 10.0


def fingerprint_host(
    ip: str,
    ports: list[int] | tuple[int, ...],
    *,
    config: ProbeConfig | None = None,
) -> list[DeviceFingerprint]:
    """Run all supported non-intrusive probes against a host."""
    probe_config = config or ProbeConfig()
    fingerprints: list[DeviceFingerprint] = []

    for port in ports:
        if port in DEFAULT_TLS_PORTS:
            tls_result = fingerprint_tls(ip, port, config=probe_config)
            if tls_result is not None:
                fingerprints.append(tls_result)

        http_result = fingerprint_http(ip, port, config=probe_config)
        if http_result is not None:
            fingerprints.append(http_result)

        if port in DEFAULT_BANNER_PORTS:
            banner_result = fingerprint_banner(ip, port, config=probe_config)
            if banner_result is not None:
                fingerprints.append(banner_result)

    return fingerprints


def fingerprint_tls(
    ip: str,
    port: int,
    *,
    config: ProbeConfig | None = None,
) -> DeviceFingerprint | None:
    """Collect a TLS certificate fingerprint if available."""
    probe_config = config or ProbeConfig()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection(
            (ip, port), timeout=probe_config.connection_timeout
        ) as raw_socket:
            raw_socket.settimeout(probe_config.read_timeout)
            with context.wrap_socket(raw_socket, server_hostname=ip) as tls_socket:
                certificate = tls_socket.getpeercert()
    except (OSError, socket.timeout, ssl.SSLError):
        return None

    if not certificate:
        return None

    raw_data = json.dumps(certificate, sort_keys=True)
    return match_fingerprint(ip, port, "tls_cert", raw_data)


def fingerprint_http(
    ip: str,
    port: int,
    *,
    config: ProbeConfig | None = None,
) -> DeviceFingerprint | None:
    """Collect HTTP response headers and a small response body sample."""
    probe_config = config or ProbeConfig()
    connection_class: type[http.client.HTTPConnection | http.client.HTTPSConnection]
    if port in DEFAULT_TLS_PORTS:
        connection_class = http.client.HTTPSConnection
    else:
        connection_class = http.client.HTTPConnection

    connection = connection_class(
        ip,
        port=port,
        timeout=probe_config.connection_timeout,
    )
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read(4096)
    except (OSError, http.client.HTTPException):
        connection.close()
        return None

    headers = "\n".join(f"{key}: {value}" for key, value in response.getheaders())
    raw_data = (
        f"status: {response.status}\n"
        f"reason: {response.reason}\n"
        f"{headers}\n\n"
        f"{body.decode('utf-8', errors='replace')}"
    )
    connection.close()
    return match_fingerprint(ip, port, "http_header", raw_data)


def fingerprint_banner(
    ip: str,
    port: int,
    *,
    config: ProbeConfig | None = None,
) -> DeviceFingerprint | None:
    """Collect an application banner from a TCP port."""
    probe_config = config or ProbeConfig()
    try:
        with socket.create_connection(
            (ip, port), timeout=probe_config.connection_timeout
        ) as connection:
            connection.settimeout(probe_config.read_timeout)
            banner = connection.recv(4096)
    except (OSError, socket.timeout):
        return None

    if not banner:
        return None

    raw_data = banner.decode("utf-8", errors="replace")
    return match_fingerprint(ip, port, "banner", raw_data)

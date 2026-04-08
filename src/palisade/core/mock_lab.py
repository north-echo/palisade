"""Local fixture-backed HTTP lab helpers."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Final

FIXTURE_ROOT: Final[Path] = Path(__file__).resolve().parents[3] / "tests" / "fixtures"


@dataclass(frozen=True)
class FixtureHTTPResponse:
    """Parsed fixture-backed HTTP response."""

    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True)
class FixtureServer:
    """Running fixture-backed HTTP server."""

    name: str
    fixture_path: Path
    host: str
    port: int
    url: str


def load_http_fixture_response(path: Path) -> FixtureHTTPResponse:
    """Parse a stored HTTP fixture into response parts."""
    raw_text = path.read_text(encoding="utf-8")
    header_text, body_text = raw_text.split("\n\n", 1)
    lines = header_text.splitlines()
    status = 200
    reason = "OK"
    headers: list[tuple[str, str]] = []
    for line in lines:
        if line.startswith("status:"):
            status = int(line.split(":", 1)[1].strip())
            continue
        if line.startswith("reason:"):
            reason = line.split(":", 1)[1].strip()
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers.append((key.strip(), value.strip()))
    return FixtureHTTPResponse(
        status=status,
        reason=reason,
        headers=tuple(headers),
        body=body_text.encode("utf-8"),
    )


def start_fixture_http_server(
    path: Path, *, name: str, host: str = "127.0.0.1"
) -> tuple[ThreadingHTTPServer, Thread, FixtureServer]:
    """Start a threaded HTTP server that replays a stored fixture response."""
    response = load_http_fixture_response(path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(response.status, response.reason)
            for key, value in response.headers:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args
            return None

    server = ThreadingHTTPServer((host, 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fixture_server = FixtureServer(
        name=name,
        fixture_path=path,
        host=host,
        port=int(server.server_port),
        url=f"http://{host}:{int(server.server_port)}",
    )
    return server, thread, fixture_server


def start_named_fixture_servers(
    fixtures: dict[str, Path],
) -> tuple[ExitStack, list[FixtureServer]]:
    """Start multiple named fixture HTTP servers."""
    stack = ExitStack()
    servers: list[FixtureServer] = []
    for name, path in fixtures.items():
        httpd, _thread, fixture_server = start_fixture_http_server(path, name=name)
        stack.callback(httpd.shutdown)
        stack.callback(httpd.server_close)
        servers.append(fixture_server)
    return stack, servers

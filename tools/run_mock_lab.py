#!/usr/bin/env python3
"""Run local fixture-backed HTTP targets for PALISADE validation demos."""

from __future__ import annotations

import time

from palisade.core.mock_lab import default_http_fixtures, start_named_fixture_servers


def main() -> int:
    fixtures = default_http_fixtures()
    stack, servers = start_named_fixture_servers(fixtures)
    with stack:
        print("PALISADE mock lab running")
        for server in servers:
            print(f"{server.name}: {server.url}")
        print("")
        print("Example scan:")
        ports = ",".join(str(server.port) for server in servers)
        print(
            "PYTHONPATH=src python3 -m palisade edge-audit "
            f"--target 127.0.0.1 --ports {ports}"
        )
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build a repeatable PALISADE demo environment."""

from __future__ import annotations

import argparse
from pathlib import Path

from palisade.core.demo import build_demo_environment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("demo") / "out",
        help="Directory where the demo database, reports, and bundles should be written.",
    )
    args = parser.parse_args()
    result = build_demo_environment(args.output_dir)
    print(f"demo output: {result.output_dir}")
    print(f"database: {result.db_path}")
    print(f"config: {result.config_path}")
    print(f"baseline scan: {result.baseline_scan_id}")
    print(f"latest scan: {result.latest_scan_id}")
    print(f"latest report: {result.latest_report_path}")
    print(f"diff report: {result.diff_report_path}")
    print(f"bundle: {result.bundle_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

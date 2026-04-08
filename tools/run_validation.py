#!/usr/bin/env python3
"""Run replay-lab validation and write summary artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

from palisade.core.validation import run_http_fixture_validation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("validation") / "out",
        help="Directory where validation outputs should be written.",
    )
    args = parser.parse_args()
    result = run_http_fixture_validation(args.output_dir)
    print(f"validation output: {result.output_dir}")
    print(f"database: {result.db_path}")
    print(f"summary: {result.summary_path}")
    print(f"json: {result.json_path}")
    print(f"scan id: {result.scan_id}")
    print(f"devices: {result.device_count}")
    print(f"findings: {result.finding_count}")
    print(f"matched vendors: {', '.join(result.matched_vendors)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

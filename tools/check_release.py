#!/usr/bin/env python3
"""Run lightweight release-prep consistency checks."""

from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    init_text = (PROJECT_ROOT / "src" / "palisade" / "__init__.py").read_text(encoding="utf-8")
    setup_text = (PROJECT_ROOT / "setup.py").read_text(encoding="utf-8")
    changelog_text = (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    init_version = extract_pattern(init_text, r'__version__ = "([^"]+)"')
    setup_version = extract_pattern(setup_text, r'version="([^"]+)"')

    if init_version != setup_version:
        raise SystemExit(
            f"Version mismatch: src/palisade/__init__.py={init_version}, setup.py={setup_version}"
        )

    if f"## [{init_version}]" not in changelog_text:
        raise SystemExit(f"CHANGELOG.md is missing an entry for version {init_version}")

    print(f"release checks passed for version {init_version}")
    return 0


def extract_pattern(text: str, pattern: str) -> str:
    """Extract a single regex capture group."""
    match = re.search(pattern, text)
    if match is None:
        raise SystemExit(f"Unable to find pattern: {pattern}")
    return match.group(1)


if __name__ == "__main__":
    raise SystemExit(main())

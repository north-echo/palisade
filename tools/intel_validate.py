"""Validate PALISADE intel handoff artifacts."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def main(argv: list[str]) -> int:
    from palisade.core.intel import validate_intel_artifact

    if len(argv) < 2:
        print("usage: python3 tools/intel_validate.py <artifact.json> [<artifact.json> ...]")
        return 1

    has_errors = False
    for raw_path in argv[1:]:
        path = Path(raw_path)
        errors = validate_intel_artifact(path)
        if errors:
            has_errors = True
            print(f"{path}: invalid")
            for error in errors:
                print(f"  - {error}")
            continue
        print(f"{path}: valid")
    return 1 if has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

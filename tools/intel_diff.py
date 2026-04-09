"""Diff PALISADE intel handoff artifacts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def main(argv: list[str]) -> int:
    from palisade.core.intel import diff_intel_artifacts

    if len(argv) != 3:
        print("usage: python3 tools/intel_diff.py <baseline.json> <candidate.json>")
        return 1

    baseline = Path(argv[1])
    candidate = Path(argv[2])
    diff = diff_intel_artifacts(baseline, candidate)
    print(json.dumps(diff, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

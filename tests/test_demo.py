from __future__ import annotations

from pathlib import Path

from palisade.core.demo import build_demo_environment


def test_build_demo_environment_writes_expected_outputs(tmp_path: Path) -> None:
    result = build_demo_environment(tmp_path / "demo-out")

    assert result.db_path.exists()
    assert result.config_path.exists()
    assert result.latest_report_path.exists()
    assert result.diff_report_path.exists()
    assert result.bundle_path.exists()
    assert (result.output_dir / "SUMMARY.md").exists()

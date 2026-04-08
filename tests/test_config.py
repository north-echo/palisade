from __future__ import annotations

from pathlib import Path

from palisade.core.config import PalisadeConfig, config_to_json, load_config, write_default_config


def test_load_config_returns_defaults_when_missing(tmp_path: Path) -> None:
    config = load_config(tmp_path / "missing.json")

    assert config.db_path == Path("data") / "palisade.db"
    assert config.default_kev_scope == "expanded"
    assert config.default_concurrency == 1


def test_load_config_parses_values(tmp_path: Path) -> None:
    config_path = tmp_path / "palisade.json"
    config_path.write_text(
        """
        {
          "db_path": "state/custom.db",
          "default_kev_scope": "strict",
          "default_concurrency": 4,
          "default_artifact_dir": "bundles",
          "vulncheck_token": "secret"
        }
        """,
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.db_path == Path("state/custom.db")
    assert config.default_kev_scope == "strict"
    assert config.default_concurrency == 4
    assert config.default_artifact_dir == Path("bundles")
    assert config.vulncheck_token == "secret"


def test_write_default_config_creates_file(tmp_path: Path) -> None:
    config_path = write_default_config(tmp_path / "palisade.json")

    assert config_path.exists()
    assert '"default_kev_scope": "expanded"' in config_path.read_text(encoding="utf-8")


def test_config_to_json_masks_token() -> None:
    rendered = config_to_json(PalisadeConfig(vulncheck_token="secret"))

    assert '"db_path": "data/palisade.db"' in rendered
    assert "***configured***" in rendered

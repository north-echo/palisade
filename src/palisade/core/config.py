"""Configuration helpers for PALISADE."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

DEFAULT_CONFIG_PATH: Final[Path] = Path("palisade.json")


@dataclass(frozen=True)
class PalisadeConfig:
    """Resolved CLI and runtime defaults."""

    db_path: Path = Path("data") / "palisade.db"
    default_kev_scope: str = "expanded"
    default_concurrency: int = 1
    default_artifact_dir: Path = Path("artifacts")
    vulncheck_token: str | None = None


def resolve_config_path(explicit_path: Path | None = None) -> Path:
    """Return the config path to load."""
    if explicit_path is not None:
        return explicit_path
    env_path = os.getenv("PALISADE_CONFIG")
    if env_path:
        return Path(env_path)
    return DEFAULT_CONFIG_PATH


def load_config(path: Path | None = None) -> PalisadeConfig:
    """Load config from disk or return defaults when missing."""
    resolved_path = resolve_config_path(path)
    if not resolved_path.exists():
        return PalisadeConfig()

    payload = json.loads(resolved_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Config file must contain a JSON object")

    db_path = parse_path(payload, "db_path", Path("data") / "palisade.db")
    default_artifact_dir = parse_path(payload, "default_artifact_dir", Path("artifacts"))
    default_kev_scope = parse_choice(
        payload, "default_kev_scope", ("strict", "expanded"), "expanded"
    )
    default_concurrency = parse_int(payload, "default_concurrency", minimum=1, default=1)
    vulncheck_token = parse_optional_string(payload, "vulncheck_token")
    return PalisadeConfig(
        db_path=db_path,
        default_kev_scope=default_kev_scope,
        default_concurrency=default_concurrency,
        default_artifact_dir=default_artifact_dir,
        vulncheck_token=vulncheck_token,
    )


def write_default_config(path: Path) -> Path:
    """Write a starter config file if one does not already exist."""
    payload = {
        "db_path": "data/palisade.db",
        "default_kev_scope": "expanded",
        "default_concurrency": 1,
        "default_artifact_dir": "artifacts",
        "vulncheck_token": "",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def config_to_json(config: PalisadeConfig) -> str:
    """Render config as pretty JSON."""
    payload = {
        "db_path": str(config.db_path),
        "default_kev_scope": config.default_kev_scope,
        "default_concurrency": config.default_concurrency,
        "default_artifact_dir": str(config.default_artifact_dir),
        "vulncheck_token": "***configured***" if config.vulncheck_token else None,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_path(payload: dict[str, Any], key: str, default: Path) -> Path:
    """Return a config path field."""
    value = payload.get(key)
    if value in (None, ""):
        return default
    if not isinstance(value, str):
        raise ValueError(f"Config field {key!r} must be a string path")
    return Path(value)


def parse_optional_string(payload: dict[str, Any], key: str) -> str | None:
    """Return an optional string field."""
    value = payload.get(key)
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError(f"Config field {key!r} must be a string when present")
    return value


def parse_choice(
    payload: dict[str, Any], key: str, choices: tuple[str, ...], default: str
) -> str:
    """Return a constrained string field."""
    value = payload.get(key)
    if value is None:
        return default
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"Config field {key!r} must be one of: {', '.join(choices)}")
    return value


def parse_int(payload: dict[str, Any], key: str, *, minimum: int, default: int) -> int:
    """Return an integer field with bounds."""
    value = payload.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or value < minimum:
        raise ValueError(f"Config field {key!r} must be an integer >= {minimum}")
    return value

"""Configuration loading.

Precedence: explicit ``--config`` path > ``./config/signatures.yaml`` (if the
working directory has one) > packaged defaults. User files are deep-merged
over the defaults, so a config may override a single threshold without
restating everything.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml

DEFAULT_USER_CONFIG = Path("config/signatures.yaml")


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_default_config() -> dict:
    text = files("sentryd.data").joinpath("default_config.yaml").read_text()
    return yaml.safe_load(text)


def load_config(path: Path | None = None) -> dict:
    """Load effective config: packaged defaults merged with the user file."""
    config = load_default_config()
    if path is None and DEFAULT_USER_CONFIG.is_file():
        path = DEFAULT_USER_CONFIG
    if path is not None:
        user = yaml.safe_load(Path(path).read_text()) or {}
        if not isinstance(user, dict):
            raise ValueError(f"config file {path} must contain a YAML mapping")
        config = _deep_merge(config, user)
    return config

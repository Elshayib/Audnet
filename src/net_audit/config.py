"""Configuration loaders for device inventory and security baselines."""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import yaml

from pydantic import ValidationError

from net_audit.exceptions import ConfigError
from net_audit.models import Device, SecurityBaseline

logger = logging.getLogger(__name__)

_ENV_RE = re.compile(r"\$\{(\w+)\}")


def _resolve_env(value: str) -> str:
    def replacer(match: re.Match[str]) -> str:
        var = match.group(1)
        return os.environ.get(var, match.group(0))

    return _ENV_RE.sub(replacer, value)


def _deep_resolve(obj: Any) -> Any:
    if isinstance(obj, str):
        return _resolve_env(obj)
    if isinstance(obj, dict):
        return {k: _deep_resolve(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_resolve(v) for v in obj]
    return obj


def load_inventory(path: str) -> tuple[dict[str, Any], list[Device]]:
    logger.info("Loading inventory from %s", path)
    try:
        with open(path) as f:
            data: dict[str, Any] = yaml.safe_load(f)
    except FileNotFoundError as exc:
        raise ConfigError(f"Inventory file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in inventory: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Inventory YAML must be a mapping at the top level")

    data = _deep_resolve(data)
    defaults = data.get("defaults", {})
    devices = []
    for entry in data.get("devices", []):
        merged = {**defaults, **entry}
        devices.append(Device(**merged))
    logger.info("Loaded %d devices", len(devices))
    return defaults, devices


def load_baseline(path: str) -> dict[str, Any]:
    logger.info("Loading baseline from %s", path)
    try:
        with open(path) as f:
            data: dict[str, Any] = yaml.safe_load(f)
    except FileNotFoundError as exc:
        raise ConfigError(f"Baseline file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in baseline: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Baseline YAML must be a mapping at the top level")
    try:
        baseline = SecurityBaseline(**data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid baseline schema: {exc}") from exc
    return baseline.model_dump()

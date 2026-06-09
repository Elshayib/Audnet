"""Configuration loaders for device inventory and security baselines."""

from __future__ import annotations

import os
import re
from typing import Any

import yaml

from net_audit.models import Device


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
    with open(path) as f:
        data: dict[str, Any] = yaml.safe_load(f)
    data = _deep_resolve(data)
    defaults = data.get("defaults", {})
    devices = []
    for entry in data.get("devices", []):
        merged = {**defaults, **entry}
        devices.append(Device(**merged))
    return defaults, devices


def load_baseline(path: str) -> dict[str, Any]:
    with open(path) as f:
        data: dict[str, Any] = yaml.safe_load(f)
    return data

"""Configuration loaders for device inventory and security baselines."""

import os
import re

import yaml

from net_audit.models import Device


_ENV_RE = re.compile(r"\$\{(\w+)\}")


def _resolve_env(value: str) -> str:
    def replacer(match: re.Match) -> str:
        var = match.group(1)
        return os.environ.get(var, match.group(0))
    return _ENV_RE.sub(replacer, value)


def _deep_resolve(obj):
    if isinstance(obj, str):
        return _resolve_env(obj)
    if isinstance(obj, dict):
        return {k: _deep_resolve(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_resolve(v) for v in obj]
    return obj


def load_inventory(path: str) -> tuple[dict, list[Device]]:
    with open(path) as f:
        data = yaml.safe_load(f)
    data = _deep_resolve(data)
    defaults = data.get("defaults", {})
    devices = []
    for entry in data.get("devices", []):
        merged = {**defaults, **entry}
        devices.append(Device(**merged))
    return defaults, devices


def load_baseline(path: str) -> dict:
    with open(path) as f:
        data = yaml.safe_load(f)
    return data

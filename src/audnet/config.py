"""Configuration loaders for device inventory and security baselines."""

from __future__ import annotations

import logging
import os
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

import yaml

from pydantic import ValidationError

from audnet.exceptions import ConfigError
from audnet.models import Device, SecurityBaseline

logger = logging.getLogger(__name__)

_ENV_RE = re.compile(r"\$\{(\w+)\}")
_PLAIN_PASSWORD_RE = re.compile(r"^(?!\$\{).+$", re.DOTALL)


def _is_plaintext(value: str) -> bool:
    """Return True if *value* looks like a plaintext secret (not a ${VAR} reference)."""
    return bool(value and _PLAIN_PASSWORD_RE.match(value))


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


def load_inventory(path: str, strict: bool = False) -> tuple[dict[str, Any], list[Device]]:
    logger.info("Loading inventory from %s", path)

    # Dynamic inventory sources
    if path.startswith("netbox://"):
        from audnet.inventory_sources.netbox import fetch_netbox_devices

        parsed = urlparse(path)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        filters: dict[str, str] = {}
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                if values:
                    filters[key] = values[0]
        devices = fetch_netbox_devices(base_url, filters=filters)
        if strict:
            _check_strict_credentials(devices)
        logger.info("Loaded %d devices from NetBox", len(devices))
        return {}, devices

    try:
        with open(path) as f:
            data: dict[str, Any] = yaml.safe_load(f)
    except FileNotFoundError as exc:
        raise ConfigError(f"Inventory file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in inventory: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Inventory YAML must be a mapping at the top level")

    # Check for plaintext passwords BEFORE env resolution so that
    # ${VAR} references are not mistaken for resolved plaintext values.
    defaults = data.get("defaults", {})
    plaintext_devices: list[str] = []
    _SENSITIVE_FIELDS = ("password", "secret", "passwd", "token")
    for entry in data.get("devices", []):
        merged = {**defaults, **entry}
        for field in _SENSITIVE_FIELDS:
            val = merged.get(field, "")
            if isinstance(val, str) and _is_plaintext(val):
                plaintext_devices.append(
                    f"{merged.get('name', merged.get('host', 'unknown'))} ({field})"
                )
    if plaintext_devices:
        msg = (
            f"Plaintext secrets found for device(s): {', '.join(plaintext_devices)}. "
            "Use ${ENV_VAR} references or an external secret store in production."
        )
        if strict:
            raise ConfigError(msg)
        logger.warning(msg)

    raw_data = _deep_resolve(data)
    defaults = raw_data.get("defaults", {})
    devices: list[Device] = []
    for entry in raw_data.get("devices", []):
        merged = {**defaults, **entry}
        try:
            devices.append(Device(**merged))
        except ValidationError as exc:
            name = merged.get("name", merged.get("host", "unknown"))
            logger.warning("Skipping invalid device '%s': %s", name, exc)
    if not devices:
        raise ConfigError("No valid devices found in inventory")
    logger.info("Loaded %d devices", len(devices))
    return defaults, devices


def _check_strict_credentials(devices: list[Device]) -> None:
    """Raise ConfigError if any device has a plaintext password."""
    plaintext: list[str] = []
    for d in devices:
        pw = d.get_password()
        if pw and _is_plaintext(pw):
            plaintext.append(f"{d.name} (password)")
    if plaintext:
        raise ConfigError(
            f"Plaintext secrets found for device(s): {', '.join(plaintext)}. "
            "Use ${ENV_VAR} references or an external secret store in production."
        )


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

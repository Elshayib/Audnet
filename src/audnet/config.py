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
        if var not in os.environ:
            raise ConfigError(f"Environment variable '{var}' is not set")
        return os.environ[var]

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
    if path.startswith("netbox://") or path.startswith("netbox+http://"):
        from audnet.inventory_sources.netbox import fetch_netbox_devices

        parsed = urlparse(path)
        # netbox://host/path -> https://host/path (path prefix preserved)
        # netbox+http://host/path -> http://host/path (lab only)
        if parsed.scheme == "netbox+http":
            scheme = "http"
            allow_http = True
        else:
            scheme = "https" if parsed.scheme == "netbox" else parsed.scheme
            allow_http = False
        path_prefix = parsed.path.rstrip("/") if parsed.path and parsed.path != "/" else ""
        base_url = f"{scheme}://{parsed.netloc}{path_prefix}"
        filters: dict[str, str] = {}
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                if values:
                    filters[key] = values[0]
        devices = fetch_netbox_devices(base_url, filters=filters, allow_http=allow_http)
        # Resolve ${ENV_VAR} placeholders in credential fields (same as YAML path)
        devices = [_resolve_device_env(d) for d in devices]
        if strict:
            _check_strict_credentials(devices)
        logger.info("Loaded %d devices from NetBox", len(devices))
        return {}, devices
    try:
        with open(path, encoding="utf-8") as f:
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
    yaml_devices: list[Device] = []
    for entry in raw_data.get("devices", []):
        merged = {**defaults, **entry}
        try:
            yaml_devices.append(Device(**merged))
        except ValidationError as exc:
            name = merged.get("name", merged.get("host", "unknown"))
            logger.warning("Skipping invalid device '%s': %s", name, exc)
    if not yaml_devices:
        raise ConfigError("No valid devices found in inventory")
    logger.info("Loaded %d devices", len(yaml_devices))
    return defaults, yaml_devices


def _resolve_device_env(device: Device) -> Device:
    """Resolve ``${ENV_VAR}`` placeholders in Device secret fields.

    NetBox config_context often stores ``${NETBOX_AUDNET_PASSWORD}``-style
    references; the YAML inventory path resolves these via ``_deep_resolve``,
    but the NetBox path builds Device objects from raw context and must
    resolve secrets the same way.
    """
    updates: dict[str, Any] = {}
    for field in ("password", "secret", "passwd", "token", "username", "key_file"):
        val = getattr(device, field, None)
        if val is None:
            continue
        if hasattr(val, "get_secret_value"):
            raw = val.get_secret_value()
        else:
            raw = val
        if isinstance(raw, str) and "${" in raw:
            updates[field] = _resolve_env(raw)
    if not updates:
        return device
    # Re-validate so SecretStr fields stay SecretStr (model_copy does not coerce)
    data = device.model_dump(mode="python")
    data.update(updates)
    return Device.model_validate(data)


def _check_strict_credentials(devices: list[Device]) -> None:
    """Raise ConfigError if any device lacks secure credential configuration."""
    issues: list[str] = []
    for d in devices:
        pw = d.get_password()
        if pw and _is_plaintext(pw):
            issues.append(f"{d.name} (password)")
        elif not pw and not d.use_keys:
            issues.append(f"{d.name} (no password or SSH key)")
        for field_name, getter in (
            ("secret", d.get_secret),
            ("token", lambda: d.token.get_secret_value()),
        ):
            val = getter()
            if val and _is_plaintext(val):
                issues.append(f"{d.name} ({field_name})")
    if issues:
        raise ConfigError(
            f"Insecure credentials for device(s): {', '.join(issues)}. "
            "Use ${ENV_VAR} references, SSH keys, or an external secret store."
        )


def load_baseline(path: str) -> dict[str, Any]:
    logger.info("Loading baseline from %s", path)
    try:
        with open(path, encoding="utf-8") as f:
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

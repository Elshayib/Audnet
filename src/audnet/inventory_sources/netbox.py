"""NetBox dynamic inventory source.

Fetches devices from a NetBox instance via its REST API and maps them
to the local :class:`audnet.models.Device` model.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from audnet.exceptions import ConfigError
from audnet.models import Device

logger = logging.getLogger(__name__)

# NetBox device status we care about
_DEFAULT_STATUS = "active"


def _build_url(base: str, filters: dict[str, str]) -> str:
    """Append query parameters to a base URL."""
    parsed = urlparse(base)
    existing = parse_qs(parsed.query)
    merged: dict[str, list[str]] = {}
    for k, v in existing.items():
        merged[k] = v
    for k, v in filters.items():
        merged[k] = [v]
    new_qs = urlencode(sorted(merged.items()), doseq=True)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_qs, parsed.fragment)
    )


def _normalize_device(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a NetBox device dict to Device constructor kwargs."""
    name = raw.get("name", "")
    # NetBox primary_ip field is like "10.0.0.1/24"
    primary_ip = raw.get("primary_ip") or raw.get("primary_ip4", "")
    if isinstance(primary_ip, dict):
        address = primary_ip.get("address", "")
    elif isinstance(primary_ip, str):
        address = primary_ip
    else:
        address = ""

    # Strip CIDR prefix if present -- we just want the host
    host = address.split("/")[0] if address else ""

    # NetBox platform -> e.g. "ios", "juniper_junos", "paloalto_panos"
    platform = raw.get("platform")
    if isinstance(platform, dict):
        platform_slug = platform.get("slug", "cisco_ios")
    elif isinstance(platform, str):
        platform_slug = platform
    else:
        platform_slug = "cisco_ios"

    # NetBox platform slug to device_type mapping
    platform_map = {
        "ios": "cisco_ios",
        "iosxe": "cisco_ios",
        "nxos": "cisco_nxos",
        "nx-os": "cisco_nxos",
        "asa": "cisco_asa",
        "junos": "juniper_junos",
        "juniper_junos": "juniper_junos",
        "panos": "paloalto_panos",
        "paloalto_panos": "paloalto_panos",
        "arista_eos": "arista_eos",
    }
    device_type = platform_map.get(platform_slug, "cisco_ios")

    # Optional: pull credentials from device config context
    config_ctx: dict[str, Any] = raw.get("config_context", None) or {}
    username = config_ctx.get("audit_username", "admin")
    port = config_ctx.get("audit_port", 22)
    use_keys = config_ctx.get("audit_use_keys", False)
    key_file = config_ctx.get("audit_key_file", "")

    kwargs: dict[str, Any] = {
        "name": name,
        "host": host,
        "device_type": device_type,
        "username": username,
        "port": int(port) if isinstance(port, str) and port.isdigit() else port,
        "use_keys": bool(use_keys),
    }
    if key_file:
        kwargs["key_file"] = key_file
    audit_password = config_ctx.get("audit_password", "")
    if audit_password:
        kwargs["password"] = audit_password

    return kwargs


def fetch_netbox_devices(
    url: str,
    token: str | None = None,
    filters: dict[str, str] | None = None,
) -> list[Device]:
    """Fetch devices from NetBox and return a list of Device objects.

    Parameters
    ----------
    url:
        Base NetBox URL, e.g. ``https://netbox.example.com``.
    token:
        API token. Falls back to ``NETBOX_TOKEN`` env var if not given.
    filters:
        Extra query parameters (e.g. ``{"site": "dc1", "role": "router"}``).

    Raises
    ------
    ConfigError
        If the token is missing, the API returns an error, or no devices
        are returned.
    """
    if token is None:
        token = os.environ.get("NETBOX_TOKEN")
    if not token:
        raise ConfigError(
            "NetBox API token required. Set NETBOX_TOKEN environment variable "
            "or pass token explicitly."
        )

    if filters is None:
        filters = {}
    filters.setdefault("status", _DEFAULT_STATUS)

    api_url = _build_url(f"{url.rstrip('/')}/api/dcim/devices/", filters)
    logger.info("Fetching NetBox devices from %s", api_url)

    req = Request(
        api_url,
        headers={
            "Authorization": f"Token {token}",
            "Accept": "application/json",
        },
    )

    try:
        with urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail", "")
        except Exception:
            pass
        msg = f"NetBox API error: {exc.code}"
        if detail:
            msg += f" -- {detail}"
        raise ConfigError(msg) from exc
    except URLError as exc:
        raise ConfigError(f"NetBox connection failed: {exc.reason}") from exc

    results = body.get("results", [])
    if not results:
        raise ConfigError("No active devices returned from NetBox")

    devices: list[Device] = []
    for raw in results:
        kwargs = _normalize_device(raw)
        try:
            devices.append(Device(**kwargs))
        except Exception as exc:
            logger.warning("Skipping invalid NetBox device '%s': %s", kwargs.get("name", "?"), exc)

    if not devices:
        raise ConfigError("No valid devices could be built from NetBox results")

    logger.info("Fetched %d devices from NetBox", len(devices))
    return devices

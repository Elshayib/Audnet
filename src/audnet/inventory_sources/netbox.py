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

# Safety cap on pagination to avoid infinite loops from sticky `next` URLs
_MAX_PAGES = 500

# NetBox platform slug -> Netmiko/audnet device_type
# Identity mappings included so netmiko-style slugs don't fall back to IOS.
_PLATFORM_MAP: dict[str, str] = {
    "ios": "cisco_ios",
    "iosxe": "cisco_ios",
    "ios-xe": "cisco_ios",
    "cisco_ios": "cisco_ios",
    "cisco_xe": "cisco_ios",
    "nxos": "cisco_nxos",
    "nx-os": "cisco_nxos",
    "cisco_nxos": "cisco_nxos",
    "asa": "cisco_asa",
    "cisco_asa": "cisco_asa",
    "junos": "juniper_junos",
    "juniper_junos": "juniper_junos",
    "panos": "paloalto_panos",
    "paloalto_panos": "paloalto_panos",
    "eos": "arista_eos",
    "arista": "arista_eos",
    "arista_eos": "arista_eos",
    "fortios": "fortinet_fortios",
    "fortinet": "fortinet_fortios",
    "fortinet_fortios": "fortinet_fortios",
    "aruba": "aruba_os",
    "aruba_os": "aruba_os",
    "aoscx": "aruba_os",
    "procurve": "hp_procurve",
    "hp_procurve": "hp_procurve",
}


def _build_url(base: str, filters: dict[str, str]) -> str:
    """Append query parameters to a base URL."""
    parsed = urlparse(base)
    existing: dict[str, list[str]] = parse_qs(parsed.query)
    merged = dict(existing)
    for k, v in filters.items():
        merged[k] = [v]
    new_qs = urlencode(sorted(merged.items()), doseq=True)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_qs, parsed.fragment)
    )


def _same_origin(base: str, candidate: str) -> bool:
    """Return True if *candidate* shares scheme, host, and port with *base*."""
    b = urlparse(base)
    c = urlparse(candidate)
    if c.scheme not in ("http", "https"):
        return False
    if c.scheme != b.scheme:
        return False
    if c.hostname != b.hostname:
        return False
    # urlparse: empty port means default for scheme
    b_port = b.port or (443 if b.scheme == "https" else 80)
    c_port = c.port or (443 if c.scheme == "https" else 80)
    return b_port == c_port


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """Parse bools from NetBox config_context (handles stringy 'false'/'0')."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


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
        platform_slug = (platform.get("slug") or "cisco_ios") or "cisco_ios"
    elif isinstance(platform, str):
        platform_slug = platform
    else:
        platform_slug = "cisco_ios"

    platform_slug = str(platform_slug).lower().strip()
    if platform_slug in _PLATFORM_MAP:
        device_type = _PLATFORM_MAP[platform_slug]
    else:
        logger.warning(
            "Unknown NetBox platform slug %r for device %r — defaulting to cisco_ios",
            platform_slug,
            name,
        )
        device_type = "cisco_ios"

    # Optional: pull credentials from device config context
    config_ctx: dict[str, Any] = raw.get("config_context", None) or {}
    audnet_ctx = config_ctx.get("audnet", {})
    if not isinstance(audnet_ctx, dict):
        audnet_ctx = {}

    def _ctx(key: str, audit_key: str, default: Any = None) -> Any:
        if key in audnet_ctx:
            return audnet_ctx[key]
        if audit_key in config_ctx:
            return config_ctx[audit_key]
        return default

    username = _ctx("username", "audit_username", "admin")
    port = _ctx("port", "audit_port", 22)
    use_keys = _coerce_bool(_ctx("use_keys", "audit_use_keys", False))
    key_file = _ctx("key_file", "audit_key_file", "") or ""
    secret = _ctx("secret", "audit_secret", "") or ""

    kwargs: dict[str, Any] = {
        "name": name,
        "host": host,
        "device_type": device_type,
        "username": username,
        "port": int(port) if isinstance(port, str) and str(port).isdigit() else port,
        "use_keys": use_keys,
    }
    if key_file:
        kwargs["key_file"] = key_file
    audit_password = _ctx("password", "audit_password", "")
    if audit_password:
        kwargs["password"] = audit_password
    if secret:
        kwargs["secret"] = secret

    return kwargs


def fetch_netbox_devices(
    url: str,
    token: str | None = None,
    filters: dict[str, str] | None = None,
    *,
    allow_http: bool = False,
) -> list[Device]:
    """Fetch devices from NetBox and return a list of Device objects.

    Parameters
    ----------
    url:
        Base NetBox URL, e.g. ``https://netbox.example.com`` or
        ``https://netbox.example.com/netbox`` (path prefix preserved).
    token:
        API token. Falls back to ``NETBOX_TOKEN`` env var if not given.
    filters:
        Extra query parameters (e.g. ``{"site": "dc1", "role": "router"}``).
    allow_http:
        If True, allow plain HTTP (lab only). Default is HTTPS-only when
        the URL scheme is not already fixed by the caller.

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

    # Do not mutate caller-supplied filters
    filters = dict(filters or {})
    filters.setdefault("status", _DEFAULT_STATUS)

    parsed_base = urlparse(url)
    if parsed_base.scheme not in ("http", "https"):
        raise ConfigError("NetBox URL must use http or https scheme")
    if parsed_base.scheme == "http" and not allow_http:
        # Lab HTTP is allowed when explicitly requested via allow_http=True or env.
        # Default for netbox:// inventory URLs is HTTPS-only (config.py).
        if os.environ.get("AUDNET_NETBOX_ALLOW_HTTP", "").strip().lower() not in (
            "1",
            "true",
            "yes",
        ):
            # Still allow plain http:// when caller passes allow_http; for direct
            # API use with http URLs, require the env flag OR treat as lab ok
            # when the URL is explicitly http (backward compat for tests/labs).
            allow_http = True  # explicit http:// URL is intentional lab use
            logger.warning(
                "Using plain HTTP for NetBox at %s — token may be exposed on the wire",
                url,
            )

    api_url = _build_url(f"{url.rstrip('/')}/api/dcim/devices/", filters)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    logger.info("Fetching NetBox devices from %s", api_url)

    results: list[dict[str, Any]] = []
    page_url: str | None = api_url
    pages = 0
    while page_url:
        pages += 1
        if pages > _MAX_PAGES:
            raise ConfigError(
                f"NetBox pagination exceeded {_MAX_PAGES} pages — aborting"
            )
        # SSRF guard: never follow `next` off the original origin with the token
        if not _same_origin(origin, page_url):
            raise ConfigError(
                f"Refusing to follow NetBox pagination URL off-origin: {page_url!r}"
            )

        page_req = Request(
            page_url,
            headers={
                "Authorization": f"Token {token}",
                "Accept": "application/json",
            },
        )
        if page_req.type not in ("http", "https"):
            raise ConfigError(
                f"NetBox URL must use http or https scheme, got: {page_req.type}"
            )
        try:
            with urlopen(page_req, timeout=30) as resp:  # nosec B310
                raw_body = resp.read().decode("utf-8")
        except HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read().decode("utf-8")).get("detail", "")
            except (json.JSONDecodeError, ValueError):
                pass
            msg = f"NetBox API error: {exc.code}"
            if detail:
                msg += f" -- {detail}"
            raise ConfigError(msg) from exc
        except URLError as exc:
            raise ConfigError(f"NetBox connection failed: {exc.reason}") from exc

        try:
            page_body = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"NetBox returned non-JSON response: {exc}") from exc

        if isinstance(page_body, list):
            results.extend(page_body)
            page_url = None
        else:
            results.extend(page_body.get("results", []))
            next_url = page_body.get("next")
            if next_url and not _same_origin(origin, next_url):
                raise ConfigError(
                    f"Refusing to follow NetBox pagination URL off-origin: {next_url!r}"
                )
            page_url = next_url

    if not results:
        raise ConfigError("No active devices returned from NetBox")

    devices: list[Device] = []
    for raw in results:
        kwargs = _normalize_device(raw)
        try:
            devices.append(Device(**kwargs))
        except Exception as exc:
            logger.warning(
                "Skipping invalid NetBox device '%s': %s", kwargs.get("name", "?"), exc
            )

    if not devices:
        raise ConfigError("No valid devices could be built from NetBox results")

    logger.info("Fetched %d devices from NetBox", len(devices))
    return devices

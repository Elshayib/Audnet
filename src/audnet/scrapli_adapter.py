"""Scrapli transport adapter behind the raw-transport seam.

The adapter only moves bytes: connect/run/close. Retry, snapshot assembly,
fan-out, and the failure contract live in :mod:`audnet.collection`.

Transport-specific knobs (per-Device driver choice, SSH strict-key handling,
key auth) live here, not on the collection interface.

This module is optional — it requires the 'scrapli' extra:
    pip install "audnet[scrapli]"
"""

from __future__ import annotations

import logging
import os
from typing import Any, cast

from audnet.models import Device

logger = logging.getLogger(__name__)

_SCRAPLI_AVAILABLE = False
_RETRYABLE_EXCEPTIONS: tuple[type[BaseException], ...] = ()
_SCRAPLI_DRIVER_MAP: dict[str, type] = {}

try:
    from scrapli.driver.core import (
        AsyncEOSDriver,
        AsyncIOSXEDriver,
        AsyncJunosDriver,
        AsyncNXOSDriver,
    )
    from scrapli.driver.network.async_driver import AsyncNetworkDriver
    from scrapli.exceptions import (
        ScrapliAuthenticationFailed,
        ScrapliConnectionError,
        ScrapliTimeout,
    )

    _SCRAPLI_AVAILABLE = True

    _RETRYABLE_EXCEPTIONS = (
        ScrapliConnectionError,
        ScrapliTimeout,
        OSError,
        ConnectionError,
    )

    _SCRAPLI_DRIVER_MAP = {
        "cisco_ios": AsyncIOSXEDriver,
        "cisco_xe": AsyncIOSXEDriver,
        "cisco_asa": AsyncNetworkDriver,
        "cisco_nxos": AsyncNXOSDriver,
        "arista_eos": AsyncEOSDriver,
        "juniper_junos": AsyncJunosDriver,
        "fortinet_fortios": AsyncNetworkDriver,
        "paloalto_panos": AsyncNetworkDriver,
        "aruba_os": AsyncNetworkDriver,
        "hp_procurve": AsyncNetworkDriver,
    }
except ImportError:
    _SCRAPLI_AVAILABLE = False


# textfsm_platform override for vendors using AsyncNetworkDriver
# (core drivers have sensible defaults built in)
_TEXTFSM_PLATFORM_MAP: dict[str, str] = {
    "fortinet_fortios": "fortinet_fortios",
    "paloalto_panos": "paloalto_panos",
    "cisco_asa": "cisco_asa",
    "aruba_os": "aruba_aoscx",
    "hp_procurve": "hp_procurve",
}


def _check_scrapli_available() -> None:
    """Raise ImportError with helpful message if scrapli is not installed."""
    if not _SCRAPLI_AVAILABLE:
        raise ImportError(
            "scrapli is required for the Scrapli collector. "
            'Install it with: pip install "audnet[scrapli]"'
        )


def _ssh_strict_enabled(strict_key: bool | None = None) -> bool:
    """Return whether SSH host-key verification is enforced (default: on)."""
    if strict_key is not None:
        return strict_key
    val = os.environ.get("AUDNET_SSH_STRICT_KEY", "1").strip().lower()
    return val not in ("0", "false", "no", "off")


def _get_scrapli_driver(device_type: str) -> type:
    """Return the Scrapli driver class for a given audnet device_type."""
    _check_scrapli_available()
    # AsyncNetworkDriver is only defined when scrapli is installed; the
    # availability check above guarantees the name exists here.
    return _SCRAPLI_DRIVER_MAP.get(device_type, AsyncNetworkDriver)


def _is_retryable(exc: BaseException) -> bool:
    """Return True if *exc* is a transient Scrapli error worth retrying.

    Backward-compat helper (the shared failure contract lives in
    :mod:`audnet.collection`). Explicitly excludes authentication failures.
    Returns False when scrapli is not installed.
    """
    if not _SCRAPLI_AVAILABLE:
        return False
    # ScrapliAuthenticationFailed only exists when scrapli is installed; the
    # availability guard above ensures the name is defined here.
    if isinstance(exc, ScrapliAuthenticationFailed):
        return False
    return isinstance(exc, _RETRYABLE_EXCEPTIONS)


def _build_conn_params(
    device: Device, strict_key: bool | None = None
) -> dict[str, Any]:
    """Build connection parameters dict for Scrapli driver."""
    strict = _ssh_strict_enabled(strict_key)
    params: dict[str, Any] = {
        "host": device.host,
        "auth_username": device.username,
        "auth_strict_key": strict,
        "transport": "asyncssh",
        "timeout_socket": device.timeout,
        "timeout_transport": device.timeout,
        "timeout_ops": device.timeout,
    }
    password = device.get_password()
    if password:
        params["auth_password"] = password
    secret = device.get_secret()
    if secret:
        params["auth_secondary"] = secret
    if device.use_keys and device.key_file:
        params["auth_private_key"] = device.key_file
        params["auth_private_key_passphrase"] = password or None
    if device.port != 22:
        params["port"] = device.port
    return params


class ScrapliAdapter:
    """Raw-transport adapter for the Scrapli (async) transport.

    Per-Device driver choice lives here, never on the shared
    :mod:`audnet.collection` interface.

    Args:
        strict_key: Override SSH strict-key handling. None reads
            ``AUDNET_SSH_STRICT_KEY`` env var per-connect (default: on).

    Usage (via :mod:`audnet.collection`)::

        adapter = ScrapliAdapter()
        conn = await adapter.connect(device)
        try:
            out = await adapter.run(conn, "show version", timeout=device.timeout)
        finally:
            await adapter.close(conn)
    """

    def __init__(self, strict_key: bool | None = None) -> None:
        _check_scrapli_available()
        self._strict_key = strict_key

    async def connect(self, device: Device) -> Any:
        """Open a Scrapli connection for *device* (per-Device driver choice)."""
        _check_scrapli_available()
        driver_cls = _get_scrapli_driver(device.device_type)
        conn_params = _build_conn_params(device, strict_key=self._strict_key)
        conn = driver_cls(**conn_params)
        await conn.open()
        return conn

    async def run(
        self, connection: Any, command: str, *, timeout: float | None = None
    ) -> str:
        """Run one command, returning raw CLI output."""
        if timeout is not None:
            response = await connection.send_command(command, timeout_ops=timeout)
        else:
            response = await connection.send_command(command)
        return cast(str, response.result)

    async def close(self, connection: Any) -> None:
        """Close a connection, never raising."""
        try:
            await connection.close()
        except Exception as exc:  # pragma: no cover
            logger.warning("Failed to close Scrapli connection: %s", exc)

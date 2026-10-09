"""Default sync transport adapter (Netmiko) behind the raw-transport seam.

The adapter only moves bytes: connect/run/close. Retry, snapshot assembly,
fan-out, and the failure contract live in :mod:`audnet.collection`.

Transport-specific knobs (SSH strict-key handling, enable mode, key auth)
live here, not on the collection interface.
"""

from __future__ import annotations

import logging
import os
from typing import Any, cast

from netmiko import ConnectHandler

from audnet.models import Device

logger = logging.getLogger(__name__)


def _ssh_strict_enabled(strict_key: bool | None = None) -> bool:
    """Return whether SSH host-key verification is enforced (default: on).

    Args:
        strict_key: Explicit override. When None (default), reads
            ``AUDNET_SSH_STRICT_KEY`` env var (``1`` = on).
    """
    if strict_key is not None:
        return strict_key
    val = os.environ.get("AUDNET_SSH_STRICT_KEY", "1").strip().lower()
    return val not in ("0", "false", "no", "off")


class NetmikoAdapter:
    """Raw-transport adapter for the default sync (Netmiko) transport.

    Usage (via :mod:`audnet.collection`)::

        adapter = NetmikoAdapter()
        conn = adapter.connect(device)
        try:
            out = adapter.run(conn, "show version")
        finally:
            adapter.close(conn)
    """

    def __init__(self, strict_key: bool | None = None) -> None:
        """Args:
        strict_key: Override SSH strict-key handling. None reads env per-connect.
        """
        self._strict_key = strict_key

    def connect(self, device: Device) -> Any:
        """Open an SSH connection and enter enable mode when a secret exists."""
        params: dict[str, object] = {
            "device_type": device.device_type,
            "host": device.host,
            "username": device.username,
            "password": device.get_password(),
            "port": device.port,
            # Netmiko: conn_timeout = TCP/SSH connect; timeout = read/session
            "timeout": device.timeout,
            "conn_timeout": device.timeout,
            "system_host_keys": True,
            "ssh_strict": _ssh_strict_enabled(self._strict_key),
        }
        if device.use_keys:
            params["use_keys"] = True
            if device.key_file:
                params["key_file"] = device.key_file
        secret = device.get_secret()
        if secret:
            params["secret"] = secret
        conn = ConnectHandler(**params)
        if secret:
            try:
                conn.enable()
            except Exception as exc:  # pragma: no cover
                logger.warning("Failed to enter enable mode on %s: %s", device.name, exc)
        return conn

    def run(self, connection: Any, command: str) -> str:
        """Run one command, returning raw CLI output."""
        return cast(str, connection.send_command(command))

    def close(self, connection: Any) -> None:
        """Close a connection, never raising."""
        try:
            connection.disconnect()
        except Exception as exc:  # pragma: no cover
            logger.warning("Failed to disconnect: %s", exc)

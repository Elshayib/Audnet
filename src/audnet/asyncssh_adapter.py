"""AsyncSSH transport adapter behind the raw-transport seam.

The adapter only moves bytes: connect/run/close. Retry, snapshot assembly,
fan-out, and the failure contract live in :mod:`audnet.collection`.

Transport-specific knobs (host-key verification, key auth) live here, not
on the collection interface.
"""

from __future__ import annotations

import logging
from typing import Any, cast

import asyncssh

from audnet.models import Device

logger = logging.getLogger(__name__)


class AsyncSSHAdapter:
    """Raw-transport adapter for the async (asyncssh) transport.

    Args:
        known_hosts: Path to known_hosts file. When None (default),
            asyncssh uses the system default (``~/.ssh/known_hosts``).
            Pass an empty string to explicitly disable verification
            (lab/testing only).

    Usage (via :mod:`audnet.collection`)::

        adapter = AsyncSSHAdapter()
        conn = await adapter.connect(device)
        try:
            out = await adapter.run(conn, "show version", timeout=device.timeout)
        finally:
            await adapter.close(conn)
    """

    def __init__(self, known_hosts: str | None = None) -> None:
        self._known_hosts = known_hosts

    async def connect(self, device: Device) -> Any:
        """Open an async SSH connection for *device*."""
        connect_kwargs: dict[str, Any] = {
            "host": device.host,
            "port": device.port,
            "username": device.username,
            "connect_timeout": device.timeout or 30,
        }
        password = device.get_password()
        if password:
            connect_kwargs["password"] = password
        if device.use_keys and device.key_file:
            connect_kwargs["client_keys"] = [device.key_file]
        elif device.use_keys:
            connect_kwargs["client_keys"] = "default"
        if self._known_hosts is not None:
            connect_kwargs["known_hosts"] = self._known_hosts
        conn = await asyncssh.connect(**connect_kwargs)
        return conn

    async def run(
        self, connection: Any, command: str, *, timeout: float | None = None
    ) -> str:
        """Run one command, returning raw CLI output.

        Treats real non-zero exit / missing stdout as a collection failure
        so we never silently build empty snapshots that look like compliance.
        """
        result = await connection.run(command, timeout=timeout)
        stdout = result.stdout
        # Treat real non-zero exit / missing stdout as collection failure so
        # we never silently build empty snapshots that look like compliance.
        exit_status = getattr(result, "exit_status", None)
        if isinstance(exit_status, int) and exit_status != 0:
            stderr = getattr(result, "stderr", None) or ""
            if not isinstance(stderr, str):
                stderr = str(stderr)
            raise OSError(
                f"Command {command!r} failed (exit={exit_status}): {stderr.strip()}"
            )
        if stdout is None:
            raise OSError(f"Command {command!r} returned no stdout")
        return cast(str, stdout)

    async def close(self, connection: Any) -> None:
        """Close a connection, never raising."""
        try:
            connection.close()
        except Exception as exc:  # pragma: no cover
            logger.warning("Failed to close connection: %s", exc)
            return
        wait_closed = getattr(connection, "wait_closed", None)
        if wait_closed is None:
            return
        try:
            await wait_closed()
        except Exception as exc:  # pragma: no cover
            logger.warning("Failed to wait for connection close: %s", exc)

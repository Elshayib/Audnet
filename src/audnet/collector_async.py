"""Async SSH collector for network device data.

Uses asyncssh for concurrent SSH collection with lower per-connection overhead
than the ThreadPool + Netmiko sync collector. Integrated into the CLI via
``--async`` or ``--backend asyncssh``.
"""

import asyncio
import logging
from typing import Any, cast

import asyncssh
from asyncssh import (
    ChannelOpenError,
    DisconnectError,
    PermissionDenied,
    TimeoutError as AsyncSshTimeoutError,
)
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

from audnet.exceptions import ParseError
from audnet.models import Device, DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig
from audnet.parser import parse_interfaces, parse_version, parse_config
from audnet.vendor_registry import Slot, get_commands

logger = logging.getLogger(__name__)
_RETRYABLE_EXCEPTIONS = (
    DisconnectError,
    ChannelOpenError,
    AsyncSshTimeoutError,
    OSError,
    ConnectionError,
)


def _is_retryable(exc: BaseException) -> bool:
    """Return True if *exc* is a transient error worth retrying.

    Explicitly excludes authentication failures -- those are never transient.
    """
    if isinstance(exc, PermissionDenied):
        return False
    return isinstance(exc, _RETRYABLE_EXCEPTIONS)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
async def _do_ssh_collect(device: Device, known_hosts: str | None = None) -> dict[Slot, str]:
    """Perform async SSH collection with retry for transient errors.

    Args:
        device: Device to collect from.
        known_hosts: Path to known_hosts file. When not provided (default),
            asyncssh uses the system default (``~/.ssh/known_hosts``).
            Pass an empty string to explicitly disable verification
            (lab/testing only).
    """
    commands = get_commands(device.device_type)
    password = device.get_password()
    slot_map = (Slot.INTERFACES, Slot.VERSION, Slot.RUNNING_CONFIG)
    connect_kwargs: dict[str, Any] = {
        "host": device.host,
        "port": device.port,
        "username": device.username,
        "connect_timeout": device.timeout or 30,
    }
    if password:
        connect_kwargs["password"] = password
    if device.use_keys and device.key_file:
        connect_kwargs["client_keys"] = [device.key_file]
    elif device.use_keys:
        connect_kwargs["client_keys"] = "default"
    if known_hosts is not None:
        connect_kwargs["known_hosts"] = known_hosts
    async with asyncssh.connect(**connect_kwargs) as conn:
        results: dict[Slot, str] = {}
        for slot, cmd in zip(slot_map, commands):
            result = await conn.run(cmd, timeout=device.timeout)
            stdout = result.stdout
            # Treat real non-zero exit / missing stdout as collection failure so
            # we never silently build empty snapshots that look like compliance.
            exit_status = getattr(result, "exit_status", None)
            if isinstance(exit_status, int) and exit_status != 0:
                stderr = (getattr(result, "stderr", None) or "")
                if not isinstance(stderr, str):
                    stderr = str(stderr)
                raise OSError(
                    f"Command {cmd!r} failed (exit={exit_status}): {stderr.strip()}"
                )
            if stdout is None:
                raise OSError(f"Command {cmd!r} returned no stdout")
            results[slot] = cast(str, stdout)
        return results


async def collect_device_async(
    device: Device,
    known_hosts: str | None = None,
) -> DeviceSnapshot:
    """Collect data from one device asynchronously.

    Same interface as sync collect_device(), but uses asyncio + asyncssh
    instead of ThreadPool + Netmiko.

    Args:
        device: Device to collect from.
        known_hosts: Path to known_hosts file. When not provided (default),
            asyncssh uses the system default (``~/.ssh/known_hosts``).
            Pass an empty string to explicitly disable verification
            (lab/testing only).
    """
    logger.info("Collecting data from %s (%s)", device.name, device.host)
    try:
        raw_outputs = await _do_ssh_collect(device, known_hosts=known_hosts)

        logger.info("Successfully collected from %s", device.name)
        parsed_version = parse_version(raw_outputs[Slot.VERSION], device_type=device.device_type)
        return DeviceSnapshot(
            device_name=device.name,
            device_type=device.device_type,
            interfaces=ParsedInterfaces(
                interfaces=parse_interfaces(
                    raw_outputs[Slot.INTERFACES], device_type=device.device_type
                )
            ),
            version=ParsedVersion(**parsed_version, raw=raw_outputs[Slot.VERSION]),
            config=ParsedConfig(
                lines=parse_config(raw_outputs[Slot.RUNNING_CONFIG]),
                raw=raw_outputs[Slot.RUNNING_CONFIG],
            ),
        )
    except (
        PermissionDenied,
        DisconnectError,
        ChannelOpenError,
        AsyncSshTimeoutError,
        OSError,
        ValueError,
        ConnectionError,
        ParseError,
    ) as exc:
        logger.error("Failed to collect from %s: %s", device.name, exc)
        return DeviceSnapshot(
            device_name=device.name,
            device_type=device.device_type,
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
            collection_error=str(exc),
        )


async def collect_all_async(
    devices: list[Device],
    max_workers: int = 50,
    timeout: float | None = None,
    known_hosts: str | None = None,
) -> list[DeviceSnapshot]:
    """Run async collection across all devices concurrently.

    Uses an asyncio.Semaphore to limit concurrent connections, which is
    more memory-efficient than a ThreadPool for large inventories.

    Args:
        devices: List of devices to collect from.
        max_workers: Maximum concurrent SSH connections (semaphore limit).
            Defaults to 50 -- much higher than the sync default of 4
            because async connections have minimal per-connection overhead.
        timeout: Optional per-device timeout in seconds.
        known_hosts: Path to known_hosts file. When not provided (default),
            asyncssh uses the system default (``~/.ssh/known_hosts``).
            Pass an empty string to explicitly disable verification
            (lab/testing only).

    Returns:
        List of DeviceSnapshot results, one per device.
    """
    semaphore = asyncio.Semaphore(max_workers)

    async def _bounded_collect(device: Device) -> DeviceSnapshot:
        async with semaphore:
            if timeout:
                try:
                    return await asyncio.wait_for(
                        collect_device_async(device, known_hosts=known_hosts),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    logger.error("Collection from %s timed out after %ss", device.name, timeout)
                    return DeviceSnapshot(
                        device_name=device.name,
                        device_type=device.device_type,
                        interfaces=ParsedInterfaces(),
                        version=ParsedVersion(),
                        config=ParsedConfig(),
                        collection_error=f"Collection timed out after {timeout}s",
                    )
            return await collect_device_async(device, known_hosts=known_hosts)

    tasks = [asyncio.create_task(_bounded_collect(d)) for d in devices]
    # Isolate per-device failures so one bad host cannot abort the batch
    raw = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[DeviceSnapshot] = []
    for device, item in zip(devices, raw):
        if isinstance(item, DeviceSnapshot):
            results.append(item)
        elif isinstance(item, BaseException):
            logger.error("Unexpected error collecting from %s: %s", device.name, item)
            results.append(
                DeviceSnapshot(
                    device_name=device.name,
                    device_type=device.device_type,
                    interfaces=ParsedInterfaces(),
                    version=ParsedVersion(),
                    config=ParsedConfig(),
                    collection_error=str(item),
                )
            )
        else:  # pragma: no cover
            results.append(
                DeviceSnapshot(
                    device_name=device.name,
                    device_type=device.device_type,
                    interfaces=ParsedInterfaces(),
                    version=ParsedVersion(),
                    config=ParsedConfig(),
                    collection_error="Unknown collection result",
                )
            )
    return results

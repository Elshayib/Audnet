"""Async SSH collector prototype for network device data.

This module provides an asyncio-based alternative to the ThreadPool + Netmiko
collector. It uses asyncssh for SSH connections and is designed to scale to
hundreds of devices with lower memory and thread overhead.

Architecture:
    - asyncio event loop manages all concurrent SSH sessions
    - asyncssh handles SSH transport (no thread per connection)
    - Same DeviceSnapshot output format as sync collector
    - Same retry logic via tenacity (async-compatible)

Trade-offs vs sync collector (collector.py):
    + Single-threaded: no GIL contention, lower memory per connection
    + Native concurrency: scales to 100s of devices without thread overhead
    + No thread pool sizing: concurrency limited by semaphore, not OS threads
    - Requires asyncssh dependency (not in current dependency tree)
    - No Netmiko device-type abstraction: commands sent raw
    - Prototype status: not yet integrated into CLI

Migration path:
    1. Install asyncssh: uv add asyncssh
    2. Switch collector import in cli.py: from net_audit.collector_async import collect_all
    3. Add --workers flag maps to asyncio.Semaphore limit
    4. Keep sync collector as fallback for environments without asyncssh
"""

import asyncio
import logging
from typing import cast

import asyncssh
from asyncssh import (
    ChannelOpenError,
    DisconnectError,
    PermissionDenied,
    TimeoutError as AsyncSshTimeoutError,
)
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

from net_audit.models import Device, DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig
from net_audit.parser import parse_interfaces, parse_version, parse_config
from net_audit.vendor_registry import get_commands

logger = logging.getLogger(__name__)

# Transient exceptions that are safe to retry on (asyncssh equivalents)
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
async def _do_ssh_collect(device: Device) -> list[str]:
    """Perform async SSH collection with retry for transient errors."""
    commands = get_commands(device.device_type)
    password = device.get_password()
    async with asyncssh.connect(
        device.host,
        port=device.port,
        username=device.username,
        password=password,
        # Security fix: Removed known_hosts=None to enable default SSH host key verification
        # and prevent Man-in-the-Middle (MitM) attacks.
        connect_timeout=str(device.timeout) if device.timeout else "30",
    ) as conn:
        results: list[str] = []
        for cmd in commands:
            result = await conn.run(cmd, timeout=device.timeout)
            results.append(cast(str, result.stdout))
        return results


async def collect_device_async(device: Device) -> DeviceSnapshot:
    """Collect data from one device asynchronously.

    Same interface as sync collect_device(), but uses asyncio + asyncssh
    instead of ThreadPool + Netmiko.
    """
    logger.info("Collecting data from %s (%s)", device.name, device.host)
    try:
        raw_outputs = await _do_ssh_collect(device)

        logger.info("Successfully collected from %s", device.name)
        parsed_version = parse_version(raw_outputs[1], device_type=device.device_type)
        return DeviceSnapshot(
            device_name=device.name,
            interfaces=ParsedInterfaces(
                interfaces=parse_interfaces(raw_outputs[0], device_type=device.device_type)
            ),
            version=ParsedVersion(**parsed_version, raw=raw_outputs[1]),
            config=ParsedConfig(lines=parse_config(raw_outputs[2]), raw=raw_outputs[2]),
        )
    except (
        PermissionDenied,
        DisconnectError,
        ChannelOpenError,
        AsyncSshTimeoutError,
        OSError,
        ValueError,
        ConnectionError,
    ) as exc:
        logger.error("Failed to collect from %s: %s", device.name, exc)
        return DeviceSnapshot(
            device_name=device.name,
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
            collection_error=str(exc),
        )


async def collect_all_async(
    devices: list[Device],
    max_workers: int = 50,
    timeout: float | None = None,
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

    Returns:
        List of DeviceSnapshot results, one per device.
    """
    semaphore = asyncio.Semaphore(max_workers)

    async def _bounded_collect(device: Device) -> DeviceSnapshot:
        async with semaphore:
            if timeout:
                try:
                    return await asyncio.wait_for(
                        collect_device_async(device),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    logger.error("Collection from %s timed out after %ss", device.name, timeout)
                    return DeviceSnapshot(
                        device_name=device.name,
                        interfaces=ParsedInterfaces(),
                        version=ParsedVersion(),
                        config=ParsedConfig(),
                        collection_error=f"Collection timed out after {timeout}s",
                    )
            return await collect_device_async(device)

    tasks = [asyncio.create_task(_bounded_collect(d)) for d in devices]
    return list(await asyncio.gather(*tasks))

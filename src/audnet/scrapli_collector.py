"""Scrapli-based async collector for network device data.

Uses Scrapli's async drivers for concurrent SSH collection.
Produces the same DeviceSnapshot output as the sync (Netmiko) and
asyncssh collectors, ensuring full backward compatibility.

Usage:
    from audnet.scrapli_collector import collect_all_scrapli
    snapshots = await collect_all_scrapli(devices, max_workers=50)

This module is optional — it requires the 'scrapli' extra:
    pip install "audnet[scrapli]"
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

from audnet.models import Device, DeviceSnapshot, ParsedInterfaces, ParsedVersion, ParsedConfig
from audnet.parser import parse_interfaces, parse_version, parse_config
from audnet.vendor_registry import Slot, get_commands

logger = logging.getLogger(__name__)

# Scrapli is an optional dependency
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

    # Transient exceptions worth retrying
    _RETRYABLE_EXCEPTIONS = (
        ScrapliConnectionError,
        ScrapliTimeout,
        OSError,
        ConnectionError,
    )

    # Map audnet device_type -> Scrapli driver class
    # Vendors with dedicated core drivers get those; others use AsyncNetworkDriver
    _SCRAPLI_DRIVER_MAP = {
        "cisco_ios": AsyncIOSXEDriver,
        "cisco_xe": AsyncIOSXEDriver,
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


def _check_scrapli_available() -> None:
    """Raise ImportError with helpful message if scrapli is not installed."""
    if not _SCRAPLI_AVAILABLE:
        raise ImportError(
            "scrapli is required for the Scrapli collector. "
            'Install it with: pip install "audnet[scrapli]"'
        )


def _is_retryable(exc: BaseException) -> bool:
    if not _SCRAPLI_AVAILABLE:
        return False
    if isinstance(exc, ScrapliAuthenticationFailed):
        return False
    return isinstance(exc, _RETRYABLE_EXCEPTIONS)


# textfsm_platform override for vendors using AsyncNetworkDriver
# (core drivers have sensible defaults built in)
_TEXTFSM_PLATFORM_MAP: dict[str, str] = {
    "fortinet_fortios": "fortinet_fortios",
    "paloalto_panos": "paloalto_panos",
    "aruba_os": "aruba_aoscx",
    "hp_procurve": "hp_procurve",
}


def _get_scrapli_driver(device_type: str) -> type:
    """Return the Scrapli driver class for a given audnet device_type."""
    return _SCRAPLI_DRIVER_MAP.get(device_type, AsyncNetworkDriver)


def _build_conn_params(device: Device) -> dict[str, Any]:
    """Build connection parameters dict for Scrapli driver."""
    params: dict[str, Any] = {
        "host": device.host,
        "auth_username": device.username,
        "auth_password": device.get_password(),
        "auth_strict_key": False,
        "transport": "asyncssh",
        "timeout_socket": device.timeout,
        "timeout_transport": device.timeout,
        "timeout_ops": device.timeout,
    }
    if device.port != 22:
        params["port"] = device.port
    return params


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
async def _do_scrapli_collect(device: Device) -> dict[Slot, str]:
    """Perform Scrapli SSH collection with retry for transient errors."""
    _check_scrapli_available()
    driver_cls = _get_scrapli_driver(device.device_type)
    commands = get_commands(device.device_type)
    slot_map = (Slot.INTERFACES, Slot.VERSION, Slot.RUNNING_CONFIG)
    conn_params = _build_conn_params(device)

    async with driver_cls(**conn_params) as conn:
        results: dict[Slot, str] = {}
        for slot, cmd in zip(slot_map, commands):
            response = await conn.send_command(cmd)
            results[slot] = response.result
        return results


async def collect_device_scrapli(device: Device) -> DeviceSnapshot:
    """Collect data from one device via Scrapli.

    Same interface as collect_device() and collect_device_async().
    """
    _check_scrapli_available()
    logger.info("Collecting data from %s (%s) via Scrapli", device.name, device.host)
    try:
        raw_outputs = await _do_scrapli_collect(device)
        logger.info("Successfully collected from %s via Scrapli", device.name)
        parsed_version = parse_version(raw_outputs[Slot.VERSION], device_type=device.device_type)
        return DeviceSnapshot(
            device_name=device.name,
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
        ScrapliConnectionError,
        ScrapliTimeout,
        ScrapliAuthenticationFailed,
        OSError,
        ValueError,
        ConnectionError,
    ) as exc:
        logger.error("Failed to collect from %s via Scrapli: %s", device.name, exc)
        return DeviceSnapshot(
            device_name=device.name,
            interfaces=ParsedInterfaces(),
            version=ParsedVersion(),
            config=ParsedConfig(),
            collection_error=str(exc),
        )


async def collect_all_scrapli(
    devices: list[Device],
    max_workers: int = 50,
    timeout: float | None = None,
) -> list[DeviceSnapshot]:
    """Run Scrapli collection across all devices concurrently.

    Uses asyncio.Semaphore for concurrency limiting.
    Same interface as collect_all_async().
    """
    _check_scrapli_available()
    semaphore = asyncio.Semaphore(max_workers)

    async def _bounded_collect(device: Device) -> DeviceSnapshot:
        async with semaphore:
            if timeout:
                try:
                    return await asyncio.wait_for(
                        collect_device_scrapli(device),
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
            return await collect_device_scrapli(device)

    tasks = [asyncio.create_task(_bounded_collect(d)) for d in devices]
    return list(await asyncio.gather(*tasks))

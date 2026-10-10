"""Scrapli-based async collector for network device data.

Backward-compatible shim over :mod:`audnet.collection` (the deep
collection module). The old Scrapli fan-out lives in ``collection`` now;
this module only preserves the public ``collect_device_scrapli`` /
``collect_all_scrapli`` import path used by the CLI and existing callers.

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

from audnet.collection import collect_all_async, collect_device_async
from audnet.models import Device, DeviceSnapshot
from audnet.scrapli_adapter import ScrapliAdapter as ScrapliAdapter
from audnet.scrapli_adapter import _build_conn_params as _build_conn_params
from audnet.scrapli_adapter import (
    _check_scrapli_available as _check_scrapli_available,
)
from audnet.scrapli_adapter import _get_scrapli_driver as _get_scrapli_driver
from audnet.scrapli_adapter import _is_retryable as _is_retryable
from audnet.scrapli_adapter import _RETRYABLE_EXCEPTIONS as _RETRYABLE_EXCEPTIONS
from audnet.scrapli_adapter import _SCRAPLI_AVAILABLE as _SCRAPLI_AVAILABLE
from audnet.scrapli_adapter import _SCRAPLI_DRIVER_MAP as _SCRAPLI_DRIVER_MAP
from audnet.scrapli_adapter import _TEXTFSM_PLATFORM_MAP as _TEXTFSM_PLATFORM_MAP

__all__ = [
    "ScrapliAdapter",
    "collect_all_scrapli",
    "collect_device_scrapli",
]


async def collect_device_scrapli(device: Device) -> DeviceSnapshot:
    """Collect data from one device via Scrapli.

    Same interface as collect_device() and collect_device_async().
    Collects through the deep module with the Scrapli transport behind
    the adapter seam.
    """
    return await collect_device_async(device, adapter=ScrapliAdapter())


async def collect_all_scrapli(
    devices: list[Device],
    max_workers: int = 50,
    timeout: float | None = None,
) -> list[DeviceSnapshot]:
    """Run Scrapli collection across all devices concurrently.

    Same interface as collect_all_async(). Collects through the deep
    module with the Scrapli transport behind the adapter seam.
    """
    return await collect_all_async(
        devices, max_workers=max_workers, timeout=timeout, adapter=ScrapliAdapter()
    )

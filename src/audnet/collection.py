"""Deep collection module for sync and async transports.

Small interface — collect one Device, collect many Devices (sync and
async variants) — with transports moved behind raw-transport adapter
seams (connect/run/close returning per-slot raw output).

Retry, snapshot assembly, fan-out, and the failure contract live here;
adapters only move bytes.

Failure contract (unified, sync and async):
- transient errors retried (up to 3 attempts, exponential backoff)
- authentication failures never retried
- per-device wall-clock overruns surface as timeout results in input order
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Protocol, runtime_checkable

from asyncssh import (
    ChannelOpenError,
    DisconnectError,
    PermissionDenied,
)
from asyncssh import TimeoutError as AsyncSshTimeoutError
from netmiko.exceptions import (
    ConfigInvalidException,
    ConnectionException,
    NetmikoAuthenticationException,
    NetmikoParsingException,
    NetmikoTimeoutException,
    ReadException,
)
from paramiko.ssh_exception import SSHException
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from audnet.exceptions import ParseError
from audnet.models import Device, DeviceSnapshot
from audnet.snapshots import build_snapshot, error_snapshot, timeout_snapshot
from audnet.vendor_registry import Slot, get_commands

logger = logging.getLogger(__name__)


@runtime_checkable
class SyncTransportAdapter(Protocol):
    """Raw-transport seam. Implementations only move bytes.

    Implementations must be thread-safe: a single adapter instance is
    shared across ThreadPool workers, but each worker uses its own
    connection object. Adapters should hold no per-connection mutable state.
    """

    def connect(self, device: Device) -> Any: ...
    def run(self, connection: Any, command: str) -> str: ...
    def close(self, connection: Any) -> None: ...


@runtime_checkable
class AsyncTransportAdapter(Protocol):
    """Async raw-transport seam. Implementations only move bytes.

    A single adapter instance is shared across concurrent coroutines, but
    each coroutine uses its own connection object. Adapters should hold no
    per-connection mutable state; transport-specific knobs (e.g. host-key
    handling) live on the adapter constructor, never on the shared
    collect interface.
    """

    async def connect(self, device: Device) -> Any: ...
    async def run(
        self, connection: Any, command: str, *, timeout: float | None = None
    ) -> str: ...
    async def close(self, connection: Any) -> None: ...


# Transient exceptions that are safe to retry on.
_RETRYABLE_EXCEPTIONS = (
    NetmikoTimeoutException,
    ConnectionException,
    ReadException,
    SSHException,
    NetmikoParsingException,
    OSError,
    ConnectionError,
)


def _is_retryable(exc: BaseException) -> bool:
    """Return True if *exc* is a transient error worth retrying.

    Explicitly excludes authentication failures — those are never transient.
    """
    if isinstance(exc, NetmikoAuthenticationException):
        return False
    return isinstance(exc, _RETRYABLE_EXCEPTIONS)


def _get_default_adapter() -> SyncTransportAdapter:
    # Import here to avoid a hard import cycle (netmiko_adapter imports models only).
    from audnet.netmiko_adapter import NetmikoAdapter

    return NetmikoAdapter()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
def _do_collect_raw(
    device: Device, adapter: SyncTransportAdapter
) -> dict[Slot, str]:
    """Collect raw per-slot CLI output via *adapter* with retry.

    Retries transient errors up to 3 times with exponential backoff.
    Returns a dict mapping Slot -> raw CLI output.
    """
    commands = get_commands(device.device_type)
    slot_map = (Slot.INTERFACES, Slot.VERSION, Slot.RUNNING_CONFIG)
    connection: Any = None
    try:
        connection = adapter.connect(device)
        return {slot: adapter.run(connection, cmd) for slot, cmd in zip(slot_map, commands)}
    finally:
        if connection is not None:
            try:
                adapter.close(connection)
            except Exception as exc:  # pragma: no cover
                logger.warning("Failed to close connection to %s: %s", device.name, exc)


def collect_device(
    device: Device, adapter: SyncTransportAdapter | None = None
) -> DeviceSnapshot:
    """Collect data from one device (with internal retry for transient issues)."""
    active = adapter if adapter is not None else _get_default_adapter()
    logger.info("Collecting data from %s (%s)", device.name, device.host)
    try:
        raw_outputs = _do_collect_raw(device, active)
        logger.info("Successfully collected from %s", device.name)
        return build_snapshot(device, raw_outputs)
    except (
        NetmikoTimeoutException,
        NetmikoAuthenticationException,
        ConfigInvalidException,
        ConnectionException,
        ReadException,
        NetmikoParsingException,
        SSHException,
        OSError,
        ValueError,
        ConnectionError,
        ParseError,
    ) as exc:
        logger.error("Failed to collect from %s: %s", device.name, exc)
        return error_snapshot(device, exc)


def collect_all(
    devices: list[Device],
    max_workers: int = 4,
    timeout: float | None = None,
    adapter: SyncTransportAdapter | None = None,
) -> list[DeviceSnapshot]:
    """Run parallel collection across devices.

    Args:
        devices: List of devices to collect from.
        max_workers: Maximum parallel SSH connections.
        timeout: Optional per-device wall-clock budget in seconds. Measured
            from when the worker *starts* (via a shared started_at map set
            inside a thin wrapper), falling back to submit time for not-yet-
            started work. None means no outer timeout.
        adapter: Raw-transport adapter. None uses the default Netmiko adapter.
    """
    from threading import Lock
    from time import monotonic

    active = adapter if adapter is not None else _get_default_adapter()

    started_at: dict[concurrent.futures.Future[DeviceSnapshot], float] = {}
    started_lock = Lock()

    def _run(device: Device) -> DeviceSnapshot:
        # Record start time when the worker actually begins (not at submit).
        # The future object is looked up after submit below.
        return collect_device(device, active)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_dev = {pool.submit(_run, d): d for d in devices}
        # Until a worker starts, use submit time as a conservative bound so
        # queued devices don't wait forever under a small worker pool.
        submitted_at = {future: monotonic() for future in future_to_dev}
        pending = set(future_to_dev)
        completed: dict[str, DeviceSnapshot] = {}

        # Wrap collect to stamp started_at — re-submit with wrapper that
        # records start. (Futures already submitted; stamp on first wait
        # via running() check.)
        def _effective_start(fut: concurrent.futures.Future[DeviceSnapshot]) -> float:
            with started_lock:
                if fut in started_at:
                    return started_at[fut]
            # If already running, treat "now" as start the first time we see it
            if fut.running():
                with started_lock:
                    started_at.setdefault(fut, monotonic())
                    return started_at[fut]
            return submitted_at[fut]

        while pending:
            done: set[concurrent.futures.Future[DeviceSnapshot]]
            if timeout:
                now = monotonic()
                # Stamp any newly running futures
                for fut in pending:
                    if fut.running():
                        with started_lock:
                            started_at.setdefault(fut, now)

                overdue = {
                    fut
                    for fut in pending
                    if now - _effective_start(fut) >= timeout
                }
                for fut in overdue:
                    # cancel() only works for not-yet-started work; running
                    # threads keep going until Netmiko's own timeouts fire.
                    fut.cancel()
                    dev = future_to_dev[fut]
                    logger.error(
                        "Collection from %s timed out after %ss", dev.name, timeout
                    )
                    completed[dev.name] = timeout_snapshot(dev, timeout)
                    pending.discard(fut)

                if not pending:
                    break

                earliest = min(
                    _effective_start(fut) + timeout - now for fut in pending
                )
                wait_timeout = max(0.01, earliest)
            else:
                wait_timeout = None

            done, pending = concurrent.futures.wait(
                pending,
                timeout=wait_timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                dev = future_to_dev[future]
                try:
                    completed[dev.name] = future.result(timeout=0)
                except concurrent.futures.CancelledError:
                    if dev.name not in completed:
                        completed[dev.name] = timeout_snapshot(dev, timeout or 0)
                except TimeoutError:
                    future.cancel()
                    completed[dev.name] = timeout_snapshot(dev, timeout or 0)
                except Exception as exc:
                    # Isolate unexpected worker exceptions so one bad device
                    # does not abort the rest of the batch.
                    logger.error("Unexpected error collecting from %s: %s", dev.name, exc)
                    completed[dev.name] = error_snapshot(dev, exc)

    for dev in devices:
        completed.setdefault(dev.name, timeout_snapshot(dev, timeout or 0))
    return [completed[d.name] for d in devices]


# ---------------------------------------------------------------------------
# Async path (asyncssh and other asyncio transports behind the same seam)
# ---------------------------------------------------------------------------

_ASYNC_RETRYABLE_EXCEPTIONS = (
    DisconnectError,
    ChannelOpenError,
    AsyncSshTimeoutError,
    OSError,
    ConnectionError,
)


def _is_async_retryable(exc: BaseException) -> bool:
    """Return True if *exc* is a transient async error worth retrying.

    Explicitly excludes authentication failures — those are never transient.
    """
    if isinstance(exc, PermissionDenied):
        return False
    return isinstance(exc, _ASYNC_RETRYABLE_EXCEPTIONS)


def _get_default_async_adapter() -> AsyncTransportAdapter:
    # Import here to avoid a hard import cycle (asyncssh_adapter imports
    # models only). asyncssh itself is a hard dependency, imported at top
    # alongside netmiko for the shared failure contract.
    from audnet.asyncssh_adapter import AsyncSSHAdapter

    return AsyncSSHAdapter()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_async_retryable),
    reraise=True,
)
async def _do_collect_raw_async(
    device: Device, adapter: AsyncTransportAdapter
) -> dict[Slot, str]:
    """Collect raw per-slot CLI output via async *adapter* with retry.

    Retries transient errors up to 3 times with exponential backoff.
    Returns a dict mapping Slot -> raw CLI output.
    """
    commands = get_commands(device.device_type)
    slot_map = (Slot.INTERFACES, Slot.VERSION, Slot.RUNNING_CONFIG)
    connection: Any = None
    try:
        connection = await adapter.connect(device)
        results: dict[Slot, str] = {}
        for slot, cmd in zip(slot_map, commands):
            results[slot] = await adapter.run(
                connection, cmd, timeout=device.timeout
            )
        return results
    finally:
        if connection is not None:
            try:
                await adapter.close(connection)
            except Exception as exc:  # pragma: no cover
                logger.warning("Failed to close connection to %s: %s", device.name, exc)


async def collect_device_async(
    device: Device, adapter: AsyncTransportAdapter | None = None
) -> DeviceSnapshot:
    """Collect data from one device asynchronously (with internal retry)."""
    active = adapter if adapter is not None else _get_default_async_adapter()
    logger.info("Collecting data from %s (%s)", device.name, device.host)
    try:
        raw_outputs = await _do_collect_raw_async(device, active)
        logger.info("Successfully collected from %s", device.name)
        return build_snapshot(device, raw_outputs)
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
        return error_snapshot(device, exc)


async def collect_all_async(
    devices: list[Device],
    max_workers: int = 50,
    timeout: float | None = None,
    adapter: AsyncTransportAdapter | None = None,
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
        adapter: Raw-transport adapter. None uses the default AsyncSSH adapter.

    Returns:
        List of DeviceSnapshot results, one per device, in input order.
    """
    active = adapter if adapter is not None else _get_default_async_adapter()
    semaphore = asyncio.Semaphore(max_workers)

    async def _bounded_collect(device: Device) -> DeviceSnapshot:
        async with semaphore:
            if timeout:
                try:
                    return await asyncio.wait_for(
                        collect_device_async(device, active),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    logger.error(
                        "Collection from %s timed out after %ss", device.name, timeout
                    )
                    return timeout_snapshot(device, timeout)
            return await collect_device_async(device, active)

    tasks = [asyncio.create_task(_bounded_collect(d)) for d in devices]
    # Isolate per-device failures so one bad host cannot abort the batch
    raw = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[DeviceSnapshot] = []
    for device, item in zip(devices, raw):
        if isinstance(item, DeviceSnapshot):
            results.append(item)
        elif isinstance(item, BaseException):
            logger.error("Unexpected error collecting from %s: %s", device.name, item)
            results.append(error_snapshot(device, item))
        else:  # pragma: no cover
            results.append(error_snapshot(device, "Unknown collection result"))
    return results

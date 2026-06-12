"""Tests for the async collector prototype (collector_async).

Tests use mocked asyncssh to avoid real SSH connections, mirroring the
test patterns from test_collector.py.
"""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from asyncssh import DisconnectError, PermissionDenied
from pydantic import SecretStr

from audnet.collector_async import collect_all_async, collect_device_async
from audnet.models import Device


def _make_device(name: str = "test-device", host: str = "10.0.0.1") -> Device:
    return Device(
        name=name,
        host=host,
        username="admin",
        password=SecretStr("test-pass"),
        device_type="cisco_ios",
    )


def _mock_raw_outputs() -> list[str]:
    return [
        "Interface  IP-Address  Status  Protocol\nGi0/0      10.0.0.1    up      up",
        "Cisco IOS Software, Version 15.2",
        "hostname test-device\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0",
    ]


def _make_mock_ssh(outputs: list[str] | None = None):
    """Create a properly structured mock for asyncssh.connect().

    Returns (mock_module, set_outputs_fn) where set_outputs_fn allows
    configuring what run() returns per call.
    """
    if outputs is None:
        outputs = _mock_raw_outputs()

    call_count = 0

    async def _run_side_effect(*args, **kwargs):
        nonlocal call_count
        result = MagicMock()
        result.stdout = outputs[min(call_count, len(outputs) - 1)]
        call_count += 1
        return result

    mock_conn = AsyncMock()
    mock_conn.run = AsyncMock(side_effect=_run_side_effect)

    @asynccontextmanager
    async def _connect_cm(*args, **kwargs):
        yield mock_conn

    mock_mod = MagicMock()
    mock_mod.connect = _connect_cm
    return mock_mod


@pytest.mark.asyncio
async def test_collect_device_async_success():
    """Async collector returns a valid DeviceSnapshot on success."""
    device = _make_device()
    mock_mod = _make_mock_ssh()

    with patch("audnet.collector_async.asyncssh", mock_mod):
        snapshot = await collect_device_async(device)

    assert snapshot.device_name == "test-device"
    assert snapshot.collection_error is None
    assert snapshot.interfaces is not None


@pytest.mark.asyncio
async def test_collect_device_async_auth_failure():
    """Async collector returns error snapshot on auth failure."""
    device = _make_device()

    @asynccontextmanager
    async def _connect_cm(*args, **kwargs):
        raise PermissionDenied("auth denied")
        yield  # noqa

    mock_mod = MagicMock()
    mock_mod.connect = _connect_cm

    with patch("audnet.collector_async.asyncssh", mock_mod):
        snapshot = await collect_device_async(device)

    assert snapshot.device_name == "test-device"
    assert snapshot.collection_error is not None
    assert len(snapshot.collection_error) > 0


@pytest.mark.asyncio
async def test_collect_device_async_connection_lost():
    """Async collector returns error snapshot on connection lost."""
    device = _make_device()

    @asynccontextmanager
    async def _connect_cm(*args, **kwargs):
        raise DisconnectError(1, "connection lost")
        yield  # noqa

    mock_mod = MagicMock()
    mock_mod.connect = _connect_cm

    with patch("audnet.collector_async.asyncssh", mock_mod):
        snapshot = await collect_device_async(device)

    assert snapshot.device_name == "test-device"
    assert snapshot.collection_error is not None
    assert len(snapshot.collection_error) > 0


@pytest.mark.asyncio
async def test_collect_all_async_multiple_devices():
    """Async collector handles multiple devices concurrently."""
    devices = [_make_device(f"dev-{i}", f"10.0.0.{i}") for i in range(4)]
    mock_mod = _make_mock_ssh()

    with patch("audnet.collector_async.asyncssh", mock_mod):
        results = await collect_all_async(devices, max_workers=4)

    assert len(results) == 4
    for r in results:
        assert r.device_name.startswith("dev-")


@pytest.mark.asyncio
async def test_collect_all_async_empty_list():
    """Async collector handles empty device list."""
    results = await collect_all_async([], max_workers=4)
    assert results == []


@pytest.mark.asyncio
async def test_collect_all_async_timeout():
    """Async collector returns error snapshot on timeout."""
    device = _make_device()

    async def _slow_run(*args, **kwargs):
        await asyncio.sleep(10)
        return MagicMock(stdout="output")

    mock_conn = AsyncMock()
    mock_conn.run = _slow_run

    @asynccontextmanager
    async def _connect_cm(*args, **kwargs):
        yield mock_conn

    mock_mod = MagicMock()
    mock_mod.connect = _connect_cm

    with patch("audnet.collector_async.asyncssh", mock_mod):
        results = await collect_all_async([device], max_workers=1, timeout=0.1)

    assert len(results) == 1
    assert results[0].collection_error is not None
    assert len(results[0].collection_error) > 0


@pytest.mark.asyncio
async def test_collect_all_async_mixed_results():
    """Async collector handles mix of successful and failed devices."""
    devices = [
        _make_device("good-dev", "10.0.0.1"),
        _make_device("bad-dev", "10.0.0.2"),
    ]

    call_count = 0
    outputs = _mock_raw_outputs()

    async def _run_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count <= 3:
            result = MagicMock()
            result.stdout = outputs[call_count - 1]
            return result
        raise DisconnectError(1, "refused")

    mock_conn = AsyncMock()
    mock_conn.run = AsyncMock(side_effect=_run_side_effect)

    @asynccontextmanager
    async def _connect_cm(*args, **kwargs):
        yield mock_conn

    mock_mod = MagicMock()
    mock_mod.connect = _connect_cm

    with patch("audnet.collector_async.asyncssh", mock_mod):
        results = await collect_all_async(devices, max_workers=2)

    assert len(results) == 2
    errors = [r for r in results if r.collection_error]
    assert len(errors) >= 1

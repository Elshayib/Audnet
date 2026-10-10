"""Tests for the async collector via the deep collection module.

Tests use mocked asyncssh (patched at the adapter seam) to avoid real SSH
connections, mirroring the test patterns from test_collector.py.

Collection goes end to end through :mod:`audnet.collection` with the
asyncssh transport behind the ``AsyncTransportAdapter`` seam.
"""

import asyncio
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


def _ok_result(stdout: str) -> MagicMock:
    result = MagicMock()
    result.exit_status = 0
    result.stdout = stdout
    result.stderr = ""
    return result


def _make_mock_ssh(outputs: list[str] | None = None):
    """Create a mocked asyncssh module for the AsyncSSHAdapter seam.

    Patches ``audnet.asyncssh_adapter.asyncssh``: ``connect`` is an
    AsyncMock returning a shared mock connection whose ``run`` returns
    per-command outputs with exit_status 0.
    """
    if outputs is None:
        outputs = _mock_raw_outputs()

    call_count = 0

    async def _run_side_effect(*args, **kwargs):
        nonlocal call_count
        result = _ok_result(outputs[min(call_count, len(outputs) - 1)])
        call_count += 1
        return result

    mock_conn = MagicMock()
    mock_conn.run = AsyncMock(side_effect=_run_side_effect)
    mock_conn.close = MagicMock()
    mock_conn.wait_closed = AsyncMock()

    mock_mod = MagicMock()
    mock_mod.connect = AsyncMock(return_value=mock_conn)
    return mock_mod


@pytest.mark.asyncio
async def test_collect_device_async_success():
    """Async collector returns a valid DeviceSnapshot on success."""
    device = _make_device()
    mock_mod = _make_mock_ssh()

    with patch("audnet.asyncssh_adapter.asyncssh", mock_mod):
        snapshot = await collect_device_async(device)

    assert snapshot.device_name == "test-device"
    assert snapshot.collection_error is None
    assert snapshot.interfaces is not None


@pytest.mark.asyncio
async def test_collect_device_async_auth_failure():
    """Async collector returns error snapshot on auth failure."""
    device = _make_device()

    mock_mod = MagicMock()
    mock_mod.connect = AsyncMock(side_effect=PermissionDenied("auth denied"))

    with patch("audnet.asyncssh_adapter.asyncssh", mock_mod):
        snapshot = await collect_device_async(device)

    assert snapshot.device_name == "test-device"
    assert snapshot.collection_error is not None
    assert len(snapshot.collection_error) > 0


@pytest.mark.asyncio
async def test_collect_device_async_connection_lost():
    """Async collector returns error snapshot on connection lost."""
    device = _make_device()

    mock_mod = MagicMock()
    mock_mod.connect = AsyncMock(side_effect=DisconnectError(1, "connection lost"))

    with patch("audnet.asyncssh_adapter.asyncssh", mock_mod):
        snapshot = await collect_device_async(device)

    assert snapshot.device_name == "test-device"
    assert snapshot.collection_error is not None
    assert len(snapshot.collection_error) > 0


@pytest.mark.asyncio
async def test_collect_all_async_multiple_devices():
    """Async collector handles multiple devices concurrently."""
    devices = [_make_device(f"dev-{i}", f"10.0.0.{i}") for i in range(4)]
    mock_mod = _make_mock_ssh()

    with patch("audnet.asyncssh_adapter.asyncssh", mock_mod):
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
        return _ok_result("output")

    mock_conn = MagicMock()
    mock_conn.run = AsyncMock(side_effect=_slow_run)
    mock_conn.close = MagicMock()
    mock_conn.wait_closed = AsyncMock()

    mock_mod = MagicMock()
    mock_mod.connect = AsyncMock(return_value=mock_conn)

    with patch("audnet.asyncssh_adapter.asyncssh", mock_mod):
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
            return _ok_result(outputs[call_count - 1])
        raise DisconnectError(1, "refused")

    mock_conn = MagicMock()
    mock_conn.run = AsyncMock(side_effect=_run_side_effect)
    mock_conn.close = MagicMock()
    mock_conn.wait_closed = AsyncMock()

    mock_mod = MagicMock()
    mock_mod.connect = AsyncMock(return_value=mock_conn)

    with patch("audnet.asyncssh_adapter.asyncssh", mock_mod):
        results = await collect_all_async(devices, max_workers=2)

    assert len(results) == 2
    errors = [r for r in results if r.collection_error]
    assert len(errors) >= 1

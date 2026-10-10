"""Contract suite for the async path of the deep collection module (issue #206).

Exercises the async interface (collect one / collect many) through a fake
async raw-transport adapter, plus a thin per-adapter smoke proving the
real AsyncSSH transport satisfies the seam:

- transient errors retried, then succeed or surface as error snapshots
- authentication failures never retried
- per-device overruns surface as timeout results in input order
- exit-status failures surface as collection errors, never silent empty
- host-key configuration lives on the adapter, never on the shared interface
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from asyncssh import DisconnectError, PermissionDenied

from audnet.asyncssh_adapter import AsyncSSHAdapter
from audnet.collection import collect_all_async, collect_device_async
from audnet.models import Device
from audnet.vendor_registry import Slot


def _make_device(name="rtr01", host="10.0.0.1"):
    return Device(name=name, host=host, username="admin", password="x")


def _raw_outputs():
    return {
        Slot.INTERFACES: (
            "Interface              IP-Address      OK? Method Status                Protocol\n"
            "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up"
        ),
        Slot.VERSION: (
            "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
            "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
            "router uptime is 5 days, 3 hours, 22 minutes"
        ),
        Slot.RUNNING_CONFIG: "hostname rtr01\nip ssh version 2\nntp server 10.0.0.50\n",
    }


class FakeAsyncAdapter:
    """Fake async raw-transport adapter: connect/run/close, only moves bytes."""

    def __init__(
        self,
        raw: dict[Slot, str] | None = None,
        fail_connect_with: BaseException | list[BaseException] | None = None,
        delay_s: float = 0.0,
    ) -> None:
        self._raw = raw if raw is not None else _raw_outputs()
        self._sticky: BaseException | None = None
        if isinstance(fail_connect_with, list):
            self._failures = list(fail_connect_with)
        elif fail_connect_with is not None:
            self._failures = []
            self._sticky = fail_connect_with
        else:
            self._failures = []
        self.delay_s = delay_s
        self.connect_calls = 0
        self.run_calls = 0
        self.close_calls = 0

    async def connect(self, device: Device) -> Any:
        self.connect_calls += 1
        if self._sticky is not None:
            raise self._sticky
        if self._failures:
            raise self._failures.pop(0)
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        return object()

    async def run(
        self, connection: Any, command: str, *, timeout: float | None = None
    ) -> str:
        self.run_calls += 1
        cmd = command.lower()
        if "interface" in cmd or "terse" in cmd or "system interface" in cmd:
            return self._raw[Slot.INTERFACES]
        if "version" in cmd or "system status" in cmd or "system info" in cmd:
            return self._raw[Slot.VERSION]
        return self._raw[Slot.RUNNING_CONFIG]

    async def close(self, connection: Any) -> None:
        self.close_calls += 1


class _StickyFailAdapter(FakeAsyncAdapter):
    def __init__(self, exc: BaseException, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._exc = exc

    async def connect(self, device: Device) -> Any:
        self.connect_calls += 1
        raise self._exc


class _SequenceFailAdapter(FakeAsyncAdapter):
    def __init__(self, failures: list[BaseException], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._seq = list(failures)

    async def connect(self, device: Device) -> Any:
        self.connect_calls += 1
        if self._seq:
            raise self._seq.pop(0)
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        return object()


class TestCollectOneAsyncThroughFake:
    @pytest.mark.asyncio
    async def test_success_builds_snapshot(self):
        snap = await collect_device_async(_make_device(), adapter=FakeAsyncAdapter())
        assert snap.device_name == "rtr01"
        assert snap.collection_error is None
        assert "15.2" in snap.version.version

    @pytest.mark.asyncio
    async def test_transient_retried_then_succeeds(self):
        adapter = _SequenceFailAdapter(
            [DisconnectError(1, "t1"), DisconnectError(1, "t2")]
        )
        with patch("asyncio.sleep", return_value=None):
            snap = await collect_device_async(_make_device(), adapter=adapter)
        assert snap.collection_error is None
        assert adapter.connect_calls == 3

    @pytest.mark.asyncio
    async def test_auth_never_retried(self):
        adapter = _StickyFailAdapter(PermissionDenied("auth failed"))
        with patch("asyncio.sleep", return_value=None):
            snap = await collect_device_async(_make_device(), adapter=adapter)
        assert snap.collection_error is not None
        assert "auth failed" in snap.collection_error
        assert adapter.connect_calls == 1

    @pytest.mark.asyncio
    async def test_transient_exhausted_surfaces_error(self):
        adapter = _StickyFailAdapter(DisconnectError(1, "down"))
        with patch("asyncio.sleep", return_value=None):
            snap = await collect_device_async(_make_device(), adapter=adapter)
        assert snap.collection_error is not None
        assert adapter.connect_calls == 3


class TestCollectManyAsyncThroughFake:
    @pytest.mark.asyncio
    async def test_ordering_preserved_in_input_order(self):
        devices = [_make_device(f"r{i:02d}", f"10.0.0.{i}") for i in range(1, 4)]
        snaps = await collect_all_async(
            devices, max_workers=3, adapter=FakeAsyncAdapter()
        )
        assert [s.device_name for s in snaps] == [d.name for d in devices]

    @pytest.mark.asyncio
    async def test_timeout_results_in_input_order(self):
        fast = _make_device("fast", "10.0.0.1")
        slow = _make_device("slow", "10.0.0.2")

        class _MixedDelay(FakeAsyncAdapter):
            async def connect(self, device: Device) -> Any:
                self.connect_calls += 1
                if device.name == "slow":
                    await asyncio.sleep(3)
                return object()

        snaps = await collect_all_async(
            [fast, slow], max_workers=2, timeout=0.5, adapter=_MixedDelay()
        )
        by_name = {s.device_name: s for s in snaps}
        assert snaps[0].device_name == "fast"
        assert snaps[1].device_name == "slow"
        assert by_name["fast"].collection_error is None
        assert by_name["slow"].collection_error is not None
        assert "timed out" in by_name["slow"].collection_error

    @pytest.mark.asyncio
    async def test_empty_list_returns_empty(self):
        assert await collect_all_async([], max_workers=2, adapter=FakeAsyncAdapter()) == []


class TestAsyncSeamPlacement:
    def test_transport_knobs_not_on_interface(self):
        sig_one = inspect.signature(collect_device_async)
        sig_many = inspect.signature(collect_all_async)
        for name in ("known_hosts", "strict_key", "ssh_strict", "enable", "secret"):
            assert name not in sig_one.parameters, f"{name} leaked onto collect_device_async"
            assert name not in sig_many.parameters, f"{name} leaked onto collect_all_async"

    def test_host_key_lives_on_adapter(self):
        sig = inspect.signature(AsyncSSHAdapter.__init__)
        assert "known_hosts" in sig.parameters
        assert hasattr(AsyncSSHAdapter, "connect")
        assert hasattr(AsyncSSHAdapter, "run")
        assert hasattr(AsyncSSHAdapter, "close")


class TestAsyncSSHAdapterSmoke:
    """Thin per-adapter smoke: the real AsyncSSH transport satisfies the seam."""

    @pytest.mark.asyncio
    async def test_exit_status_failure_surfaces_as_collection_error(self):
        mock_result = MagicMock()
        mock_result.exit_status = 1
        mock_result.stdout = ""
        mock_result.stderr = "fail"

        mock_conn = MagicMock()
        mock_conn.run = AsyncMock(return_value=mock_result)
        mock_conn.close = MagicMock()
        mock_conn.wait_closed = AsyncMock()

        with patch(
            "audnet.asyncssh_adapter.asyncssh.connect",
            new=AsyncMock(return_value=mock_conn),
        ):
            snap = await collect_device_async(
                _make_device(), adapter=AsyncSSHAdapter()
            )
        # Must surface as an error, never a silent empty result.
        assert snap.collection_error is not None
        assert "exit=1" in snap.collection_error

    @pytest.mark.asyncio
    async def test_missing_stdout_surfaces_as_collection_error(self):
        mock_result = MagicMock()
        mock_result.exit_status = 0
        mock_result.stdout = None

        mock_conn = MagicMock()
        mock_conn.run = AsyncMock(return_value=mock_result)
        mock_conn.close = MagicMock()
        mock_conn.wait_closed = AsyncMock()

        with patch(
            "audnet.asyncssh_adapter.asyncssh.connect",
            new=AsyncMock(return_value=mock_conn),
        ):
            snap = await collect_device_async(
                _make_device(), adapter=AsyncSSHAdapter()
            )
        assert snap.collection_error is not None
        assert "no stdout" in snap.collection_error

    @pytest.mark.asyncio
    async def test_host_key_option_reaches_transport(self):
        mock_conn = MagicMock()
        mock_conn.run = AsyncMock()
        mock_conn.close = MagicMock()
        mock_conn.wait_closed = AsyncMock()
        mock_connect = AsyncMock(return_value=mock_conn)

        with patch("audnet.asyncssh_adapter.asyncssh.connect", new=mock_connect):
            adapter = AsyncSSHAdapter(known_hosts="")
            await adapter.connect(
                Device(
                    name="r1",
                    host="10.0.0.1",
                    username="u",
                    password="",
                    use_keys=True,
                    key_file="/tmp/id_rsa",
                )
            )
        kwargs = mock_connect.call_args.kwargs
        assert kwargs.get("client_keys") == ["/tmp/id_rsa"]
        assert kwargs.get("known_hosts") == ""

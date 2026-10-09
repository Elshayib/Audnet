"""Contract suite for the deep collection module (issue #204).

Exercises the small interface (collect one / collect many) through a fake
raw-transport adapter. Covers the unified failure contract:

- transient errors retried, then succeed or surface as error snapshots
- authentication failures never retried
- per-device overruns surface as timeout results in input order
"""

from __future__ import annotations

import inspect
import time
from typing import Any

from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from audnet.collection import collect_all, collect_device
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


class FakeAdapter:
    """Fake raw-transport adapter: connect/run/close, only moves bytes."""

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
        self.connected_devices: list[str] = []

    def connect(self, device: Device) -> Any:
        self.connect_calls += 1
        self.connected_devices.append(device.name)
        if self._sticky is not None:
            raise self._sticky
        if self._failures:
            raise self._failures.pop(0)
        if self.delay_s:
            time.sleep(self.delay_s)
        return object()

    def run(self, connection: Any, command: str) -> str:
        self.run_calls += 1
        # Map command text to slot so parallel workers cannot misattribute
        # outputs via a shared counter.
        cmd = command.lower()
        if "interface" in cmd or "terse" in cmd or "system interface" in cmd:
            return self._raw[Slot.INTERFACES]
        if "version" in cmd or "system status" in cmd or "system info" in cmd:
            return self._raw[Slot.VERSION]
        return self._raw[Slot.RUNNING_CONFIG]

    def close(self, connection: Any) -> None:
        self.close_calls += 1


class _StickyFailAdapter(FakeAdapter):
    """Adapter that fails every connect with the same exception."""

    def __init__(self, exc: BaseException, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._exc = exc

    def connect(self, device: Device) -> Any:
        self.connect_calls += 1
        raise self._exc


class _SequenceFailAdapter(FakeAdapter):
    """Adapter that fails the first *n* connects, then succeeds."""

    def __init__(self, failures: list[BaseException], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._seq = list(failures)

    def connect(self, device: Device) -> Any:
        self.connect_calls += 1
        if self._seq:
            raise self._seq.pop(0)
        if self.delay_s:
            time.sleep(self.delay_s)
        return object()


class TestCollectOneThroughFake:
    def test_success_builds_snapshot(self):
        snap = collect_device(_make_device(), adapter=FakeAdapter())
        assert snap.device_name == "rtr01"
        assert snap.collection_error is None
        assert "15.2" in snap.version.version

    def test_transient_retried_then_succeeds(self):
        import unittest.mock as mock

        adapter = _SequenceFailAdapter(
            [NetmikoTimeoutException("t1"), NetmikoTimeoutException("t2")]
        )
        # Patch sleep to keep the contract suite fast (retry backoff).
        with mock.patch("time.sleep", return_value=None):
            snap = collect_device(_make_device(), adapter=adapter)
        assert snap.collection_error is None
        assert adapter.connect_calls == 3

    def test_auth_never_retried(self):
        import unittest.mock as mock

        adapter = _StickyFailAdapter(NetmikoAuthenticationException("auth failed"))
        with mock.patch("time.sleep", return_value=None):
            snap = collect_device(_make_device(), adapter=adapter)
        assert snap.collection_error is not None
        assert "auth failed" in snap.collection_error
        assert adapter.connect_calls == 1

    def test_transient_exhausted_surfaces_error(self):
        import unittest.mock as mock

        adapter = _StickyFailAdapter(NetmikoTimeoutException("down"))
        with mock.patch("time.sleep", return_value=None):
            snap = collect_device(_make_device(), adapter=adapter)
        assert snap.collection_error is not None
        assert "down" in snap.collection_error
        assert adapter.connect_calls == 3


class TestCollectManyThroughFake:
    def test_ordering_preserved_in_input_order(self):
        devices = [_make_device(f"r{i:02d}", f"10.0.0.{i}") for i in range(1, 4)]
        adapter = FakeAdapter()
        snaps = collect_all(devices, max_workers=3, adapter=adapter)
        assert [s.device_name for s in snaps] == [d.name for d in devices]

    def test_timeout_results_in_input_order(self):
        fast = _make_device("fast", "10.0.0.1")
        slow = _make_device("slow", "10.0.0.2")

        # Adapter that sleeps only for the slow device.
        class _MixedDelay(FakeAdapter):
            def connect(self, device: Device) -> Any:
                self.connect_calls += 1
                if device.name == "slow":
                    time.sleep(3)
                return object()

        adapter = _MixedDelay()
        # Use real sleeps here for the timeout path (short timeout).
        snaps = collect_all([fast, slow], max_workers=2, timeout=0.5, adapter=adapter)
        by_name = {s.device_name: s for s in snaps}
        assert snaps[0].device_name == "fast"
        assert snaps[1].device_name == "slow"
        assert by_name["fast"].collection_error is None
        assert by_name["slow"].collection_error is not None
        assert "timed out" in by_name["slow"].collection_error

    def test_empty_list_returns_empty(self):
        assert collect_all([], max_workers=2, adapter=FakeAdapter()) == []


class TestSeamPlacement:
    def test_transport_knobs_not_on_interface(self):
        sig_one = inspect.signature(collect_device)
        sig_many = inspect.signature(collect_all)
        for name in ("strict_key", "ssh_strict", "enable", "secret"):
            assert name not in sig_one.parameters, f"{name} leaked onto collect_device"
            assert name not in sig_many.parameters, f"{name} leaked onto collect_all"

    def test_transport_knobs_live_on_adapter(self):
        from audnet.netmiko_adapter import NetmikoAdapter

        sig = inspect.signature(NetmikoAdapter.__init__)
        assert "strict_key" in sig.parameters
        # Adapter exposes the raw-transport seam.
        assert hasattr(NetmikoAdapter, "connect")
        assert hasattr(NetmikoAdapter, "run")
        assert hasattr(NetmikoAdapter, "close")

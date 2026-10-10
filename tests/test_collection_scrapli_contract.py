"""Thin per-adapter smoke for the scrapli transport (issue #205, thinned #207).

The shared failure contract (transient-retried, auth-never-retried,
timeout results, ordering) lives in the contract suites
(:mod:`tests.test_collection_contract` and
:mod:`tests.test_collection_async_contract`). This module only proves the
real Scrapli transport satisfies the async seam:

- Operator audit with the scrapli backend collects through the deep module
- Per-Device driver choice lives on the adapter, never on the shared interface
- Missing optional dependency produces the clear install-hint error
"""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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


def _make_mock_scrapli_driver(outputs: list[str] | None = None):
    """Mock scrapli driver class yielding a conn with send_command."""
    if outputs is None:
        outputs = [
            _raw_outputs()[Slot.INTERFACES],
            _raw_outputs()[Slot.VERSION],
            _raw_outputs()[Slot.RUNNING_CONFIG],
        ]
    call_count = 0

    async def _send_side_effect(*args, **kwargs):
        nonlocal call_count
        response = MagicMock()
        response.result = outputs[min(call_count, len(outputs) - 1)]
        call_count += 1
        return response

    mock_conn = AsyncMock()
    mock_conn.send_command = AsyncMock(side_effect=_send_side_effect)
    mock_conn.open = AsyncMock()
    mock_conn.close = AsyncMock()

    mock_instance = AsyncMock()
    mock_instance.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_instance.__aexit__ = AsyncMock(return_value=False)
    # Adapter uses explicit open()/close(), not context manager.
    # Expose the conn for open/close assertions via the instance.
    mock_instance.open = mock_conn.open
    mock_instance.close = mock_conn.close
    mock_instance.send_command = mock_conn.send_command

    # Driver class returns an object with open()/send_command()/close().
    # Simulate real driver: instance IS the connection.
    mock_driver_cls = MagicMock(return_value=mock_conn)
    return mock_driver_cls, mock_conn


class TestScrapliSeamPlacement:
    def test_transport_knobs_not_on_interface(self):
        sig_one = inspect.signature(collect_device_async)
        sig_many = inspect.signature(collect_all_async)
        for name in ("driver", "scrapli", "textfsm", "auth_strict_key", "transport"):
            assert name not in sig_one.parameters, f"{name} leaked onto collect_device_async"
            assert name not in sig_many.parameters, f"{name} leaked onto collect_all_async"

    def test_driver_choice_lives_on_adapter(self):
        from audnet.scrapli_adapter import ScrapliAdapter

        assert hasattr(ScrapliAdapter, "connect")
        assert hasattr(ScrapliAdapter, "run")
        assert hasattr(ScrapliAdapter, "close")
        # Per-Device driver choice lives on the adapter module.
        from audnet import scrapli_adapter as mod

        assert hasattr(mod, "_get_scrapli_driver") or hasattr(ScrapliAdapter, "_get_driver")
        # Shared interface must not expose driver choice.
        assert "device_type" not in inspect.signature(collect_all_async).parameters


class TestScrapliAdapterSmoke:
    """Thin per-adapter smoke: the real Scrapli transport satisfies the seam."""

    @pytest.mark.asyncio
    async def test_collect_through_deep_module_no_behavior_change(self):
        from audnet.scrapli_adapter import ScrapliAdapter

        mock_driver_cls, _ = _make_mock_scrapli_driver()
        with patch(
            "audnet.scrapli_adapter._get_scrapli_driver", return_value=mock_driver_cls
        ):
            snap = await collect_device_async(_make_device(), adapter=ScrapliAdapter())
        assert snap.device_name == "rtr01"
        assert snap.collection_error is None
        assert "15.2" in snap.version.version

    @pytest.mark.asyncio
    async def test_shim_collects_through_shared_interface(self):
        """The scrapli backend shim collects through the deep module."""

        from audnet.scrapli_collector import (
            collect_all_scrapli,
            collect_device_scrapli,
        )

        mock_driver_cls, _ = _make_mock_scrapli_driver()
        with patch(
            "audnet.scrapli_adapter._get_scrapli_driver", return_value=mock_driver_cls
        ):
            snap = await collect_device_scrapli(_make_device())
            assert snap.collection_error is None
            snaps = await collect_all_scrapli([_make_device()])
            assert len(snaps) == 1
            assert snaps[0].collection_error is None

    @pytest.mark.asyncio
    async def test_missing_dependency_install_hint(self):
        import builtins as _builtins
        import sys

        for key in list(sys.modules):
            if key == "audnet.scrapli_adapter" or key == "scrapli" or key.startswith(
                "scrapli."
            ):
                del sys.modules[key]
        _real_import = _builtins.__import__

        def _blocked(name, *args, **kwargs):
            if name == "scrapli" or name.startswith("scrapli."):
                raise ImportError("scrapli not available (test)")
            return _real_import(name, *args, **kwargs)

        _builtins.__import__ = _blocked
        try:
            import importlib

            mod = importlib.import_module("audnet.scrapli_adapter")
            assert mod._SCRAPLI_AVAILABLE is False
            try:
                mod.ScrapliAdapter()
                assert False, "Expected ImportError"
            except ImportError as e:
                assert "scrapli is required" in str(e)
                assert 'pip install "audnet[scrapli]"' in str(e)
        finally:
            _builtins.__import__ = _real_import
            for key in list(sys.modules):
                if key == "audnet.scrapli_adapter":
                    del sys.modules[key]

    def test_strict_key_lives_on_adapter(self):
        from audnet.scrapli_adapter import ScrapliAdapter

        sig = inspect.signature(ScrapliAdapter.__init__)
        # Transport-specific knob lives on adapter constructor.
        assert "strict_key" in sig.parameters or hasattr(ScrapliAdapter, "_strict_key")

    @pytest.mark.asyncio
    async def test_run_passes_timeout_to_transport(self):
        from audnet.scrapli_adapter import ScrapliAdapter

        mock_conn = AsyncMock()
        resp = MagicMock()
        resp.result = "ok"
        mock_conn.send_command = AsyncMock(return_value=resp)
        adapter = ScrapliAdapter.__new__(ScrapliAdapter)
        # Bypass __init__ availability check when scrapli installed.
        out = await adapter.run(mock_conn, "show version", timeout=7.5)
        assert out == "ok"
        _, kwargs = mock_conn.send_command.call_args
        assert kwargs.get("timeout_ops") == 7.5

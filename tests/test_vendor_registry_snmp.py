"""Tests for the SNMP-based vendor auto-detection path in vendor_registry.

The transport target is isolated because a real SNMP query would hit the
network. These tests exercise ``detect_vendor_snmp``'s branching logic with a
mocked ``get_cmd``; a separate live test confirms the pysnmp 7.x
``await UdpTransportTarget.create(...)`` call shape works without crashing.
"""

from typing import Any

import pysnmp.hlapi.asyncio as _asyncio_hlapi
from _pytest.monkeypatch import MonkeyPatch

from audnet.vendor_registry import detect_vendor_snmp

# A pysnmp hlapi 4-tuple: (errorIndication, errorStatus, errorIndex, varBinds).
_SnmpResult = tuple[Any, Any, Any, list[tuple[Any, Any]]]


class _DummyTransportTarget:
    """Stand-in for UdpTransportTarget mirroring the pysnmp 7.x awaitable
    factory: ``await UdpTransportTarget.create((host, port), timeout=, retries=)``."""

    def __init__(self, address: Any, timeout: float = 1, retries: int = 5, **_kwargs: Any) -> None:
        self.address = address

    @classmethod
    async def create(
        cls, address: Any, timeout: float = 1, retries: int = 5, **_kwargs: Any
    ) -> "_DummyTransportTarget":
        return cls(address, timeout=timeout, retries=retries)


def _patch_snmp(
    monkeypatch: MonkeyPatch,
    get_cmd_result: _SnmpResult | None = None,
    raise_exc: Exception | None = None,
) -> None:
    """Patch the in-function imports used by ``detect_vendor_snmp``."""

    async def _fake_get_cmd(*_args: Any, **_kwargs: Any) -> _SnmpResult:
        if raise_exc is not None:
            raise raise_exc
        assert get_cmd_result is not None
        return get_cmd_result

    monkeypatch.setattr(_asyncio_hlapi, "get_cmd", _fake_get_cmd)
    monkeypatch.setattr(_asyncio_hlapi, "UdpTransportTarget", _DummyTransportTarget)


class TestDetectVendorSnmp:
    async def test_detects_cisco_ios_from_sys_descr(self, monkeypatch: MonkeyPatch) -> None:
        var_binds: list[tuple[Any, Any]] = [(object(), "Cisco IOS Software, Version 15.2")]
        _patch_snmp(monkeypatch, get_cmd_result=(None, 0, 0, var_binds))
        assert await detect_vendor_snmp("10.0.0.1") == "cisco_ios"

    async def test_detects_arista_eos_from_sys_descr(self, monkeypatch: MonkeyPatch) -> None:
        var_binds = [(object(), "Arista Networks EOS")]
        _patch_snmp(monkeypatch, get_cmd_result=(None, 0, 0, var_binds))
        assert await detect_vendor_snmp("10.0.0.1") == "arista_eos"

    async def test_detects_juniper_from_sys_descr(self, monkeypatch: MonkeyPatch) -> None:
        var_binds = [(object(), "Juniper Networks, Inc. JUNOS")]
        _patch_snmp(monkeypatch, get_cmd_result=(None, 0, 0, var_binds))
        assert await detect_vendor_snmp("10.0.0.1") == "juniper_junos"

    async def test_falls_back_on_error_indication(self, monkeypatch: MonkeyPatch) -> None:
        _patch_snmp(monkeypatch, get_cmd_result=("timeout", 0, 0, []))
        assert await detect_vendor_snmp("10.0.0.1") == "cisco_ios"

    async def test_falls_back_on_error_status(self, monkeypatch: MonkeyPatch) -> None:
        _patch_snmp(monkeypatch, get_cmd_result=(None, 1, 1, []))
        assert await detect_vendor_snmp("10.0.0.1") == "cisco_ios"

    async def test_empty_var_binds_falls_back(self, monkeypatch: MonkeyPatch) -> None:
        # var_binds list present but empty -> for-loop body never runs ->
        # trailing `return _DEFAULT_VENDOR` (line 380) is covered.
        _patch_snmp(monkeypatch, get_cmd_result=(None, 0, 0, []))
        assert await detect_vendor_snmp("10.0.0.1") == "cisco_ios"

    async def test_falls_back_when_get_cmd_raises(self, monkeypatch: MonkeyPatch) -> None:
        _patch_snmp(monkeypatch, raise_exc=RuntimeError("transport down"))
        assert await detect_vendor_snmp("10.0.0.1") == "cisco_ios"

    async def test_falls_back_when_pysnmp_unavailable(self, monkeypatch: MonkeyPatch) -> None:
        # The top-level `from pysnmp.hlapi.asyncio import (...)` ImportError
        # branch (lines 343-348) -> returns _DEFAULT_VENDOR.
        real_import = __import__

        def _blocked_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "pysnmp.hlapi.asyncio":
                raise ImportError("no pysnmp")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", _blocked_import)
        assert await detect_vendor_snmp("10.0.0.1") == "cisco_ios"

    async def test_pysnmp_4x_getcmd_fallback(self, monkeypatch: MonkeyPatch) -> None:
        # Remove `get_cmd` so `from ... import get_cmd` raises ImportError,
        # exercising the pysnmp 4.x `getCmd` fallback branch (lines 350-353).
        async def _fake_getCmd(*_args: Any, **_kwargs: Any) -> _SnmpResult:
            return (None, 0, 0, [(object(), "Cisco IOS Software")])

        monkeypatch.delattr(_asyncio_hlapi, "get_cmd", raising=False)
        monkeypatch.setattr(_asyncio_hlapi, "getCmd", _fake_getCmd, raising=False)
        monkeypatch.setattr(_asyncio_hlapi, "UdpTransportTarget", _DummyTransportTarget)
        assert await detect_vendor_snmp("10.0.0.1") == "cisco_ios"

    async def test_live_pysnmp7_create_does_not_crash(self, monkeypatch: MonkeyPatch) -> None:
        # Bug fix regression: pysnmp 7.x requires `await UdpTransportTarget.create(...)`.
        # Use the REAL UdpTransportTarget (not the dummy) so .create() is exercised.
        async def _fake_get_cmd(*_args: Any, **_kwargs: Any) -> _SnmpResult:
            return ("RequestTimedOut", 0, 0, [])

        monkeypatch.setattr(_asyncio_hlapi, "get_cmd", _fake_get_cmd)
        result = await detect_vendor_snmp("192.0.2.1", timeout=1, port=161)
        assert result == "cisco_ios"

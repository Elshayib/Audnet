"""Tests for the SNMP-based vendor auto-detection path in vendor_registry.

NOTE: these unit tests isolate the external SNMP transport
(``pysnmp.hlapi.asyncio.UdpTransportTarget``) because the project's current
call signature is incompatible with pysnmp 7.x (see flagged issue). The tests
exercise ``detect_vendor_snmp``'s branching logic, not the live transport.
"""

from typing import Any

import pysnmp.hlapi.asyncio as _asyncio_hlapi
from _pytest.monkeypatch import MonkeyPatch

from audnet.vendor_registry import detect_vendor_snmp

# A pysnmp hlapi 4-tuple: (errorIndication, errorStatus, errorIndex, varBinds).
_SnmpResult = tuple[Any, Any, Any, list[tuple[Any, Any]]]


class _DummyTransportTarget:
    """Stand-in for UdpTransportTarget so the code under test can run without
    hitting the pysnmp 7.x constructor incompatibility. Accepts the same
    call shape the project uses: ``UdpTransportTarget((host, port), timeout=, retries=)``."""

    def __init__(self, address: Any, timeout: float = 1, retries: int = 5, **_kwargs: Any) -> None:
        self.address = address


def _patch_snmp(
    monkeypatch: MonkeyPatch,
    get_cmd_result: _SnmpResult | None = None,
    raise_exc: Exception | None = None,
) -> None:
    """Patch the in-function imports used by ``detect_vendor_snmp``.

    Either ``get_cmd_result`` (a pysnmp 4-tuple) is returned when awaited, or
    ``raise_exc`` is raised when the (mocked) get_cmd is invoked.
    """

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

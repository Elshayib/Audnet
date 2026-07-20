"""Additional branch-coverage tests for the real-time listener module.

Targets defensive / branch paths not exercised by test_realtime.py:
- AlertManager.send_alert dry_run suppression
- AlertManager._get_client lazy creation + close()
- aiosmtplib-unavailable guard in _send_email
- pysnmp-unavailable guard in SnmpTrapReceiver
- _on_snmp_trap callback (sync + async on_trap)
- _handle_change baseline-enrichment path (pass + fail compliance)
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import asyncio
import pytest

from audnet.models import Device
from audnet.realtime import (
    AlertConfig,
    AlertManager,
    ChangeEvent,
    RealtimeListener,
    SnmpTrapReceiver,
)


def _event(**kw: Any) -> ChangeEvent:
    base = dict(
        device_name="rtr01",
        source_ip="10.0.0.1",
        event_type="syslog",
        timestamp=1234567890.0,
        raw_message="%SYS-5-CONFIG: changed",
        change_summary="config changed",
    )
    base.update(kw)
    return ChangeEvent(**base)


class TestSendAlertDryRun:
    @pytest.mark.asyncio
    async def test_dry_run_suppresses_alert(self) -> None:
        config = AlertConfig(dry_run=True)
        manager = AlertManager(config)
        await manager.send_alert(_event())
        # dry_run returns before incrementing the counter
        assert manager._alert_count == 0


class TestClientLifecycle:
    @pytest.mark.asyncio
    async def test_get_client_lazy_creation_and_close(self) -> None:
        config = AlertConfig(webhook_url="https://hooks.example.com/audit")
        manager = AlertManager(config)
        # _get_client creates the httpx client on first call (line 146)
        client = await manager._get_client()
        assert client is not None
        assert manager._httpx_client is client
        # close() releases it (lines 159-160)
        await manager.close()
        assert manager._httpx_client is None


class TestSendEmailGuards:
    @pytest.mark.asyncio
    async def test_email_skipped_without_from(self) -> None:
        config = AlertConfig(smtp_host="smtp.example.com", email_to=["ops@example.com"])
        manager = AlertManager(config)
        # No email_from -> returns immediately (line 287-288)
        await manager._send_email(_event())

    @pytest.mark.asyncio
    async def test_email_skipped_when_aiosmtplib_unavailable(self) -> None:
        config = AlertConfig(
            smtp_host="smtp.example.com",
            email_from="audnet@example.com",
            email_to=["ops@example.com"],
        )
        manager = AlertManager(config)
        with patch("audnet.realtime._AIOSMTPLIB_AVAILABLE", False):
            # Should log error and return without raising (lines 290-292)
            await manager._send_email(_event())


class TestSnmpTrapReceiverGuard:
    def test_raises_when_pysnmp_unavailable(self) -> None:
        config = AlertConfig()
        with patch("audnet.realtime._PYSNMP_AVAILABLE", False):
            with pytest.raises(ImportError, match="pysnmp"):
                SnmpTrapReceiver(config, lambda *a: None, {})


class TestOnSnmpTrap:
    @pytest.mark.asyncio
    async def test_on_snmp_trap_schedules_alert(self) -> None:
        config = AlertConfig()
        manager = AlertManager(config)
        listener = RealtimeListener(config, manager, {})
        # _on_snmp_trap builds a ChangeEvent and schedules _handle_change,
        # which (no baseline) forwards to send_alert -> alert counter bumps.
        listener._on_snmp_trap("rtr01", "10.0.0.1", "linkDown")
        await asyncio.sleep(0.1)
        assert manager._alert_count == 1

    @pytest.mark.asyncio
    async def test_on_snmp_trap_runs_with_baseline(self) -> None:
        config = AlertConfig()
        manager = AlertManager(config)
        device = Device(name="rtr01", host="10.0.0.1", username="admin", password="x")
        listener = RealtimeListener(config, manager, {"rtr01": device}, baseline={"rtr01": {}})
        fake_snapshot = MagicMock()
        fake_snapshot.collection_error = None
        with patch(
            "audnet.collector_async.collect_device_async",
            new=AsyncMock(return_value=fake_snapshot),
        ):
            listener._on_snmp_trap("rtr01", "10.0.0.1", "linkDown")
            await asyncio.sleep(0.1)
        assert manager._alert_count == 1


async def _await_pending() -> None:
    import asyncio

    await asyncio.sleep(0.05)


class TestHandleChangeBaseline:
    @pytest.mark.asyncio
    async def test_enriches_with_compliance_results(self) -> None:
        config = AlertConfig()
        manager = AlertManager(config)
        device = Device(name="rtr01", host="10.0.0.1", username="admin", password="x")
        listener = RealtimeListener(config, manager, {"rtr01": device}, baseline={"rtr01": {}})

        fake_snapshot = MagicMock()
        fake_snapshot.collection_error = None
        fake_results = [
            MagicMock(check_name="ssh_v2_only", passed=True, severity="high", detail="ok"),
            MagicMock(check_name="strong_crypto", passed=False, severity="high", detail="weak"),
        ]
        with patch(
            "audnet.collector_async.collect_device_async",
            new=AsyncMock(return_value=fake_snapshot),
        ):
            with patch("audnet.compliance.run_checks", return_value=fake_results):
                event = _event()
                await listener._handle_change(event)

        assert event.compliance_results  # enriched
        # At least one failing check -> severity escalated to high
        assert event.severity == "high"
        await manager.send_alert(event)
        assert manager._alert_count == 1

    @pytest.mark.asyncio
    async def test_skips_enrichment_when_device_unknown(self) -> None:
        config = AlertConfig()
        manager = AlertManager(config)
        listener = RealtimeListener(config, manager, {}, baseline={"rtr01": {}})
        event = _event(device_name="unknown-rtr")
        # device not in inventory -> baseline enrichment branch skipped
        await listener._handle_change(event)
        assert event.compliance_results == []

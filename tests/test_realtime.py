"""Tests for real-time change detection listener."""

import asyncio
import time
from pathlib import Path

import pytest

from audnet.realtime import (
    AlertConfig,
    AlertManager,
    ChangeDetector,
    ChangeEvent,
    RealtimeListener,
    SyslogProtocol,
)


# ---------------------------------------------------------------------------
# ChangeDetector
# ---------------------------------------------------------------------------


class TestChangeDetector:
    def test_detects_syslog_config_change(self):
        assert ChangeDetector.is_config_change("%SYS-5-CONFIG: Configured from console")

    def test_detects_config_keyword(self):
        assert ChangeDetector.is_config_change("Configuration changed by admin")

    def test_detects_interface_change(self):
        assert ChangeDetector.is_config_change("%LINEPROTO-5-UPDOWN: Line protocol changed")

    def test_detects_link_change(self):
        assert ChangeDetector.is_config_change("%LINK-3-UPDOWN: Interface Gig0/1, changed state")

    def test_ignores_non_config_messages(self):
        assert not ChangeDetector.is_config_change("SYS-6-LOGGING_START: Logging started")

    def test_ignores_empty_message(self):
        assert not ChangeDetector.is_config_change("")

    def test_summarize_extracts_context(self):
        msg = "router1 %SYS-5-CONFIG: Configured from console by admin"
        summary = ChangeDetector.summarize_change(msg)
        assert "SYS-5-CONFIG" in summary
        assert len(summary) <= 200

    def test_summarize_returns_truncated_for_no_match(self):
        msg = "some ordinary log message"
        summary = ChangeDetector.summarize_change(msg)
        assert len(summary) <= 200


# ---------------------------------------------------------------------------
# ChangeEvent
# ---------------------------------------------------------------------------


class TestChangeEvent:
    def test_dedup_key_is_deterministic(self):
        event = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=1234567890.0,
            raw_message="test",
            change_summary="test change",
        )
        assert event.dedup_key == event.dedup_key

    def test_dedup_key_differs_for_different_devices(self):
        event1 = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=1234567890.0,
            raw_message="test",
            change_summary="test change",
        )
        event2 = ChangeEvent(
            device_name="rtr02",
            source_ip="10.0.0.2",
            event_type="syslog",
            timestamp=1234567890.0,
            raw_message="test",
            change_summary="test change",
        )
        assert event1.dedup_key != event2.dedup_key

    def test_dedup_key_differs_for_different_summaries(self):
        event1 = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=1234567890.0,
            raw_message="test",
            change_summary="change A",
        )
        event2 = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=1234567890.0,
            raw_message="test",
            change_summary="change B",
        )
        assert event1.dedup_key != event2.dedup_key


# ---------------------------------------------------------------------------
# AlertConfig
# ---------------------------------------------------------------------------


class TestAlertConfig:
    def test_defaults(self):
        config = AlertConfig()
        assert config.webhook_url is None
        assert config.smtp_host is None
        assert config.rate_limit_seconds == 60
        assert config.dedup_window == 300
        assert config.poll_interval == 300
        assert config.syslog_bind_port == 514

    def test_custom_values(self):
        config = AlertConfig(
            webhook_url="https://hooks.example.com/audit",
            rate_limit_seconds=120,
            poll_interval=600,
        )
        assert config.webhook_url == "https://hooks.example.com/audit"
        assert config.rate_limit_seconds == 120
        assert config.poll_interval == 600


# ---------------------------------------------------------------------------
# AlertManager
# ---------------------------------------------------------------------------


class TestAlertManager:
    def setup_method(self):
        self.config = AlertConfig(
            rate_limit_seconds=60,
            dedup_window=300,
        )
        self.manager = AlertManager(self.config)

    def test_not_rate_limited_initially(self):
        assert not self.manager._is_rate_limited("rtr01")

    def test_rate_limited_after_first_alert(self):
        self.manager._is_rate_limited("rtr01")
        assert self.manager._is_rate_limited("rtr01")

    def test_different_devices_not_rate_limited(self):
        self.manager._is_rate_limited("rtr01")
        assert not self.manager._is_rate_limited("rtr02")

    def test_not_duplicate_initially(self):
        event = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="test",
            change_summary="test change",
        )
        assert not self.manager._is_duplicate(event)

    def test_duplicate_within_window(self):
        event = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="test",
            change_summary="test change",
        )
        self.manager._is_duplicate(event)
        assert self.manager._is_duplicate(event)

    def test_email_body_format(self):
        event = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=1234567890.0,
            raw_message="%SYS-5-CONFIG: changed",
            change_summary="Config changed by admin",
            severity="high",
            compliance_results=[
                {"check_name": "ssh_v2_only", "passed": False, "detail": "SSHv1 detected"},
            ],
        )
        body = self.manager._format_email_body(event)
        assert "rtr01" in body
        assert "syslog" in body
        assert "high" in body
        assert "ssh_v2_only" in body
        assert "FAIL" in body


# ---------------------------------------------------------------------------
# AlertManager.send_alert (async)
# ---------------------------------------------------------------------------


class TestAlertManagerSendAlert:
    def setup_method(self):
        self.config = AlertConfig(
            rate_limit_seconds=60,
            dedup_window=300,
        )
        self.manager = AlertManager(self.config)

    @pytest.mark.asyncio
    async def test_send_alert_increments_counter(self):
        self.config = AlertConfig(rate_limit_seconds=0, dedup_window=0)
        manager = AlertManager(self.config)
        event = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="test",
            change_summary="test",
        )
        await manager.send_alert(event)
        assert manager._alert_count == 1

    @pytest.mark.asyncio
    async def test_send_alert_skips_duplicate(self):
        self.config = AlertConfig(rate_limit_seconds=0, dedup_window=300)
        manager = AlertManager(self.config)
        event = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="test",
            change_summary="same change",
        )
        await manager.send_alert(event)
        await manager.send_alert(event)
        assert manager._alert_count == 1

    @pytest.mark.asyncio
    async def test_send_alert_skips_rate_limited(self):
        self.config = AlertConfig(rate_limit_seconds=3600, dedup_window=0)
        manager = AlertManager(self.config)
        event = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="test 1",
            change_summary="change 1",
        )
        event2 = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="test 2",
            change_summary="change 2",
        )
        await manager.send_alert(event)
        await manager.send_alert(event2)
        assert manager._alert_count == 1


# ---------------------------------------------------------------------------
# SyslogProtocol
# ---------------------------------------------------------------------------


class TestSyslogProtocol:
    @pytest.mark.asyncio
    async def test_datagram_received_decodes_message(self):
        received = []

        async def on_message(device, ip, msg):
            received.append((device, ip, msg))

        protocol = SyslogProtocol(on_message, {"10.0.0.1": "rtr01"})
        protocol.datagram_received(b"%SYS-5-CONFIG: changed", ("10.0.0.1", 12345))
        # Give the event loop a chance to process the coroutine
        await asyncio.sleep(0.1)
        assert len(received) == 1
        assert received[0] == ("rtr01", "10.0.0.1", "%SYS-5-CONFIG: changed")

    @pytest.mark.asyncio
    async def test_datagram_received_maps_unknown_ip(self):
        received = []

        async def on_message(device, ip, msg):
            received.append((device, ip, msg))

        protocol = SyslogProtocol(on_message, {})
        protocol.datagram_received(b"test message", ("192.168.1.100", 12345))
        await asyncio.sleep(0.1)
        assert len(received) == 1
        assert "unknown-192.168.1.100" == received[0][0]


# ---------------------------------------------------------------------------
# RealtimeListener
# ---------------------------------------------------------------------------


class TestRealtimeListener:
    def test_builds_device_map(self):
        config = AlertConfig()
        manager = AlertManager(config)
        inventory = {"rtr01": "10.0.0.1", "sw01": "10.0.0.2"}
        listener = RealtimeListener(config, manager, inventory)
        assert listener._device_map == {"10.0.0.1": "rtr01", "10.0.0.2": "sw01"}

    @pytest.mark.asyncio
    async def test_stop_cancels_tasks(self):
        config = AlertConfig(poll_interval=0)
        manager = AlertManager(config)
        inventory = {"rtr01": "10.0.0.1"}
        listener = RealtimeListener(config, manager, inventory)
        listener._running = True
        task = asyncio.create_task(asyncio.sleep(10))
        listener._tasks.append(task)
        await listener.stop()
        assert task.cancelled()


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCliListen:
    def test_listen_command_exists(self):
        from audnet.cli import app
        command_names = []
        for cmd in app.registered_commands:
            if cmd.name:
                command_names.append(cmd.name)
            elif cmd.callback:
                command_names.append(cmd.callback.__name__)
        assert "listen" in command_names

    def test_listen_dry_run_no_smtp_to(self, tmp_path: Path):
        from typer.testing import CliRunner
        from audnet.cli import app

        runner = CliRunner()
        # Create a minimal inventory
        inv = tmp_path / "devices.yaml"
        inv.write_text("devices:\n  - name: rtr01\n    host: 10.0.0.1\n    username: admin\n    password: test\n")

        result = runner.invoke(
            app,
            [
                "listen",
                "--inventory", str(inv),
                "--smtp-host", "smtp.example.com",
                "--email-from", "test@example.com",
                # Missing --email-to
            ],
        )
        assert result.exit_code == 1
        assert "email-to" in result.output

"""Tests for real-time change detection listener."""

import asyncio
import time
from pathlib import Path

import pytest

from audnet.models import Device
from audnet.realtime import (
    AlertConfig,
    AlertManager,
    ChangeDetector,
    ChangeEvent,
    RealtimeListener,
    SyslogProtocol,
)


def _devices(inventory: dict[str, str]) -> dict[str, Device]:
    return {
        name: Device(name=name, host=host, username="admin", password="test")
        for name, host in inventory.items()
    }


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
        listener = RealtimeListener(config, manager, _devices(inventory))
        assert listener._device_map == {"10.0.0.1": "rtr01", "10.0.0.2": "sw01"}

    @pytest.mark.asyncio
    async def test_stop_cancels_tasks(self):
        config = AlertConfig(poll_interval=0)
        manager = AlertManager(config)
        inventory = {"rtr01": "10.0.0.1"}
        listener = RealtimeListener(config, manager, _devices(inventory))
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
        inv.write_text(
            "devices:\n  - name: rtr01\n    host: 10.0.0.1\n    username: admin\n    password: test\n"
        )

        env = {"AUDNET_SMTP_PASSWORD": "testpass"}
        result = runner.invoke(
            app,
            [
                "listen",
                "--inventory",
                str(inv),
                "--smtp-host",
                "smtp.example.com",
                "--email-from",
                "test@example.com",
                # Missing --email-to
            ],
            env=env,
        )
        assert result.exit_code == 1
        assert "email-to" in result.output


# ---------------------------------------------------------------------------
# Webhook sender (mocked)
# ---------------------------------------------------------------------------


class TestWebhookSender:
    """Tests for AlertManager._send_webhook with mocked HTTP."""

    @pytest.fixture
    def webhook_config(self):
        return AlertConfig(
            webhook_url="https://hooks.example.com/audit",
            webhook_secret="test-secret",
            webhook_timeout=5,
            webhook_retries=2,
        )

    @pytest.fixture
    def sample_event(self):
        return ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="%SYS-5-CONFIG: Configured from console",
            change_summary="Config changed from console",
            severity="high",
        )

    @pytest.mark.asyncio
    async def test_send_webhook_success(self, webhook_config, sample_event):
        from unittest.mock import AsyncMock, MagicMock

        manager = AlertManager(webhook_config)
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        manager._httpx_client = mock_client

        await manager._send_webhook(sample_event)

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert call_kwargs[0][0] == "https://hooks.example.com/audit"
        assert call_kwargs[1]["headers"]["Content-Type"] == "application/json"

    @pytest.mark.asyncio
    async def test_send_webhook_includes_hmac_signature(self, webhook_config, sample_event):
        from unittest.mock import AsyncMock, MagicMock

        manager = AlertManager(webhook_config)
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        manager._httpx_client = mock_client

        await manager._send_webhook(sample_event)

        call_kwargs = mock_client.post.call_args
        headers = call_kwargs[1]["headers"]
        assert "X-Signature" in headers
        assert headers["X-Signature"].startswith("sha256=")

    @pytest.mark.asyncio
    async def test_send_webhook_retries_on_failure(self, webhook_config, sample_event):
        from unittest.mock import AsyncMock, MagicMock

        manager = AlertManager(webhook_config)
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                Exception("connection refused"),
                mock_resp,
            ],
        )
        manager._httpx_client = mock_client

        await manager._send_webhook(sample_event)

        assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_send_webhook_exhausts_retries(self, webhook_config, sample_event):
        from unittest.mock import AsyncMock

        manager = AlertManager(webhook_config)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("connection refused"))
        manager._httpx_client = mock_client

        # Should not raise — retries are caught internally
        await manager._send_webhook(sample_event)

        assert mock_client.post.call_count == webhook_config.webhook_retries

    @pytest.mark.asyncio
    async def test_send_webhook_skipped_when_httpx_unavailable(
        self, webhook_config, sample_event
    ):
        from unittest.mock import patch

        with patch("audnet.realtime._HTTPX_AVAILABLE", False):
            manager = AlertManager(webhook_config)
            # Should return immediately without error
            await manager._send_webhook(sample_event)
            assert manager._httpx_client is None


# ---------------------------------------------------------------------------
# Email sender (mocked)
# ---------------------------------------------------------------------------


class TestEmailSender:
    """Tests for AlertManager._send_email with mocked SMTP."""

    @pytest.fixture
    def email_config(self):
        return AlertConfig(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_username="user@example.com",
            smtp_password="secret",
            smtp_use_tls=True,
            email_from="audnet@example.com",
            email_to=["admin@example.com"],
        )

    @pytest.fixture
    def sample_event(self):
        return ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="%SYS-5-CONFIG: test",
            change_summary="Config change detected",
            severity="medium",
            compliance_results=[{"rule": "test", "status": "FAIL"}],
        )

    @pytest.mark.asyncio
    async def test_send_email_success(self, email_config, sample_event):
        from unittest.mock import patch, AsyncMock

        manager = AlertManager(email_config)

        with patch("audnet.realtime.aiosmtplib.send", new_callable=AsyncMock) as mock_send:
            await manager._send_email(sample_event)

        mock_send.assert_called_once()
        call_kwargs = mock_send.call_args.kwargs
        assert call_kwargs["hostname"] == "smtp.example.com"
        assert call_kwargs["port"] == 587
        assert call_kwargs["username"] == "user@example.com"
        assert call_kwargs["use_tls"] is True

    @pytest.mark.asyncio
    async def test_send_email_skips_without_recipients(self, email_config, sample_event):
        from unittest.mock import patch, AsyncMock

        config = AlertConfig(
            smtp_host="smtp.example.com",
            email_from="audnet@example.com",
            email_to=[],  # no recipients
        )
        manager = AlertManager(config)

        with patch("audnet.realtime.aiosmtplib.send", new_callable=AsyncMock) as mock_send:
            await manager._send_email(sample_event)

        mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_email_includes_compliance_results(self, email_config, sample_event):
        from unittest.mock import patch, AsyncMock

        manager = AlertManager(email_config)

        with patch("audnet.realtime.aiosmtplib.send", new_callable=AsyncMock) as mock_send:
            await manager._send_email(sample_event)

        # Verify the message was sent
        assert mock_send.call_count == 1
        msg = mock_send.call_args.args[0]
        assert "rtr01" in msg["Subject"]
        assert "Config change detected" in msg.get_payload(decode=True).decode("utf-8")

    @pytest.mark.asyncio
    async def test_send_email_skips_when_aiosmtplib_not_installed(self, email_config, sample_event):
        """_send_email logs error and returns early when aiosmtplib is not available."""
        from unittest.mock import patch

        manager = AlertManager(email_config)
        with patch("audnet.realtime._AIOSMTPLIB_AVAILABLE", False):
            # Should not raise, just log and return
            await manager._send_email(sample_event)


# ---------------------------------------------------------------------------
# SNMP Trap Receiver
# ---------------------------------------------------------------------------


class TestSnmpTrapReceiver:
    """Tests for SnmpTrapReceiver configuration."""

    def test_snmp_receiver_stores_config(self):
        from audnet.realtime import SnmpTrapReceiver

        config = AlertConfig(snmp_community="my-community")
        receiver = SnmpTrapReceiver.__new__(SnmpTrapReceiver)
        receiver._alert_config = config
        assert receiver._alert_config.snmp_community == "my-community"

    def test_snmp_receiver_default_community(self):
        from audnet.realtime import SnmpTrapReceiver

        config = AlertConfig()
        receiver = SnmpTrapReceiver.__new__(SnmpTrapReceiver)
        receiver._alert_config = config
        assert receiver._alert_config.snmp_community == "public"


# ---------------------------------------------------------------------------
# RealtimeListener
# ---------------------------------------------------------------------------


class TestRealtimeListenerExtended:
    """Extended tests for RealtimeListener."""

    def test_listener_stores_config(self):
        config = AlertConfig(
            syslog_bind_host="127.0.0.1",
            syslog_bind_port=1514,
        )
        alert_mgr = AlertManager(config)
        listener = RealtimeListener(config, alert_mgr, _devices({}))
        assert listener._alert_config.syslog_bind_host == "127.0.0.1"
        assert listener._alert_config.syslog_bind_port == 1514

    def test_listener_initializes_with_empty_tasks(self):
        config = AlertConfig()
        alert_mgr = AlertManager(config)
        listener = RealtimeListener(config, alert_mgr, _devices({}))
        assert listener._tasks == []
        assert listener._running is False

    def test_device_map_empty_inventory(self):
        config = AlertConfig()
        alert_mgr = AlertManager(config)
        listener = RealtimeListener(config, alert_mgr, _devices({}))
        assert listener._device_map == {}

    def test_device_map_with_devices(self):
        config = AlertConfig()
        alert_mgr = AlertManager(config)
        inventory = {"rtr01": "10.0.0.1", "rtr02": "10.0.0.2"}
        listener = RealtimeListener(config, alert_mgr, _devices(inventory))
        assert listener._device_map["10.0.0.1"] == "rtr01"
        assert listener._device_map["10.0.0.2"] == "rtr02"


# ---------------------------------------------------------------------------
# send_alert with both webhook + email (task gathering paths)
# ---------------------------------------------------------------------------


class TestSendAlertTaskGathering:
    """Tests for send_alert task creation and gathering (lines 160-170)."""

    @pytest.mark.asyncio
    async def test_send_alert_triggers_both_webhook_and_email(self):
        from unittest.mock import patch, AsyncMock

        config = AlertConfig(
            webhook_url="https://hooks.example.com/audit",
            smtp_host="smtp.example.com",
            email_from="audnet@example.com",
            email_to=["admin@example.com"],
            rate_limit_seconds=0,
            dedup_window=0,
        )
        manager = AlertManager(config)
        event = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="%SYS-5-CONFIG: test",
            change_summary="Config change",
            severity="high",
        )

        with (
            patch.object(manager, "_send_webhook", new_callable=AsyncMock) as mock_webhook,
            patch.object(manager, "_send_email", new_callable=AsyncMock) as mock_email,
        ):
            await manager.send_alert(event)

        mock_webhook.assert_called_once_with(event)
        mock_email.assert_called_once_with(event)
        assert manager._alert_count == 1

    @pytest.mark.asyncio
    async def test_send_alert_task_exception_is_caught(self):
        """Test that exceptions in tasks are caught by gather (line 169-170)."""
        from unittest.mock import patch, AsyncMock

        config = AlertConfig(
            webhook_url="https://hooks.example.com/audit",
            smtp_host="smtp.example.com",
            email_from="audnet@example.com",
            email_to=["admin@example.com"],
            rate_limit_seconds=0,
            dedup_window=0,
        )
        manager = AlertManager(config)
        event = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="%SYS-5-CONFIG: test",
            change_summary="Config change",
            severity="high",
        )

        # Make webhook raise an exception
        with (
            patch.object(
                manager,
                "_send_webhook",
                new_callable=AsyncMock,
                side_effect=Exception("network error"),
            ),
            patch.object(manager, "_send_email", new_callable=AsyncMock),
        ):
            # Should not raise — exceptions are caught by gather(return_exceptions=True)
            await manager.send_alert(event)

        assert manager._alert_count == 1


# ---------------------------------------------------------------------------
# Email error handling (lines 246-248)
# ---------------------------------------------------------------------------


class TestEmailErrorHandling:
    """Tests for _send_email error handling."""

    @pytest.mark.asyncio
    async def test_send_email_raises_on_failure(self):
        from unittest.mock import patch, AsyncMock

        config = AlertConfig(
            smtp_host="smtp.example.com",
            email_from="audnet@example.com",
            email_to=["admin@example.com"],
        )
        manager = AlertManager(config)
        event = ChangeEvent(
            device_name="rtr01",
            source_ip="10.0.0.1",
            event_type="syslog",
            timestamp=time.time(),
            raw_message="test",
            change_summary="test",
            severity="medium",
        )

        with patch(
            "audnet.realtime.aiosmtplib.send",
            new_callable=AsyncMock,
            side_effect=Exception("SMTP error"),
        ):
            with pytest.raises(Exception, match="SMTP error"):
                await manager._send_email(event)


# ---------------------------------------------------------------------------
# _poll_device — SHA256 hash comparison
# ---------------------------------------------------------------------------


class TestPollDeviceHash:
    """Tests for _poll_device returning SHA256 hashes instead of full config."""

    def test_poll_device_returns_hash_not_full_config(self):
        """_poll_device should return a 64-char SHA256 hex digest."""
        import hashlib
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_result = MagicMock()
        mock_result.stdout = b"hostname rtr01\ninterface Gig0/0\n"

        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_result)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("audnet.realtime.asyncssh.connect", return_value=mock_conn):
            import asyncio
            from audnet.realtime import RealtimeListener

            config = {
                "syslog_bind_host": "0.0.0.0",
                "syslog_bind_port": 514,
                "snmp_trap_bind_host": "0.0.0.0",
                "snmp_trap_bind_port": 162,
                "poll_interval": 60,
                "rate_limit_seconds": 60,
                "dedup_window": 300,
                "webhook_url": None,
                "webhook_secret": None,
                "smtp_host": None,
                "smtp_port": 587,
                "smtp_username": None,
                "smtp_password": None,
                "email_from": None,
                "email_to": [],
                "smtp_use_tls": True,
            }
            alert_config = AlertConfig(**config)
            listener = RealtimeListener.__new__(RealtimeListener)
            listener._alert_config = alert_config

            device = Device(name="rtr01", host="10.0.0.1", username="admin", password="test")
            result = asyncio.run(listener._poll_device(device))

        expected_hash = hashlib.sha256(mock_result.stdout).hexdigest()
        assert result == expected_hash
        assert len(result) == 64  # SHA256 hex digest length

    def test_poll_device_hash_changes_with_config(self):
        """Different configs produce different hashes."""
        import hashlib

        config_a = b"hostname rtr01\ninterface Gig0/0\n"
        config_b = b"hostname rtr01\ninterface Gig0/0\n ip address 10.0.0.1 255.255.255.0\n"

        hash_a = hashlib.sha256(config_a).hexdigest()
        hash_b = hashlib.sha256(config_b).hexdigest()
        assert hash_a != hash_b

    def test_poll_device_returns_empty_on_error(self):
        """_poll_device returns None on connection failure (keep last good hash)."""
        from unittest.mock import AsyncMock, patch

        mock_conn = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(side_effect=Exception("Connection refused"))
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("audnet.realtime.asyncssh.connect", return_value=mock_conn):
            import asyncio
            from audnet.realtime import RealtimeListener

            config = {
                "syslog_bind_host": "0.0.0.0",
                "syslog_bind_port": 514,
                "snmp_trap_bind_host": "0.0.0.0",
                "snmp_trap_bind_port": 162,
                "poll_interval": 60,
                "rate_limit_seconds": 60,
                "dedup_window": 300,
                "webhook_url": None,
                "webhook_secret": None,
                "smtp_host": None,
                "smtp_port": 587,
                "smtp_username": None,
                "smtp_password": None,
                "email_from": None,
                "email_to": [],
                "smtp_use_tls": True,
            }
            alert_config = AlertConfig(**config)
            listener = RealtimeListener.__new__(RealtimeListener)
            listener._alert_config = alert_config

            device = Device(name="rtr01", host="10.0.0.1", username="admin", password="test")
            result = asyncio.run(listener._poll_device(device))
        assert result is None

    def test_poll_device_handles_string_stdout(self):
        """_poll_device handles str stdout (not just bytes)."""
        import hashlib
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_result = MagicMock()
        mock_result.stdout = "hostname rtr01\n"  # str, not bytes

        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_result)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("audnet.realtime.asyncssh.connect", return_value=mock_conn):
            import asyncio
            from audnet.realtime import RealtimeListener

            config = {
                "syslog_bind_host": "0.0.0.0",
                "syslog_bind_port": 514,
                "snmp_trap_bind_host": "0.0.0.0",
                "snmp_trap_bind_port": 162,
                "poll_interval": 60,
                "rate_limit_seconds": 60,
                "dedup_window": 300,
                "webhook_url": None,
                "webhook_secret": None,
                "smtp_host": None,
                "smtp_port": 587,
                "smtp_username": None,
                "smtp_password": None,
                "email_from": None,
                "email_to": [],
                "smtp_use_tls": True,
            }
            alert_config = AlertConfig(**config)
            listener = RealtimeListener.__new__(RealtimeListener)
            listener._alert_config = alert_config

            device = Device(name="rtr01", host="10.0.0.1", username="admin", password="test")
            result = asyncio.run(listener._poll_device(device))

        expected_hash = hashlib.sha256(b"hostname rtr01\n").hexdigest()
        assert result == expected_hash

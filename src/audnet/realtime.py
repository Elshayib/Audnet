"""Real-time change detection via syslog and SNMP traps.

Listens for syslog messages and SNMP traps from network devices,
maps them to inventory entries, triggers compliance checks on
detected changes, and sends alerts via webhook and email.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from typing import Any, Callable

import asyncssh

try:
    import httpx  # noqa: F401

    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

try:
    import aiosmtplib  # noqa: F401

    _AIOSMTPLIB_AVAILABLE = True
except ImportError:
    _AIOSMTPLIB_AVAILABLE = False

try:
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config as snmp_config, engine
    from pysnmp.entity.rfc3413 import ntfrcv

    _PYSNMP_AVAILABLE = True
except ImportError:
    _PYSNMP_AVAILABLE = False


logger = logging.getLogger(__name__)

__all__ = [
    "AlertConfig",
    "AlertManager",
    "RealtimeListener",
    "start_listener",
]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class AlertConfig:
    """Configuration for real-time alerting."""

    # Webhook
    webhook_url: str | None = None
    webhook_secret: str | None = None
    webhook_timeout: int = 10
    webhook_retries: int = 3

    # Email
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    email_from: str | None = None
    email_to: list[str] = field(default_factory=list)

    # Alert throttling
    rate_limit_seconds: int = 60  # min seconds between alerts per device
    dedup_window: int = 300  # dedup window in seconds

    # Listener bind addresses
    syslog_bind_host: str = "0.0.0.0"  # nosec B104 — intentional: listen on all interfaces by default, overridable
    syslog_bind_port: int = 514
    snmp_trap_bind_host: str = "0.0.0.0"  # nosec B104 — intentional: listen on all interfaces by default, overridable
    snmp_trap_bind_port: int = 162

    # Syslog facility/priority filter (only process these)
    # Empty means process all
    syslog_facilities: list[str] = field(default_factory=list)

    # SNMP community
    snmp_community: str = "public"

    # Polling fallback interval (seconds)
    poll_interval: int = 300


@dataclass
class ChangeEvent:
    """Represents a detected configuration change."""

    device_name: str
    source_ip: str
    event_type: str  # "syslog", "snmp_trap", "poll"
    timestamp: float
    raw_message: str
    change_summary: str = ""
    severity: str = "medium"
    compliance_results: list[dict[str, Any]] = field(default_factory=list)
    config_snapshot: dict[str, str] = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        """Generate a deduplication key for this event."""
        raw = f"{self.device_name}:{self.event_type}:{self.change_summary}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Alert Manager
# ---------------------------------------------------------------------------


class AlertManager:
    """Manages alert delivery via webhook and email with rate limiting."""

    def __init__(self, config: AlertConfig) -> None:
        self._config = config
        self._last_alert_time: dict[str, float] = {}
        self._dedup_cache: dict[str, float] = {}
        self._alert_count = 0
        self._httpx_client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazily create and reuse an httpx AsyncClient with connection pooling."""
        if self._httpx_client is None:
            self._httpx_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.webhook_timeout),
                limits=httpx.Limits(
                    max_connections=20,
                    max_keepalive_connections=10,
                    keepalive_expiry=30,
                ),
            )
        return self._httpx_client

    async def close(self) -> None:
        """Close the httpx client if open."""
        if self._httpx_client is not None:
            await self._httpx_client.aclose()
            self._httpx_client = None

    def _is_rate_limited(self, key: str) -> bool:
        """Check if an alert for this key is rate limited."""
        now = time.time()
        last = self._last_alert_time.get(key, 0)
        if now - last < self._config.rate_limit_seconds:
            return True
        self._last_alert_time[key] = now
        # In-place cleanup of expired entries
        expired = [k for k, v in self._last_alert_time.items()
                   if now - v >= self._config.rate_limit_seconds * 2]
        for k in expired:
            del self._last_alert_time[k]
        return False

    def _is_duplicate(self, event: ChangeEvent) -> bool:
        """Check if this event is a duplicate within the dedup window."""
        key = event.dedup_key
        now = time.time()
        last = self._dedup_cache.get(key, 0)
        if now - last < self._config.dedup_window:
            return True
        self._dedup_cache[key] = now
        # In-place cleanup of expired entries instead of rebuilding the dict
        expired = [k for k, v in self._dedup_cache.items()
                   if now - v >= self._config.dedup_window * 2]
        for k in expired:
            del self._dedup_cache[k]
        return False

    async def send_alert(self, event: ChangeEvent) -> None:
        """Send alert for a change event, respecting rate limits and dedup."""
        if self._is_duplicate(event):
            logger.debug("Deduped alert for %s", event.device_name)
            return

        if self._is_rate_limited(event.device_name):
            logger.debug("Rate limited alert for %s", event.device_name)
            return

        self._alert_count += 1
        logger.info(
            "Alert #%d: %s change on %s (%s)",
            self._alert_count,
            event.event_type,
            event.device_name,
            event.severity,
        )

        tasks: list[asyncio.Task[None]] = []
        if self._config.webhook_url:
            tasks.append(asyncio.create_task(self._send_webhook(event)))
        if self._config.smtp_host and self._config.email_to:
            tasks.append(asyncio.create_task(self._send_email(event)))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.warning("Alert delivery failed: %s", result)

    async def _send_webhook(self, event: ChangeEvent) -> None:
        """Send webhook POST with retry using async HTTP client and connection pooling."""
        if not _HTTPX_AVAILABLE:
            logger.error("httpx is not installed — cannot send webhook alerts")
            return

        payload = json.dumps(
            {
                "device_name": event.device_name,
                "source_ip": event.source_ip,
                "event_type": event.event_type,
                "timestamp": event.timestamp,
                "severity": event.severity,
                "change_summary": event.change_summary,
                "compliance_results": event.compliance_results,
            }
        ).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if self._config.webhook_secret:
            signature = hmac.new(
                self._config.webhook_secret.encode(),
                payload,
                "sha256",
            ).hexdigest()
            headers["X-Signature"] = f"sha256={signature}"

        client = await self._get_client()

        for attempt in range(self._config.webhook_retries):
            try:
                resp = await client.post(
                    self._config.webhook_url,  # type: ignore[arg-type]
                    content=payload,
                    headers=headers,
                )
                logger.debug("Webhook sent: HTTP %s", resp.status_code)
                return
            except Exception as exc:
                logger.warning(
                    "Webhook attempt %d/%d failed: %s",
                    attempt + 1,
                    self._config.webhook_retries,
                    exc,
                )
                if attempt < self._config.webhook_retries - 1:
                    await asyncio.sleep(2**attempt)

    async def _send_email(self, event: ChangeEvent) -> None:
        """Send email alert via SMTP."""
        if not self._config.email_from or not self._config.email_to:
            return

        if not _AIOSMTPLIB_AVAILABLE:
            logger.error("Email alerts require aiosmtplib. Install it with: pip install aiosmtplib")
            return

        subject = f"[{event.severity.upper()}] Config change on {event.device_name}"
        body = self._format_email_body(event)

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = self._config.email_from
        msg["To"] = ", ".join(self._config.email_to)

        try:
            await aiosmtplib.send(
                msg,
                hostname=self._config.smtp_host,
                port=self._config.smtp_port,
                username=self._config.smtp_username,
                password=self._config.smtp_password,
                use_tls=self._config.smtp_use_tls,
            )
            logger.debug("Email sent to %s", self._config.email_to)
        except Exception as exc:
            logger.error("Email send failed: %s", exc)
            raise

    def _format_email_body(self, event: ChangeEvent) -> str:
        """Format the email body for a change event."""
        lines = [
            f"Device: {event.device_name}",
            f"Source: {event.source_ip}",
            f"Event Type: {event.event_type}",
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(event.timestamp))}",
            f"Severity: {event.severity}",
            "",
            "Change Summary:",
            event.change_summary or "(no summary available)",
            "",
        ]
        if event.compliance_results:
            lines.append("Compliance Results:")
            for r in event.compliance_results:
                status = "PASS" if r.get("passed") else "FAIL"
                lines.append(
                    f"  [{status}] {r.get('check_name', 'unknown')}: {r.get('detail', '')}"
                )
            lines.append("")
        lines.append("Raw Message:")
        lines.append(event.raw_message[:2000] if event.raw_message else "(empty)")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Syslog Listener
# ---------------------------------------------------------------------------


class SyslogProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP protocol for receiving syslog messages."""

    def __init__(
        self,
        on_message: Callable[[str, str, str], Any],
        device_map: dict[str, str],  # ip -> device_name
    ) -> None:
        self._on_message = on_message
        self._device_map = device_map

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        source_ip = addr[0]
        try:
            message = data.decode("utf-8", errors="replace").strip()
        except Exception:  # pragma: no cover
            return

        # Map source IP to device name
        device_name = self._device_map.get(source_ip, f"unknown-{source_ip}")
        asyncio.ensure_future(self._on_message(device_name, source_ip, message))


# ---------------------------------------------------------------------------
# SNMP Trap Receiver
# ---------------------------------------------------------------------------


class SnmpTrapReceiver:
    """SNMP trap receiver using pysnmp asyncio transport."""

    def __init__(  # pragma: no cover
        self,
        alert_config: AlertConfig,
        on_trap: Callable[[str, str, str], Any],
        device_map: dict[str, str],
    ) -> None:
        if not _PYSNMP_AVAILABLE:
            raise ImportError(
                "SNMP trap reception requires pysnmp. "
                "Install it with: pip install pysnmp"
            )
        self._alert_config = alert_config
        self._on_trap = on_trap
        self._device_map = device_map
        self._snmp_engine = engine.SnmpEngine()

        # Configure SNMPv2c community
        snmp_config.add_v1_system(self._snmp_engine, "audnet", self._alert_config.snmp_community)

        # Configure transport
        snmp_config.add_transport(
            self._snmp_engine,
            udp.DOMAIN_NAME,
            udp.UdpTransport().open_server_mode(
                (self._alert_config.snmp_trap_bind_host, self._alert_config.snmp_trap_bind_port),
            ),
        )

        # Register notification receiver
        ntfrcv.NotificationReceiver(self._snmp_engine, self._trap_callback)

    def _trap_callback(  # pragma: no cover
        self,
        snmp_engine: engine.SnmpEngine,
        state_reference: dict[str, Any],
        context_engine_id: Any,
        context_name: Any,
        var_binds: list[Any],
        cb_ctx: Any,
    ) -> None:
        """Callback for received SNMP traps."""
        transport_info = snmp_engine.msg_and_pdu_dsp.get_transport_info(state_reference)
        if transport_info:
            transport_addr = transport_info[1]
            source_ip = str(transport_addr[0]) if transport_addr else "unknown"
        else:
            source_ip = "unknown"

        device_name = self._device_map.get(source_ip, f"unknown-{source_ip}")

        # Extract trap details
        trap_details = []
        for var_bind in var_binds:
            oid = str(var_bind[0])
            value = str(var_bind[1])
            trap_details.append(f"{oid}={value}")

        message = "; ".join(trap_details) if trap_details else "SNMP trap received"
        asyncio.ensure_future(self._on_trap(device_name, source_ip, message))

    def close(self) -> None:  # pragma: no cover
        """Close the SNMP engine."""
        self._snmp_engine.transport_dispatcher.close_dispatcher()


# ---------------------------------------------------------------------------
# Change Detector
# ---------------------------------------------------------------------------


class ChangeDetector:
    """Detects relevant configuration changes from syslog/SNMP messages."""

    # Common syslog patterns that indicate config changes
    _CONFIG_CHANGE_PATTERNS = [
        re.compile(r"%SYS-5-CONFIG", re.IGNORECASE),
        re.compile(r"%CONFIG", re.IGNORECASE),
        re.compile(r"configuration\s+changed", re.IGNORECASE),
        re.compile(r"config\s+(modified|changed|updated)", re.IGNORECASE),
        re.compile(r"%LINEPROTO", re.IGNORECASE),
        re.compile(r"%LINK-\d+-UPDOWN", re.IGNORECASE),
        re.compile(r"%TRAP", re.IGNORECASE),
    ]

    @classmethod
    def is_config_change(cls, message: str) -> bool:
        """Check if a syslog message indicates a configuration change."""
        return any(p.search(message) for p in cls._CONFIG_CHANGE_PATTERNS)

    @classmethod
    def summarize_change(cls, message: str) -> str:
        """Extract a brief summary from the change message."""
        for pattern in cls._CONFIG_CHANGE_PATTERNS:
            match = pattern.search(message)
            if match:
                # Get surrounding context (50 chars each side)
                start = max(0, match.start() - 30)
                end = min(len(message), match.end() + 70)
                return message[start:end].strip()
        return message[:200]


# ---------------------------------------------------------------------------
# Realtime Listener (orchestrator)
# ---------------------------------------------------------------------------


class RealtimeListener:
    """Orchestrates syslog/SNMP listeners, polling, and alerting."""

    def __init__(
        self,
        alert_config: AlertConfig,
        alert_manager: AlertManager,
        inventory: dict[str, str],  # device_name -> host_ip
    ) -> None:
        self._alert_config = alert_config
        self._alert_manager = alert_manager
        self._inventory = inventory
        self._device_map = {ip: name for name, ip in inventory.items()}  # ip -> name
        self._running = False
        self._tasks: list[asyncio.Task[None]] = []

    async def start(self) -> None:  # pragma: no cover
        """Start all listener tasks."""
        self._running = True
        logger.info("Starting real-time listener...")

        # Build device map from inventory
        logger.info("Device map: %s", self._device_map)

        # Start syslog listener
        syslog_task = asyncio.create_task(self._run_syslog())
        self._tasks.append(syslog_task)

        # Start polling fallback
        if self._alert_config.poll_interval > 0:
            poll_task = asyncio.create_task(self._run_polling())
            self._tasks.append(poll_task)

        # Start SNMP trap receiver
        if self._alert_config.snmp_trap_bind_port > 0:
            try:
                snmp_receiver = SnmpTrapReceiver(
                    self._alert_config,
                    self._on_snmp_trap,
                    self._device_map,
                )
                snmp_task = asyncio.create_task(self._run_snmp(snmp_receiver))
                self._tasks.append(snmp_task)
            except ImportError as exc:
                logger.warning("SNMP trap receiver not available: %s", exc)

        logger.info(
            "Real-time listener started. Syslog on %s:%d, polling every %ds",
            self._alert_config.syslog_bind_host,
            self._alert_config.syslog_bind_port,
            self._alert_config.poll_interval,
        )

        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False

    async def stop(self) -> None:  # pragma: no cover
        """Stop all listener tasks."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._alert_manager.close()
        logger.info("Real-time listener stopped")

    async def _run_syslog(self) -> None:  # pragma: no cover
        """Run the syslog UDP listener."""
        loop = asyncio.get_event_loop()

        def on_message(device_name: str, source_ip: str, message: str) -> None:
            if not ChangeDetector.is_config_change(message):
                return
            event = ChangeEvent(
                device_name=device_name,
                source_ip=source_ip,
                event_type="syslog",
                timestamp=time.time(),
                raw_message=message,
                change_summary=ChangeDetector.summarize_change(message),
                severity="high",
            )
            asyncio.ensure_future(self._alert_manager.send_alert(event))

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(on_message, self._device_map),
            local_addr=(self._alert_config.syslog_bind_host, self._alert_config.syslog_bind_port),
        )
        logger.info(
            "Syslog listener bound to %s:%d",
            self._alert_config.syslog_bind_host,
            self._alert_config.syslog_bind_port,
        )

        try:
            while self._running:
                await asyncio.sleep(1)
        finally:
            transport.close()

    async def _run_polling(self) -> None:  # pragma: no cover
        """Run periodic polling as fallback."""
        logger.info("Polling fallback enabled (interval=%ds)", self._alert_config.poll_interval)
        last_configs: dict[str, str] = {}

        while self._running:
            await asyncio.sleep(self._alert_config.poll_interval)
            if not self._running:
                break

            for device_name, host_ip in self._inventory.items():
                try:
                    config_text = await self._poll_device(host_ip)
                    if device_name in last_configs and last_configs[device_name] != config_text:
                        event = ChangeEvent(
                            device_name=device_name,
                            source_ip=host_ip,
                            event_type="poll",
                            timestamp=time.time(),
                            raw_message="Configuration changed (poll detected)",
                            change_summary="Configuration drift detected by scheduled poll",
                            severity="medium",
                        )
                        asyncio.ensure_future(self._alert_manager.send_alert(event))
                    last_configs[device_name] = config_text
                except Exception as exc:
                    logger.warning("Poll failed for %s: %s", device_name, exc)

    def _on_snmp_trap(self, device_name: str, source_ip: str, message: str) -> None:
        """Callback for SNMP trap reception — creates ChangeEvent and sends alert."""
        event = ChangeEvent(
            device_name=device_name,
            source_ip=source_ip,
            event_type="snmp",
            timestamp=time.time(),
            raw_message=message,
            change_summary=f"SNMP trap from {device_name}: {message}",
            severity="high",
        )
        asyncio.ensure_future(self._alert_manager.send_alert(event))

    async def _run_snmp(self, receiver: SnmpTrapReceiver) -> None:  # pragma: no cover
        """Run the SNMP trap receiver.

        The SnmpTrapReceiver sets up its own asyncio transport internally.
        This method keeps the task alive until the listener is stopped.
        """
        logger.info(
            "SNMP trap receiver listening on %s:%d",
            self._alert_config.snmp_trap_bind_host,
            self._alert_config.snmp_trap_bind_port,
        )
        try:
            while self._running:
                await asyncio.sleep(1)
        finally:
            receiver.close()

    async def _poll_device(self, host_ip: str) -> str:  # pragma: no cover
        """Poll a single device for its running config hash (lightweight).

        Returns the SHA256 hex digest of the running config, not the full
        config text. This reduces memory from O(config_size) to O(32 bytes)
        per device in the polling loop's last_configs cache.
        """
        try:
            async with asyncssh.connect(
                host_ip,
                known_hosts=None,
                connect_timeout=10,
            ) as conn:
                result = await conn.run("show running-config", timeout=30)
                stdout = result.stdout
                if isinstance(stdout, bytes):
                    return hashlib.sha256(stdout).hexdigest()
                return hashlib.sha256((stdout or "").encode()).hexdigest()
        except Exception:
            return ""


async def start_listener(  # pragma: no cover
    alert_config: AlertConfig,
    inventory: dict[str, str],
) -> None:
    """Convenience function to start the real-time listener."""
    alert_manager = AlertManager(alert_config)
    listener = RealtimeListener(alert_config, alert_manager, inventory)
    await listener.start()

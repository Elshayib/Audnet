from __future__ import annotations

import json
import logging
from io import StringIO

import structlog

from audnet.cli import _redact_secrets, _setup_logging, _SECRET_KEYS


class TestRedactSecrets:
    def test_password_is_redacted(self) -> None:
        event_dict = {"password": "s3cret", "other": "ok"}
        result = _redact_secrets(logging.getLogger(), "info", event_dict)
        assert result["password"] == "***REDACTED***"
        assert result["other"] == "ok"

    def test_key_file_is_redacted(self) -> None:
        event_dict = {"key_file": "/home/admin/.ssh/id_rsa"}
        result = _redact_secrets(logging.getLogger(), "info", event_dict)
        assert result["key_file"] == "***REDACTED***"

    def test_secret_is_redacted(self) -> None:
        event_dict = {"secret": "api-token-xyz"}
        result = _redact_secrets(logging.getLogger(), "info", event_dict)
        assert result["secret"] == "***REDACTED***"

    def test_passwd_is_redacted(self) -> None:
        event_dict = {"passwd": "old_password"}
        result = _redact_secrets(logging.getLogger(), "info", event_dict)
        assert result["passwd"] == "***REDACTED***"

    def test_token_is_redacted(self) -> None:
        event_dict = {"token": "bearer-abc-123"}
        result = _redact_secrets(logging.getLogger(), "info", event_dict)
        assert result["token"] == "***REDACTED***"

    def test_non_secret_fields_pass_through(self) -> None:
        event_dict = {"host": "10.0.0.1", "username": "admin", "port": 22}
        result = _redact_secrets(logging.getLogger(), "info", event_dict)
        assert result == event_dict

    def test_none_value_not_redacted(self) -> None:
        event_dict = {"password": None, "host": "10.0.0.1"}
        result = _redact_secrets(logging.getLogger(), "info", event_dict)
        assert result["password"] is None

    def test_all_secret_keys_are_covered(self) -> None:
        for key in _SECRET_KEYS:
            event_dict = {key: "should-be-hidden"}
            result = _redact_secrets(logging.getLogger(), "info", event_dict)
            assert result[key] == "***REDACTED***", f"Key '{key}' was not redacted"


class TestSetupLogging:
    def _reset_logging(self) -> None:
        root = logging.getLogger()
        root.setLevel(logging.WARNING)
        for h in root.handlers[:]:
            root.removeHandler(h)
        structlog.configure(
            processors=[structlog.dev.ConsoleRenderer()],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=False,
        )

    def test_verbose_sets_debug_level(self) -> None:
        self._reset_logging()
        _setup_logging(verbose=True)
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_non_verbose_sets_info_level(self) -> None:
        self._reset_logging()
        _setup_logging(verbose=False)
        root = logging.getLogger()
        assert root.level == logging.INFO

    def test_structlog_is_configured(self) -> None:
        self._reset_logging()
        _setup_logging(verbose=False)
        logger = structlog.get_logger("audnet.test")
        assert logger is not None

    def test_json_output_in_non_verbose(self) -> None:
        self._reset_logging()
        _setup_logging(verbose=False)
        buf = StringIO()
        handler = logging.StreamHandler(buf)
        handler.setLevel(logging.INFO)
        root = logging.getLogger()
        root.addHandler(handler)

        logger = structlog.get_logger("audnet.json_test")
        logger.info("test_event", host="10.0.0.1", password="supersecret")

        root.removeHandler(handler)
        output = buf.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["password"] == "***REDACTED***"
        assert parsed["host"] == "10.0.0.1"
        assert parsed["event"] == "test_event"

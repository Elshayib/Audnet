"""Tests for custom exceptions."""

from net_audit.exceptions import (
    NetAuditError,
    ConfigError,
    CollectionError,
    ParseError,
    ComplianceError,
    ReportError,
)


class TestExceptionHierarchy:
    def test_all_inherit_from_base(self):
        assert issubclass(ConfigError, NetAuditError)
        assert issubclass(CollectionError, NetAuditError)
        assert issubclass(ParseError, NetAuditError)
        assert issubclass(ComplianceError, NetAuditError)
        assert issubclass(ReportError, NetAuditError)

    def test_config_error_message(self):
        err = ConfigError("test message")
        assert str(err) == "test message"

    def test_parse_error_message(self):
        err = ParseError("template broken")
        assert str(err) == "template broken"

    def test_base_catches_all(self):
        """Any NetAuditError subclass should be catchable as NetAuditError."""
        errors = [
            ConfigError("a"),
            CollectionError("b"),
            ParseError("c"),
            ComplianceError("d"),
            ReportError("e"),
        ]
        for err in errors:
            assert isinstance(err, NetAuditError)

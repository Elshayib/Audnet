"""Custom exceptions for audnet."""


class NetAuditError(Exception):
    """Base exception for all audnet errors."""


class ConfigError(NetAuditError):
    """Raised when inventory or baseline YAML is invalid or unreadable."""


class CollectionError(NetAuditError):
    """Raised when device data collection fails."""


class ParseError(NetAuditError):
    """Raised when CLI output parsing fails."""


class ComplianceError(NetAuditError):
    """Raised when compliance checking encounters an unrecoverable error."""


class ReportError(NetAuditError):
    """Raised when report generation or writing fails."""


class GitHistoryError(NetAuditError):
    """Raised when Git history operations fail."""

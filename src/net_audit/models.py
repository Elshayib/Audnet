"""Pydantic data models for net-audit."""

import ipaddress

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


def _validate_host(value: str) -> str:
    """Validate that host is a valid IP address or resolvable hostname."""
    if not value or not value.strip():
        raise ValueError("host must not be empty")
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    # Allow hostnames: must have at least one dot, no spaces, no special chars
    if " " in value or "\t" in value:
        raise ValueError(f"invalid host: {value!r}")
    if "." not in value and value != "localhost":
        raise ValueError(f"invalid host: {value!r} — must be a valid IP, FQDN, or 'localhost'")
    # Reject characters that are invalid in hostnames
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    if not all(c in allowed for c in value):
        raise ValueError(f"invalid host: {value!r} — contains invalid characters")
    return value


class Device(BaseModel):
    name: str
    host: str
    device_type: str = "cisco_ios"
    username: str = "admin"
    password: SecretStr = SecretStr("")
    port: int = Field(default=22, ge=1, le=65535)
    timeout: int = 30
    use_keys: bool = False
    key_file: str | None = None

    _validate_host_field = field_validator("host", mode="before")(_validate_host)

    def get_password(self) -> str:
        """Return the plaintext password for use in SSH connections."""
        return self.password.get_secret_value()


class ParsedInterfaces(BaseModel):
    interfaces: list[dict[str, str]] = Field(default_factory=list)


class ParsedVersion(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hostname: str = ""
    version: str = ""
    uptime: str = ""
    serial: str = ""
    raw: str = ""


class ParsedConfig(BaseModel):
    lines: list[str] = Field(default_factory=list)
    raw: str = ""


class DeviceSnapshot(BaseModel):
    device_name: str
    interfaces: ParsedInterfaces
    version: ParsedVersion
    config: ParsedConfig
    collection_error: str | None = None


class ComplianceResult(BaseModel):
    check_name: str
    passed: bool
    severity: str
    detail: str


class AuditReport(BaseModel):
    device_name: str
    overall_pass: bool
    checks: list[ComplianceResult]

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed)


class CheckConfig(BaseModel):
    description: str
    severity: str
    rule: str
    allowed_vlans: list[int] | None = None
    approved_servers: list[str] | None = None


class SecurityBaseline(BaseModel):
    checks: dict[str, CheckConfig]

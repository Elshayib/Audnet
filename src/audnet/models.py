"""Pydantic data models for audnet."""

import ipaddress
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


def _validate_host(value: str) -> str:
    """Validate that host is a valid IP address or hostname."""
    if not value or not value.strip():
        raise ValueError("host must not be empty")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if " " in value or "\t" in value:
        raise ValueError(f"invalid host: {value!r}")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    if not all(c in allowed for c in value):
        raise ValueError(f"invalid host: {value!r} — contains invalid characters")
    if value[0] == "-" or value[-1] == "-":
        raise ValueError(f"invalid host: {value!r} — hostname cannot start or end with '-'")
    return value


class Device(BaseModel):
    name: str
    host: str
    device_type: str = "cisco_ios"
    username: str = "admin"
    password: SecretStr = SecretStr("")
    secret: SecretStr = SecretStr("")
    passwd: SecretStr = SecretStr("")
    token: SecretStr = SecretStr("")
    port: int = Field(default=22, ge=1, le=65535)
    timeout: int = 30
    use_keys: bool = False
    key_file: str | None = None

    _validate_host_field = field_validator("host", mode="before")(_validate_host)

    @field_validator("key_file", mode="before")
    @classmethod
    def _expand_key_file(cls, value: str | None) -> str | None:
        if value is None or not value:
            return value
        if value.startswith("~"):
            return str(Path(value).expanduser())
        return value

    @model_validator(mode="before")
    @classmethod
    def _merge_passwd(cls, data: object) -> object:
        if isinstance(data, dict) and not data.get("password") and data.get("passwd"):
            data["password"] = data["passwd"]
        return data

    def get_password(self) -> str:
        """Return the plaintext password for use in SSH connections."""
        return self.password.get_secret_value()

    def get_secret(self) -> str:
        """Return the enable/secret password for privileged mode."""
        return self.secret.get_secret_value()


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
    device_type: str = "cisco_ios"
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
    model_config = ConfigDict(extra="allow")

    description: str
    severity: str
    rule: str
    allowed_vlans: list[int] | None = None
    approved_servers: list[str] | None = None
    vendor_patterns: dict[str, dict[str, str]] | None = None
    max_timeout_minutes: int | None = None
    required_pattern: str | None = None


class SecurityBaseline(BaseModel):
    checks: dict[str, CheckConfig]

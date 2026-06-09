"""Pydantic data models for net-audit."""

from pydantic import BaseModel, Field


class Device(BaseModel):
    name: str
    host: str
    device_type: str = "cisco_ios"
    username: str = "admin"
    password: str = ""
    port: int = Field(default=22, ge=1, le=65535)
    timeout: int = 30


class ParsedInterfaces(BaseModel):
    interfaces: list[dict[str, str]] = Field(default_factory=list)


class ParsedVersion(BaseModel):
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

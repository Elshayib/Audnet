"""Network Security & Compliance State Auditor."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("net-audit")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

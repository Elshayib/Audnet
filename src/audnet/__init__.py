"""Network Security & Compliance State Auditor."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("audnet")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

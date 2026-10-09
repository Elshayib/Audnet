"""Parallel SSH collector for network device data.

Backward-compatible shim over :mod:`audnet.collection` (the deep
collection module). The old sync fan-out lives in ``collection`` now;
this module only preserves the public ``collect_device`` / ``collect_all``
import path used by the CLI and existing callers.

Uses the vendor registry for multi-vendor command dispatch.
"""

from audnet.collection import SyncTransportAdapter as SyncTransportAdapter
from audnet.collection import collect_all as collect_all
from audnet.collection import collect_device as collect_device
from audnet.netmiko_adapter import NetmikoAdapter as NetmikoAdapter
from audnet.netmiko_adapter import _ssh_strict_enabled as _ssh_strict_enabled

# Public interface is collect_device/collect_all + the adapter seam.
# _ssh_strict_enabled is re-exported only for backward compat with existing
# imports (e.g. `from audnet.collector import _ssh_strict_enabled`).
__all__ = [
    "SyncTransportAdapter",
    "NetmikoAdapter",
    "collect_all",
    "collect_device",
]

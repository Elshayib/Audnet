"""Async SSH collector for network device data.

Backward-compatible shim over :mod:`audnet.collection` (the deep
collection module). The old async fan-out lives in ``collection`` now;
this module only preserves the public ``collect_device_async`` /
``collect_all_async`` import path used by the CLI and existing callers.

Uses asyncssh for concurrent SSH collection with lower per-connection
overhead than the ThreadPool + Netmiko sync collector. Integrated into
the CLI via ``--async`` or ``--backend asyncssh``.
"""

from audnet.asyncssh_adapter import AsyncSSHAdapter as AsyncSSHAdapter
from audnet.collection import AsyncTransportAdapter as AsyncTransportAdapter
from audnet.collection import collect_all_async as collect_all_async
from audnet.collection import collect_device_async as collect_device_async

# Public interface is collect_device_async/collect_all_async + the adapter seam.
__all__ = [
    "AsyncTransportAdapter",
    "AsyncSSHAdapter",
    "collect_all_async",
    "collect_device_async",
]

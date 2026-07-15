"""PacketSource protocol: anything that yields normalized Events."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol, runtime_checkable

from sentryd.core.events import Event


class SourceError(RuntimeError):
    """Raised by sources for user-facing problems (missing file, no perms).

    The CLI catches this and prints the message without a traceback.
    """


def register_scapy_layers() -> None:
    """Import scapy's layer modules to register their link-layer bindings.

    Load-bearing for every raw-packet source: without it, readers decode
    frames as Raw, packet_to_event() returns None for all of them, and
    detection silently sees zero events. Call before opening any reader
    or capture socket. (Kept out of module import time — scapy is heavy
    and the log source doesn't need it.)
    """
    import scapy.layers.inet  # noqa: F401
    import scapy.layers.l2  # noqa: F401


@runtime_checkable
class PacketSource(Protocol):
    def events(self) -> Iterator[Event]:
        """Yield normalized events until the source is exhausted/stopped."""
        ...

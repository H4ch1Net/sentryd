"""PacketSource protocol: anything that yields normalized Events."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol, runtime_checkable

from sentryd.core.events import Event


class SourceError(RuntimeError):
    """Raised by sources for user-facing problems (missing file, no perms).

    The CLI catches this and prints the message without a traceback.
    """


@runtime_checkable
class PacketSource(Protocol):
    def events(self) -> Iterator[Event]:
        """Yield normalized events until the source is exhausted/stopped."""
        ...

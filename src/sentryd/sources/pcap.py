"""Offline pcap replay — the primary safe demo mode.

Streams packets with scapy's PcapReader rather than loading the whole file,
so large captures replay in constant memory.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sentryd.core.events import Event, packet_to_event
from sentryd.sources.base import SourceError, register_scapy_layers


class PcapFileSource:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def events(self) -> Iterator[Event]:
        register_scapy_layers()
        from scapy.error import Scapy_Exception
        from scapy.utils import PcapReader

        if not self.path.is_file():
            raise SourceError(f"pcap file not found: {self.path}")
        try:
            reader = PcapReader(str(self.path))
        except Scapy_Exception as exc:
            raise SourceError(f"could not read {self.path}: {exc}") from exc

        with reader:
            for pkt in reader:
                event = packet_to_event(pkt)
                if event is not None:
                    yield event

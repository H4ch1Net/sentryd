"""Live interface capture (requires root/CAP_NET_RAW).

The socket is opened eagerly in the caller's thread so permission problems
surface as a clean SourceError before any capture starts — the CLI turns
that into actionable advice instead of a traceback.
"""

from __future__ import annotations

from collections.abc import Iterator

from sentryd.core.events import Event, packet_to_event
from sentryd.sources.base import SourceError


class LiveCaptureSource:
    def __init__(self, interface: str | None = None, bpf_filter: str | None = None) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter

    def events(self) -> Iterator[Event]:
        import scapy.layers.inet  # noqa: F401  (register link-layer bindings)
        import scapy.layers.l2  # noqa: F401
        from scapy.config import conf
        from scapy.data import ETH_P_ALL

        try:
            sock = conf.L2listen(
                type=ETH_P_ALL, iface=self.interface, filter=self.bpf_filter
            )
        except PermissionError as exc:
            raise SourceError(
                "live capture needs root (or CAP_NET_RAW) — rerun with sudo, "
                "or demo offline with: sentryd replay tests/fixtures/portscan.pcap"
            ) from exc
        except OSError as exc:
            iface = self.interface or "default interface"
            raise SourceError(f"could not open {iface} for capture: {exc}") from exc

        try:
            while True:
                pkt = sock.recv()
                if pkt is None:
                    continue
                event = packet_to_event(pkt)
                if event is not None:
                    yield event
        finally:
            sock.close()

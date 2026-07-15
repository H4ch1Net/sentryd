"""Normalized event model.

Every input source (pcap replay, live sniffing, log tailing) converts its
records into :class:`Event` before anything else sees them. Detection rules
consume only Events — never scapy packets — which keeps rules unit-testable
with hand-built values and identical in behavior across all sources.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ArpInfo:
    """ARP-specific fields, present only when ``Event.protocol == "arp"``."""

    op: int  # 1 = who-has (request), 2 = is-at (reply)
    sender_mac: str
    sender_ip: str
    target_ip: str


@dataclass(frozen=True, slots=True)
class Event:
    ts: float
    protocol: str  # "tcp" | "udp" | "icmp" | "arp" | "other"
    length: int = 0
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str = ""  # scapy flag letters, e.g. "S", "SA", "FA"
    arp: ArpInfo | None = None
    summary: str = ""

    @property
    def is_syn_only(self) -> bool:
        """True for a bare connection attempt (SYN set, ACK not set)."""
        return "S" in self.tcp_flags and "A" not in self.tcp_flags


def packet_to_event(pkt) -> Event | None:
    """Convert a scapy packet to an Event; None if it carries nothing we model.

    This is the only place in the codebase (outside sources/ and test
    fixtures) that touches scapy types.
    """
    # Imported lazily: scapy import is slow and only sources need it.
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP

    ts = float(pkt.time)
    length = len(pkt)

    if ARP in pkt:
        arp = pkt[ARP]
        return Event(
            ts=ts,
            protocol="arp",
            length=length,
            src_ip=arp.psrc,
            dst_ip=arp.pdst,
            arp=ArpInfo(
                op=int(arp.op),
                sender_mac=arp.hwsrc,
                sender_ip=arp.psrc,
                target_ip=arp.pdst,
            ),
            summary=pkt.summary(),
        )

    if IP not in pkt:
        return None

    ip = pkt[IP]
    common = dict(
        ts=ts,
        length=length,
        src_ip=ip.src,
        dst_ip=ip.dst,
        summary=pkt.summary(),
    )

    if TCP in pkt:
        tcp = pkt[TCP]
        return Event(
            protocol="tcp",
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            tcp_flags=str(tcp.flags),
            **common,
        )
    if UDP in pkt:
        udp = pkt[UDP]
        return Event(
            protocol="udp",
            src_port=int(udp.sport),
            dst_port=int(udp.dport),
            **common,
        )
    if ICMP in pkt:
        return Event(protocol="icmp", **common)

    return Event(protocol="other", **common)

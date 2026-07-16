"""Shared test helpers: hand-built Events and synthetic pcap builders.

Rule unit tests feed Events directly (fast, no scapy in the loop).
Integration tests craft real packets with scapy, write them to a temp pcap,
and replay them through PcapFileSource, exercising the same path as
`sentryd replay`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from sentryd.core.events import Event


def make_event(
    ts: float = 0.0,
    protocol: str = "tcp",
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.9",
    src_port: int = 40000,
    dst_port: int = 80,
    tcp_flags: str = "S",
    length: int = 60,
    **kwargs,
) -> Event:
    if protocol != "tcp":
        tcp_flags = ""
    return Event(
        ts=ts,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        length=length,
        **kwargs,
    )


# -- scapy packet builders -----------------------------------------------------


def tcp_packet(
    src: str,
    dst: str,
    dport: int,
    ts: float,
    sport: int = 40123,
    flags: str = "S",
) -> Ether:
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    pkt.time = ts
    return pkt


def udp_packet(src: str, dst: str, dport: int, ts: float, sport: int = 40123) -> Ether:
    pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    pkt.time = ts
    return pkt


def arp_reply(sender_ip: str, sender_mac: str, target_ip: str, ts: float) -> Ether:
    pkt = Ether(src=sender_mac) / ARP(
        op=2, hwsrc=sender_mac, psrc=sender_ip, pdst=target_ip
    )
    pkt.time = ts
    return pkt


def syn_scan_packets(
    src: str = "192.168.1.66",
    target: str = "192.168.1.10",
    ports: range = range(1, 41),
    start_ts: float = 1000.0,
    interval: float = 0.05,
) -> list:
    """A classic vertical SYN scan: one source raking ports on one host."""
    return [
        tcp_packet(src, target, port, start_ts + i * interval)
        for i, port in enumerate(ports)
    ]


def benign_packets(start_ts: float = 1000.0) -> list:
    """Ordinary traffic: a couple of full handshakes and some DNS lookups."""
    packets = []
    ts = start_ts
    for i, dport in enumerate([80, 443, 443, 8080]):
        client, server = f"192.168.1.{20 + i}", "93.184.216.34"
        sport = 50000 + i
        packets += [
            tcp_packet(client, server, dport, ts, sport=sport, flags="S"),
            tcp_packet(server, client, sport, ts + 0.01, sport=dport, flags="SA"),
            tcp_packet(client, server, dport, ts + 0.02, sport=sport, flags="A"),
            tcp_packet(client, server, dport, ts + 0.5, sport=sport, flags="PA"),
            tcp_packet(client, server, dport, ts + 1.0, sport=sport, flags="FA"),
        ]
        ts += 2.0
    for i in range(5):
        packets.append(udp_packet(f"192.168.1.{20 + i}", "192.168.1.1", 53, ts + i))
    return packets


@pytest.fixture
def write_pcap(tmp_path: Path):
    """Write packets to a temp pcap file and return its path."""

    def _write(packets: list, name: str = "test.pcap") -> Path:
        path = tmp_path / name
        wrpcap(str(path), packets)
        return path

    return _write
